from unittest import mock

import pytest

from cybercover.github_templates import (
    TemplateLookupError,
    fetch_changed_templates,
    get_changed_templates,
    installed_templates_version,
)
from cybercover.modules.cybercover_nuclei_configuration import (
    ChangeType,
    CybercoverNucleiConfiguration,
    parse_version,
)

def test_config_roundtrip_and_validation():
    config = CybercoverNucleiConfiguration.deserialize({"after_version": "v10.5.0"})
    assert config.after_version == "v10.5.0"
    assert config.validate()
    assert CybercoverNucleiConfiguration.deserialize(config.serialize()).serialize() == config.serialize()


@pytest.mark.parametrize(
    "bad",
    [{"after": "2026-11-01"}, {"after_version": "v10.5.0", "x": 1}, {"after_version": "v10.5.0", "change_type": "all"}],
)
def test_config_rejects(bad):
    with pytest.raises((KeyError, ValueError)):
        CybercoverNucleiConfiguration.deserialize(bad)


@pytest.mark.parametrize("bad", [None, "10.5.0", "v10.5", "latest", "v10.5.0; rm"])
def test_config_validation_rejects_bad_version(bad):
    assert not CybercoverNucleiConfiguration(after_version=bad).validate()


def test_parse_version_orders_numerically():
    assert parse_version("v10.5.1") > parse_version("v9.9.9")
    assert parse_version("v10.10.0") > parse_version("v10.9.0")


class FakeSession:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, params))
        body = self.responses(url, params)
        response = mock.Mock()
        response.json.return_value = body
        response.raise_for_status.return_value = None
        return response


def _files(*items):
    return [{"filename": name, "status": status} for name, status in items]


def test_fetch_changed_templates_filters_by_status():
    def responses(url, params):
        assert url.endswith("/compare/v10.4.0...v10.5.0")
        return {
            "files": _files(
                ("http/a.yaml", "added"),
                ("http/b.yaml", "modified"),
                ("http/c.yaml", "renamed"),
                ("http/d.yaml", "removed"),
                ("README.md", "added"),
            )
        }

    session = FakeSession(responses)
    assert fetch_changed_templates("v10.4.0", ChangeType.ADDED, "v10.5.0", session) == (
        {"http/a.yaml", "http/c.yaml"},
        "v10.5.0",
    )
    assert fetch_changed_templates("v10.4.0", ChangeType.ADDED_OR_MODIFIED, "v10.5.0", session)[0] == {
        "http/a.yaml",
        "http/b.yaml",
        "http/c.yaml",
    }


@pytest.mark.parametrize("after", ["v10.5.0", "v10.6.0"])
def test_fetch_same_or_newer_version_returns_installed_without_diff(after):
    session = FakeSession(lambda url, params: pytest.fail("no request expected"))
    assert fetch_changed_templates(after, ChangeType.ADDED_OR_MODIFIED, "v10.5.0", session) == (set(), "v10.5.0")
    assert session.calls == []


def test_fetch_refuses_truncated_list():
    full = {"files": _files(*[(f"http/{i}.yaml", "added") for i in range(300)])}
    with pytest.raises(TemplateLookupError):
        fetch_changed_templates("v10.4.0", ChangeType.ADDED, "v10.5.0", FakeSession(lambda u, p: full))
    ok = {"files": _files(*[(f"http/{i}.yaml", "added") for i in range(299)])}
    assert len(fetch_changed_templates("v10.4.0", ChangeType.ADDED, "v10.5.0", FakeSession(lambda u, p: ok))[0]) == 299


def test_fetch_rejects_unknown_installed_or_invalid_version():
    with pytest.raises(TemplateLookupError):
        fetch_changed_templates("v10.4.0", ChangeType.ADDED, None, FakeSession(lambda u, p: {}))
    with pytest.raises(TemplateLookupError):
        fetch_changed_templates("bogus", ChangeType.ADDED, "v10.5.0", FakeSession(lambda u, p: {}))


def test_fetch_errors_are_wrapped():
    import requests

    session = mock.Mock()
    session.get.side_effect = requests.ConnectionError("boom")
    with pytest.raises(TemplateLookupError):
        fetch_changed_templates("v10.4.0", ChangeType.ADDED, "v10.5.0", session)


def test_cache_is_used_for_second_lookup():
    store = {}
    covered_until = "v10.5.0"
    with mock.patch(
        "cybercover.github_templates.fetch_changed_templates", return_value=({"a.yaml"}, covered_until)
    ) as fetch:
        args = ("v10.4.0", ChangeType.ADDED, "v10.5.0", store.get, lambda k, v: store.__setitem__(k, v))
        assert get_changed_templates(*args) == ({"a.yaml"}, covered_until)
        assert get_changed_templates(*args) == ({"a.yaml"}, covered_until)
    assert fetch.call_count == 1


def test_installed_version(tmp_path):
    path = tmp_path / "c.json"
    path.write_text('{"nuclei-templates-version": "v10.1.2"}')
    assert installed_templates_version(str(path)) == "v10.1.2"
    assert installed_templates_version(str(tmp_path / "missing")) is None


def _module():
    from cybercover.modules.cybercover_nuclei import CybercoverNuclei

    return CybercoverNuclei.__new__(CybercoverNuclei)  # skip the heavy Nuclei.__init__


@pytest.fixture(autouse=True)
def _mock_log():
    from cybercover.modules.cybercover_nuclei import CybercoverNuclei

    with mock.patch.object(CybercoverNuclei, "log", new_callable=mock.PropertyMock):
        yield


def test_scan_filters_templates_and_skips_workflows():
    from artemis.modules.nuclei import ScanUsing

    module = _module()
    module._changed = {"http/cves/new.yaml"}
    with mock.patch("artemis.modules.nuclei.Nuclei._scan", return_value=[]) as parent:
        module._scan(
            ["/root/nuclei-templates/http/cves/new.yaml", "http/cves/old.yaml", "/custom/x.yaml"],
            ScanUsing.TEMPLATES,
            ["t"],
        )
        assert module._scan(["/workflows"], ScanUsing.WORKFLOWS, ["t"]) == []
    assert parent.call_count == 1
    assert parent.call_args.args[0] == ["/root/nuclei-templates/http/cves/new.yaml"]


def test_run_multiple_reports_error_when_lookup_fails():
    from artemis.binds import TaskStatus

    module = _module()
    module.cache = mock.Mock()
    module.save_task_result = mock.Mock()
    task = mock.Mock()
    task.payload_persistent = {"module_runtime_configurations": {"cybercover_nuclei": {"after_version": "v10.4.0"}}}
    with mock.patch("cybercover.modules.cybercover_nuclei.get_changed_templates", side_effect=TemplateLookupError("down")):
        module.run_multiple([task])
    assert module.save_task_result.call_args.kwargs["status"] == TaskStatus.ERROR


def test_run_multiple_sets_changed_and_delegates():
    module = _module()
    module.cache = mock.Mock()
    task = mock.Mock()
    task.payload_persistent = {"module_runtime_configurations": {"cybercover_nuclei": {"after_version": "v10.4.0"}}}
    seen = {}
    covered_until = "v10.5.0"
    with mock.patch(
        "cybercover.modules.cybercover_nuclei.get_changed_templates",
        return_value=({"a.yaml"}, covered_until),
    ), mock.patch(
        "artemis.modules.nuclei.Nuclei.run_multiple", lambda self, tasks: seen.update(changed=self._changed)
    ):
        module.run_multiple([task])
    assert seen["changed"] == {"a.yaml"}
    task.add_payload.assert_called_once_with("covered_until", covered_until, persistent=True)
    assert module._changed is None


def test_main_patches_artemis_api():
    # needs a writable /data (artemis.main stores its secrets there on import)
    import cybercover.main as m

    calls = []
    wrapped = m.wrap_create_tasks(lambda *a, **k: calls.append(k))
    cfg = {"cybercover_nuclei": {"after_version": "v10.4.0"}}
    wrapped(["x"], disabled_modules=["port_scanner", "nuclei-router", "ssh_bruter", "cybercover_nuclei"], module_runtime_configurations=cfg)
    wrapped(["x"], disabled_modules=["ssh_bruter"])
    assert sorted(calls[0]["disabled_modules"]) == ["nuclei-module", "ssh_bruter"]
    assert calls[1]["disabled_modules"] == ["ssh_bruter", "cybercover_nuclei"]
    assert "cybercover_nuclei" in m.artemis_api.RUNTIME_CONFIGURATION_CLASSES
    assert "cybercover_nuclei" in m.Config.Miscellaneous.MODULES_DISABLED_BY_DEFAULT
