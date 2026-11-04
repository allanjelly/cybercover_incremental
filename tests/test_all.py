import datetime
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
    parse_after,
    today_utc,
)

DAY = datetime.timedelta(days=1)


def test_config_roundtrip_and_validation():
    yesterday = (today_utc() - DAY).isoformat()
    config = CybercoverNucleiConfiguration.deserialize({"after": yesterday})
    assert config.after == today_utc() - DAY
    assert config.validate()
    assert CybercoverNucleiConfiguration.deserialize(config.serialize()).serialize() == config.serialize()


@pytest.mark.parametrize(
    "bad",
    [{"after": "yesterday"}, {"after": "2026-11-01", "x": 1}, {"after": "2026-11-01", "change_type": "all"}],
)
def test_config_rejects(bad):
    with pytest.raises((ValueError, KeyError)):
        CybercoverNucleiConfiguration.deserialize(bad)


def test_config_after_range():
    assert not CybercoverNucleiConfiguration().validate()
    assert not CybercoverNucleiConfiguration(after=today_utc() + DAY).validate()
    assert not CybercoverNucleiConfiguration(after=today_utc() - 31 * DAY).validate()
    assert CybercoverNucleiConfiguration(after=today_utc() - 30 * DAY).validate()
    assert CybercoverNucleiConfiguration(after=today_utc()).validate()


def test_parse_after_datetime_becomes_utc_date():
    assert parse_after("2026-11-01T23:30:00-02:00") == datetime.date(2026, 11, 2)


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
        if url.endswith("/commits"):
            assert params["until"].startswith("2026-11-03T00:00:00")
            return [{"sha": "base123"}]
        assert url.endswith("/compare/base123...v10.0.0")
        return {
            "files": _files(
                ("http/a.yaml", "added"),
                ("http/b.yaml", "modified"),
                ("http/c.yaml", "removed"),
                ("http/d.yaml", "renamed"),
                ("README.md", "added"),
            )
        }

    session = FakeSession(responses)
    after = datetime.date(2026, 11, 3)
    assert fetch_changed_templates(after, ChangeType.ADDED, "v10.0.0", session) == {"http/a.yaml", "http/d.yaml"}
    assert fetch_changed_templates(after, ChangeType.ADDED_OR_MODIFIED, "v10.0.0", session) == {
        "http/a.yaml",
        "http/b.yaml",
        "http/d.yaml",
    }


def test_fetch_paginates_and_refuses_partial_lists():
    pages = {1: _files(*[(f"p1/{i}.yaml", "added") for i in range(100)]), 2: _files(("p2/x.yaml", "added"))}

    def responses(url, params):
        return [{"sha": "b"}] if url.endswith("/commits") else {"files": pages[params["page"]]}

    assert len(fetch_changed_templates(datetime.date(2026, 11, 3), ChangeType.ADDED, "v1", FakeSession(responses))) == 101

    def too_many(url, params):
        return [{"sha": "b"}] if url.endswith("/commits") else {"files": _files(*[(f"{params['page']}/{i}.yaml", "added") for i in range(100)])}

    with pytest.raises(TemplateLookupError):
        fetch_changed_templates(datetime.date(2026, 11, 3), ChangeType.ADDED, "v1", FakeSession(too_many))


def test_fetch_errors_are_wrapped():
    import requests

    session = mock.Mock()
    session.get.side_effect = requests.ConnectionError("boom")
    with pytest.raises(TemplateLookupError):
        fetch_changed_templates(datetime.date(2026, 11, 3), ChangeType.ADDED, "v1", session)


def test_cache_is_used_for_second_lookup():
    store = {}
    with mock.patch("cybercover.github_templates.fetch_changed_templates", return_value={"a.yaml"}) as fetch:
        args = (datetime.date(2026, 11, 3), ChangeType.ADDED, "v1", store.get, lambda k, v: store.__setitem__(k, v))
        assert get_changed_templates(*args) == {"a.yaml"}
        assert get_changed_templates(*args) == {"a.yaml"}
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
    task.payload_persistent = {"module_runtime_configurations": {"cybercover_nuclei": {"after": today_utc().isoformat()}}}
    with mock.patch("cybercover.modules.cybercover_nuclei.get_changed_templates", side_effect=TemplateLookupError("down")):
        module.run_multiple([task])
    assert module.save_task_result.call_args.kwargs["status"] == TaskStatus.ERROR


def test_run_multiple_sets_changed_and_delegates():
    module = _module()
    module.cache = mock.Mock()
    task = mock.Mock()
    task.payload_persistent = {"module_runtime_configurations": {"cybercover_nuclei": {"after": today_utc().isoformat()}}}
    seen = {}
    with mock.patch("cybercover.modules.cybercover_nuclei.get_changed_templates", return_value={"a.yaml"}), mock.patch(
        "artemis.modules.nuclei.Nuclei.run_multiple", lambda self, tasks: seen.update(changed=self._changed)
    ):
        module.run_multiple([task])
    assert seen["changed"] == {"a.yaml"}
    assert module._changed is None


def test_main_patches_artemis_api():
    # needs a writable /data (artemis.main stores its secrets there on import)
    import cybercover.main as m

    calls = []
    wrapped = m.wrap_create_tasks(lambda *a, **k: calls.append(k))
    cfg = {"cybercover_nuclei": {"after": "2026-11-01"}}
    wrapped(["x"], disabled_modules=["port_scanner", "nuclei-router", "ssh_bruter", "cybercover_nuclei"], module_runtime_configurations=cfg)
    wrapped(["x"], disabled_modules=["ssh_bruter"])
    assert sorted(calls[0]["disabled_modules"]) == ["nuclei-module", "ssh_bruter"]
    assert calls[1]["disabled_modules"] == ["ssh_bruter", "cybercover_nuclei"]
    assert "cybercover_nuclei" in m.artemis_api.RUNTIME_CONFIGURATION_CLASSES
    assert "cybercover_nuclei" in m.Config.Miscellaneous.MODULES_DISABLED_BY_DEFAULT
