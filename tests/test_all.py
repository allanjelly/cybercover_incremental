from unittest import mock

import pytest
import requests
from sqlalchemy import create_engine  # type: ignore

from cybercover.github_templates import (
    TemplateLookupError,
    TooManyChangesError,
    fetch_changed_templates,
    get_changed_templates,
    get_previous_release,
    installed_templates_version,
    parse_version,
    previous_release,
)
from cybercover.state import ScanStateStore


class FakeSession:
    def __init__(self, responses):
        self.responses = responses

    def get(self, url, params=None, headers=None, timeout=None):
        response = mock.Mock()
        response.json.return_value = self.responses(url, params)
        response.raise_for_status.return_value = None
        return response


def _files(*items):
    return [{"filename": name, "status": status} for name, status in items]


def test_parse_version_orders_numerically():
    assert parse_version("v10.5.1") > parse_version("v9.9.9")
    assert parse_version("v10.10.0") > parse_version("v10.9.0")
    for bad in (None, "10.5.0", "v10.5", "latest"):
        with pytest.raises(ValueError):
            parse_version(bad)


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

    assert fetch_changed_templates("v10.4.0", "v10.5.0", FakeSession(responses)) == {
        "http/a.yaml",
        "http/b.yaml",
        "http/c.yaml",
    }


def test_fetch_refuses_truncated_list():
    full = {"files": _files(*[(f"http/{i}.yaml", "added") for i in range(300)])}
    with pytest.raises(TooManyChangesError):
        fetch_changed_templates("v10.4.0", "v10.5.0", FakeSession(lambda u, p: full))
    ok = {"files": _files(*[(f"http/{i}.yaml", "added") for i in range(299)])}
    assert len(fetch_changed_templates("v10.4.0", "v10.5.0", FakeSession(lambda u, p: ok))) == 299


def test_fetch_errors_are_wrapped():
    session = mock.Mock()
    session.get.side_effect = requests.ConnectionError("down")
    with pytest.raises(TemplateLookupError):
        fetch_changed_templates("v10.4.0", "v10.5.0", session)


def test_previous_release_picks_newest_older_tag():
    releases = [{"tag_name": t} for t in ("v10.5.1", "v10.5.0", "v10.4.9", "junk", "v10.10.0")]
    session = FakeSession(lambda u, p: releases)
    assert previous_release("v10.5.1", session) == "v10.5.0"
    assert previous_release("v10.10.0", session) == "v10.5.1"
    with pytest.raises(TemplateLookupError):
        previous_release("v10.4.9", session)


def test_cache_is_used_for_second_lookup():
    store = {}
    with mock.patch("cybercover.github_templates.fetch_changed_templates", return_value={"a.yaml"}) as fetch:
        args = ("v10.4.0", "v10.5.0", store.get, lambda k, v: store.__setitem__(k, v))
        assert get_changed_templates(*args) == {"a.yaml"}
        assert get_changed_templates(*args) == {"a.yaml"}
    assert fetch.call_count == 1


def test_too_many_changes_is_cached():
    store = {}
    args = ("v10.0.0", "v10.5.0", store.get, lambda k, v: store.__setitem__(k, v))
    with mock.patch(
        "cybercover.github_templates.fetch_changed_templates", side_effect=TooManyChangesError("x")
    ) as fetch:
        for _ in range(2):
            with pytest.raises(TooManyChangesError):
                get_changed_templates(*args)
    assert fetch.call_count == 1


def test_previous_release_is_cached():
    store = {}
    with mock.patch("cybercover.github_templates.previous_release", return_value="v10.5.0") as prev:
        args = ("v10.5.1", store.get, lambda k, v: store.__setitem__(k, v))
        assert get_previous_release(*args) == "v10.5.0"
        assert get_previous_release(*args) == "v10.5.0"
    assert prev.call_count == 1


def test_installed_version(tmp_path):
    path = tmp_path / "c.json"
    path.write_text('{"nuclei-templates-version": "v10.1.2"}')
    assert installed_templates_version(str(path)) == "v10.1.2"
    assert installed_templates_version(str(tmp_path / "missing")) is None


def test_state_store_roundtrip():
    store = ScanStateStore(engine=create_engine("sqlite://"))
    assert store.get_versions(["a:80"]) == {}
    store.set_versions(["a:80", "b:443"], "v10.5.0")
    store.set_versions(["a:80"], "v10.5.1")
    assert store.get_versions(["a:80", "b:443", "c:1"]) == {"a:80": "v10.5.1", "b:443": "v10.5.0"}


def _module():
    from cybercover.modules.cybercover_nuclei import CybercoverNuclei

    module = CybercoverNuclei.__new__(CybercoverNuclei)  # skip the heavy Nuclei.__init__
    module._state = ScanStateStore(engine=create_engine("sqlite://"))
    module.cache = mock.Mock()
    module.cache.get.return_value = None
    module.save_task_result = mock.Mock()
    return module


def _task(host, port=80):
    task = mock.Mock()
    task.get_payload.side_effect = {"host": host, "port": port}.get
    return task


@pytest.fixture(autouse=True)
def _mock_log():
    from cybercover.modules.cybercover_nuclei import CybercoverNuclei

    with mock.patch.object(CybercoverNuclei, "log", new_callable=mock.PropertyMock):
        yield


def test_scan_filters_templates_and_skips_workflows():
    from artemis.modules.nuclei import ScanUsing

    module = _module()
    module._incremental = True
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


def test_scan_is_unfiltered_when_not_incremental():
    from artemis.modules.nuclei import ScanUsing

    module = _module()
    with mock.patch("artemis.modules.nuclei.Nuclei._scan", return_value=[]) as parent:
        module._scan(["a.yaml", "b.yaml"], ScanUsing.TEMPLATES, ["t"])
    assert parent.call_args.args[0] == ["a.yaml", "b.yaml"]


def _run(module, tasks, changed=None, head="v10.5.1", previous="v10.5.0"):
    seen = []
    if isinstance(changed, Exception):
        lookup = mock.Mock(side_effect=changed)
    else:
        lookup = mock.Mock(side_effect=lambda after, h, *a: changed[after])
    with mock.patch(
        "cybercover.modules.cybercover_nuclei.installed_templates_version", return_value=head
    ), mock.patch(
        "cybercover.modules.cybercover_nuclei.get_previous_release", return_value=previous
    ), mock.patch(
        "cybercover.modules.cybercover_nuclei.get_changed_templates", lookup
    ), mock.patch(
        "artemis.modules.nuclei.Nuclei.run_multiple",
        lambda self, t: seen.append((self._incremental, self._changed, len(t))),
    ):
        module.run_multiple(tasks)
    return seen


def test_new_target_starts_from_previous_release_and_state_is_saved():
    module = _module()
    seen = _run(module, [_task("a.pl")], changed={"v10.5.0": {"x.yaml"}})
    assert seen == [(True, {"x.yaml"}, 1)]
    assert module.state.get_versions(["a.pl:80"]) == {"a.pl:80": "v10.5.1"}
    assert module._changed is None and module._incremental is False


def test_known_targets_are_grouped_by_their_version():
    module = _module()
    module.state.set_versions(["old.pl:80"], "v10.4.0")
    module.state.set_versions(["same.pl:80"], "v10.5.1")
    seen = _run(
        module,
        [_task("old.pl"), _task("same.pl"), _task("new.pl"), _task("old.pl", 8080)],
        changed={"v10.4.0": {"o.yaml"}, "v10.5.0": {"n.yaml"}},
    )
    assert sorted(seen, key=lambda s: sorted(s[1])) == [(True, {"n.yaml"}, 2), (True, {"o.yaml"}, 1)]
    # same.pl is already up to date: no scan, OK result
    assert module.save_task_result.call_args.kwargs["status_reason"] == "No new templates"
    assert set(module.state.get_versions(["old.pl:80", "same.pl:80", "new.pl:80", "old.pl:8080"]).values()) == {"v10.5.1"}


def test_too_many_changes_falls_back_to_full_scan():
    module = _module()
    module.state.set_versions(["a.pl:80"], "v10.0.0")
    seen = _run(module, [_task("a.pl")], changed=TooManyChangesError("big"))
    assert seen == [(False, None, 1)]
    assert module.state.get_versions(["a.pl:80"]) == {"a.pl:80": "v10.5.1"}


def test_lookup_error_reports_error_and_keeps_state():
    from artemis.binds import TaskStatus

    module = _module()
    module.state.set_versions(["a.pl:80"], "v10.4.0")
    seen = _run(module, [_task("a.pl")], changed=TemplateLookupError("down"))
    assert seen == []
    assert module.save_task_result.call_args.kwargs["status"] == TaskStatus.ERROR
    assert module.state.get_versions(["a.pl:80"]) == {"a.pl:80": "v10.4.0"}


def test_failed_scan_keeps_state():
    module = _module()
    module.state.set_versions(["a.pl:80"], "v10.4.0")
    with mock.patch("cybercover.modules.cybercover_nuclei.installed_templates_version", return_value="v10.5.1"), mock.patch(
        "cybercover.modules.cybercover_nuclei.get_changed_templates", return_value={"x.yaml"}
    ), mock.patch("artemis.modules.nuclei.Nuclei.run_multiple", side_effect=RuntimeError("nuclei crashed")):
        with pytest.raises(RuntimeError):
            module.run_multiple([_task("a.pl")])
    assert module.state.get_versions(["a.pl:80"]) == {"a.pl:80": "v10.4.0"}
    assert module._changed is None and module._incremental is False


def test_unknown_installed_version_reports_error():
    module = _module()
    seen = _run(module, [_task("a.pl")], changed={}, head=None)
    assert seen == []
    assert module.save_task_result.call_count == 1
