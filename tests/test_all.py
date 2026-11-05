import datetime
from unittest import mock

import pytest
import requests
from sqlalchemy import create_engine  # type: ignore

from cybercover.github_templates import (
    CACHE_TTL,
    TemplateLookupError,
    get_daily_additions,
    get_template_contents,
    installed_templates_version,
    latest_release,
    parse_version,
    templates_to_scan,
)
from cybercover.state import ScanStateStore


class FakeSession:
    def __init__(self, response, status_code=200):
        self.response = response
        self.status_code = status_code
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append(url)
        response = mock.Mock()
        response.status_code = self.status_code
        response.raise_for_status.return_value = None
        response.json.return_value = self.response
        response.content = self.response if isinstance(self.response, bytes) else b""
        return response


def _cache_set(cache, key, value, timeout=None):
    cache[key] = value


def test_parse_version_orders_numerically():
    assert parse_version("v10.5.1") > parse_version("v9.9.9")
    assert parse_version("v10.10.0") > parse_version("v10.9.0")
    for bad in (None, "10.5.0", "v10.5", "latest"):
        with pytest.raises(ValueError):
            parse_version(bad)


def test_daily_additions_is_cached_by_date_and_release():
    cache = {}
    ttl = []
    session = FakeSession(b"http/a.yaml\nhttp/b.yml\n")
    day = datetime.date(2026, 11, 5)
    def cache_set(key, value, timeout=None):
        ttl.append(timeout)
        _cache_set(cache, key, value)

    assert get_daily_additions(day, "v10.5.1", cache.get, cache_set, session) == {
        "http/a.yaml",
        "http/b.yml",
    }
    assert get_daily_additions(day, "v10.5.1", cache.get, cache_set, session) == {
        "http/a.yaml",
        "http/b.yml",
    }
    assert len(session.calls) == 1
    assert any("v10.5.1" in key for key in cache)
    assert ttl == [CACHE_TTL]


@pytest.mark.parametrize("bad_path", ["../outside.yaml", "/absolute.yaml", "http/README.md"])
def test_additions_reject_invalid_paths(bad_path):
    cache = {}
    session = FakeSession(f"{bad_path}\n".encode())
    with pytest.raises(TemplateLookupError):
        get_daily_additions(
            datetime.date(2026, 11, 5),
            "v10.5.1",
            cache.get,
            lambda k, v, timeout=None: _cache_set(cache, k, v),
            session,
        )


def test_template_selection_for_first_scan_and_release_transition():
    today = datetime.date(2026, 11, 5)
    additions = {"http/a.yaml"}
    assert templates_to_scan(None, None, "v10.5.1", today, additions, lambda _: None) == (additions, True)
    assert templates_to_scan(
        "v10.5.0",
        datetime.date(2026, 11, 4),
        "v10.5.1",
        today,
        additions,
        lambda _: None,
    ) == (additions, True)


def test_template_selection_diffs_daily_snapshots():
    today = datetime.date(2026, 11, 5)
    yesterday = datetime.date(2026, 11, 4)
    additions = {"http/a.yaml", "http/b.yaml"}
    old = {"http/a.yaml"}
    cache = {f"cybercover:additions:{yesterday.isoformat()}:v10.5.1": b'["http/a.yaml"]'}
    assert templates_to_scan(
        "v10.5.1",
        yesterday,
        "v10.5.1",
        today,
        additions,
        cache.get,
    ) == ({"http/b.yaml"}, False)


def test_template_selection_rescans_current_list_when_snapshot_was_evicted():
    today = datetime.date(2026, 11, 5)
    additions = {"http/a.yaml"}
    assert templates_to_scan(
        "v10.5.1",
        datetime.date(2026, 11, 4),
        "v10.5.1",
        today,
        additions,
        lambda _: None,
    ) == (additions, False)


def test_same_day_scan_has_no_delta():
    today = datetime.date(2026, 11, 5)
    assert templates_to_scan(
        "v10.5.1", today, "v10.5.1", today, {"http/a.yaml"}, lambda _: None
    ) == (set(), False)


def test_template_contents_are_cached_per_path_day_and_release():
    cache = {}
    session = FakeSession(b"id: test\n")
    paths = {"http/test.yaml"}
    day = datetime.date(2026, 11, 5)
    fetch = lambda: get_template_contents(
        paths, day, "v10.5.1", cache.get, lambda k, v, timeout=None: _cache_set(cache, k, v), session
    )
    assert fetch() == {"http/test.yaml": b"id: test\n"}
    assert fetch() == {"http/test.yaml": b"id: test\n"}
    assert len(session.calls) == 1


def test_latest_release_is_cached():
    cache = {}
    session = FakeSession({"tag_name": "v10.5.1"})
    assert latest_release(cache.get, lambda k, v, timeout=None: _cache_set(cache, k, v), session) == "v10.5.1"
    latest_release(cache.get, lambda k, v, timeout=None: _cache_set(cache, k, v), session)
    assert len(session.calls) == 1


def test_request_errors_are_reported():
    session = mock.Mock()
    session.get.side_effect = requests.ConnectionError("down")
    with pytest.raises(TemplateLookupError):
        get_daily_additions(
            datetime.date(2026, 11, 5),
            "v10.5.1",
            lambda _: None,
            lambda *args, **kwargs: None,
            session,
        )


def test_installed_version(tmp_path):
    path = tmp_path / "c.json"
    path.write_text('{"nuclei-templates-version": "v10.1.2"}')
    assert installed_templates_version(str(path)) == "v10.1.2"
    assert installed_templates_version(str(tmp_path / "missing")) is None


def test_state_store_roundtrip():
    store = ScanStateStore(engine=create_engine("sqlite://"))
    assert store.get_states(["a:80"]) == {}
    store.set_versions(["a:80", "b:443"], "v10.5.0")
    states = store.get_states(["a:80", "b:443", "c:1"])
    assert {target: value[0] for target, value in states.items()} == {"a:80": "v10.5.0", "b:443": "v10.5.0"}
    assert all(isinstance(value[1], datetime.datetime) for value in states.values())


def _module():
    from cybercover.modules.cybercover_nuclei import CybercoverNuclei

    module = CybercoverNuclei.__new__(CybercoverNuclei)
    module._state = ScanStateStore(engine=create_engine("sqlite://"))
    module.cache = mock.Mock()
    module.cache.get.return_value = None
    module.save_task_result = mock.Mock()
    module.lock = mock.MagicMock()
    module._incremental = False
    module._scanned_categories = set()
    module._nuclei_failures = 0
    module._custom_template_paths = {}
    module._use_native_nt = False
    return module


def _stored_version(module, target):
    return module.state.get_states([target])[target][0]


def _task(host, port=80):
    task = mock.Mock()
    task.get_payload.side_effect = {"host": host, "port": port}.get
    return task


@pytest.fixture(autouse=True)
def _mock_log():
    from cybercover.modules.cybercover_nuclei import CybercoverNuclei

    with mock.patch.object(CybercoverNuclei, "log", new_callable=mock.PropertyMock):
        yield


def test_scan_supplies_cached_custom_and_native_nt_templates(tmp_path):
    from artemis.modules.nuclei import ScanUsing

    module = _module()
    custom = tmp_path / "custom.yaml"
    custom.write_text("id: custom")
    module._incremental = True
    module._custom_template_paths = {"http/custom.yaml": str(custom)}
    module._use_native_nt = True
    module._severity_levels = ["high", "critical"]
    with mock.patch("artemis.modules.nuclei.Nuclei._scan", return_value=[]) as parent:
        module._scan(
            ["/root/nuclei-templates/http/old.yaml"],
            ScanUsing.TEMPLATES,
            ["https://example.com"],
            extra_nuclei_args=["-itags", "cve"],
        )
    assert parent.call_args.args[0] == [str(custom)]
    assert parent.call_args.kwargs["extra_nuclei_args"] == [
        "-itags",
        "cve",
        "-severity",
        "high,critical",
        "-nt",
    ]


def test_scan_keeps_dast_templates_separate():
    from artemis.modules.nuclei import ScanUsing

    module = _module()
    module._incremental = True
    module._custom_template_paths = {
        "http/custom.yaml": "/tmp/custom.yaml",
        "dast/custom.yaml": "/tmp/dast.yaml",
    }
    module._use_native_nt = True
    module._severity_levels = ["high"]
    with mock.patch("artemis.modules.nuclei.Nuclei._scan", return_value=[]) as parent:
        module._scan(
            ["dast/old.yaml"],
            ScanUsing.TEMPLATES,
            ["https://example.com"],
            extra_nuclei_args=["-dast"],
        )
    assert parent.call_args.args[0] == ["/tmp/dast.yaml"]
    assert parent.call_args.kwargs["extra_nuclei_args"] == ["-dast", "-severity", "high"]


def test_new_release_runs_nuclei_template_updater():
    module = _module()
    with mock.patch(
        "cybercover.modules.cybercover_nuclei.latest_release", return_value="v10.6.0"
    ), mock.patch(
        "cybercover.modules.cybercover_nuclei.installed_templates_version",
        return_value="v10.6.0",
    ), mock.patch(
        "cybercover.modules.cybercover_nuclei.directory_backup"
    ) as backup, mock.patch(
        "cybercover.modules.cybercover_nuclei.subprocess.check_call"
    ) as update:
        assert module._update_templates_if_needed("v10.5.1") == "v10.6.0"
    backup.assert_called_once()
    update.assert_called_once_with(["nuclei", "-update-templates"])


def test_native_nt_without_custom_templates_uses_placeholder():
    from artemis.modules.nuclei import ScanUsing
    from cybercover.modules.cybercover_nuclei import NEW_ADDITIONS_PLACEHOLDER

    module = _module()
    module._incremental = True
    module._use_native_nt = True
    with mock.patch("artemis.modules.nuclei.Nuclei._scan", return_value=[]) as parent:
        module._scan([], ScanUsing.TEMPLATES, ["https://example.com"], extra_nuclei_args=[])
    assert parent.call_args.args[0] == [NEW_ADDITIONS_PLACEHOLDER]
    assert "-nt" in parent.call_args.kwargs["extra_nuclei_args"]


def test_no_changes_saves_success_and_advances_state():
    from artemis.binds import TaskStatus

    module = _module()
    task = _task("example.com")
    day = datetime.date(2026, 11, 5)
    with mock.patch(
        "cybercover.modules.cybercover_nuclei.templates_to_scan", return_value=(set(), False)
    ), mock.patch(
        "cybercover.modules.cybercover_nuclei.get_template_contents", return_value={}
    ):
        module._run_group([task], "v10.5.1", day, "v10.5.1", day, set())
    assert module.save_task_result.call_args.kwargs["status"] == TaskStatus.OK
    assert _stored_version(module, "example.com:80") == "v10.5.1"


def test_run_group_keeps_state_if_template_lookup_fails():
    from artemis.binds import TaskStatus

    module = _module()
    task = _task("example.com")
    module.state.set_versions(["example.com:80"], "v10.5.0")
    day = datetime.date(2026, 11, 5)
    with mock.patch(
        "cybercover.modules.cybercover_nuclei.templates_to_scan",
        side_effect=TemplateLookupError("GitHub unavailable"),
    ):
        module._run_group([task], "v10.5.0", day, "v10.5.1", day, {"http/a.yaml"})
    assert module.save_task_result.call_args.kwargs["status"] == TaskStatus.ERROR
    assert _stored_version(module, "example.com:80") == "v10.5.0"


def test_run_group_scans_cached_yaml_then_saves_version(tmp_path):
    module = _module()
    task = _task("example.com")
    day = datetime.date(2026, 11, 5)
    with mock.patch(
        "cybercover.modules.cybercover_nuclei.templates_to_scan",
        return_value=({"http/a.yaml"}, False),
    ), mock.patch(
        "cybercover.modules.cybercover_nuclei.get_template_contents",
        return_value={"http/a.yaml": b"id: template\n"},
    ), mock.patch(
        "artemis.modules.nuclei.Nuclei.run_multiple",
        side_effect=lambda tasks: (
            Path(next(iter(module._custom_template_paths.values()))).read_text(),
            module.save_task_result(task=tasks[0], status=mock.sentinel.ok, data=[]),
        ),
    ) as scan:
        from pathlib import Path

        module._run_group([task], "v10.5.0", day, "v10.5.1", day, {"http/a.yaml"})
    assert scan.call_count == 1
    assert _stored_version(module, "example.com:80") == "v10.5.1"


def test_missing_template_on_main_is_skipped():
    session = FakeSession(b"", status_code=404)
    contents = get_template_contents(
        {"http/removed.yaml"}, datetime.date(2026, 11, 5), "v10.5.1", lambda _: None, lambda *a, **k: None, session
    )
    assert contents == {}


def test_link_scan_uses_only_changed_templates_from_the_homepage_list_without_nt():
    from artemis.modules.nuclei import NUCLEI_TEMPLATES_LOCATION, ScanUsing

    module = _module()
    module._incremental = True
    module._use_native_nt = True
    module._custom_template_paths = {"http/a.yaml": "/tmp/a.yaml", "http/b.yaml": "/tmp/b.yaml"}
    with mock.patch("artemis.modules.nuclei.Nuclei._scan", return_value=[]) as parent:
        module._scan([], ScanUsing.TEMPLATES, ["https://example.com"], extra_nuclei_args=[])
        module._scan(
            [NUCLEI_TEMPLATES_LOCATION + "http/b.yaml"], ScanUsing.TEMPLATES, ["https://example.com/x"], extra_nuclei_args=[]
        )
        module._scan([NUCLEI_TEMPLATES_LOCATION + "http/other.yaml"], ScanUsing.TEMPLATES, ["https://example.com/y"])
    assert parent.call_count == 2
    assert sorted(parent.call_args_list[0].args[0]) == ["/tmp/a.yaml", "/tmp/b.yaml"]
    assert "-nt" in parent.call_args_list[0].kwargs["extra_nuclei_args"]
    assert parent.call_args_list[1].args[0] == ["/tmp/b.yaml"]
    assert "-nt" not in parent.call_args_list[1].kwargs["extra_nuclei_args"]


def test_failed_nuclei_run_does_not_advance_state():
    from artemis.utils import CalledProcessErrorWithMessage

    module = _module()
    task = _task("example.com")
    module.state.set_versions(["example.com:80"], "v10.5.0")
    day = datetime.date(2026, 11, 5)

    def failing_run(tasks):
        import artemis.modules.nuclei as nuclei_module

        try:
            nuclei_module.check_output_log_on_error_with_stderr(["nuclei"], mock.Mock())
        except CalledProcessErrorWithMessage:
            pass

    with mock.patch(
        "cybercover.modules.cybercover_nuclei.templates_to_scan", return_value=({"http/a.yaml"}, False)
    ), mock.patch(
        "cybercover.modules.cybercover_nuclei.get_template_contents", return_value={"http/a.yaml": b"id: a\n"}
    ), mock.patch("artemis.modules.nuclei.Nuclei.run_multiple", side_effect=failing_run), mock.patch(
        "artemis.modules.nuclei.check_output_log_on_error_with_stderr",
        side_effect=CalledProcessErrorWithMessage("boom", 1, ["nuclei"], b"", b"boom"),
    ):
        module._run_group([task], "v10.5.0", day, "v10.5.1", day, {"http/a.yaml"})
    assert _stored_version(module, "example.com:80") == "v10.5.0"


def _port_scanner():
    from cybercover.modules.cybercover_port_scanner import CybercoverPortScanner
    from cybercover.state import DiscoveryStore

    scanner = CybercoverPortScanner.__new__(CybercoverPortScanner)
    scanner._store = DiscoveryStore(engine=create_engine("sqlite://"))
    scanner._capture = None
    scanner.cache = mock.Mock()
    scanner.save_task_result = mock.Mock()
    return scanner


def _domain_task(host, client="client.pl"):
    task = mock.Mock()
    task.headers = {"type": "domain"}
    task.payload_persistent = {"original_target": client}
    task.get_payload.side_effect = {"domain": host}.get
    return task


@pytest.fixture
def _ports_env():
    from cybercover.modules.cybercover_port_scanner import CybercoverPortScanner

    with mock.patch.object(CybercoverPortScanner, "log", new_callable=mock.PropertyMock), mock.patch(
        "cybercover.modules.cybercover_port_scanner.get_target_host", side_effect=lambda t: t.get_payload("domain")
    ), mock.patch(
        "cybercover.modules.cybercover_port_scanner.installed_templates_version", return_value="v10.5.0"
    ), mock.patch(
        "cybercover.modules.cybercover_port_scanner.latest_release", return_value="v10.5.0"
    ):
        yield


def test_first_scan_runs_discovery_and_stores_endpoints(_ports_env):
    from artemis.binds import Service, TaskType
    from karton.core import Task

    scanner = _port_scanner()
    task = _domain_task("www.client.pl")

    def stock_run(tasks):
        service = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP}, payload={"host": "www.client.pl", "port": 443, "ssl": True}
        )
        scanner.add_task(tasks[0], service)

    with mock.patch("artemis.module_base.ArtemisBase.add_task"), mock.patch(
        "artemis.modules.port_scanner.PortScanner.run_multiple", side_effect=stock_run
    ) as stock:
        scanner.run_multiple([task])
    assert stock.call_count == 1
    assert scanner._store.get_version("client.pl", "www.client.pl") == "v10.5.0"
    assert scanner._store.get_endpoints("client.pl", "www.client.pl") == [(443, "http", True)]
    assert scanner._capture is None


def test_known_host_without_new_release_replays_endpoints_without_scanning(_ports_env):
    scanner = _port_scanner()
    scanner._store.replace("client.pl", "www.client.pl", "v10.5.0", [(443, "http", True), (8080, "http", False)])
    task = _domain_task("www.client.pl")
    with mock.patch("artemis.module_base.ArtemisBase.add_task") as add, mock.patch(
        "artemis.modules.port_scanner.PortScanner.run_multiple"
    ) as stock:
        scanner.run_multiple([task])
    stock.assert_not_called()
    assert add.call_count == 2
    created = [call.args[1] for call in add.call_args_list]
    assert [t.get_payload("port") for t in created] == [443, 8080]
    assert [t.get_payload("ssl") for t in created] == [True, False]
    assert scanner.save_task_result.call_args.kwargs["data"] == {
        "www.client.pl": {"443": {"service": "http", "ssl": True}, "8080": {"service": "http", "ssl": False}}
    }


def test_new_release_triggers_rediscovery_and_replaces_endpoints(_ports_env):
    scanner = _port_scanner()
    scanner._store.replace("client.pl", "www.client.pl", "v10.4.0", [(8080, "http", False)])
    task = _domain_task("www.client.pl")
    with mock.patch("artemis.modules.port_scanner.PortScanner.run_multiple") as stock:
        scanner.run_multiple([task])
    stock.assert_called_once_with([task])
    assert scanner._store.get_version("client.pl", "www.client.pl") == "v10.5.0"
    assert scanner._store.get_endpoints("client.pl", "www.client.pl") == []


def test_failed_discovery_does_not_store_state(_ports_env):
    scanner = _port_scanner()
    task = _domain_task("www.client.pl")
    with mock.patch("artemis.modules.port_scanner.PortScanner.run_multiple", side_effect=RuntimeError("naabu")):
        with pytest.raises(RuntimeError):
            scanner.run_multiple([task])
    assert scanner._store.get_version("client.pl", "www.client.pl") is None
    assert scanner._capture is None


def test_discovery_uses_latest_release_when_not_yet_installed(_ports_env):
    scanner = _port_scanner()
    with mock.patch("cybercover.modules.cybercover_port_scanner.latest_release", return_value="v10.6.0"):
        assert scanner._current_version() == "v10.6.0"


def test_dast_scan_uses_release_dast_templates_as_absolute_paths_without_nt(tmp_path):
    from artemis.modules.nuclei import ScanUsing

    root = tmp_path / "nuclei-templates"
    (root / "dast").mkdir(parents=True)
    (root / "dast/new.yaml").write_text("id: new")
    (root / ".new-additions").write_text("http/a.yaml\ndast/new.yaml\ndast/gone.yaml\n")
    module = _module()
    module._incremental = True
    module._use_native_nt = True
    with mock.patch("cybercover.modules.cybercover_nuclei.NUCLEI_TEMPLATES_LOCATION", str(root) + "/"), mock.patch(
        "artemis.modules.nuclei.Nuclei._scan", return_value=[]
    ) as parent:
        module._scan([], ScanUsing.TEMPLATES, ["https://example.com"], use_fake_home=True, extra_nuclei_args=["-dast"])
    assert parent.call_args.args[0] == [str(root / "dast/new.yaml")]
    assert "-nt" not in parent.call_args.kwargs["extra_nuclei_args"]


def test_dast_scan_without_any_templates_is_skipped(tmp_path):
    from artemis.modules.nuclei import ScanUsing

    module = _module()
    module._incremental = True
    module._use_native_nt = True
    with mock.patch("cybercover.modules.cybercover_nuclei.NUCLEI_TEMPLATES_LOCATION", str(tmp_path) + "/"), mock.patch(
        "artemis.modules.nuclei.Nuclei._scan", return_value=[]
    ) as parent:
        assert module._scan([], ScanUsing.TEMPLATES, ["https://example.com"], extra_nuclei_args=["-dast"]) == []
    parent.assert_not_called()
