"""Tests for the Phase 1 fixes (N1-N7, P1-P3); see README "Behaviour details"."""

import datetime
import os
from unittest import mock

import pytest
from sqlalchemy import create_engine  # type: ignore

from test_all import _ports_env  # noqa: F401 - shared fixture
from test_all import DAY, _domain_task, _module, _port_scanner, _set_state, _stored, _task, _template



def _scan_args() -> tuple:
    """Nuclei._scan's scan_using argument, which Artemis removed in 2fee327d (workflows)."""
    try:
        from artemis.modules.nuclei import ScanUsing
    except ImportError:
        return ()
    return (ScanUsing.TEMPLATES,)

def _today():
    return datetime.datetime.now(datetime.timezone.utc).date()


# --- N1: one template lock shared with Artemis' nuclei-module -------------------------------------


def test_lock_is_shared_with_stock_nuclei_module():
    from artemis.resource_lock import ResourceLock
    from cybercover.modules.cybercover_nuclei import CybercoverNuclei

    module = CybercoverNuclei.__new__(CybercoverNuclei)
    module.lock = ResourceLock(res_name=CybercoverNuclei.identity)  # what ArtemisBase.__init__ does
    assert module.lock.res_name == "nuclei-module"


def test_template_update_holds_shared_lock_and_skips_if_already_installed():
    module = _module()
    with mock.patch("cybercover.modules.cybercover_nuclei.latest_release", return_value="v10.6.0"), mock.patch(
        # Installed v10.5.1 when checked, v10.6.0 once we hold the lock (stock module updated meanwhile).
        "cybercover.modules.cybercover_nuclei.installed_templates_version",
        side_effect=["v10.6.0", "v10.6.0"],
    ), mock.patch("cybercover.modules.cybercover_nuclei.subprocess.check_call") as update:
        assert module._update_templates_if_needed("v10.5.1") == "v10.6.0"
    update.assert_not_called()
    module._shared_templates_lock.__enter__.assert_called_once()


# --- N2: state per customer -----------------------------------------------------------------------


def test_customers_sharing_an_endpoint_keep_separate_state():
    module = _module()
    today = _today()
    # Customer A was already scanned today on the shared host; customer B never.
    _set_state(module, "203.0.113.7", "v10.5.1", port=443, client="a.pl", snapshot_date=today)
    task_a = _task("203.0.113.7", 443, client="a.pl")
    task_b = _task("203.0.113.7", 443, client="b.pl")
    module._run_group = mock.Mock()
    with mock.patch(
        "cybercover.modules.cybercover_nuclei.installed_templates_version", return_value="v10.5.1"
    ), mock.patch.object(module, "_update_templates_if_needed", return_value="v10.5.1"), mock.patch.object(
        module, "_log_nuclei_version"
    ), mock.patch(
        "cybercover.modules.cybercover_nuclei.get_daily_additions", return_value={"http/new.yaml"}
    ):
        module.run_multiple([task_a, task_b])
    groups = {tuple(call.args[0]): call.args[1:3] for call in module._run_group.call_args_list}
    assert groups == {(task_a,): ("v10.5.1", today), (task_b,): (None, None)}


def test_scan_state_is_stored_per_customer():
    module = _module()
    tasks = [_task("203.0.113.7", 443, client="a.pl"), _task("203.0.113.7", 443, client="b.pl")]
    with mock.patch(
        "cybercover.modules.cybercover_nuclei.templates_to_scan", return_value=(set(), False)
    ), mock.patch("cybercover.modules.cybercover_nuclei.get_template_contents", return_value={}):
        module._run_group(tasks[:1], None, None, "v10.5.1", DAY, set())
    assert _stored(module, "203.0.113.7", 443, client="a.pl") == ("v10.5.1", DAY)
    assert _stored(module, "203.0.113.7", 443, client="b.pl") is None


# --- N4: the next scan diffs against the snapshot actually used -----------------------------------


def test_snapshot_date_is_the_batch_start_day_not_the_completion_time():
    module = _module()
    start_day = datetime.date(2026, 11, 5)

    def scan_until_after_midnight(tasks):
        # Wall clock moves to the next day while Nuclei runs; the stored date must not follow it.
        pass

    with mock.patch(
        "cybercover.modules.cybercover_nuclei.templates_to_scan", return_value=({"http/a.yaml"}, False)
    ), mock.patch(
        "cybercover.modules.cybercover_nuclei.get_template_contents", return_value={"http/a.yaml": _template("high")}
    ), mock.patch("artemis.modules.nuclei.Nuclei.run_multiple", side_effect=scan_until_after_midnight):
        module._run_group([_task("example.com")], "v10.5.1", start_day - datetime.timedelta(days=1), "v10.5.1",
                          start_day, {"http/a.yaml"})
    assert _stored(module, "example.com") == ("v10.5.1", start_day)


def test_next_day_diff_uses_stored_snapshot():
    from cybercover.github_templates import templates_to_scan

    cache = {"cybercover:additions:2026-11-05:v10.5.1": b'["http/a.yaml"]'}
    changed, native = templates_to_scan(
        "v10.5.1", datetime.date(2026, 11, 5), "v10.5.1", datetime.date(2026, 11, 6),
        {"http/a.yaml", "http/late-on-the-5th.yaml"}, cache.get,
    )
    assert (changed, native) == ({"http/late-on-the-5th.yaml"}, False)


# --- N3: invalid or missing templates are skipped -------------------------------------------------


def test_invalid_template_does_not_block_the_group():
    module = _module()
    with mock.patch(
        "cybercover.modules.cybercover_nuclei.templates_to_scan", return_value=({"http/bad.yaml", "http/good.yaml"}, False)
    ), mock.patch(
        "cybercover.modules.cybercover_nuclei.get_template_contents",
        return_value={"http/bad.yaml": b"info: [", "http/good.yaml": _template("high")},
    ), mock.patch("artemis.modules.nuclei.Nuclei.run_multiple") as scan:
        scan.side_effect = lambda _: (
            set(module._custom_template_paths) == {"http/good.yaml"} or pytest.fail(str(module._custom_template_paths))
        )
        module._run_group([_task("example.com")], "v10.5.1", DAY - datetime.timedelta(days=1), "v10.5.1", DAY, set())
    scan.assert_called_once()
    assert _stored(module, "example.com") == ("v10.5.1", DAY)


def test_only_invalid_templates_still_completes():
    from artemis.binds import TaskStatus

    module = _module()
    with mock.patch(
        "cybercover.modules.cybercover_nuclei.templates_to_scan", return_value=({"http/bad.yaml"}, False)
    ), mock.patch(
        "cybercover.modules.cybercover_nuclei.get_template_contents", return_value={"http/bad.yaml": b"info: ["}
    ), mock.patch("artemis.modules.nuclei.Nuclei.run_multiple") as scan:
        module._run_group([_task("example.com")], "v10.5.1", DAY, "v10.5.1", DAY, set())
    scan.assert_not_called()
    assert module.save_task_result.call_args.kwargs["status"] == TaskStatus.OK
    assert _stored(module, "example.com") == ("v10.5.1", DAY)


def test_release_file_missing_from_disk_is_skipped(tmp_path):
    from cybercover.modules.cybercover_nuclei import release_template_contents

    (tmp_path / "http").mkdir()
    (tmp_path / ".new-additions").write_text("http/present.yaml\nhttp/missing.yaml\nREADME.md\n")
    (tmp_path / "http/present.yaml").write_bytes(_template("high"))
    contents, missing = release_template_contents(str(tmp_path))
    assert set(contents) == {"http/present.yaml"}
    assert missing == ["http/missing.yaml"]


# --- N5: a batch Nuclei cannot load is skipped, not a failure -------------------------------------


def test_batch_nuclei_cannot_load_is_not_a_failure():
    from artemis.utils import CalledProcessErrorWithMessage

    module = _module()
    _set_state(module, "example.com", "v10.5.0")

    def run(tasks):
        import artemis.modules.nuclei as nuclei_module

        try:
            nuclei_module.check_output_log_on_error_with_stderr(["nuclei"], mock.Mock())
        except CalledProcessErrorWithMessage:
            pass  # the stock _scan logs and continues

    unloadable = CalledProcessErrorWithMessage(
        "error", 1, ["nuclei"], b"", b"[FTL] Could not run nuclei: no templates provided for scan"
    )
    with mock.patch(
        "cybercover.modules.cybercover_nuclei.templates_to_scan", return_value=({"http/a.yaml"}, False)
    ), mock.patch(
        "cybercover.modules.cybercover_nuclei.get_template_contents", return_value={"http/a.yaml": _template("high")}
    ), mock.patch("artemis.modules.nuclei.Nuclei.run_multiple", side_effect=run), mock.patch(
        "artemis.modules.nuclei.check_output_log_on_error_with_stderr", side_effect=unloadable
    ):
        module._run_group([_task("example.com")], "v10.5.0", DAY, "v10.5.1", DAY, {"http/a.yaml"})
    assert module._nuclei_failures == 0 and module._unloadable_runs == 1
    assert _stored(module, "example.com") == ("v10.5.1", DAY)


def test_real_nuclei_reports_unloadable_batch_as_expected(tmp_path):
    """Guards the error text N5 relies on against the Nuclei version in the Artemis image."""
    import shutil
    import subprocess

    from cybercover.modules.cybercover_nuclei import NO_LOADABLE_TEMPLATES

    if not shutil.which("nuclei"):
        pytest.skip("Nuclei binary not available")
    template = tmp_path / "future.yaml"
    template.write_text(
        "id: future\ninfo:\n  name: f\n  author: t\n  severity: high\nhttp:\n  - method: GET\n"
        "    path: ['{{BaseURL}}/']\n    matchers:\n      - type: future-matcher-type\n"
    )
    result = subprocess.run(
        ["nuclei", "-disable-update-check", "-silent", "-t", str(template), "-target", "http://127.0.0.1:9"],
        capture_output=True, timeout=120, env={**os.environ, "HOME": str(tmp_path)},
    )
    assert result.returncode != 0
    assert NO_LOADABLE_TEMPLATES in (result.stdout + result.stderr).decode()


# --- N6: no homepage crawl when no selected template needs it -------------------------------------


@pytest.mark.parametrize(
    "incremental, homepage_list, expected",
    [(True, ["http/other.yaml"], []), (True, ["http/selected.yaml"], ["crawled"]), (False, [], ["crawled"])],
)
def test_homepage_links_are_crawled_only_when_needed(incremental, homepage_list, expected):
    from artemis.config import Config

    module = _module()
    module._incremental = incremental
    module._custom_template_paths = {"http/selected.yaml": "/tmp/x/http/selected.yaml"}
    with mock.patch.object(
        Config.Modules.Nuclei, "NUCLEI_TEMPLATES_TO_RUN_ON_HOMEPAGE_LINKS", homepage_list
    ), mock.patch("artemis.modules.nuclei.Nuclei._get_links", return_value=["crawled"]):
        assert module._get_links("http://example.com") == expected


# --- N7: findings carry the repository path of templates from main --------------------------------


def test_findings_from_main_templates_carry_repository_path():

    module = _module()
    module._incremental = True
    module._custom_template_paths = {
        "http/cves/2026/CVE-2026-0001.yaml": "/tmp/cybercover-nuclei-x/http/cves/2026/CVE-2026-0001.yaml"
    }
    raw = [
        {"template-id": "CVE-2026-0001", "template-path": "/tmp/cybercover-nuclei-x/http/cves/2026/CVE-2026-0001.yaml"},
        {"template-id": "installed", "template-path": "/root/nuclei-templates/http/a.yaml", "template": "http/a.yaml"},
    ]
    with mock.patch("artemis.modules.nuclei.Nuclei._scan", return_value=raw):
        findings = module._scan([], *_scan_args(), ["https://example.com"], extra_nuclei_args=[])
    assert [f["template"] for f in findings] == ["http/cves/2026/CVE-2026-0001.yaml", "http/a.yaml"]


# --- P1/P2/P3: port discovery age limit, adopting the full scan, stable version -------------------


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def test_cache_older_than_max_age_is_rediscovered(_ports_env):
    scanner = _port_scanner()
    scanner._store.replace("client.pl", "www.client.pl", "v10.5.0", [(443, "http", True)],
                           discovered_at=_now() - datetime.timedelta(days=8))
    task = _domain_task("www.client.pl")
    with mock.patch("artemis.modules.port_scanner.PortScanner.run_multiple") as stock:
        scanner.run_multiple([task])
    stock.assert_called_once_with([task])
    assert _now() - scanner._store.get_state("client.pl", "www.client.pl")[1] < datetime.timedelta(minutes=1)


def test_newer_full_scan_result_is_adopted_without_scanning(_ports_env):
    from artemis.binds import TaskStatus

    scanner = _port_scanner()
    full_scan_time = _now() - datetime.timedelta(hours=3)
    scanner._stock_results.latest.return_value = (full_scan_time, [(3000, "http", False), (443, "http", True)])
    task = _domain_task("www.client.pl")
    with mock.patch("artemis.module_base.ArtemisBase.add_task") as add, mock.patch(
        "artemis.modules.port_scanner.PortScanner.run_multiple"
    ) as stock:
        scanner.run_multiple([task])
    stock.assert_not_called()
    assert sorted(call.args[1].get_payload("port") for call in add.call_args_list) == [443, 3000]
    saved = scanner.save_task_result.call_args.kwargs
    assert saved["status"] == TaskStatus.OK
    assert saved["data"]["www.client.pl"]["3000"] == {"service": "http", "ssl": False, "source": "full_scan"}
    assert "source: full_scan" in saved["status_reason"]
    # The age limit counts from the adopted scan.
    assert scanner._store.get_state("client.pl", "www.client.pl") == ("v10.5.0", full_scan_time)
    client, host, since = scanner._stock_results.latest.call_args.args
    assert (client, host) == ("client.pl", "www.client.pl")
    assert _now() - since > datetime.timedelta(days=6)  # no stored state: look back over the age limit


def test_only_full_scans_newer_than_the_cache_are_considered(_ports_env):
    scanner = _port_scanner()
    discovered = _now() - datetime.timedelta(days=2)
    scanner._store.replace("client.pl", "www.client.pl", "v10.5.0", [(443, "http", True)], discovered_at=discovered)
    with mock.patch("artemis.module_base.ArtemisBase.add_task"), mock.patch(
        "artemis.modules.port_scanner.PortScanner.run_multiple"
    ) as stock:
        scanner.run_multiple([_domain_task("www.client.pl")])
    stock.assert_not_called()
    assert scanner._stock_results.latest.call_args.args[2] == discovered
    assert scanner.save_task_result.call_args.kwargs["data"]["www.client.pl"]["443"]["source"] == "replayed"


def test_last_known_release_is_used_while_github_is_down(_ports_env):
    from cybercover.github_templates import LAST_KNOWN_RELEASE_KEY, TemplateLookupError

    scanner = _port_scanner()
    cache = {f"cybercover:{LAST_KNOWN_RELEASE_KEY.split(':', 1)[1]}": b"v10.6.0"}
    scanner.cache.get.side_effect = cache.get
    with mock.patch(
        "cybercover.modules.cybercover_port_scanner.latest_release", side_effect=TemplateLookupError("down")
    ):
        assert scanner._current_version() == "v10.6.0"
    cache.clear()
    with mock.patch(
        "cybercover.modules.cybercover_port_scanner.latest_release", side_effect=TemplateLookupError("down")
    ):
        assert scanner._current_version() == "v10.5.0"  # nothing known: the installed release


def test_latest_release_remembers_last_known_release():
    from cybercover.github_templates import LAST_KNOWN_RELEASE_KEY, last_known_release, latest_release
    from test_all import FakeSession

    cache = {}
    latest_release(cache.get, lambda k, v, timeout=None: cache.__setitem__(k, v), FakeSession({"tag_name": "v10.6.0"}))
    assert cache[LAST_KNOWN_RELEASE_KEY] == b"v10.6.0"
    assert last_known_release(cache.get) == "v10.6.0"


def test_stock_result_conversion():
    from cybercover.stock_results import endpoints_from_result

    result = {
        "192.0.2.1": {"443": {"service": "http", "ssl": True, "version": "nginx"}},
        "192.0.2.2": {"443": {"service": "http", "ssl": True}, "22": {"service": "SSH", "ssl": False}},
    }
    assert endpoints_from_result(result) == [(22, "ssh", False), (443, "http", True)]
    assert endpoints_from_result({}) == []
    assert endpoints_from_result({"192.0.2.1": {"80": "garbage"}}) is None


@pytest.fixture
def postgres_engine():
    conn_str = os.environ.get("POSTGRES_CONN_STR", "")
    if not conn_str.startswith("postgresql"):
        pytest.skip("PostgreSQL not configured (run tests/run_in_docker.sh)")
    from artemis.db import TaskResult

    engine = create_engine(conn_str)
    TaskResult.__table__.drop(engine, checkfirst=True)
    TaskResult.__table__.create(engine)
    yield engine
    TaskResult.__table__.drop(engine, checkfirst=True)


def test_stock_results_lookup_against_artemis_task_result_table(postgres_engine):
    from sqlalchemy import insert

    from artemis.db import TaskResult
    from cybercover.stock_results import StockPortResults

    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    def row(row_id, hours_ago, *, client="client.pl", host="www.client.pl", status="INTERESTING",
            receiver="port_scanner", ports=None):
        return {
            "id": row_id,
            "analysis_id": "a",
            "created_at": now - datetime.timedelta(hours=hours_ago),
            "status": status,
            "receiver": receiver,
            "target_string": host,
            "task": {"headers": {"receiver": receiver}, "payload": {"domain": host},
                     "payload_persistent": {"original_target": client}},
            "result": {"192.0.2.1": ports if ports is not None else {"443": {"service": "http", "ssl": True}}},
        }

    rows = [
        row("too-old", 24 * 10),
        row("expected", 5, ports={"443": {"service": "http", "ssl": True}, "8443": {"service": "http", "ssl": True}}),
        row("errored-newer", 2, status="ERROR"),
        row("other-customer-newer", 1, client="other.pl"),
        row("other-module-newer", 1, receiver="cybercover_port_scanner"),
        row("other-host-newer", 1, host="mail.client.pl"),
    ]
    with postgres_engine.begin() as connection:
        connection.execute(insert(TaskResult), rows)

    lookup = StockPortResults(postgres_engine)
    week_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
    scanned_at, endpoints = lookup.latest("client.pl", "www.client.pl", week_ago)
    assert endpoints == [(443, "http", True), (8443, "http", True)]
    assert abs((scanned_at - (now - datetime.timedelta(hours=5)).replace(tzinfo=datetime.timezone.utc)).total_seconds()) < 1
    # Nothing newer than the expected row's time: no adoption.
    assert lookup.latest("client.pl", "www.client.pl", scanned_at) is None


def test_invalid_path_reaching_template_download_is_skipped():
    """Regression (found in the live E2E run): one invalid path in a cached daily list failed the batch."""
    from cybercover.github_templates import get_template_contents
    from test_all import FakeSession

    session = FakeSession(b"id: ok\n")
    contents = get_template_contents(
        {"README.md", "../escape.yaml", "http/ok.yaml"}, DAY, "v10.5.1", lambda _: None, lambda *a, **k: None, session
    )
    assert contents == {"http/ok.yaml": b"id: ok\n"}
    assert len(session.calls) == 1
