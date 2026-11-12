"""Regression tests for the findings of the independent review of 2026-11-12 (F1-F7)."""

import datetime
import json
from unittest import mock

import pytest
from sqlalchemy import create_engine  # type: ignore

from cybercover.github_templates import (
    TemplateLookupError,
    get_daily_additions,
    intermediate_release_additions,
    releases_between,
    templates_to_scan,
)
from test_all import (  # noqa: F401 - shared fixtures and helpers
    DAY,
    _domain_task,
    _module,
    _mock_log,
    _port_scanner,
    _ports_env,
    _set_state,
    _stored,
    _task,
    _template,
)
from test_phase1 import postgres_engine  # noqa: F401


class Pages:
    """GitHub releases API pages, then raw .new-additions files by tag."""

    def __init__(self, pages, additions=None):
        self.pages = pages
        self.additions = additions or {}
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, params))
        response = mock.Mock()
        response.raise_for_status.return_value = None
        response.status_code = 200
        if url.endswith("/releases"):
            response.json.return_value = self.pages[params["page"] - 1] if params["page"] <= len(self.pages) else []
        else:
            tag = url.split("/")[-2]
            if tag not in self.additions:
                response.status_code = 404
            response.content = self.additions.get(tag, b"")
        return response


def _releases(*tags):
    return [{"tag_name": tag} for tag in tags]


# F1: a jump over several releases ------------------------------------------------------------


def test_releases_between_lists_only_the_releases_in_between():
    session = Pages([_releases("v10.5.2", "v10.5.1", "v10.5.0", "v10.4.9")])
    cache = {}
    tags = releases_between("v10.5.0", "v10.5.2", cache.get, lambda k, v, timeout=None: cache.update({k: v}), session)
    assert tags == ["v10.5.1"]
    assert releases_between("v10.5.1", "v10.5.2", cache.get, lambda *a, **k: None, session) == []


def test_releases_between_pages_back_until_the_older_release():
    pages = [_releases("v10.6.1", "v10.6.0"), _releases("v10.5.9", "v10.5.8"), _releases("v10.5.7")]
    session = Pages(pages)
    tags = releases_between("v10.5.8", "v10.6.1", lambda _: None, lambda *a, **k: None, session)
    assert tags == ["v10.5.9", "v10.6.0"]
    assert len(session.calls) == 2  # stopped at the page containing v10.5.8


def test_releases_that_cannot_be_listed_back_far_enough_raise():
    session = Pages([_releases("v10.6.1", "v10.6.0")] * 20)
    with pytest.raises(TemplateLookupError):
        releases_between("v10.5.0", "v10.6.1", lambda _: None, lambda *a, **k: None, session)


def test_intermediate_release_additions_are_combined():
    session = Pages(
        [_releases("v10.5.3", "v10.5.2", "v10.5.1", "v10.5.0")],
        {"v10.5.1": b"http/b.yaml\n", "v10.5.2": b"http/c.yaml\nhttp/d.yaml\n"},
    )
    paths = intermediate_release_additions("v10.5.0", "v10.5.3", lambda _: None, lambda *a, **k: None, session)
    assert paths == {"http/b.yaml", "http/c.yaml", "http/d.yaml"}


def test_intermediate_release_without_a_list_is_skipped():
    """Second review N3 (decision a): a release without .new-additions (404) is skipped and counted,
    so it cannot block the endpoints scanned before it forever."""
    session = Pages(
        [_releases("v10.5.3", "v10.5.2", "v10.5.1", "v10.5.0")], {"v10.5.2": b"http/c.yaml\n"}
    )
    missing = []
    paths = intermediate_release_additions(
        "v10.5.0", "v10.5.3", lambda _: None, lambda *a, **k: None, session, on_missing_list=missing.append
    )
    assert paths == {"http/c.yaml"}
    assert missing == ["v10.5.1"]


def test_unreachable_github_for_an_intermediate_list_still_raises():
    class Down(Pages):
        def get(self, url, params=None, headers=None, timeout=None):
            if url.endswith("/.new-additions"):
                import requests

                raise requests.ConnectionError("down")
            return super().get(url, params, headers, timeout)

    session = Down([_releases("v10.5.2", "v10.5.1", "v10.5.0")])
    with pytest.raises(TemplateLookupError):
        intermediate_release_additions("v10.5.0", "v10.5.2", lambda _: None, lambda *a, **k: None, session)


def test_release_jump_scans_templates_of_the_intermediate_release(tmp_path):
    """Inverted proof F1: v10.5.0 -> v10.5.2; the critical template added in v10.5.1 is scanned."""
    root = tmp_path / "nuclei"
    (root / "http").mkdir(parents=True)
    (root / ".new-additions").write_text("http/c.yaml\n")
    (root / "http/b.yaml").write_bytes(_template("critical"))
    (root / "http/c.yaml").write_bytes(_template("high"))
    module = _module()
    module._intermediate_release_additions.return_value = {"http/b.yaml", "http/removed-later.yaml"}
    _set_state(module, "example.com", "v10.5.0", snapshot_date=DAY)
    today = DAY + datetime.timedelta(days=1)
    scanned = {}
    with mock.patch("cybercover.modules.cybercover_nuclei.NUCLEI_TEMPLATES_LOCATION", str(root) + "/"), mock.patch(
        "cybercover.modules.cybercover_nuclei.get_template_contents", return_value={}
    ), mock.patch("artemis.modules.nuclei.Nuclei.run_multiple") as scan:
        scan.side_effect = lambda _: scanned.update(module._custom_template_paths)
        module._run_group([_task("example.com")], "v10.5.0", DAY, "v10.5.2", today, set())
    module._intermediate_release_additions.assert_called_once_with("v10.5.0", "v10.5.2")
    assert set(scanned) == {"http/b.yaml", "http/c.yaml"}
    assert _stored(module, "example.com") == ("v10.5.2", today)


def test_failed_release_jump_lookup_does_not_advance_state(tmp_path):
    from artemis.binds import TaskStatus

    root = tmp_path / "nuclei"
    root.mkdir()
    (root / ".new-additions").write_text("")
    module = _module()
    module._intermediate_release_additions.side_effect = TemplateLookupError("GitHub down")
    _set_state(module, "example.com", "v10.5.0", snapshot_date=DAY)
    with mock.patch("cybercover.modules.cybercover_nuclei.NUCLEI_TEMPLATES_LOCATION", str(root) + "/"), mock.patch(
        "cybercover.modules.cybercover_nuclei.get_template_contents", return_value={}
    ), mock.patch("artemis.modules.nuclei.Nuclei.run_multiple") as scan:
        module._run_group([_task("example.com")], "v10.5.0", DAY, "v10.5.2", DAY + datetime.timedelta(days=1), set())
    scan.assert_not_called()
    assert module.save_task_result.call_args.kwargs["status"] == TaskStatus.ERROR
    assert _stored(module, "example.com") == ("v10.5.0", DAY)


# F4: release templates are read under the shared template lock --------------------------------


def test_release_templates_are_read_under_the_shared_lock(tmp_path):
    root = tmp_path / "nuclei"
    (root / "http").mkdir(parents=True)
    (root / ".new-additions").write_text("http/c.yaml\n")
    (root / "http/c.yaml").write_bytes(_template("high"))
    module = _module()
    events = []
    module._shared_templates_lock.__enter__.side_effect = lambda *a: events.append("locked")
    module._shared_templates_lock.__exit__.side_effect = lambda *a: events.append("unlocked")

    import cybercover.modules.cybercover_nuclei as nuclei

    original = nuclei.release_template_contents

    def reading(root_path):
        events.append("read")
        return original(root_path)

    with mock.patch("cybercover.modules.cybercover_nuclei.NUCLEI_TEMPLATES_LOCATION", str(root) + "/"), mock.patch(
        "cybercover.modules.cybercover_nuclei.release_template_contents", side_effect=reading
    ):
        contents = module._release_contents(None, "v10.5.2")
    assert set(contents) == {"http/c.yaml"}
    assert events == ["locked", "read", "unlocked"]


# F5: a retry of the batch does not overwrite completed results ---------------------------------


def test_rerun_of_batch_skips_tasks_completed_in_the_first_try():
    """Inverted proof F5: endpoint A completed with a finding in try 1; try 2 (Artemis retries the
    batch because B failed) must not rescan A and overwrite its result with OK/[]."""
    from artemis.binds import TaskStatus

    module = _module()
    del module.save_task_result  # use the module's own save_task_result (tracks completed tasks)
    today = datetime.datetime.now(datetime.timezone.utc).date()
    task_a, task_b = _task("a.example.com"), _task("b.example.com")
    _set_state(module, "a.example.com", "v10.5.1", snapshot_date=today - datetime.timedelta(days=1))
    scanned = []

    def stock_run(tasks):
        for task in tasks:
            scanned.append(task)
            module.save_task_result(task=task, status=TaskStatus.INTERESTING, data=[{"template-id": "new-cve"}])

    with mock.patch("artemis.module_base.ArtemisBase.save_task_result") as saved, \
            mock.patch("cybercover.modules.cybercover_nuclei.installed_templates_version", return_value="v10.5.1"), \
            mock.patch.object(module, "_update_templates_if_needed", return_value="v10.5.1"), \
            mock.patch.object(module, "_log_nuclei_version"), \
            mock.patch("cybercover.modules.cybercover_nuclei.get_daily_additions", return_value={"http/a.yaml"}), \
            mock.patch("cybercover.modules.cybercover_nuclei.get_template_contents",
                       side_effect=lambda paths, *a, **k: {p: _template("high") for p in paths}), \
            mock.patch("cybercover.modules.cybercover_nuclei.release_template_contents",
                       side_effect=OSError("no .new-additions")), \
            mock.patch("artemis.modules.nuclei.Nuclei.run_multiple", side_effect=stock_run):
        module.run_multiple([task_a, task_b])  # try 1: A scanned, B's group fails
        module.run_multiple([task_a, task_b])  # try 2
        module.run_multiple([task_b])  # a different batch starts fresh
    assert scanned == [task_a]
    saved_a = [c.kwargs["status"] for c in saved.call_args_list if c.kwargs["task"] is task_a]
    assert saved_a == [TaskStatus.INTERESTING]
    saved_b = [c.kwargs["status"] for c in saved.call_args_list if c.kwargs["task"] is task_b]
    assert saved_b == [TaskStatus.ERROR, TaskStatus.ERROR, TaskStatus.ERROR]


# F6: concurrent snapshot fetches agree on one snapshot -----------------------------------------


def test_concurrent_snapshot_fetch_uses_the_first_stored_snapshot():
    """Inverted proof F6: worker B fetched a newer main list, but scans with the snapshot worker A
    stored, which is the one tomorrow's diff uses."""
    cache = {}
    day = datetime.date(2026, 11, 5)

    def cache_add(key, value, timeout=None):
        return cache.setdefault(key, value)

    class Session:
        def __init__(self, body):
            self.body = body

        def get(self, url, params=None, headers=None, timeout=None):
            response = mock.Mock(status_code=200, content=self.body)
            response.raise_for_status.return_value = None
            return response

    miss = lambda key: None  # noqa: E731 - both workers missed the cache
    worker_a = get_daily_additions(day, "v10.5.1", miss, None, Session(b"http/a.yaml\n"), cache_add=cache_add)
    worker_b = get_daily_additions(
        day, "v10.5.1", miss, None, Session(b"http/a.yaml\nhttp/x.yaml\n"), cache_add=cache_add
    )
    assert worker_a == worker_b == {"http/a.yaml"}
    changed, _ = templates_to_scan(
        "v10.5.1", day, "v10.5.1", day + datetime.timedelta(days=1), {"http/a.yaml", "http/x.yaml"}, cache.get
    )
    assert changed == {"http/x.yaml"}  # X is scanned the next day


def test_module_cache_add_uses_redis_set_nx():
    module = _module()
    module.cache.cache_name = "cache.cybercover_nuclei"
    module.cache.redis.set.return_value = None  # another worker stored the key first
    module.cache.redis.get.return_value = b'["http/a.yaml"]'
    assert module._cache_add("k", b'["http/x.yaml"]', 60) == b'["http/a.yaml"]'
    module.cache.redis.set.assert_called_once_with("cache.cybercover_nuclei:k", b'["http/x.yaml"]', ex=60, nx=True)


# F3: empty port lists are never replayed or adopted --------------------------------------------


def test_empty_discovery_is_rediscovered_the_next_day(_ports_env):  # noqa: F811
    """Inverted proof F3."""
    scanner = _port_scanner()
    task = _domain_task("www.client.pl")
    with mock.patch("artemis.module_base.ArtemisBase.add_task"), mock.patch(
        "artemis.modules.port_scanner.PortScanner.run_multiple"
    ) as stock:
        scanner.run_multiple([task])  # day 1: discovery, zero ports
        scanner.run_multiple([task])  # day 2
    assert stock.call_count == 2
    replays = [c for c in scanner.save_task_result.call_args_list if "Replayed" in (c.kwargs.get("status_reason") or "")]
    assert replays == []


def test_empty_stock_result_is_not_adopted(_ports_env):  # noqa: F811
    scanner = _port_scanner()
    scanner._stock_results.latest.return_value = (datetime.datetime.now(datetime.timezone.utc), [])
    task = _domain_task("www.client.pl")
    with mock.patch("artemis.modules.port_scanner.PortScanner.run_multiple") as stock:
        scanner.run_multiple([task])
    stock.assert_called_once_with([task])


# F7: duplicate ports and per-host storing ------------------------------------------------------


def test_same_port_with_two_fingerprints_is_stored_once_and_other_hosts_are_kept(_ports_env):  # noqa: F811
    """Inverted proof F7 (proof file: F9)."""
    from artemis.binds import Service, TaskType
    from karton.core import Task

    scanner = _port_scanner()
    first, second = _domain_task("multi.client.pl"), _domain_task("ok.client.pl")

    def stock_run(tasks):
        for ssl in (False, True):
            scanner.add_task(tasks[0], Task({"type": TaskType.SERVICE, "service": Service.HTTP},
                                            payload={"host": "multi.client.pl", "port": 443, "ssl": ssl}))
        scanner.add_task(tasks[1], Task({"type": TaskType.SERVICE, "service": Service.HTTP},
                                        payload={"host": "ok.client.pl", "port": 80, "ssl": False}))

    with mock.patch("artemis.module_base.ArtemisBase.add_task"), mock.patch(
        "artemis.modules.port_scanner.PortScanner.run_multiple", side_effect=stock_run
    ):
        scanner.run_multiple([first, second])
    assert scanner._store.get_endpoints("client.pl", "multi.client.pl") == [(443, "http", True)]
    assert scanner._store.get_endpoints("client.pl", "ok.client.pl") == [(80, "http", False)]


def test_storing_failure_of_one_host_keeps_the_others(_ports_env):  # noqa: F811
    from sqlalchemy.exc import SQLAlchemyError

    scanner = _port_scanner()
    first, second = _domain_task("bad.client.pl"), _domain_task("ok.client.pl")
    original = scanner._store.replace

    def replace(client, host, *args, **kwargs):
        if host == "bad.client.pl":
            raise SQLAlchemyError("boom")
        return original(client, host, *args, **kwargs)

    scanner._store.replace = replace
    with mock.patch("artemis.modules.port_scanner.PortScanner.run_multiple"):
        scanner.run_multiple([first, second])
    assert scanner._store.get_state("client.pl", "ok.client.pl") is not None


# F2: hosts known from the full scan are replayed in incremental scans --------------------------


def _with_root(task, root_uid="analysis-1"):
    task.root_uid = root_uid
    return task


def test_known_hosts_of_the_full_scan_are_added_once_per_analysis(_ports_env):  # noqa: F811
    scanner = _port_scanner()
    scanner._store.replace("client.pl", "client.pl", "v10.5.0", [(443, "http", True)])
    scanner._stock_results.known_hosts.return_value = ["client.pl", "shop.client.pl", "www.client.pl"]
    redis = {}
    scanner.cache.cache_name = "cache.cybercover_port_scanner"
    def redis_set(key, value, ex=None, nx=False):
        if nx and key in redis:
            return None
        redis[key] = value
        return True

    scanner.cache.redis.set.side_effect = redis_set
    added = []
    scanner.add_task_if_domain_exists = lambda current, new: added.append(new.get_payload("domain")) or True
    root = _with_root(_domain_task("client.pl"))
    with mock.patch("artemis.module_base.ArtemisBase.add_task"), mock.patch(
        "artemis.modules.port_scanner.PortScanner.run_multiple"
    ):
        scanner.run_multiple([root])
        # the added hosts come back as DOMAIN tasks of the same analysis: no second round
        scanner.run_multiple([_with_root(_domain_task("shop.client.pl"))])
        # a new analysis (the next daily scan) adds them again
        scanner.run_multiple([_with_root(_domain_task("client.pl"), "analysis-2")])
    assert added == ["shop.client.pl", "www.client.pl", "shop.client.pl", "www.client.pl"]
    since = scanner._stock_results.known_hosts.call_args.args[1]
    assert datetime.datetime.now(datetime.timezone.utc) - since > datetime.timedelta(days=30)


def test_known_hosts_lookup_failure_does_not_break_the_scan(_ports_env):  # noqa: F811
    from sqlalchemy.exc import SQLAlchemyError

    scanner = _port_scanner()
    scanner._store.replace("client.pl", "client.pl", "v10.5.0", [(443, "http", True)])
    scanner._stock_results.known_hosts.side_effect = SQLAlchemyError("down")
    scanner.cache.redis.set.return_value = True
    with mock.patch("artemis.module_base.ArtemisBase.add_task") as add:
        scanner.run_multiple([_with_root(_domain_task("client.pl"))])
    assert add.call_count == 1  # the replayed SERVICE task of the requested target


def test_known_hosts_query_against_artemis_task_result_table(postgres_engine):  # noqa: F811
    from sqlalchemy import insert

    from artemis.db import TaskResult
    from cybercover.stock_results import StockPortResults

    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    def row(row_id, host, *, days_ago=1, client="client.pl", task_type="domain", status="OK",
            receiver="port_scanner"):
        return {
            "id": row_id, "analysis_id": "full", "created_at": now - datetime.timedelta(days=days_ago),
            "status": status, "receiver": receiver, "target_string": host,
            "task": {"headers": {"type": task_type, "receiver": receiver}, "payload": {"domain": host},
                     "payload_persistent": {"original_target": client}},
            "result": {},
        }

    rows = [
        row("root", "client.pl"),
        row("shop", "shop.client.pl", status="INTERESTING"),
        row("shop-again", "shop.client.pl", days_ago=20),
        row("www", "WWW.client.pl"),
        row("ip", "192.0.2.1", task_type="ip"),
        row("old", "old.client.pl", days_ago=60),
        row("failed", "failed.client.pl", status="ERROR"),
        row("other-client", "shop.other.pl", client="other.pl"),
        row("own-module", "own.client.pl", receiver="cybercover_port_scanner"),
    ]
    with postgres_engine.begin() as connection:
        connection.execute(insert(TaskResult), rows)
    lookup = StockPortResults(postgres_engine)
    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=40)
    assert lookup.known_hosts("client.pl", since, limit=10) == ["shop.client.pl", "www.client.pl"]
    assert lookup.known_hosts("client.pl", since, limit=1) == ["shop.client.pl"]


# Second review (N1-N4) and its test gaps ------------------------------------------------------


def _batch_module(today):
    from artemis.binds import TaskType

    module = _module()
    del module.save_task_result  # the module's own save_task_result, as in production
    task_a, task_b = _task("a.example.com"), _task("b.example.com")
    for task in (task_a, task_b):
        task.headers = {"type": TaskType.NUCLEI_TARGET}
    _set_state(module, "a.example.com", "v10.5.1", snapshot_date=today - datetime.timedelta(days=1))
    module.db = mock.Mock()
    module.db.save_module_started_task.return_value = True
    module.db.get_task_by_id.return_value = {"status": "INTERESTING"}
    module._current_task_locks = {}
    module.check_connection_to_base_url_and_save_error = lambda task: True
    return module, task_a, task_b


def _batch_patches(module, stock_run):
    from contextlib import ExitStack

    stack = ExitStack()
    for target, kwargs in [
        ("cybercover.modules.cybercover_nuclei.installed_templates_version", {"return_value": "v10.5.1"}),
        ("cybercover.modules.cybercover_nuclei.get_daily_additions", {"return_value": {"http/a.yaml"}}),
        ("cybercover.modules.cybercover_nuclei.get_template_contents",
         {"side_effect": lambda paths, *a, **k: {p: _template("high") for p in paths}}),
        ("cybercover.modules.cybercover_nuclei.release_template_contents", {"return_value": ({}, [])}),
        ("artemis.modules.nuclei.Nuclei.run_multiple", {"side_effect": stock_run}),
    ]:
        stack.enter_context(mock.patch(target, **kwargs))
    stack.enter_context(mock.patch.object(module, "_update_templates_if_needed", return_value="v10.5.1"))
    stack.enter_context(mock.patch.object(module, "_log_nuclei_version"))
    return stack


def test_exception_in_a_later_group_does_not_overwrite_a_completed_group():
    """Inverted second-review proof N1, through the real ArtemisBase.process_multiple."""
    from artemis.binds import TaskStatus
    from artemis.module_base import ArtemisBase

    today = datetime.datetime.now(datetime.timezone.utc).date()
    module, task_a, task_b = _batch_module(today)

    def stock_run(tasks):
        if task_b in tasks:
            raise AssertionError("Cannot match finding: {...}")
        for task in tasks:
            module.save_task_result(task=task, status=TaskStatus.INTERESTING, data=[{"template-id": "new-cve"}])

    with mock.patch("artemis.module_base.ArtemisBase.save_task_result") as saved, _batch_patches(module, stock_run):
        ArtemisBase.process_multiple(module, [task_a, task_b])  # the failing group no longer escapes
    by_task = {}
    for call in saved.call_args_list:
        by_task.setdefault(call.kwargs["task"], []).append(call.kwargs["status"])
    assert by_task == {task_a: [TaskStatus.INTERESTING], task_b: [TaskStatus.ERROR]}
    assert _stored(module, "a.example.com") == ("v10.5.1", today)
    assert _stored(module, "b.example.com") is None


def test_timeout_keeps_the_results_of_completed_tasks():
    """A timeout still reaches Artemis, which saves ERROR for the whole batch; completed tasks keep
    their results."""
    import timeout_decorator

    from artemis.binds import TaskStatus
    from artemis.module_base import ArtemisBase

    today = datetime.datetime.now(datetime.timezone.utc).date()
    module, task_a, task_b = _batch_module(today)

    def stock_run(tasks):
        if task_b in tasks:
            raise timeout_decorator.TimeoutError("Timed Out")
        for task in tasks:
            module.save_task_result(task=task, status=TaskStatus.INTERESTING, data=[{"template-id": "new-cve"}])

    with mock.patch("artemis.module_base.ArtemisBase.save_task_result") as saved, _batch_patches(module, stock_run):
        with pytest.raises(timeout_decorator.TimeoutError):
            ArtemisBase.process_multiple(module, [task_a, task_b])
    statuses_a = [c.kwargs["status"] for c in saved.call_args_list if c.kwargs["task"] is task_a]
    statuses_b = [c.kwargs["status"] for c in saved.call_args_list if c.kwargs["task"] is task_b]
    assert statuses_a == [TaskStatus.INTERESTING]
    assert statuses_b == [TaskStatus.ERROR]


def test_run_multiple_passes_the_set_nx_cache_to_the_daily_snapshot():
    """Test gap 2: the F6 fix depends on run_multiple passing cache_add."""
    today = datetime.datetime.now(datetime.timezone.utc).date()
    module, task_a, _ = _batch_module(today)
    with _batch_patches(module, lambda tasks: None), mock.patch(
        "cybercover.modules.cybercover_nuclei.get_daily_additions", return_value=set()
    ) as daily, mock.patch("artemis.module_base.ArtemisBase.save_task_result"):
        module.run_multiple([task_a])
    assert daily.call_args.kwargs["cache_add"] == module._cache_add


def test_intermediate_release_lookup_uses_the_module_cache():
    """Test gap 3: the bridge from the module to intermediate_release_additions."""
    module = _module()
    del module._intermediate_release_additions
    with mock.patch(
        "cybercover.modules.cybercover_nuclei.intermediate_release_additions", return_value={"http/b.yaml"}
    ) as lookup:
        assert module._intermediate_release_additions("v10.5.0", "v10.5.2") == {"http/b.yaml"}
    args, kwargs = lookup.call_args
    assert args == ("v10.5.0", "v10.5.2", module.cache.get, module.cache.set)
    kwargs["on_missing_list"]("v10.5.1")  # counted, does not raise


def test_cached_release_list_is_refetched_when_it_does_not_reach_the_installed_release():
    """Inverted second-review proof N4."""
    cache = {}

    def cache_set(key, value, timeout=None):
        cache[key] = value

    morning = Pages([_releases("v10.5.2", "v10.5.1", "v10.5.0")])
    assert releases_between("v10.5.0", "v10.5.2", cache.get, cache_set, morning) == ["v10.5.1"]
    evening = Pages([_releases("v10.5.4", "v10.5.3", "v10.5.2", "v10.5.1", "v10.5.0")])
    assert releases_between("v10.5.0", "v10.5.4", cache.get, cache_set, evening) == ["v10.5.1", "v10.5.2", "v10.5.3"]
    assert len(evening.calls) == 1
    # a cached list that reaches the newer release is used as it is
    assert releases_between("v10.5.0", "v10.5.3", cache.get, cache_set, Pages([])) == ["v10.5.1", "v10.5.2"]


def test_releases_between_ignores_drafts_and_unparsable_tags():
    """Test gap 6."""
    page = [{"tag_name": "v10.5.3"}, {"tag_name": "v10.5.2", "draft": True}, {"tag_name": "nightly"},
            {"tag_name": "v10.5.1"}, {"tag_name": "v10.5.0"}]
    tags = releases_between("v10.5.0", "v10.5.3", lambda _: None, lambda *a, **k: None, Pages([page]))
    assert tags == ["v10.5.1"]


def _fake_redis(scanner):
    store = {}
    scanner.cache.cache_name = "cache.cybercover_port_scanner"

    def redis_set(key, value, ex=None, nx=False):
        if nx and key in store:
            return None
        store[key] = value
        return True

    scanner.cache.redis.set.side_effect = redis_set
    scanner.cache.redis.delete.side_effect = lambda key: store.pop(key, None)
    return store


def test_known_hosts_are_added_again_after_a_failure(_ports_env):  # noqa: F811
    """Inverted second-review proof N2a: a failed host does not lose the others, and a retry of the
    task adds the hosts again."""
    scanner = _port_scanner()
    _fake_redis(scanner)
    scanner._store.replace("client.pl", "client.pl", "v10.5.0", [(443, "http", True)])
    scanner._stock_results.known_hosts.return_value = ["a.client.pl", "b.client.pl", "c.client.pl"]
    added = []

    def add(current, new):
        host = new.get_payload("domain")
        if host == "b.client.pl" and "failed-once" not in added:
            added.append("failed-once")
            raise ConnectionError("redis hiccup while sending the task")
        added.append(host)
        return True

    scanner.add_task_if_domain_exists = add
    root = _with_root(_domain_task("client.pl"))
    with mock.patch("artemis.module_base.ArtemisBase.add_task"):
        scanner.run_multiple([root])
        scanner.run_multiple([root])  # retry of the same task
        scanner.run_multiple([root])  # nothing failed in the retry: done for this analysis
    assert added == ["a.client.pl", "failed-once", "c.client.pl", "a.client.pl", "b.client.pl", "c.client.pl"]


def test_fallback_discovery_path_adds_the_known_hosts(_ports_env):  # noqa: F811
    """Inverted second-review proof N2b."""
    scanner = _port_scanner()
    _fake_redis(scanner)
    scanner._stock_results.known_hosts.return_value = ["shop.client.pl"]
    scanner.add_task_if_domain_exists = mock.Mock(return_value=True)
    root = _with_root(_domain_task("client.pl"))
    with mock.patch("cybercover.modules.cybercover_port_scanner.installed_templates_version", return_value=None), \
            mock.patch("artemis.modules.port_scanner.PortScanner.run_multiple") as stock:
        scanner.run_multiple([root])
    stock.assert_called_once()
    assert [c.args[1].get_payload("domain") for c in scanner.add_task_if_domain_exists.call_args_list] == [
        "shop.client.pl"
    ]


@pytest.mark.parametrize("stopped", [False, True])
def test_known_hosts_through_real_artemis_add_task(_ports_env, stopped):  # noqa: F811
    """Test gap 4: the emitted DOMAIN task keeps original_target (client key, port adoption), and a
    stopped analysis gets no tasks."""
    from karton.core import Task

    scanner = _port_scanner()
    _fake_redis(scanner)
    scanner._store.replace("client.pl", "client.pl", "v10.5.0", [(443, "http", True)])
    scanner._stock_results.known_hosts.return_value = ["shop.client.pl"]
    scanner.db = mock.Mock()
    scanner.db.get_analysis_by_id.return_value = {"stopped": stopped}
    scanner.send_task = mock.Mock()
    scanner.check_domain_exists_or_is_placeholder = mock.Mock(return_value=True)
    root = Task({"type": "domain"}, payload={"domain": "client.pl"},
                payload_persistent={"original_target": "client.pl"})
    scanner.run_multiple([root])
    sent = [call.args[0] for call in scanner.send_task.call_args_list]
    domains = [task for task in sent if task.headers["type"] == "domain"]
    if stopped:
        assert sent == []
    else:
        assert [task.payload["domain"] for task in domains] == ["shop.client.pl"]
        assert domains[0].payload_persistent["original_target"] == "client.pl"
        assert domains[0].root_uid == root.root_uid
