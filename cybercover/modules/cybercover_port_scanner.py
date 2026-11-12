#!/usr/bin/env python3
import datetime
import os
from typing import Any, Dict, List, Optional, Tuple

from karton.core import Task
from prometheus_client import start_http_server
from sqlalchemy.exc import SQLAlchemyError  # type: ignore

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.port_scanner import PortScanner
from artemis.task_utils import get_target_host

from cybercover.github_templates import (
    TemplateLookupError,
    installed_templates_version,
    last_known_release,
    latest_release,
    parse_version,
)
from cybercover.keys import client_key
from cybercover.state import DiscoveryStore, as_utc, unique_ports
from cybercover.stock_results import StockPortResults

Endpoint = Tuple[int, str, bool]

# Stored endpoints older than this are rediscovered even without a new nuclei-templates release.
MAX_AGE = datetime.timedelta(days=float(os.environ.get("CYBERCOVER_PORT_DISCOVERY_MAX_AGE_DAYS", "7")))

# Marks endpoints that were not scanned in this task, in each port entry of the saved result
# ({host: {port: {"service", "ssl", "source"}}}). Reporters must not present them as new findings.
SOURCE_CACHE = "replayed"  # Cybercover's own earlier discovery
SOURCE_FULL_SCAN = "full_scan"  # adopted from a stock port_scanner result (e.g. the monthly full scan)
REPLAY_STATUS_REASON = "Replayed {count} stored endpoints without port scanning (source: {source})"

# Subdomain enumeration does not run in an incremental scan (enabled_modules disables it). The hosts
# of a client found by its last full scan are therefore replayed as DOMAIN tasks, once per analysis.
KNOWN_HOSTS_MAX_AGE = datetime.timedelta(
    days=float(os.environ.get("CYBERCOVER_FULL_SCAN_HOSTS_MAX_AGE_DAYS", "40"))
)
KNOWN_HOSTS_LIMIT = int(os.environ.get("CYBERCOVER_FULL_SCAN_HOSTS_LIMIT", "500"))
KNOWN_HOSTS_EMITTED_TTL = 7 * 24 * 60 * 60


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class CybercoverPortScanner(PortScanner):
    """
    Port scanner that runs full port discovery only when needed.

    For each (client, host) - the client is the original target, the host the DOMAIN/IP of the task:

    - stored endpoints from the current nuclei-templates release, younger than
      CYBERCOVER_PORT_DISCOVERY_MAX_AGE_DAYS (default 7): replayed as SERVICE tasks, no network scan;
    - otherwise, if Artemis' stock port_scanner scanned the same (client, host) more recently and
      within the age limit (typically the monthly full scan), its result is adopted and replayed;
    - otherwise the stock scanner runs (naabu + fingerprintx) and its result is stored.

    Disabled by default (add it to MODULES_DISABLED_BY_DEFAULT). Enable it instead of port_scanner.
    """

    identity = "cybercover_port_scanner"

    _store: Optional[DiscoveryStore] = None
    _stock_results: Optional[StockPortResults] = None
    _capture: Optional[Dict[Tuple[str, str], List[Endpoint]]] = None

    @property
    def store(self) -> DiscoveryStore:
        if self._store is None:
            self._store = DiscoveryStore()
        return self._store

    @property
    def stock_results(self) -> StockPortResults:
        if self._stock_results is None:
            self._stock_results = StockPortResults(self.store.engine)
        return self._stock_results

    def add_task(self, current_task: Task, new_task: Task) -> None:
        if self._capture is not None and new_task.headers.get("type") == TaskType.SERVICE:
            key = (client_key(current_task), get_target_host(current_task))
            self._capture.setdefault(key, []).append(
                (
                    int(new_task.get_payload("port")),
                    Service(new_task.headers["service"]).value,
                    bool(new_task.get_payload("ssl")),
                )
            )
        super().add_task(current_task, new_task)

    def _current_version(self) -> str:
        installed = installed_templates_version()
        if not installed:
            raise TemplateLookupError("Unable to determine the installed nuclei-templates release")
        try:
            remote: Optional[str] = latest_release(self.cache.get, self.cache.set)
        except TemplateLookupError:
            # Keep using the newest release seen recently; falling back to the installed release
            # would flip the version back and forth and trigger needless rediscoveries.
            remote = last_known_release(self.cache.get)
        if remote and parse_version(remote) > parse_version(installed):
            return remote
        return installed

    def _replay(self, task: Task, endpoints: List[Endpoint], source: str) -> None:
        host = get_target_host(task)
        data: Dict[str, Dict[str, Dict[str, Any]]] = {host: {}}
        for port, service, ssl in endpoints:
            self.add_task(
                task,
                Task(
                    {"type": TaskType.SERVICE, "service": Service(service)},
                    payload={"host": host, "port": port, "ssl": ssl},
                ),
            )
            data[host][str(port)] = {"service": service, "ssl": ssl, "source": source}
        self.save_task_result(
            task=task,
            status=TaskStatus.OK,
            status_reason=REPLAY_STATUS_REASON.format(count=len(endpoints), source=source),
            data=data,
        )

    def _plan(self, task: Task, version: str, now: datetime.datetime) -> Tuple[str, List[Endpoint]]:
        """Decide how to get the endpoints of a task: ("replay"|"adopt"|"discover", endpoints)."""
        client, host = client_key(task), get_target_host(task)
        stored = self.store.get_state(client, host)

        # A stock port_scanner result (e.g. the monthly full scan) that is newer than what we have
        # and within the age limit is the freshest data: adopt it instead of scanning.
        newer_than = max(stored[1], now - MAX_AGE) if stored else now - MAX_AGE
        adopted = self.stock_results.latest(client, host, newer_than)
        if adopted is not None:
            scanned_at, endpoints = adopted
            # An empty result (host down or filtered during that scan) is not adopted: replaying it
            # would skip Nuclei on the host for the whole age limit. Discover instead.
            if endpoints:
                self.store.replace(client, host, version, endpoints, discovered_at=scanned_at)
                self.log.info(
                    "Adopted %d endpoints of %s from the stock port_scanner result of %s",
                    len(endpoints),
                    host,
                    scanned_at.isoformat(),
                )
                return SOURCE_FULL_SCAN, unique_ports(endpoints)

        if stored and stored[0] == version and now - stored[1] < MAX_AGE:
            endpoints = self.store.get_endpoints(client, host)
            # Likewise, an empty stored discovery is never replayed: discovery runs again.
            if endpoints:
                return SOURCE_CACHE, endpoints
        return "discover", []

    def _replay_known_hosts(self, tasks: List[Task], now: datetime.datetime) -> None:
        """Add DOMAIN tasks for the client's hosts known from its last full scan (e.g. subdomains),
        once per analysis and client. They are then handled like the requested target: adopted,
        replayed or discovered, and scanned by Nuclei."""
        for task in tasks:
            if task.headers.get("type") != TaskType.DOMAIN:
                continue
            client = client_key(task)
            marker = f"{self.cache.cache_name}:known-hosts:{task.root_uid}:{client}"
            if not self.cache.redis.set(marker, b"1", ex=KNOWN_HOSTS_EMITTED_TTL, nx=True):
                continue  # already done for this analysis (including for the emitted hosts themselves)
            try:
                hosts = self.stock_results.known_hosts(client, now - KNOWN_HOSTS_MAX_AGE, KNOWN_HOSTS_LIMIT)
            except Exception:  # noqa: BLE001
                self.log.exception("Unable to read the known hosts of %s; scanning only the requested target", client)
                self.cache.redis.delete(marker)  # a retry of the task tries again
                continue
            current = get_target_host(task)
            added = failed = 0
            for host in hosts:
                if host in (current, client):
                    continue
                try:
                    if self.add_task_if_domain_exists(task, Task({"type": TaskType.DOMAIN}, payload={"domain": host})):
                        added += 1
                except Exception:  # noqa: BLE001 - one host must not stop the others
                    failed += 1
                    self.log.exception("Unable to add known host %s of %s", host, client)
            if failed:
                # A retry of the task adds the hosts again; Artemis drops the ones already added.
                self.cache.redis.delete(marker)
            if hosts:
                self.log.info(
                    "Replaying %d of %d hosts of %s known from the last full scan (%d failed)",
                    added,
                    len(hosts),
                    client,
                    failed,
                )

    def run_multiple(self, tasks: List[Task]) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        try:
            version = self._current_version()
            to_replay: List[Tuple[Task, List[Endpoint], str]] = []
            to_discover: List[Task] = []
            for task in tasks:
                action, endpoints = self._plan(task, version, now)
                if action == "discover":
                    to_discover.append(task)
                else:
                    to_replay.append((task, endpoints, action))
        except (TemplateLookupError, SQLAlchemyError, ValueError, OSError) as exc:
            # Fall back to full discovery rather than skipping the scan.
            self.log.error("Unable to read discovery state (%s); running full port discovery", exc)
            try:
                self._replay_known_hosts(tasks, now)
            except Exception:  # noqa: BLE001
                self.log.exception("Unable to replay the known hosts of the batch")
            super().run_multiple(tasks)
            return

        for task, endpoints, source in to_replay:
            self._replay(task, endpoints, source)
        try:
            self._replay_known_hosts(tasks, now)
        except Exception:  # never fail the port scan because of the extra hosts
            self.log.exception("Unable to replay the known hosts of the batch")
        self.log.info(
            "%d targets replayed (%d from the stock port scanner), %d need discovery",
            len(to_replay),
            sum(1 for _, _, source in to_replay if source == SOURCE_FULL_SCAN),
            len(to_discover),
        )

        if to_discover:
            self._capture = {}
            try:
                super().run_multiple(to_discover)
                captured = self._capture
            finally:
                self._capture = None
            for task in to_discover:
                key = (client_key(task), get_target_host(task))
                try:
                    # Each host separately, so one failure does not lose the other hosts of the batch.
                    self.store.replace(key[0], key[1], version, captured.get(key, []), discovered_at=as_utc(now))
                except SQLAlchemyError:
                    self.log.exception("Unable to store endpoints of %s; discovery will repeat next time", key[1])


if __name__ == "__main__":
    start_http_server(9001)
    CybercoverPortScanner.parallel_loop()
