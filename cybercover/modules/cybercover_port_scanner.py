#!/usr/bin/env python3
from typing import Dict, List, Optional, Tuple

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
    latest_release,
    parse_version,
)
from cybercover.state import DiscoveryStore

Endpoint = Tuple[int, str, bool]


def client_key(task: Task) -> str:
    return task.payload_persistent.get("original_target") or get_target_host(task)


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class CybercoverPortScanner(PortScanner):
    """
    Port scanner that runs full port discovery only when needed.

    Discovery (naabu + fingerprintx, i.e. the stock PortScanner) runs for a (client, host) that has
    no stored endpoints or whose endpoints were discovered before the newest nuclei-templates release.
    Otherwise the stored endpoints are replayed as SERVICE tasks without touching the network.

    Disabled by default (add it to MODULES_DISABLED_BY_DEFAULT). Enable it instead of port_scanner.
    """

    identity = "cybercover_port_scanner"

    _store: Optional[DiscoveryStore] = None
    _capture: Optional[Dict[Tuple[str, str], List[Endpoint]]] = None

    @property
    def store(self) -> DiscoveryStore:
        if self._store is None:
            self._store = DiscoveryStore()
        return self._store

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
            remote = latest_release(self.cache.get, self.cache.set)
        except TemplateLookupError:
            return installed
        return remote if parse_version(remote) > parse_version(installed) else installed

    def _replay(self, task: Task, endpoints: List[Endpoint]) -> None:
        host = get_target_host(task)
        data: Dict[str, Dict[str, Dict[str, object]]] = {host: {}}
        for port, service, ssl in endpoints:
            self.add_task(
                task,
                Task(
                    {"type": TaskType.SERVICE, "service": Service(service)},
                    payload={"host": host, "port": port, "ssl": ssl},
                ),
            )
            data[host][str(port)] = {"service": service, "ssl": ssl}
        self.save_task_result(
            task=task,
            status=TaskStatus.OK,
            status_reason=f"Replayed {len(endpoints)} stored endpoints without port scanning",
            data=data,
        )

    def run_multiple(self, tasks: List[Task]) -> None:
        try:
            version = self._current_version()
            to_replay: List[Tuple[Task, List[Endpoint]]] = []
            to_discover: List[Task] = []
            for task in tasks:
                client, host = client_key(task), get_target_host(task)
                if self.store.get_version(client, host) == version:
                    to_replay.append((task, self.store.get_endpoints(client, host)))
                else:
                    to_discover.append(task)
        except (TemplateLookupError, SQLAlchemyError, ValueError, OSError) as exc:
            # Fall back to full discovery rather than skipping the scan.
            self.log.error("Unable to read discovery state (%s); running full port discovery", exc)
            super().run_multiple(tasks)
            return

        for task, endpoints in to_replay:
            self._replay(task, endpoints)
        self.log.info("%d targets replayed from stored endpoints, %d need discovery", len(to_replay), len(to_discover))

        if to_discover:
            self._capture = {}
            try:
                super().run_multiple(to_discover)
                captured = self._capture
            finally:
                self._capture = None
            try:
                for task in to_discover:
                    key = (client_key(task), get_target_host(task))
                    self.store.replace(key[0], key[1], version, captured.get(key, []))
            except SQLAlchemyError:
                self.log.exception("Unable to store discovered endpoints; discovery will repeat next time")


if __name__ == "__main__":
    start_http_server(9001)
    CybercoverPortScanner.parallel_loop()
