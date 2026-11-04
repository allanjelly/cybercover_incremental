#!/usr/bin/env python3
from typing import Any, Dict, List, Optional, Set

from karton.core import Task
from prometheus_client import start_http_server

from artemis import load_risk_class
from artemis.binds import TaskStatus
from artemis.modules.nuclei import NUCLEI_TEMPLATES_LOCATION, Nuclei, ScanUsing

from cybercover.github_templates import (
    TemplateLookupError,
    TooManyChangesError,
    get_changed_templates,
    get_previous_release,
    installed_templates_version,
    parse_version,
)
from cybercover.state import ScanStateStore


def target_key(task: Task) -> str:
    return f"{task.get_payload('host')}:{task.get_payload('port')}"


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class CybercoverNuclei(Nuclei):
    """
    Incremental Nuclei scan. For every scanned host:port the module remembers (in PostgreSQL) the
    nuclei-templates version it was last scanned with, and runs only the standard templates added or
    modified since then. A target seen for the first time starts from the release before the installed
    one. If the gap is too large for the GitHub compare API, that target gets a full scan.
    Custom templates and workflows are not part of incremental scans.

    Disabled by default (add it to MODULES_DISABLED_BY_DEFAULT) - enable it explicitly through /api/add.
    """

    identity = "cybercover_nuclei"

    _changed: Optional[Set[str]] = None  # None means: no filtering (full scan)
    _incremental = False
    _state: Optional[ScanStateStore] = None

    @property
    def state(self) -> ScanStateStore:
        if self._state is None:
            self._state = ScanStateStore()
        return self._state

    def _scan(  # type: ignore[override]
        self,
        templates_or_workflows: List[str],
        scan_using: ScanUsing,
        targets: List[str],
        *args: Any,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        if not self._incremental:
            return super()._scan(templates_or_workflows, scan_using, targets, *args, **kwargs)
        assert self._changed is not None
        if scan_using == ScanUsing.WORKFLOWS:
            return []
        selected = [
            item
            for item in templates_or_workflows
            if (item[len(NUCLEI_TEMPLATES_LOCATION) :] if item.startswith(NUCLEI_TEMPLATES_LOCATION) else item)
            in self._changed
        ]
        self.log.info("Incremental filter: %d of %d templates selected", len(selected), len(templates_or_workflows))
        return super()._scan(selected, scan_using, targets, *args, **kwargs)

    def _fail(self, tasks: List[Task], reason: str) -> None:
        self.log.error("Skipping tasks: %s", reason)
        for task in tasks:
            self.save_task_result(task=task, status=TaskStatus.ERROR, status_reason=reason, data=[])

    def run_multiple(self, tasks: List[Task]) -> None:
        head = installed_templates_version()
        if not head:
            self._fail(tasks, "Unable to determine the installed nuclei-templates release")
            return

        try:
            stored = self.state.get_versions(target_key(task) for task in tasks)
            default_version = None
            if any(target_key(task) not in stored for task in tasks):
                default_version = get_previous_release(head, self.cache.get, self.cache.set)
        except Exception as exc:  # DB or GitHub problems must not lose the tasks silently
            self._fail(tasks, f"Unable to determine the previous scan version: {exc}")
            return

        groups: Dict[str, List[Task]] = {}
        for task in tasks:
            after_version = stored.get(target_key(task)) or default_version
            assert after_version is not None
            groups.setdefault(after_version, []).append(task)

        for after_version, group in groups.items():
            self._run_group(group, after_version, head)

    def _run_group(self, tasks: List[Task], after_version: str, head: str) -> None:
        full_scan = False
        changed: Set[str] = set()
        try:
            if parse_version(after_version) < parse_version(head):
                changed = get_changed_templates(after_version, head, self.cache.get, self.cache.set)
        except TooManyChangesError:
            full_scan = True
        except (TemplateLookupError, ValueError) as exc:
            self._fail(tasks, str(exc))
            return

        for task in tasks:
            task.add_payload("templates_after_version", None if full_scan else after_version, persistent=True)
            task.add_payload("templates_version", head, persistent=True)

        self.log.info(
            "%d targets: %s since %s (installed %s)",
            len(tasks),
            "full scan" if full_scan else f"{len(changed)} changed templates",
            after_version,
            head,
        )
        if not full_scan and not changed:
            for task in tasks:
                self.save_task_result(task=task, status=TaskStatus.OK, status_reason="No new templates", data=[])
        else:
            self._changed = None if full_scan else changed
            self._incremental = not full_scan
            try:
                super().run_multiple(tasks)
            finally:
                self._changed = None
                self._incremental = False

        # Only reached when the scan did not raise - a failed scan keeps the old version
        self.state.set_versions((target_key(task) for task in tasks), head)


if __name__ == "__main__":
    start_http_server(9001)
    CybercoverNuclei.parallel_loop()
