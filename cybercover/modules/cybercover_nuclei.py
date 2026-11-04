#!/usr/bin/env python3
from typing import Any, Dict, List, Optional, Set

from karton.core import Task
from prometheus_client import start_http_server

from artemis import load_risk_class
from artemis.binds import TaskStatus
from artemis.modules.nuclei import NUCLEI_TEMPLATES_LOCATION, Nuclei, ScanUsing

from cybercover.github_templates import (
    TemplateLookupError,
    get_changed_templates,
    installed_templates_version,
)
from cybercover.modules.cybercover_nuclei_configuration import (
    CybercoverNucleiConfiguration,
)


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class CybercoverNuclei(Nuclei):
    """
    Incremental Nuclei scan: runs only the standard templates added/modified after the
    configured `after_version` templates release. Disabled by default - enable it explicitly through /api/add.
    Custom templates and workflows are not part of incremental scans.
    """

    identity = "cybercover_nuclei"

    _changed: Optional[Set[str]] = None

    def get_runtime_configuration(self, task: Task) -> CybercoverNucleiConfiguration:  # type: ignore[override]
        config_dict = task.payload_persistent.get("module_runtime_configurations", {}).get(self.identity)
        if config_dict is None:
            return CybercoverNucleiConfiguration()
        try:
            configuration = CybercoverNucleiConfiguration.deserialize(config_dict)
            if not configuration.validate():
                raise ValueError(f"Invalid configuration for module {self.identity}")
        except (KeyError, TypeError, ValueError) as exc:
            self.log.warning("Failed to load configuration from task payload: %s", exc)
            return CybercoverNucleiConfiguration()
        return configuration

    def _scan(  # type: ignore[override]
        self,
        templates_or_workflows: List[str],
        scan_using: ScanUsing,
        targets: List[str],
        *args: Any,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
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

    def run_multiple(self, tasks: List[Task]) -> None:
        configuration = self.get_runtime_configuration(tasks[0])
        try:
            if configuration.after_version is None:
                raise TemplateLookupError("cybercover_nuclei requires a valid 'after_version' value")
            self._changed, covered_until = get_changed_templates(
                configuration.after_version,
                configuration.change_type,
                installed_templates_version(),
                self.cache.get,
                self.cache.set,
            )
        except TemplateLookupError as exc:
            self.log.error("Skipping tasks: %s", exc)
            for task in tasks:
                self.save_task_result(task=task, status=TaskStatus.ERROR, status_reason=str(exc), data=[])
            return

        for task in tasks:
            task.add_payload("covered_until", covered_until, persistent=True)

        self.log.info(
            "%d templates changed since %s (%s); installed templates version %s; scanning %d targets",
            len(self._changed),
            configuration.after_version,
            configuration.change_type.value,
            covered_until,
            len(tasks),
        )
        try:
            super().run_multiple(tasks)
        finally:
            self._changed = None


if __name__ == "__main__":
    start_http_server(9001)
    CybercoverNuclei.parallel_loop()
