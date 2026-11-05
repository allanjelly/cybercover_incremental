#!/usr/bin/env python3
import datetime
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from karton.core import Task
from prometheus_client import start_http_server
from sqlalchemy.exc import SQLAlchemyError  # type: ignore

from artemis import load_risk_class
from artemis.binds import TaskStatus
from artemis.modules.nuclei import Nuclei, ScanUsing
from artemis.modules.runtime_configuration.nuclei_configuration import SeverityThreshold
from artemis.utils import check_output_log_on_error, directory_backup

from cybercover.github_templates import (
    TemplateLookupError,
    get_daily_additions,
    get_template_contents,
    installed_templates_version,
    latest_release,
    parse_version,
    templates_to_scan,
)
from cybercover.state import ScanStateStore


def target_key(task: Task) -> str:
    return f"{task.get_payload('host')}:{task.get_payload('port')}"


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class CybercoverNuclei(Nuclei):
    """
    Incremental scan using daily changes from nuclei-templates/.new-additions.

    The worker remembers a last-scan date and release per host:port. It downloads changed YAML
    files from GitHub as custom templates; on first scans and release transitions it also uses
    Nuclei's native -nt selection for the installed release.

    Disabled by default (add it to MODULES_DISABLED_BY_DEFAULT) - enable it explicitly through /api/add.
    """

    identity = "cybercover_nuclei"

    _custom_template_paths: Dict[str, str] = {}
    _native_templates: Set[str] = set()
    _native_dast_templates: Set[str] = set()
    _severity_levels: List[str] = []
    _incremental = False
    _include_native_new_templates = False
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
        if scan_using == ScanUsing.WORKFLOWS:
            return []
        extra_nuclei_args = kwargs.get("extra_nuclei_args", [])
        is_dast = "-dast" in extra_nuclei_args
        category = "dast" if is_dast else "templates"

        selected = [
            local_path
            for path, local_path in self._custom_template_paths.items()
            if path.startswith("dast/") == is_dast
        ]
        native_templates = self._native_dast_templates if is_dast else self._native_templates
        extra_nuclei_args = list(extra_nuclei_args)
        if self._severity_levels:
            extra_nuclei_args.extend(["-severity", ",".join(self._severity_levels)])
        if self._include_native_new_templates:
            selected.extend(sorted(native_templates))
            extra_nuclei_args.append("-nt")
        kwargs["extra_nuclei_args"] = extra_nuclei_args

        self.log.info(
            "Incremental %s scan: %d custom templates and %d native release templates",
            category,
            len([path for path in self._custom_template_paths if path.startswith("dast/") == is_dast]),
            len(native_templates) if self._include_native_new_templates else 0,
        )
        return super()._scan(selected, scan_using, targets, *args, **kwargs)

    def _fail(self, tasks: List[Task], reason: str) -> None:
        self.log.error("Skipping tasks: %s", reason)
        for task in tasks:
            self.save_task_result(task=task, status=TaskStatus.ERROR, status_reason=reason, data=[])

    def _update_templates_if_needed(self, installed: str) -> str:
        remote = latest_release(self.cache.get, self.cache.set)
        if parse_version(remote) <= parse_version(installed):
            return installed

        self.log.warning(
            "A newer nuclei-templates release is available (%s vs installed %s); updating before scan",
            remote,
            installed,
        )
        with self.lock:
            with directory_backup(
                "/root/nuclei-templates/",
                "/root/.config/nuclei/",
                logger=self.log,
            ):
                subprocess.check_call(["nuclei", "-update-templates"])

        updated = installed_templates_version()
        if not updated or parse_version(updated) < parse_version(remote):
            raise TemplateLookupError(
                f"Template update did not install the latest release {remote}; installed version is {updated!r}"
            )
        return updated

    def _list_native_new_templates(self, tasks: List[Task]) -> tuple[Set[str], Set[str]]:
        severity_levels = self.get_runtime_configuration(tasks[0]).get_severity_options()
        regular_paths: Set[str] = set()
        for severity in SeverityThreshold.get_severity_list(SeverityThreshold.ALL):
            if severity not in severity_levels:
                continue
            listed = check_output_log_on_error(["nuclei", "-s", severity, "-tl", "-nt"], self.log)
            regular_paths.update(
                path for path in listed.decode("utf-8").split() if path.endswith((".yaml", ".yml"))
            )
        dast = check_output_log_on_error(["nuclei", "-dast", "-tl", "-nt"], self.log).decode("utf-8").split()
        dast_paths = {path for path in dast if path.endswith((".yaml", ".yml")) and path.startswith("dast/")}
        return regular_paths, dast_paths

    def run_multiple(self, tasks: List[Task]) -> None:
        if not tasks:
            return

        try:
            head = installed_templates_version()
            if not head:
                raise TemplateLookupError("Unable to determine the installed nuclei-templates release")
            head = self._update_templates_if_needed(head)
            today = datetime.datetime.now(datetime.timezone.utc).date()
            additions = get_daily_additions(today, head, self.cache.get, self.cache.set)
            stored = self.state.get_states(target_key(task) for task in tasks)
        except (TemplateLookupError, SQLAlchemyError, OSError, subprocess.CalledProcessError, ValueError) as exc:
            self._fail(tasks, f"Unable to prepare incremental scan: {exc}")
            return

        groups: Dict[tuple[Optional[str], Optional[datetime.date]], List[Task]] = {}
        for task in tasks:
            state = stored.get(target_key(task))
            group_key = (state[0], state[1].date()) if state else (None, None)
            groups.setdefault(group_key, []).append(task)

        for (version, scanned_day), group in groups.items():
            self._run_group(group, version, scanned_day, head, today, additions)

    def _run_group(
        self,
        tasks: List[Task],
        after_version: Optional[str],
        last_scanned_at: Optional[datetime.date],
        head: str,
        today: datetime.date,
        additions: Set[str],
    ) -> None:
        try:
            changed, use_native_nt = templates_to_scan(
                after_version, last_scanned_at, head, today, additions, self.cache.get
            )
            contents = get_template_contents(changed, today, head, self.cache.get, self.cache.set)
            if use_native_nt:
                native_templates, native_dast_templates = self._list_native_new_templates(tasks)
            else:
                native_templates, native_dast_templates = set(), set()
        except (TemplateLookupError, OSError, subprocess.CalledProcessError, ValueError) as exc:
            self._fail(tasks, str(exc))
            return

        for task in tasks:
            task.add_payload("templates_after_version", after_version, persistent=True)
            task.add_payload("templates_version", head, persistent=True)

        self.log.info(
            "%d targets: %d changed templates since %s (installed %s; native -nt=%s)",
            len(tasks),
            len(changed),
            last_scanned_at,
            head,
            use_native_nt,
        )
        if not changed and not use_native_nt:
            for task in tasks:
                self.save_task_result(task=task, status=TaskStatus.OK, status_reason="No new templates", data=[])
            self.state.set_versions((target_key(task) for task in tasks), head)
        else:
            with tempfile.TemporaryDirectory(prefix="cybercover-nuclei-") as directory:
                custom_paths: Dict[str, str] = {}
                for relative_path, content in contents.items():
                    destination = Path(directory) / relative_path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(content)
                    custom_paths[relative_path] = str(destination)

                self._custom_template_paths = custom_paths
                self._native_templates = native_templates
                self._native_dast_templates = native_dast_templates
                self._severity_levels = self.get_runtime_configuration(tasks[0]).get_severity_options()
                self._incremental = True
                self._include_native_new_templates = use_native_nt
                try:
                    super().run_multiple(tasks)
                    self.state.set_versions((target_key(task) for task in tasks), head)
                finally:
                    self._custom_template_paths = {}
                    self._native_templates = set()
                    self._native_dast_templates = set()
                    self._severity_levels = []
                    self._incremental = False
                    self._include_native_new_templates = False


if __name__ == "__main__":
    start_http_server(9001)
    CybercoverNuclei.parallel_loop()
