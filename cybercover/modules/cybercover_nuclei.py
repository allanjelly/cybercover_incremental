#!/usr/bin/env python3
import contextlib
import datetime
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set

from karton.core import Task
from prometheus_client import start_http_server
from sqlalchemy.exc import SQLAlchemyError  # type: ignore

from artemis import load_risk_class
from artemis.binds import TaskStatus
from artemis.modules import nuclei as nuclei_module
from artemis.modules.nuclei import NUCLEI_TEMPLATES_LOCATION, Nuclei, ScanUsing
from artemis.utils import CalledProcessErrorWithMessage, directory_backup

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


NEW_ADDITIONS_PLACEHOLDER = "/root/nuclei-templates/.new-additions"


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
    _severity_levels: List[str] = []
    _incremental = False
    _use_native_nt = False
    _scanned_categories: Set[bool] = set()
    _nuclei_failures = 0
    _state: Optional[ScanStateStore] = None

    @property
    def state(self) -> ScanStateStore:
        if self._state is None:
            self._state = ScanStateStore()
        return self._state

    @contextlib.contextmanager
    def _count_nuclei_failures(self) -> Iterator[None]:
        # The stock _scan logs and swallows failed Nuclei runs, so we observe them one level below.
        original = nuclei_module.check_output_log_on_error_with_stderr

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return original(*args, **kwargs)
            except CalledProcessErrorWithMessage:
                self._nuclei_failures += 1
                raise

        nuclei_module.check_output_log_on_error_with_stderr = wrapper
        try:
            yield
        finally:
            nuclei_module.check_output_log_on_error_with_stderr = original

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
        extra_nuclei_args = list(kwargs.get("extra_nuclei_args", []))
        is_dast = "-dast" in extra_nuclei_args

        # The stock run_multiple scans the whole template list once per category and then repeats
        # scans on homepage links with a short template list. Link scans may only use the changed
        # templates that are also on that list and never the native -nt selection.
        is_link_scan = is_dast in self._scanned_categories
        self._scanned_categories.add(is_dast)

        selected = [
            local_path
            for path, local_path in self._custom_template_paths.items()
            if path.startswith("dast/") == is_dast
            and (not is_link_scan or NUCLEI_TEMPLATES_LOCATION + path in templates_or_workflows)
        ]
        if self._severity_levels:
            extra_nuclei_args.extend(["-severity", ",".join(self._severity_levels)])
        use_native_nt = self._use_native_nt and not is_link_scan
        if use_native_nt:
            extra_nuclei_args.append("-nt")
            if not selected:
                # The stock _scan skips empty template lists; nuclei ignores this config file as a template
                # and adds the installed release's new templates because of -nt.
                selected.append(NEW_ADDITIONS_PLACEHOLDER)
        if not selected:
            return []
        kwargs["extra_nuclei_args"] = extra_nuclei_args

        self.log.info(
            "Incremental %s %s scan: %d custom templates, native -nt=%s",
            "dast" if is_dast else "templates",
            "link" if is_link_scan else "main",
            len(selected),
            use_native_nt,
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

    def run_multiple(self, tasks: List[Task]) -> None:
        if not tasks:
            return

        try:
            installed_version = installed_templates_version()
            if not installed_version:
                raise TemplateLookupError("Unable to determine the installed nuclei-templates release")
            installed_version = self._update_templates_if_needed(installed_version)
            today = datetime.datetime.now(datetime.timezone.utc).date()
            additions = get_daily_additions(today, installed_version, self.cache.get, self.cache.set)
            stored = self.state.get_states(target_key(task) for task in tasks)
        except (TemplateLookupError, SQLAlchemyError, OSError, subprocess.CalledProcessError, ValueError) as exc:
            self._fail(tasks, f"Unable to prepare incremental scan: {exc}")
            return

        groups: Dict[tuple[Optional[str], Optional[datetime.date]], List[Task]] = {}
        for task in tasks:
            state = stored.get(target_key(task))
            group_key = (state[0], state[1].date()) if state else (None, None)
            groups.setdefault(group_key, []).append(task)

        for (last_version, last_scan_date), group in groups.items():
            self._run_group(group, last_version, last_scan_date, installed_version, today, additions)

    def _run_group(
        self,
        tasks: List[Task],
        last_version: Optional[str],
        last_scan_date: Optional[datetime.date],
        installed_version: str,
        today: datetime.date,
        additions: Set[str],
    ) -> None:
        try:
            changed, use_native_nt = templates_to_scan(
                last_version, last_scan_date, installed_version, today, additions, self.cache.get
            )
            contents = get_template_contents(changed, today, installed_version, self.cache.get, self.cache.set)
        except (TemplateLookupError, OSError, subprocess.CalledProcessError, ValueError) as exc:
            self._fail(tasks, str(exc))
            return

        for task in tasks:
            task.add_payload("templates_after_version", last_version, persistent=True)
            task.add_payload("templates_version", installed_version, persistent=True)

        self.log.info(
            "%d targets: %d changed templates (%d downloaded) since %s (installed %s; native -nt=%s)",
            len(tasks),
            len(changed),
            len(contents),
            last_scan_date,
            installed_version,
            use_native_nt,
        )
        if not contents and not use_native_nt:
            for task in tasks:
                self.save_task_result(task=task, status=TaskStatus.OK, status_reason="No new templates", data=[])
            self.state.set_versions((target_key(task) for task in tasks), installed_version)
        else:
            with tempfile.TemporaryDirectory(prefix="cybercover-nuclei-") as directory:
                custom_paths: Dict[str, str] = {}
                for relative_path, content in contents.items():
                    destination = Path(directory) / relative_path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(content)
                    custom_paths[relative_path] = str(destination)

                self._custom_template_paths = custom_paths
                self._severity_levels = self.get_runtime_configuration(tasks[0]).get_severity_options()
                self._incremental = True
                self._use_native_nt = use_native_nt
                self._scanned_categories = set()
                self._nuclei_failures = 0
                try:
                    with self._count_nuclei_failures():
                        super().run_multiple(tasks)
                    if self._nuclei_failures:
                        self.log.error(
                            "%d Nuclei runs failed; not advancing scan state for %d targets",
                            self._nuclei_failures,
                            len(tasks),
                        )
                    else:
                        self.state.set_versions((target_key(task) for task in tasks), installed_version)
                finally:
                    self._custom_template_paths = {}
                    self._severity_levels = []
                    self._incremental = False
                    self._use_native_nt = False
                    self._scanned_categories = set()


if __name__ == "__main__":
    start_http_server(9001)
    CybercoverNuclei.parallel_loop()
