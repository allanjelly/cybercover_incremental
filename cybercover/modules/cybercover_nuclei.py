#!/usr/bin/env python3
import contextlib
import datetime
import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

import yaml
from karton.core import Task
from prometheus_client import Counter, start_http_server
from sqlalchemy.exc import SQLAlchemyError  # type: ignore

from artemis import load_risk_class
from artemis.binds import TaskStatus
from artemis.config import Config
from artemis.modules import nuclei as nuclei_module
from artemis.modules.nuclei import NUCLEI_TEMPLATES_LOCATION, Nuclei, ScanUsing
from artemis.resource_lock import ResourceLock
from artemis.utils import CalledProcessErrorWithMessage, directory_backup

from cybercover.github_templates import (
    TemplateLookupError,
    _parse_additions,
    get_daily_additions,
    get_template_contents,
    installed_templates_version,
    latest_release,
    parse_version,
    templates_to_scan,
)
from cybercover.keys import client_key
from cybercover.state import EndpointKey, ScanStateStore

log = logging.getLogger(__name__)

ALLOWED_SEVERITIES = {"high", "critical"}

# Nuclei exits with this error when every template of a run failed to load, e.g. templates from main
# that need a newer Nuclei engine than the installed one. A mix of loadable and unloadable templates
# exits 0 and Nuclei silently skips the unloadable ones.
NO_LOADABLE_TEMPLATES = "no templates provided for scan"

TEMPLATES_SKIPPED = Counter(
    "cybercover_templates_skipped_total",
    "Incremental templates skipped instead of failing the scan",
    ["reason"],
)


def filter_templates(
    contents: Dict[str, bytes], severity_levels: Set[str]
) -> Tuple[Dict[str, bytes], Dict[str, Set[str]], Dict[str, str]]:
    """Select eligible templates.

    Returns (selected contents, tags by path, skipped invalid templates with the reason). Templates
    outside the severity policy or using headless are filtered silently; templates whose YAML or
    metadata is invalid are skipped and reported, so one broken file never blocks the other templates.
    """
    selected: Dict[str, bytes] = {}
    tags_by_path: Dict[str, Set[str]] = {}
    skipped: Dict[str, str] = {}
    for path, content in contents.items():
        try:
            template = yaml.safe_load(content)
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            skipped[path] = f"invalid YAML: {exc}"
            continue
        if not isinstance(template, dict) or not isinstance(template.get("info"), dict):
            skipped[path] = "missing template metadata"
            continue
        info = template["info"]
        severity = info.get("severity")
        if not isinstance(severity, str):
            skipped[path] = "missing or invalid severity"
            continue
        if severity.lower() not in severity_levels or path.startswith("headless/") or "headless" in template:
            continue
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = tags.split(",")
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            skipped[path] = "invalid tags"
            continue
        selected[path] = content
        tags_by_path[path] = {tag.strip().lower() for tag in tags if tag.strip()}
    for path, reason in sorted(skipped.items()):
        log.warning("Skipping invalid incremental template %s: %s", path, reason)
        TEMPLATES_SKIPPED.labels(reason="invalid_template").inc()
    return selected, tags_by_path, skipped


def release_template_contents(root: str) -> Tuple[Dict[str, bytes], List[str]]:
    """Read the installed release's new templates (the list Nuclei's -nt uses).

    A missing ``.new-additions`` file raises OSError (the installation is broken, so the scan must
    not count as done); a listed template missing from disk is skipped and returned as missing.
    """
    directory = Path(root)
    paths = _parse_additions((directory / ".new-additions").read_bytes())
    contents: Dict[str, bytes] = {}
    missing: List[str] = []
    for path in sorted(paths):
        try:
            contents[path] = (directory / path).read_bytes()
        except OSError:
            missing.append(path)
    for path in missing:
        log.warning("Skipping template listed in the installed release's .new-additions but missing: %s", path)
        TEMPLATES_SKIPPED.labels(reason="missing_release_file").inc()
    return contents, missing


def endpoint_key(task: Task) -> EndpointKey:
    host = str(task.get_payload("host"))
    return client_key(task, fallback=host), host, int(task.get_payload("port"))


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class CybercoverNuclei(Nuclei):
    """
    Incremental scan using daily changes from nuclei-templates/.new-additions.

    The worker remembers, per customer endpoint (original target, host, port), the release and the
    daily snapshot its last successful scan used. It downloads newly added YAML files from GitHub as
    custom templates; on first scans and release transitions it also reads the installed release's
    native new-template list.

    Disabled by default (add it to MODULES_DISABLED_BY_DEFAULT) - enable it explicitly through /api/add.
    """

    identity = "cybercover_nuclei"

    _custom_template_paths: Dict[str, str] = {}
    _template_tags: Dict[str, Set[str]] = {}
    _severity_levels: List[str] = []
    _incremental = False
    _scanned_categories: Set[bool] = set()
    _nuclei_failures = 0
    _unloadable_runs = 0
    _state: Optional[ScanStateStore] = None
    _shared_templates_lock: Optional[ResourceLock] = None
    _nuclei_version: Optional[str] = None

    @property
    def lock(self) -> ResourceLock:
        """The template lock shared with Artemis' nuclei-module.

        Both modules update the same nuclei-templates volume (at startup and, here, before a scan
        when a new release exists). Artemis names the lock after the module identity, which would
        give the two modules different locks, so the assignment in ArtemisBase is replaced by the
        stock module's lock.
        """
        if self._shared_templates_lock is None:
            self._shared_templates_lock = ResourceLock(res_name=Nuclei.identity)
        return self._shared_templates_lock

    @lock.setter
    def lock(self, _value: Any) -> None:
        self._shared_templates_lock = ResourceLock(res_name=Nuclei.identity)

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
            except CalledProcessErrorWithMessage as exc:
                stderr = (exc.stderr or b"").decode("utf-8", errors="ignore")
                if NO_LOADABLE_TEMPLATES in stderr or NO_LOADABLE_TEMPLATES in str(exc):
                    # Not a scan failure: no selected template could be loaded by this Nuclei engine.
                    self._unloadable_runs += 1
                    TEMPLATES_SKIPPED.labels(reason="unloadable_by_nuclei").inc()
                    self.log.warning(
                        "Nuclei %s could not load any template of a batch; skipping it",
                        self._nuclei_version or "(unknown version)",
                    )
                else:
                    self._nuclei_failures += 1
                raise

        nuclei_module.check_output_log_on_error_with_stderr = wrapper
        try:
            yield
        finally:
            nuclei_module.check_output_log_on_error_with_stderr = original

    def _get_links(self, url: str) -> List[str]:
        # Links of the homepage are scanned only with NUCLEI_TEMPLATES_TO_RUN_ON_HOMEPAGE_LINKS; skip
        # the crawl when no selected template is on that list.
        if self._incremental:
            homepage_templates = set(Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_RUN_ON_HOMEPAGE_LINKS)
            if not homepage_templates.intersection(self._custom_template_paths):
                return []
        return super()._get_links(url)

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
        # templates that are also on that list.
        is_link_scan = is_dast in self._scanned_categories
        self._scanned_categories.add(is_dast)

        excluded_tags: Set[str] = set()
        included_tags: Set[str] = set()
        for index, flag in enumerate(extra_nuclei_args[:-1]):
            if flag in ("-etags", "-exclude-tags"):
                excluded_tags.update(tag.strip().lower() for tag in extra_nuclei_args[index + 1].split(","))
            elif flag in ("-itags", "-include-tags"):
                included_tags.update(tag.strip().lower() for tag in extra_nuclei_args[index + 1].split(","))
        excluded_tags -= included_tags
        selected = [
            local_path
            for path, local_path in self._custom_template_paths.items()
            if path.startswith("dast/") == is_dast
            and (not is_link_scan or NUCLEI_TEMPLATES_LOCATION + path in templates_or_workflows)
            and not (self._template_tags.get(path, set()) & excluded_tags)
        ]
        if self._severity_levels:
            extra_nuclei_args.extend(["-severity", ",".join(self._severity_levels)])
        if not selected:
            self.log.info("No eligible incremental templates for %s scan", "dast" if is_dast else "templates")
            return []
        extra_nuclei_args.extend(["-new-templates=false", "-new-templates-version=", "-headless=false"])
        kwargs["extra_nuclei_args"] = extra_nuclei_args

        self.log.info(
            "Incremental %s %s scan: %d eligible templates",
            "dast" if is_dast else "templates",
            "link" if is_link_scan else "main",
            len(selected),
        )
        findings = super()._scan(selected, scan_using, targets, *args, **kwargs)

        # Templates from main run from a temporary directory; record their repository path like the
        # stock module does for installed templates, so reporters and deduplication see e.g.
        # "http/cves/2026/CVE-2026-0001.yaml" rather than a random temporary path.
        relative_paths = {local: path for path, local in self._custom_template_paths.items()}
        for finding in findings:
            if "template" not in finding and finding.get("template-path") in relative_paths:
                finding["template"] = relative_paths[finding["template-path"]]
        return findings

    def save_task_result(
        self, task: Task, *, status: TaskStatus, status_reason: Optional[str] = None, data: Optional[Any] = None
    ) -> None:
        if self._incremental and self._nuclei_failures:
            status = TaskStatus.ERROR
            status_reason = f"{self._nuclei_failures} Nuclei runs failed; results may be incomplete"
        super().save_task_result(task=task, status=status, status_reason=status_reason, data=data)

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
            # Another module may have installed it while we waited for the lock.
            current = installed_templates_version()
            if not current or parse_version(current) < parse_version(remote):
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

    def _log_nuclei_version(self) -> None:
        if CybercoverNuclei._nuclei_version is None:
            try:
                output = subprocess.run(["nuclei", "-version"], capture_output=True, timeout=60)
                match = re.search(rb"Nuclei Engine Version: (v[\d.]+)", output.stdout + output.stderr)
                CybercoverNuclei._nuclei_version = match.group(1).decode() if match else "unknown"
            except (OSError, subprocess.SubprocessError):
                CybercoverNuclei._nuclei_version = "unknown"
        self.log.info("Nuclei engine %s", CybercoverNuclei._nuclei_version)

    def run_multiple(self, tasks: List[Task]) -> None:
        if not tasks:
            return

        try:
            installed_version = installed_templates_version()
            if not installed_version:
                raise TemplateLookupError("Unable to determine the installed nuclei-templates release")
            installed_version = self._update_templates_if_needed(installed_version)
            self._log_nuclei_version()
            # The snapshot date is fixed when the batch starts and stored with the result, so the
            # next scan diffs against the snapshot that was actually used (even past midnight).
            today = datetime.datetime.now(datetime.timezone.utc).date()
            additions = get_daily_additions(today, installed_version, self.cache.get, self.cache.set)
            stored = self.state.get_states(endpoint_key(task) for task in tasks)
        except (TemplateLookupError, SQLAlchemyError, OSError, subprocess.CalledProcessError, ValueError) as exc:
            self._fail(tasks, f"Unable to prepare incremental scan: {exc}")
            return

        groups: Dict[Tuple[Optional[str], Optional[datetime.date]], List[Task]] = {}
        for task in tasks:
            state = stored.get(endpoint_key(task))
            group_key = (state[0], state[1]) if state else (None, None)
            groups.setdefault(group_key, []).append(task)

        for (last_version, last_snapshot_date), group in groups.items():
            self._run_group(group, last_version, last_snapshot_date, installed_version, today, additions)

    def _run_group(
        self,
        tasks: List[Task],
        last_version: Optional[str],
        last_snapshot_date: Optional[datetime.date],
        installed_version: str,
        today: datetime.date,
        additions: Set[str],
    ) -> None:
        try:
            changed, use_native_nt = templates_to_scan(
                last_version, last_snapshot_date, installed_version, today, additions, self.cache.get
            )
            contents = get_template_contents(changed, today, installed_version, self.cache.get, self.cache.set)
            downloaded_count = len(contents)
            release_paths: Set[str] = set()
            if use_native_nt:
                release_contents, _missing = release_template_contents(NUCLEI_TEMPLATES_LOCATION)
                release_paths = set(release_contents) - set(contents)
                release_contents.update(contents)
                contents = release_contents
            severity_levels = [
                level
                for level in self.get_runtime_configuration(tasks[0]).get_severity_options()
                if level in ALLOWED_SEVERITIES
            ]
            contents, tags_by_path, skipped = filter_templates(contents, set(severity_levels))
        except (TemplateLookupError, OSError, subprocess.CalledProcessError, ValueError) as exc:
            self._fail(tasks, str(exc))
            return

        for task in tasks:
            task.add_payload("templates_after_version", last_version, persistent=True)
            task.add_payload("templates_version", installed_version, persistent=True)

        self.log.info(
            "%d targets: %d changed templates (%d downloaded), %d eligible, %d invalid skipped, since snapshot %s "
            "(installed %s; release list=%s)",
            len(tasks),
            len(changed),
            downloaded_count,
            len(contents),
            len(skipped),
            last_snapshot_date,
            installed_version,
            use_native_nt,
        )
        keys = [endpoint_key(task) for task in tasks]
        if not contents:
            for task in tasks:
                self.save_task_result(
                    task=task, status=TaskStatus.OK, status_reason="No eligible new templates", data=[]
                )
            self.state.set_versions(keys, installed_version, today)
        else:
            with tempfile.TemporaryDirectory(prefix="cybercover-nuclei-") as directory:
                custom_paths: Dict[str, str] = {}
                for relative_path, content in contents.items():
                    if relative_path in release_paths:
                        destination = Path(NUCLEI_TEMPLATES_LOCATION) / relative_path
                    else:
                        destination = Path(directory) / relative_path
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(content)
                    custom_paths[relative_path] = str(destination)

                self._custom_template_paths = custom_paths
                self._template_tags = tags_by_path
                self._severity_levels = severity_levels
                self._incremental = True
                self._scanned_categories = set()
                self._nuclei_failures = 0
                self._unloadable_runs = 0
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
                        self.state.set_versions(keys, installed_version, today)
                finally:
                    self._custom_template_paths = {}
                    self._template_tags = {}
                    self._severity_levels = []
                    self._incremental = False
                    self._scanned_categories = set()


if __name__ == "__main__":
    start_http_server(9001)
    CybercoverNuclei.parallel_loop()
