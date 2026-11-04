"""Lists nuclei-templates files added/modified since a date, using the GitHub compare API."""

import datetime
import json
import os
from typing import Callable, Optional, Set

import requests

from cybercover.modules.cybercover_nuclei_configuration import ChangeType

REPO = os.environ.get("CYBERCOVER_TEMPLATES_REPO", "projectdiscovery/nuclei-templates")
API = "https://api.github.com"
TEMPLATES_CONFIG_PATH = os.path.expanduser("~/.config/nuclei/.templates-config.json")
PER_PAGE = 100
COMPARE_FILES_LIMIT = 3000  # GitHub does not return more files than this from /compare

ADDED_STATUSES = {"added", "renamed"}
MODIFIED_STATUSES = {"modified", "changed", "copied"}


class TemplateLookupError(Exception):
    pass


def installed_templates_version(path: str = TEMPLATES_CONFIG_PATH) -> Optional[str]:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f).get("nuclei-templates-version") or None
    except (OSError, ValueError):
        return None


def _get(session: requests.Session, url: str, **params: object) -> object:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("CYBERCOVER_GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = session.get(url, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as exc:
        raise TemplateLookupError(f"GitHub request failed: {url}: {exc}") from exc


def fetch_changed_templates(
    after: datetime.date,
    change_type: ChangeType,
    head: Optional[str],
    session: Optional[requests.Session] = None,
) -> Set[str]:
    """Paths of templates changed from the last commit before ``after`` up to ``head``
    (the installed release tag; the default branch if unknown)."""
    session = session or requests.Session()
    head = head or "HEAD"

    until = datetime.datetime.combine(after, datetime.time.min, tzinfo=datetime.timezone.utc).isoformat()
    commits = _get(session, f"{API}/repos/{REPO}/commits", until=until, per_page=1)
    if not isinstance(commits, list) or not commits:
        raise TemplateLookupError(f"No commit found before {after}")
    base = commits[0]["sha"]

    wanted = ADDED_STATUSES if change_type == ChangeType.ADDED else ADDED_STATUSES | MODIFIED_STATUSES
    paths: Set[str] = set()
    num_files = 0
    page = 1
    while True:
        data = _get(session, f"{API}/repos/{REPO}/compare/{base}...{head}", per_page=PER_PAGE, page=page)
        if not isinstance(data, dict):
            raise TemplateLookupError("Unexpected GitHub compare response")
        files = data.get("files", [])
        num_files += len(files)
        paths.update(
            item["filename"]
            for item in files
            if item.get("status") in wanted and item["filename"].endswith((".yaml", ".yml"))
        )
        if len(files) < PER_PAGE or num_files >= COMPARE_FILES_LIMIT:
            break
        page += 1
    if num_files >= COMPARE_FILES_LIMIT:
        raise TemplateLookupError(f"Too many changed files since {after} ({num_files}+), refusing a partial list")
    return paths


def get_changed_templates(
    after: datetime.date,
    change_type: ChangeType,
    head: Optional[str],
    cache_get: Callable[[str], Optional[bytes]],
    cache_set: Callable[[str, bytes], None],
) -> Set[str]:
    """Cached wrapper (Artemis RedisCache): every scan in a day shares one lookup."""
    key = f"{after.isoformat()}:{change_type.value}:{head}"
    cached = cache_get(key)
    if cached is not None:
        return set(json.loads(cached))
    result = fetch_changed_templates(after, change_type, head)
    cache_set(key, json.dumps(sorted(result)).encode("utf-8"))
    return result
