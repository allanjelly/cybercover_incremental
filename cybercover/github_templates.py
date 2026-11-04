"""Lists nuclei-templates files added/modified since a release, between two release tags, using the GitHub compare API."""

import json
import os
from typing import Callable, Optional, Set, Tuple

import requests

from cybercover.modules.cybercover_nuclei_configuration import (
    ChangeType,
    parse_version,
)

REPO = os.environ.get("CYBERCOVER_TEMPLATES_REPO", "projectdiscovery/nuclei-templates")
API = "https://api.github.com"
TEMPLATES_CONFIG_PATH = os.path.expanduser("~/.config/nuclei/.templates-config.json")
PER_PAGE = 100
COMPARE_FILES_LIMIT = 300  # GitHub returns at most this many files from /compare

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
    after_version: str,
    change_type: ChangeType,
    head: Optional[str],
    session: Optional[requests.Session] = None,
) -> Tuple[Set[str], str]:
    """Return changed paths between ``after_version`` and the installed release, plus the covered version.

    If the client's version is not older than the installed one, nothing changed from our
    point of view; the installed version is returned so the caller retries from it.
    """
    session = session or requests.Session()
    if not head:
        raise TemplateLookupError("Unable to determine the installed nuclei-templates release")
    try:
        if parse_version(after_version) >= parse_version(head):
            return set(), head
    except ValueError as exc:
        raise TemplateLookupError(str(exc)) from exc

    data = _get(session, f"{API}/repos/{REPO}/compare/{after_version}...{head}", per_page=PER_PAGE, page=1)
    if not isinstance(data, dict):
        raise TemplateLookupError("Unexpected GitHub compare response")
    files = data.get("files", [])
    # /compare returns at most 300 files in total (later pages are empty), so a full page may be truncated
    if len(files) >= COMPARE_FILES_LIMIT:
        raise TemplateLookupError(
            f"Too many changed files between {after_version} and {head}, refusing a partial list - run a full scan"
        )
    wanted = ADDED_STATUSES if change_type == ChangeType.ADDED else ADDED_STATUSES | MODIFIED_STATUSES
    paths = {
        item["filename"]
        for item in files
        if item.get("status") in wanted and item["filename"].endswith((".yaml", ".yml"))
    }
    return paths, head


def get_changed_templates(
    after_version: str,
    change_type: ChangeType,
    head: Optional[str],
    cache_get: Callable[[str], Optional[bytes]],
    cache_set: Callable[[str, bytes], None],
) -> Tuple[Set[str], str]:
    """Cached wrapper (Artemis RedisCache): every scan with the same versions shares one lookup."""
    key = f"v3:{after_version}:{change_type.value}:{head}"
    cached = cache_get(key)
    if cached is not None:
        value = json.loads(cached)
        return set(value["templates"]), value["covered_until"]
    templates, covered_until = fetch_changed_templates(after_version, change_type, head)
    cache_set(key, json.dumps({"templates": sorted(templates), "covered_until": covered_until}).encode("utf-8"))
    return templates, covered_until
