"""Finds nuclei-templates files changed between two release tags, using the GitHub API."""

import json
import os
import re
from typing import Callable, Optional, Set, Tuple

import requests

REPO = os.environ.get("CYBERCOVER_TEMPLATES_REPO", "projectdiscovery/nuclei-templates")
API = "https://api.github.com"
TEMPLATES_CONFIG_PATH = os.path.expanduser("~/.config/nuclei/.templates-config.json")
COMPARE_FILES_LIMIT = 300  # GitHub returns at most this many files from /compare
VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
CHANGED_STATUSES = {"added", "renamed", "modified", "changed", "copied"}


class TemplateLookupError(Exception):
    pass


class TooManyChangesError(TemplateLookupError):
    """The gap is too big for the compare API: the caller should fall back to a full scan."""


def parse_version(value: object) -> Tuple[int, int, int]:
    """Parses a nuclei-templates release tag such as ``v10.5.1``."""
    match = VERSION_RE.match(value) if isinstance(value, str) else None
    if not match:
        raise ValueError(f"Invalid templates version: {value!r} (expected e.g. 'v10.5.1')")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


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


def previous_release(head: str, session: Optional[requests.Session] = None) -> str:
    """The newest nuclei-templates release older than ``head``."""
    session = session or requests.Session()
    head_version = parse_version(head)
    releases = _get(session, f"{API}/repos/{REPO}/releases", per_page=100)
    if not isinstance(releases, list):
        raise TemplateLookupError("Unexpected GitHub releases response")
    older = [
        item["tag_name"]
        for item in releases
        if isinstance(item, dict)
        and VERSION_RE.match(str(item.get("tag_name")))
        and parse_version(item["tag_name"]) < head_version
    ]
    if not older:
        raise TemplateLookupError(f"No release older than {head} found")
    return max(older, key=parse_version)


def fetch_changed_templates(
    after_version: str,
    head: str,
    session: Optional[requests.Session] = None,
) -> Set[str]:
    """Paths of templates added or modified between ``after_version`` and ``head``."""
    session = session or requests.Session()
    data = _get(session, f"{API}/repos/{REPO}/compare/{after_version}...{head}", per_page=100, page=1)
    if not isinstance(data, dict):
        raise TemplateLookupError("Unexpected GitHub compare response")
    files = data.get("files", [])
    # /compare returns at most 300 files in total (later pages are empty), so a full list may be truncated
    if len(files) >= COMPARE_FILES_LIMIT:
        raise TooManyChangesError(f"Too many changed files between {after_version} and {head}")
    return {
        item["filename"]
        for item in files
        if item.get("status") in CHANGED_STATUSES and item["filename"].endswith((".yaml", ".yml"))
    }


def get_changed_templates(
    after_version: str,
    head: str,
    cache_get: Callable[[str], Optional[bytes]],
    cache_set: Callable[[str, bytes], None],
) -> Set[str]:
    """Cached wrapper (Artemis RedisCache): scans with the same versions share one lookup."""
    key = f"v4:{after_version}:{head}"
    cached = cache_get(key)
    if cached is not None:
        value = json.loads(cached)
        if value.get("too_many"):
            raise TooManyChangesError(f"Too many changed files between {after_version} and {head}")
        return set(value["templates"])
    try:
        templates = fetch_changed_templates(after_version, head)
    except TooManyChangesError:
        cache_set(key, json.dumps({"too_many": True}).encode("utf-8"))
        raise
    cache_set(key, json.dumps({"templates": sorted(templates)}).encode("utf-8"))
    return templates


def get_previous_release(
    head: str,
    cache_get: Callable[[str], Optional[bytes]],
    cache_set: Callable[[str, bytes], None],
) -> str:
    key = f"v4:previous:{head}"
    cached = cache_get(key)
    if cached is not None:
        return cached.decode("utf-8")
    result = previous_release(head)
    cache_set(key, result.encode("utf-8"))
    return result
