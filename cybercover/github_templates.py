"""Fetch and cache daily additions from the nuclei-templates repository."""

import datetime
import json
import os
import re
from pathlib import PurePosixPath
from typing import Callable, Optional, Set, Tuple
from urllib.parse import quote

import requests

REPO = os.environ.get("CYBERCOVER_TEMPLATES_REPO", "projectdiscovery/nuclei-templates")
API = "https://api.github.com"
RAW = f"https://raw.githubusercontent.com/{REPO}"
TEMPLATES_CONFIG_PATH = os.path.expanduser("~/.config/nuclei/.templates-config.json")
CACHE_TTL = 30 * 24 * 60 * 60
RELEASE_CHECK_TTL = 6 * 60 * 60
VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")

CacheGet = Callable[[str], Optional[bytes]]
CacheSet = Callable[..., None]


class TemplateLookupError(Exception):
    pass


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


def _request(
    session: requests.Session,
    url: str,
    *,
    params: Optional[dict] = None,
    raw: bool = False,
) -> object:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("CYBERCOVER_GITHUB_TOKEN")
    if token and url.startswith(API):
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = session.get(url, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        return response.content if raw else response.json()
    except (requests.RequestException, ValueError) as exc:
        raise TemplateLookupError(f"GitHub request failed: {url}: {exc}") from exc


def _cache_set(cache_set: CacheSet, key: str, value: bytes, ttl: int = CACHE_TTL) -> None:
    cache_set(key, value, timeout=ttl)


def _validate_template_path(path: str) -> str:
    parsed = PurePosixPath(path)
    if (
        parsed.is_absolute()
        or not parsed.parts
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or parsed.suffix not in {".yaml", ".yml"}
    ):
        raise TemplateLookupError(f"Invalid template path in .new-additions: {path!r}")
    return parsed.as_posix()


def _parse_additions(data: bytes) -> Set[str]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise TemplateLookupError("Invalid UTF-8 in nuclei-templates .new-additions") from exc
    return {_validate_template_path(line.strip()) for line in lines if line.strip()}


def get_daily_additions(
    day: datetime.date,
    version: str,
    cache_get: CacheGet,
    cache_set: CacheSet,
    session: Optional[requests.Session] = None,
) -> Set[str]:
    """Return one stable snapshot of main/.new-additions per UTC date and installed release."""
    key = f"v5:additions:{day.isoformat()}:{version}"
    cached = cache_get(key)
    if cached is not None:
        return set(json.loads(cached))

    session = session or requests.Session()
    content = _request(session, f"{RAW}/main/.new-additions", raw=True)
    if not isinstance(content, bytes):
        raise TemplateLookupError("Unexpected response for nuclei-templates .new-additions")
    additions = _parse_additions(content)
    _cache_set(cache_set, key, json.dumps(sorted(additions)).encode("utf-8"))
    return additions


def get_cached_additions(day: datetime.date, version: str, cache_get: CacheGet) -> Optional[Set[str]]:
    cached = cache_get(f"v5:additions:{day.isoformat()}:{version}")
    return set(json.loads(cached)) if cached is not None else None


def templates_to_scan(
    last_version: Optional[str],
    last_scanned_at: Optional[datetime.datetime | datetime.date],
    installed_version: str,
    today: datetime.date,
    today_additions: Set[str],
    cache_get: CacheGet,
) -> Tuple[Set[str], bool]:
    """Return changed paths and whether to run Nuclei's native -nt for this scan."""
    if last_version is None or last_scanned_at is None:
        return set(today_additions), True

    try:
        release_changed = parse_version(last_version) < parse_version(installed_version)
    except ValueError as exc:
        raise TemplateLookupError(str(exc)) from exc
    if release_changed:
        # -nt covers the intervening release; today's main snapshot covers changes made after it.
        return set(today_additions), True

    previous_day = last_scanned_at.date() if isinstance(last_scanned_at, datetime.datetime) else last_scanned_at
    if previous_day >= today:
        return set(), False
    previous_additions = get_cached_additions(previous_day, last_version, cache_get)
    if previous_additions is None:
        # If Redis lost an older daily snapshot, rescan today's list rather than risk a gap.
        return set(today_additions), False
    return set(today_additions) - previous_additions, False


def latest_release(
    cache_get: CacheGet,
    cache_set: CacheSet,
    session: Optional[requests.Session] = None,
) -> str:
    key = "v5:latest-release"
    cached = cache_get(key)
    if cached is not None:
        return cached.decode("utf-8")

    session = session or requests.Session()
    data = _request(session, f"{API}/repos/{REPO}/releases/latest")
    if not isinstance(data, dict) or not isinstance(data.get("tag_name"), str):
        raise TemplateLookupError("Unexpected GitHub latest release response")
    version = data["tag_name"]
    try:
        parse_version(version)
    except ValueError as exc:
        raise TemplateLookupError(str(exc)) from exc
    _cache_set(cache_set, key, version.encode("utf-8"), RELEASE_CHECK_TTL)
    return version


def get_template_contents(
    paths: Set[str],
    day: datetime.date,
    version: str,
    cache_get: CacheGet,
    cache_set: CacheSet,
    session: Optional[requests.Session] = None,
) -> dict[str, bytes]:
    """Fetch template YAMLs from main; cache each day's content for reuse across clients."""
    session = session or requests.Session()
    contents: dict[str, bytes] = {}
    for path in sorted(paths):
        path = _validate_template_path(path)
        key = f"v5:template:{day.isoformat()}:{version}:{path}"
        cached = cache_get(key)
        if cached is not None:
            contents[path] = cached
            continue

        encoded_path = quote(path, safe="/")
        content = _request(session, f"{RAW}/main/{encoded_path}", raw=True)
        if not isinstance(content, bytes) or not content:
            raise TemplateLookupError(f"Empty or invalid template response for {path}")
        _cache_set(cache_set, key, content)
        contents[path] = content
    return contents
