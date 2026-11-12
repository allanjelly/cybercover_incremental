"""Fetch and cache daily additions from the nuclei-templates repository."""

import datetime
import json
import logging
import os
import re
from pathlib import PurePosixPath
from typing import Callable, List, Optional, Set, Tuple
from urllib.parse import quote

import requests

REPO = os.environ.get("CYBERCOVER_TEMPLATES_REPO", "projectdiscovery/nuclei-templates")
API = "https://api.github.com"
RAW = f"https://raw.githubusercontent.com/{REPO}"
TEMPLATES_CONFIG_PATH = os.path.expanduser("~/.config/nuclei/.templates-config.json")
CACHE_TTL = 30 * 24 * 60 * 60
RELEASE_CHECK_TTL = 24 * 60 * 60
LAST_KNOWN_RELEASE_KEY = "cybercover:last-known-release"
VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")

log = logging.getLogger(__name__)

CacheGet = Callable[[str], Optional[bytes]]
CacheSet = Callable[..., None]
# Stores a value only if the key is absent and returns the value that is stored afterwards (ours or
# one written concurrently by another worker), e.g. Redis SET NX followed by GET.
CacheAdd = Callable[..., bytes]

MAX_RELEASE_PAGES = 10


class TemplateLookupError(Exception):
    pass


class TemplateNotFoundError(TemplateLookupError):
    """The file does not exist on GitHub (e.g. a template listed in .new-additions was removed)."""


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
        if response.status_code == 404:
            raise TemplateNotFoundError(f"GitHub returned 404: {url}")
        response.raise_for_status()
        return response.content if raw else response.json()
    except TemplateNotFoundError:
        raise
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
    """Parse a .new-additions list. Invalid entries (non-YAML files, absolute or ``..`` paths) are
    skipped with a warning rather than failing every customer's scan; a skipped path is never
    fetched or written to disk."""
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise TemplateLookupError("Invalid UTF-8 in nuclei-templates .new-additions") from exc
    paths: Set[str] = set()
    for line in lines:
        if not line.strip():
            continue
        try:
            paths.add(_validate_template_path(line.strip()))
        except TemplateLookupError as exc:
            log.warning("Skipping entry of .new-additions: %s", exc)
    return paths


def get_daily_additions(
    day: datetime.date,
    version: str,
    cache_get: CacheGet,
    cache_set: CacheSet,
    session: Optional[requests.Session] = None,
    cache_add: Optional[CacheAdd] = None,
) -> Set[str]:
    """Return one stable snapshot of main/.new-additions per UTC date and installed release.

    With ``cache_add`` the snapshot is stored only if no other worker stored one for the same day
    first, and the stored snapshot is returned: every worker scans with the list that the next day's
    diff will use, even if main changed between their fetches.
    """
    key = f"cybercover:additions:{day.isoformat()}:{version}"
    cached = cache_get(key)
    if cached is not None:
        return set(json.loads(cached))

    session = session or requests.Session()
    content = _request(session, f"{RAW}/main/.new-additions", raw=True)
    if not isinstance(content, bytes):
        raise TemplateLookupError("Unexpected response for nuclei-templates .new-additions")
    additions = _parse_additions(content)
    value = json.dumps(sorted(additions)).encode("utf-8")
    if cache_add is None:
        _cache_set(cache_set, key, value)
        return additions
    return set(json.loads(cache_add(key, value, timeout=CACHE_TTL)))


def get_cached_additions(day: datetime.date, version: str, cache_get: CacheGet) -> Optional[Set[str]]:
    cached = cache_get(f"cybercover:additions:{day.isoformat()}:{version}")
    return set(json.loads(cached)) if cached is not None else None


def templates_to_scan(
    last_version: Optional[str],
    last_scan_date: Optional[datetime.date],
    installed_version: str,
    today: datetime.date,
    today_additions: Set[str],
    cache_get: CacheGet,
) -> Tuple[Set[str], bool]:
    """Return changed paths and whether to run Nuclei's native -nt for this scan."""
    if last_version is None or last_scan_date is None:
        return set(today_additions), True

    try:
        release_changed = parse_version(last_version) < parse_version(installed_version)
    except ValueError as exc:
        raise TemplateLookupError(str(exc)) from exc
    if release_changed:
        # -nt covers the intervening release; today's main snapshot covers changes made after it.
        return set(today_additions), True

    if last_scan_date >= today:
        return set(), False
    previous_additions = get_cached_additions(last_scan_date, last_version, cache_get)
    if previous_additions is None:
        # If Redis lost an older daily snapshot, rescan today's list rather than risk a gap.
        return set(today_additions), False
    return set(today_additions) - previous_additions, False


def releases_between(
    older: str,
    newer: str,
    cache_get: CacheGet,
    cache_set: CacheSet,
    session: Optional[requests.Session] = None,
) -> List[str]:
    """Release tags strictly between ``older`` and ``newer``, oldest first.

    Each nuclei-templates release lists in its ``.new-additions`` only what was added since the
    previous release, so a jump over several releases needs the lists of the releases in between.
    """
    try:
        low, high = parse_version(older), parse_version(newer)
    except ValueError as exc:
        raise TemplateLookupError(str(exc)) from exc
    if high <= low:
        return []
    day = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    key = f"cybercover:releases:{day}:{older}"
    cached = cache_get(key)
    tags = json.loads(cached) if cached is not None else None
    # A list cached earlier today may predate releases published since; refetch if it does not
    # reach the newer release.
    if tags is None or not any(parse_version(tag) >= high for tag in tags):
        session = session or requests.Session()
        tags = []
        reached = False
        for page in range(1, MAX_RELEASE_PAGES + 1):
            data = _request(session, f"{API}/repos/{REPO}/releases", params={"per_page": 100, "page": page})
            if not isinstance(data, list):
                raise TemplateLookupError("Unexpected GitHub releases response")
            if not data:
                reached = True  # no older releases exist
                break
            versions = []
            for release in data:
                tag = release.get("tag_name") if isinstance(release, dict) else None
                try:
                    versions.append(parse_version(tag))
                except ValueError:
                    continue
                if not release.get("draft"):
                    tags.append(tag)
            if versions and min(versions) <= low:
                reached = True
                break
        if not reached:
            raise TemplateLookupError(f"Unable to list nuclei-templates releases back to {older}")
        _cache_set(cache_set, key, json.dumps(tags).encode("utf-8"), RELEASE_CHECK_TTL)
    between = {tag for tag in tags if low < parse_version(tag) < high}
    return sorted(between, key=parse_version)


def release_additions(
    tag: str,
    cache_get: CacheGet,
    cache_set: CacheSet,
    session: Optional[requests.Session] = None,
) -> Optional[Set[str]]:
    """The ``.new-additions`` list of a published release (what it added since the previous one).

    None if the release has no such file (GitHub answers 404). A release without new templates has an
    empty file, so a missing file is abnormal upstream and its additions are unknown. Other errors
    (GitHub unreachable) raise TemplateLookupError.
    """
    key = f"cybercover:release-additions:{tag}"
    cached = cache_get(key)
    if cached is not None:
        value = json.loads(cached)
        return None if value is None else set(value)
    session = session or requests.Session()
    try:
        content = _request(session, f"{RAW}/{quote(tag, safe='')}/.new-additions", raw=True)
    except TemplateNotFoundError:
        _cache_set(cache_set, key, b"null")
        return None
    if not isinstance(content, bytes):
        raise TemplateLookupError(f"Unexpected response for .new-additions of {tag}")
    additions = _parse_additions(content)
    _cache_set(cache_set, key, json.dumps(sorted(additions)).encode("utf-8"))
    return additions


def intermediate_release_additions(
    older: str,
    newer: str,
    cache_get: CacheGet,
    cache_set: CacheSet,
    session: Optional[requests.Session] = None,
    on_missing_list: Optional[Callable[[str], None]] = None,
) -> Set[str]:
    """Templates added by the releases strictly between ``older`` and ``newer``.

    A release without a ``.new-additions`` file is skipped with a warning (and ``on_missing_list``),
    so it cannot block the endpoints scanned before it forever; its additions wait for the next full
    scan.
    """
    paths: Set[str] = set()
    for tag in releases_between(older, newer, cache_get, cache_set, session):
        additions = release_additions(tag, cache_get, cache_set, session)
        if additions is None:
            log.warning("Release %s has no .new-additions list; its new templates wait for the next full scan", tag)
            if on_missing_list:
                on_missing_list(tag)
            continue
        paths |= additions
    return paths


def latest_release(
    cache_get: CacheGet,
    cache_set: CacheSet,
    session: Optional[requests.Session] = None,
) -> str:
    key = f"cybercover:latest-release:{datetime.datetime.now(datetime.timezone.utc).date().isoformat()}"
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
    _cache_set(cache_set, LAST_KNOWN_RELEASE_KEY, version.encode("utf-8"), CACHE_TTL)
    return version


def last_known_release(cache_get: CacheGet) -> Optional[str]:
    """The newest release seen by ``latest_release`` in the last 30 days, for use while GitHub is
    unreachable (so callers don't fall back to an older installed release and flip-flop)."""
    cached = cache_get(LAST_KNOWN_RELEASE_KEY)
    if cached is None:
        return None
    version = cached.decode("utf-8")
    try:
        parse_version(version)
    except ValueError:
        return None
    return version


def get_template_contents(
    paths: Set[str],
    day: datetime.date,
    version: str,
    cache_get: CacheGet,
    cache_set: CacheSet,
    session: Optional[requests.Session] = None,
) -> dict[str, bytes]:
    """Fetch template YAMLs from main (missing files are skipped); cache each day's content for reuse across clients."""
    session = session or requests.Session()
    contents: dict[str, bytes] = {}
    for path in sorted(paths):
        try:
            path = _validate_template_path(path)
        except TemplateLookupError as exc:
            # Normally removed when the list is fetched; also skip it here (e.g. a corrupted cache).
            log.warning("Skipping template: %s", exc)
            continue
        key = f"cybercover:template:{day.isoformat()}:{version}:{path}"
        cached = cache_get(key)
        if cached is not None:
            contents[path] = cached
            continue

        encoded_path = quote(path, safe="/")
        try:
            content = _request(session, f"{RAW}/main/{encoded_path}", raw=True)
        except TemplateNotFoundError:
            log.warning("Skipping template listed in .new-additions but missing on main: %s", path)
            continue
        if not isinstance(content, bytes) or not content:
            raise TemplateLookupError(f"Empty or invalid template response for {path}")
        _cache_set(cache_set, key, content)
        contents[path] = content
    return contents
