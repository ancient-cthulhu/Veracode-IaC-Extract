#!/usr/bin/env python3
"""Standalone Veracode Container / IaC / Secrets findings extractor.

Pulls scans and findings from the Veracode Container Security query API
(the same one the Platform UI uses), filters them, and writes a flat,
developer-friendly CSV / JSON / JSONL / Excel export.

Library use (no argparse, no sys.exit; the API is the names in __all__):

    import veracode_iac_extract as vx
    scans, rows, failures = vx.collect_latest(asset="my-org/*", workers=4, rps=2)

collect_latest() reads the latest scan of every asset that passes the scan filters. It returns
(a scan row for every scan in the tenant, the finding rows of the scans it read, the failed requests
as (scope, detail) pairs). Rows use the export's column names. A scan row has "_read": True when its
findings were read in full. Bad input raises ExtractError with exit_code 2; a failed token or scan
list request raises ExtractError with exit_code 1.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import fnmatch
import hashlib
import html
import io
import json
import os
import random
import re
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterable, Optional

import requests
from requests.adapters import HTTPAdapter

__version__ = "2.0.0"

# Library API: stable for importers such as the findings tracker. Everything else is internal.
__all__ = [
    "__version__", "collect_latest", "ExtractError", "FetchError", "Client", "mint_principal_token",
    "finding_row", "mitigation_key", "code_hash", "csv_safe", "read_csv_file", "write_output", "save_output",
    "OutputLocked", "order_columns", "xlsx_too_big", "BASE_COLUMNS", "SEVERITY_RANK", "SEVERITY_LABEL",
    "main", "map_credential_env",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_IAC_BASE = "https://ui.analysiscenter.veracode.com/container-scan-query/v1"
DEFAULT_LINK_BASE = "https://web.analysiscenter.veracode.com/app/container-iac-scans"
DEFAULT_API_BASE = "https://api.veracode.com"
# Region (from the API key ID prefix) -> (query API base, Veracode Link base, REST API base).
# FedRAMP hosts are not listed: they must be given explicitly.
REGION_ENDPOINTS = {
    "global": (DEFAULT_IAC_BASE, DEFAULT_LINK_BASE, DEFAULT_API_BASE),
    "eu": ("https://ui.analysiscenter.veracode.eu/container-scan-query/v1",
           "https://web.analysiscenter.veracode.eu/app/container-iac-scans",
           "https://api.veracode.eu"),
}
AUTH_PREFIX = "VERACODE-TOKEN vsid="
PAGE_LIMIT = 5000
MAX_PAGES = 10_000
RETRYABLE = frozenset({408, 425, 429, 500, 502, 503, 504})
MAX_BACKOFF = 90.0
MULTI_SEP = " | "

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "negligible": 1, "unknown": 0}
SEVERITY_LABEL = {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Negligible", 0: "Unknown"}

# Output column -> raw API field(s).
SCAN_FIELDS: dict[str, tuple[str, ...]] = {
    "Asset Name": ("asset_name",),
    "Asset ID": ("asset_id",),
    "Asset Type": ("asset_type",),
    "Scan Type": ("scan_type",),
    "Scan Source": ("source",),
    "Is Source Link": ("is_source_link",),
    "Scan ID": ("scan_id",),
    "Scan Date": ("scanned_at",),
    "Scan Duration": ("duration",),
    "Scan Status": ("scan_status",),
    "Scanned By": ("user_name",),
    "Policy Name": ("policy_name",),
    "Policy ID": ("policy_id",),
    "Scan Policy Status": ("policy_status",),
}
FINDING_FIELDS: dict[str, tuple[str, ...]] = {
    "Finding ID": ("id",),
    "Finding Type": ("finding_type",),
    "Severity": ("severity",),
    "CVSS": ("cvss",),
    "Exploitability Score": ("exploitability_score",),
    "Impact Score": ("impact_score",),
    "Title": ("title",),
    "Description": ("description",),
    "Suggested Fix": ("suggested_fix",),
    "Rule ID": ("rule_id",),
    "Category": ("category",),
    "Provider": ("provider",),
    "Service": ("service",),
    "Resource": ("resource",),
    "File Path": ("filepath",),
    "Start Line": ("start_line",),
    "End Line": ("end_line",),
    "Code Lines": ("code_lines",),
    "Library Name": ("library_name",),
    "Library Version": ("library_version",),
    "Fix State": ("fix_state",),
    "Fixed Versions": ("fixed_versions",),
    "References": ("reference_urls",),
    "Layer IDs": ("layer_ids",),
    "Finding Policy Status": ("policy_status",),
}
IMAGE_FIELDS = {"Image Hash": "image_hash", "Image Distro": "distro", "Image Tags": "tags",
                "Image Labels": "labels", "Image Layer IDs": "layer_ids"}
HISTOGRAM_COLUMNS = {sev: f"Scan {sev.title()}" for sev in SEVERITY_RANK}

BASE_COLUMNS = [
    "Asset Name", "Asset ID", "Asset Type", "Scan Type", "Scan Source",
    "Application Name", "Application GUID", "Business Unit", "Teams",
    "Severity", "Severity Rank", "CVSS", "Exploitability Score", "Impact Score",
    "Finding Type", "Finding ID", "CVE ID", "Rule ID", "Category",
    "Title", "Description", "Suggested Fix",
    "Library", "Library Name", "Library Version", "Fix Available", "Fix State", "Fixed Versions",
    "Location", "File Path", "Start Line", "End Line", "All File Paths", "Code Lines",
    "Provider", "Service", "Resource", "References",
    "Finding Policy Status",
    "Image Tags", "Image Distro", "Image Hash", "Image Labels", "Layer IDs", "Image Layer IDs",
    "Scan ID", "Scan Date", "Scan Age Days", "Scan Duration", "Scan Status", "Scanned By",
    "Policy Name", "Policy ID", "Scan Policy Status", "Is Source Link",
    "Scan Total Findings", *HISTOGRAM_COLUMNS.values(),
    "Is Latest Scan For Asset", "First Seen", "Last Seen", "Seen In Scans",
    "Finding Key", "Veracode Link",
]
# Always kept even if empty across the export.
CORE_COLUMNS = {"Asset Name", "Severity", "Finding Type", "Finding ID", "Title",
                "File Path", "Scan ID", "Scan Date"}
POLICY_VALUES = {"failed": "error", "passed": "success", "not-assessed": "default"}
COMPACT_COLUMNS = ["Asset Name", "Scan Type", "Asset Type", "Severity", "CVSS", "Finding Type", "Finding ID", "Title",
                   "Library", "Fixed Versions", "Location", "Suggested Fix", "Scan Date", "Veracode Link"]
SCAN_INVENTORY_COLUMNS = [
    "Asset Name", "Asset ID", "Asset Type", "Scan Type", "Scan Source", "Is Source Link",
    "Scan ID", "Scan Date", "Scan Age Days", "Scan Duration", "Scan Status", "Scanned By",
    "Policy Name", "Policy ID", "Scan Policy Status",
    "Scan Total Findings", *HISTOGRAM_COLUMNS.values(),
    "Is Latest Scan For Asset", "Veracode Link",
]
APP_COLUMNS = ["Application Name", "Application GUID", "Business Unit", "Teams"]  # with --match-apps

_RE_TAG = re.compile(r"<[^>]+>")
_RE_WS = re.compile(r"\s+")
_RE_NORM = re.compile(r"[^a-z0-9]")
_RE_CVE = re.compile(r"\b(CVE-\d{4}-\d{3,}|GHSA(?:-[0-9a-z]{4}){3})\b", re.I)


# ---------------------------------------------------------------------------
# Plumbing: failures, rate limit, HTTP with retry, token
# ---------------------------------------------------------------------------

class FetchError(Exception):
    pass


class ExtractError(Exception):
    """A library call could not run. exit_code 2: bad input; 1: Veracode could not be read."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


CREDENTIAL_ALIASES = (("VERACODE_API_ID", "VERACODE_API_KEY_ID"), ("VERACODE_API_KEY", "VERACODE_API_KEY_SECRET"))


def map_credential_env() -> None:
    """VERACODE_API_ID / VERACODE_API_KEY are the standard names; the signing libraries read
    VERACODE_API_KEY_ID / VERACODE_API_KEY_SECRET. Copy them over when only the standard ones are set."""
    for std, lib in CREDENTIAL_ALIASES:
        if os.environ.get(std) and not os.environ.get(lib):
            os.environ[lib] = os.environ[std]


class Tracker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.failures: list[tuple[str, str]] = []
        self.retries = 0

    def fail(self, scope: str, detail: str) -> None:
        with self._lock:
            self.failures.append((scope, detail))
        print(f"    ! FAILED {scope}: {detail}", file=sys.stderr)

    def retry(self) -> None:
        with self._lock:
            self.retries += 1


class RateLimiter:
    """Token bucket with a global pause so one 429 stalls every worker."""

    def __init__(self, rps: float) -> None:
        self._rps = rps
        self._cap = max(1.0, rps)  # below 1 rps the bucket must still hold one whole token
        self._tokens = self._cap
        self._last = time.monotonic()
        self._pause_until = 0.0
        self._lock = threading.Lock()

    def pause(self, seconds: float) -> None:
        seconds = min(max(0.0, seconds), MAX_BACKOFF)
        with self._lock:
            self._pause_until = max(self._pause_until, time.monotonic() + seconds)

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                if now < self._pause_until:
                    wait = self._pause_until - now
                else:
                    self._tokens = min(self._cap, self._tokens + (now - self._last) * self._rps)
                    self._last = now
                    if self._tokens >= 1.0:
                        self._tokens -= 1.0
                        return
                    wait = (1.0 - self._tokens) / self._rps
            time.sleep(wait)


class TokenProvider:
    """Mints the principal token from HMAC credentials; re-mints once per expiry."""

    def __init__(self, minter: Callable[[], str]) -> None:
        self._minter = minter
        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self.refreshes = 0

    def get(self) -> str:
        with self._lock:
            if self._token is None:
                self._token = self._minter()
            return self._token

    def refresh(self, stale: str) -> None:
        with self._lock:
            if self._token == stale:  # nobody else refreshed while we waited
                self._token = self._minter()
                self.refreshes += 1


def mint_principal_token() -> str:
    """Exchange HMAC credentials for a session token (region-aware via veracode_api_py)."""
    map_credential_env()
    from veracode_api_py.apihelper import APIHelper
    try:
        principal = APIHelper()._rest_request("api/authn/v2/principal", "GET")
    except Exception as exc:
        raise RuntimeError(f"Failed to retrieve principal token: {exc}") from exc
    if not isinstance(principal, dict) or not principal.get("token"):
        raise RuntimeError("Principal response did not contain a token")
    return principal["token"]


def make_session(ca_cert: Optional[str]) -> requests.Session:
    s = requests.Session()
    adapter = HTTPAdapter(pool_connections=20, pool_maxsize=50, max_retries=0)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    if ca_cert:
        s.verify = ca_cert
    return s


class Client:
    def __init__(self, base_url: str, tokens: TokenProvider, limiter: RateLimiter,
                 tracker: Tracker, ca_cert: Optional[str], max_attempts: int, timeout: int) -> None:
        self.base = base_url.rstrip("/")
        self.tokens = tokens
        self.limiter = limiter
        self.tracker = tracker
        self.ca_cert = ca_cert
        self.max_attempts = max(1, max_attempts)
        self.timeout = timeout
        self._local = threading.local()

    def _session(self) -> requests.Session:
        if not hasattr(self._local, "s"):
            self._local.s = make_session(self.ca_cert)
        return self._local.s

    def get(self, url: str, params: dict[str, Any], scope: str) -> Optional[dict]:
        """GET with retry. Returns parsed JSON, or None on 404."""
        last = "unknown"
        refreshed = False
        attempt = 0
        while attempt < self.max_attempts:
            attempt += 1
            self.limiter.acquire()
            token = self.tokens.get()
            retry_after: Optional[float] = None
            try:
                resp = self._session().get(
                    url, params=params, timeout=self.timeout,
                    headers={"Authorization": AUTH_PREFIX + token, "Accept": "application/json"})
            except requests.RequestException as exc:
                last = f"{type(exc).__name__}: {str(exc)[:200]}"
            else:
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except ValueError as exc:
                        raise FetchError(f"{scope}: invalid JSON ({exc})") from exc
                    if not isinstance(data, dict):
                        raise FetchError(f"{scope}: expected a JSON object, got {type(data).__name__}")
                    return data
                if resp.status_code == 404:
                    return None
                if resp.status_code == 401 and not refreshed:
                    refreshed = True
                    try:
                        self.tokens.refresh(token)
                    except Exception as exc:
                        raise FetchError(f"{scope}: 401 and token refresh failed: {exc}") from exc
                    attempt -= 1
                    continue
                if resp.status_code not in RETRYABLE:
                    raise FetchError(f"{scope}: HTTP {resp.status_code}. {(resp.text or '')[:300]}")
                last = f"HTTP {resp.status_code}"
                try:  # capped: a huge Retry-After must not stall the run for hours
                    retry_after = min(MAX_BACKOFF, max(0.0, float(resp.headers.get("Retry-After", ""))))
                except ValueError:
                    retry_after = None
                if resp.status_code == 429:
                    self.limiter.pause(retry_after if retry_after is not None else 30.0)
            self.tracker.retry()
            if attempt >= self.max_attempts:
                break
            delay = retry_after if retry_after is not None else min(MAX_BACKOFF, 1.5 * 2 ** (attempt - 1))
            delay += random.uniform(0, 0.3 * max(delay, 0.5))
            print(f"    retry {attempt}/{self.max_attempts - 1} [{scope}] after {last}; sleeping {delay:.1f}s",
                  file=sys.stderr)
            time.sleep(delay)
        raise FetchError(f"{scope}: exhausted {self.max_attempts} attempts. Last error: {last}")

    def paginate(self, url: str, key: str, scope: str,
                 extra: Optional[dict[str, Any]] = None) -> list[dict]:
        out: list[dict] = []
        seen: set[str] = set()
        expected: Any = None
        prev: Optional[list] = None
        page = 0
        while True:
            params = dict(extra or {})
            params.update({"page": page, "limit": PAGE_LIMIT})
            data = self.get(url, params, f"{scope} page {page}")
            if data is None:
                break
            batch = data.get(key) or []
            if page > 0 and batch and batch == prev:
                self.tracker.fail(scope, "API returned the same page twice; stopped to avoid duplicates")
                break
            for rec in batch:  # pages can shift while reading: never keep the same record twice
                ident = json.dumps(rec, sort_keys=True, default=str)
                if ident not in seen:
                    seen.add(ident)
                    out.append(rec)
            prev = batch
            total_pages = (data.get("pagination") or {}).get("total_pages")
            expected = (data.get("pagination") or {}).get("total_elements")
            # A short page does not mean the end: the server may cap the page size.
            if not batch:
                break
            if isinstance(total_pages, (int, float)) and page >= int(total_pages) - 1:
                break
            if isinstance(expected, int) and len(out) >= expected:
                break
            page += 1
            if page >= MAX_PAGES:
                self.tracker.fail(scope, f"hit {MAX_PAGES}-page safety cap; result may be incomplete")
                break
        if isinstance(expected, int) and len(out) < expected:
            self.tracker.fail(scope, f"API reported {expected} records but only {len(out)} were returned")
        return out


# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------

def clean_text(value: Any) -> str:
    if value is None:
        return ""
    text = html.unescape(_RE_TAG.sub(" ", str(value)))
    return _RE_WS.sub(" ", text).strip()


def pick(record: dict, names: Iterable[str]) -> Any:
    for n in names:
        v = record.get(n)
        if v not in (None, "", [], {}):
            return v
    return None


def flat(value: Any) -> Any:
    """Make any JSON value fit in one cell."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, list):
        if all(not isinstance(v, (dict, list)) for v in value):
            return MULTI_SEP.join(str(v) for v in value if v not in (None, ""))
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def extras(record: dict, consumed: set[str], prefix: str) -> dict[str, Any]:
    """Every raw field not already mapped, flattened one level (a.b)."""
    out: dict[str, Any] = {}
    for k, v in record.items():
        if k in consumed or k == "detailed_findings":
            continue
        if isinstance(v, dict) and v:
            for k2, v2 in v.items():
                out[f"{prefix}: {k}.{k2}"] = flat(v2)
        else:
            out[f"{prefix}: {k}"] = flat(v)
    return out


def parse_when(value: Any) -> Optional[dt.datetime]:
    """Parse ISO 8601 or epoch (s / ms) into an aware UTC datetime."""
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            n = float(value)
            return dt.datetime.fromtimestamp(n / 1000 if n > 1e11 else n, dt.timezone.utc)
        s = str(value).strip().replace("Z", "+00:00")
        s = re.sub(r"(\.\d{6})\d+", r"\1", s)  # trim nanoseconds
        d = dt.datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def parse_cutoff(value: str, now: dt.datetime) -> dt.datetime:
    """'30d', '12h', '2w' (relative), YYYYMMDD, or an ISO date / datetime. Other bare numbers are rejected."""
    text = value.strip()
    m = re.fullmatch(r"(\d+)([hdw])", text.lower())
    if m:
        unit = {"h": "hours", "d": "days", "w": "weeks"}[m.group(2)]
        return now - dt.timedelta(**{unit: int(m.group(1))})
    error = argparse.ArgumentTypeError(f"Unrecognised date '{value}'. Use YYYY-MM-DD, YYYYMMDD or e.g. 30d")
    if text.isdigit():
        try:
            if len(text) != 8:
                raise ValueError
            return dt.datetime.strptime(text, "%Y%m%d").replace(tzinfo=dt.timezone.utc)
        except ValueError:
            raise error from None
    d = parse_when(text)
    if not d:
        raise error
    return d


def norm(name: str) -> str:
    return _RE_NORM.sub("", name.lower())


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------

def compile_pattern(pat: str, exact: bool = False) -> Callable[[str], bool]:
    """Plain text = contains (equals when exact). With * or ? = whole-value wildcard. 're:<regex>' = regex.
    Always case-insensitive."""
    pat = pat.strip()
    if pat.lower().startswith("re:"):
        rx = re.compile(pat[3:], re.I)
        return lambda s: bool(rx.search(s))
    if not any(ch in pat for ch in "*?"):
        needle = pat.lower()
        if exact:
            return lambda s: s.strip().lower() == needle
        return lambda s: needle in s.lower()
    rx = re.compile(fnmatch.translate(pat), re.I)
    return lambda s: bool(rx.match(s))


class Clause:
    """COLUMN=pat1,pat2 (any of) or COLUMN!=pat1,pat2 (none of)."""

    def __init__(self, column: str, patterns: str, negate: bool = False, source: str = "",
                 also: tuple[str, ...] = (), exact: bool = False) -> None:
        self.column = column
        self.also = also
        self.key = norm(column)
        self.negate = negate
        self.source = source or f"{column}{'!=' if negate else '='}{patterns}"
        self.patterns = split_patterns(patterns)
        self.matchers = [compile_pattern(p, exact) for p in self.patterns]
        self.resolved = False
        if not self.matchers:
            raise ValueError(f"Filter '{self.source}' has no pattern")

    @classmethod
    def parse(cls, text: str) -> "Clause":
        m = re.match(r"^\s*(.+?)\s*(!=|=)\s*(.*)$", text)
        if not m:
            raise ValueError(f"Bad --where '{text}'. Expected COLUMN=PATTERN or COLUMN!=PATTERN")
        return cls(m.group(1), m.group(3), negate=m.group(2) == "!=", source=text)

    def resolve(self, keys: Iterable[str]) -> Optional[str]:
        idx = {norm(k): k for k in keys}
        for cand in (self.key, "scan" + self.key, "finding" + self.key):
            if cand in idx:
                return idx[cand]
        return None

    def test(self, row: dict[str, Any]) -> bool:
        col = self.resolve(row.keys())
        if col is not None:
            self.resolved = True
        parts: list[str] = []
        for cell in [str(row.get(col, "")) if col else ""] + [str(row.get(c, "")) for c in self.also]:
            parts.append(cell)
            if MULTI_SEP in cell:
                parts.extend(cell.split(MULTI_SEP))
        hit = any(m(p) for m in self.matchers for p in parts)
        return hit != self.negate


def split_patterns(text: str) -> list[str]:
    """Comma-separated, but a 're:' pattern keeps its commas."""
    if text.strip().lower().startswith("re:"):
        return [text.strip()]
    return [p.strip() for p in text.split(",") if p.strip()]


# ---------------------------------------------------------------------------
# Row building
# ---------------------------------------------------------------------------

def severity_histogram(scan: dict) -> Optional[dict[str, Any]]:
    """The scan's per-severity totals with lower-case keys, or None when absent."""
    hist = scan.get("severity_histogram")
    if not isinstance(hist, dict):
        return None
    return {str(k).strip().lower(): v for k, v in hist.items()}


def scan_row(scan: dict, now: dt.datetime, link_base: str, latest_ids: set[str],
             app_index: dict[str, dict]) -> dict[str, Any]:
    consumed: set[str] = set()
    row: dict[str, Any] = {}
    for col, names in SCAN_FIELDS.items():
        row[col] = flat(pick(scan, names))
        consumed.update(n for n in names if n in scan)
    hist = severity_histogram(scan)
    if hist is not None:
        consumed.add("severity_histogram")
        for sev, col in HISTOGRAM_COLUMNS.items():
            row[col] = hist.get(sev, 0) or 0
        row["Scan Total Findings"] = sum(v for v in hist.values() if isinstance(v, (int, float)))
    when = parse_when(scan.get("scanned_at"))
    row["Scan Date"] = when.strftime("%Y-%m-%dT%H:%M:%SZ") if when else flat(scan.get("scanned_at"))
    row["Scan Age Days"] = (now - when).days if when else ""
    sid = str(scan.get("scan_id") or "")
    row["Is Latest Scan For Asset"] = "true" if sid in latest_ids else "false"
    row["Veracode Link"] = f"{link_base}/{sid}/summary" if sid and link_base else ""
    app = app_index.get(str(scan.get("asset_name") or "").lower())
    if app:
        row.update(app)
    row.update(extras(scan, consumed, "Scan"))
    return row


def finding_row(finding: dict, base: dict[str, Any]) -> dict[str, Any]:
    consumed: set[str] = set()
    row = dict(base)
    for col, names in FINDING_FIELDS.items():
        val = pick(finding, names)
        consumed.update(n for n in names if n in finding)
        row[col] = flat(val)

    image = finding.get("image")
    if isinstance(image, dict):
        consumed.add("image")
        for col, key in IMAGE_FIELDS.items():
            row[col] = flat(image.get(key)) if image.get(key) not in (None, "", [], {}) else ""
        for key in image:
            if key not in IMAGE_FIELDS.values():
                row[f"Finding: image.{key}"] = flat(image[key])

    lib, ver = str(row.get("Library Name") or ""), str(row.get("Library Version") or "")
    row["Library"] = f"{lib}@{ver}" if lib and ver else lib
    state = str(row.get("Fix State") or "").strip().lower()
    if state or row.get("Fixed Versions") or lib:
        row["Fix Available"] = "true" if (row.get("Fixed Versions") or state == "fixed") else "false"

    sev = str(finding.get("severity") or "unknown").strip().lower()
    rank = SEVERITY_RANK.get(sev, 0)
    row["Severity"] = SEVERITY_LABEL[rank] if sev in SEVERITY_RANK else sev.title()
    row["Severity Rank"] = rank

    paths = pick(finding, FINDING_FIELDS["File Path"])
    paths = [str(p) for p in paths] if isinstance(paths, list) else ([str(paths)] if paths else [])
    row["File Path"] = paths[0] if paths else ""
    row["All File Paths"] = MULTI_SEP.join(paths)
    start, end = row.get("Start Line") or "", row.get("End Line") or ""
    loc = row["File Path"]
    if start and end and str(start) != str(end):
        loc += f":{start}-{end}"
    elif start:
        loc += f":{start}"
    row["Location"] = loc

    for col in ("Title", "Description", "Suggested Fix"):
        row[col] = clean_text(row.get(col))
    if not row["Title"]:
        row["Title"] = row["Description"][:120]

    fid = str(row.get("Finding ID") or "")
    ftype = str(row.get("Finding Type") or "").strip().lower()
    row["Finding Type"] = ftype.title()
    m = _RE_CVE.search(fid)
    row["CVE ID"] = m.group(1).upper() if m else (fid if ftype == "vulnerability" else "")

    asset = str(base.get("Asset Name") or "")
    ident = [asset.lower(), ftype, fid, str(row.get("Rule ID") or ""), row["File Path"],
             lib, str(row.get("Resource") or "")]
    row["_track"] = hashlib.sha1("\x1f".join(ident).encode()).hexdigest()[:16]
    row["Finding Key"] = mitigation_key(row)  # line-independent; the tracker's identity for a finding
    row.update(extras(finding, consumed, "Finding"))
    return row


def latest_scan_ids(scans: list[dict]) -> set[str]:
    best: dict[tuple, tuple[dt.datetime, str]] = {}
    floor = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    for s in scans:
        key = (str(s.get("asset_id") or s.get("asset_name") or "").lower(),
               str(s.get("asset_type") or "").lower(), str(s.get("scan_type") or "").lower())
        when = parse_when(s.get("scanned_at")) or floor
        sid = str(s.get("scan_id") or "")
        if key not in best or when > best[key][0]:
            best[key] = (when, sid)
    return {sid for _, sid in best.values()}


def bounded_map(pool: ThreadPoolExecutor, fn: Callable[[Any], Any], items: Iterable[Any], limit: int) -> Iterable[Any]:
    """Like pool.map, in input order, but with at most `limit` tasks submitted and not yet consumed."""
    pending: deque = deque()
    it = iter(items)
    for item in it:
        pending.append(pool.submit(fn, item))
        if len(pending) >= limit:
            break
    while pending:
        result = pending.popleft().result()
        nxt = next(it, _END)
        if nxt is not _END:
            pending.append(pool.submit(fn, nxt))
        yield result


_END = object()


def fetch_scan_findings(client: "Client", tracker: Tracker, scan: dict) -> Optional[list[dict]]:
    """All findings of one scan, or None (failure recorded) when they could not be read."""
    sid, name = scan.get("scan_id"), scan.get("asset_name", "Unknown")
    if not sid:
        tracker.fail(f"scan[{name}]", "record has no scan_id")
        return None
    try:
        return client.paginate(f"{client.base}/scans/{sid}/findings", "findings",
                               f"findings[{name}:{sid}]", {"sort": "severity", "direction": "desc"})
    except FetchError as exc:
        tracker.fail(f"findings[{name}:{sid}]", str(exc))
    except Exception as exc:  # unexpected: record it and carry on with the other scans
        tracker.fail(f"findings[{name}:{sid}]", f"{type(exc).__name__}: {exc}")
    return None


def credential_region() -> str:
    """Region of the API key ID (env vars, else ~/.veracode/credentials and VERACODE_API_PROFILE).
    'global' when the credentials cannot be read; token minting reports that error."""
    map_credential_env()
    try:
        from veracode_api_signing.credentials import get_credentials
        from veracode_api_signing.regions import get_region_for_api_credential
        return get_region_for_api_credential(get_credentials()[0])
    except Exception:
        return "global"


def resolve_endpoints(args: argparse.Namespace) -> Optional[str]:
    """Fill in --base-url, --link-base and --api-base for the credentials' region.
    Explicit values win. Returns an error message when they cannot be derived."""
    if args.base_url and args.link_base and args.api_base:
        return None
    region = credential_region()
    hosts = REGION_ENDPOINTS.get(region)
    if hosts is None:
        if not args.base_url or (args.match_apps and not args.api_base):
            return (f"your API credentials are for the '{region}' region. Set --base-url (or "
                    "VERACODE_IAC_BASE_URL), --link-base and, with --match-apps, --api-base for that region")
        hosts = (args.base_url, "", "")  # no Veracode Link unless --link-base is given
    args.base_url = args.base_url or hosts[0]
    args.link_base = args.link_base or hosts[1]
    args.api_base = args.api_base or hosts[2]
    return None


def load_app_index(ca_cert: Optional[str], tracker: Tracker, api_base: str = DEFAULT_API_BASE) -> dict[str, dict]:
    """Optional: map asset names to application profiles (name match, case-insensitive)."""
    from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
    s = make_session(ca_cert)
    s.auth = RequestsAuthPluginVeracodeHMAC()
    index: dict[str, dict] = {}
    page = 0
    try:
        while True:
            r = s.get(api_base.rstrip("/") + "/appsec/v1/applications", params={"page": page, "size": 500},
                      timeout=120)
            r.raise_for_status()
            data = r.json()
            for app in (data.get("_embedded") or {}).get("applications", []) or []:
                prof = app.get("profile") or {}
                name = prof.get("name") or ""
                index[name.lower()] = {
                    "Application Name": name,
                    "Application GUID": app.get("guid") or "",
                    "Business Unit": (prof.get("business_unit") or {}).get("name") or "",
                    "Teams": MULTI_SEP.join(t.get("team_name", "") for t in prof.get("teams") or []),
                }
            total = (data.get("page") or {}).get("total_pages") or 1
            page += 1
            if page >= total:
                break
    except Exception as exc:
        tracker.fail("match-apps", f"{type(exc).__name__}: {exc}")
    finally:
        s.close()
    return index


def _as_list(value: Any) -> Optional[list[str]]:
    if value is None:
        return None
    return [value] if isinstance(value, str) else list(value)


def collect_latest(base_url: Optional[str] = None, link_base: Optional[str] = None, *,
                   asset: Any = None, exclude_asset: Any = None, scan_type: Any = None, asset_type: Any = None,
                   scanned_by: Any = None, policy: Optional[str] = None, since: Optional[str] = None,
                   until: Optional[str] = None, workers: int = 4, rps: float = 2.0, max_attempts: int = 6,
                   timeout: int = 90, ca_cert: Optional[str] = None, minter: Optional[Callable[[], str]] = None,
                   now: Optional[dt.datetime] = None, log: Optional[Callable[[str], Any]] = print,
                   ) -> tuple[list[dict], list[dict], list[tuple[str, str]]]:
    """Every finding of the latest scan per asset, for the findings tracker. Library call: no argparse, no exit.

    base_url / link_base: None derives them from the credentials' region (give them for FedRAMP).
    asset, exclude_asset, scan_type, asset_type, scanned_by: a pattern or a list of patterns, as the
    --asset ... flags. policy: failed, passed or not-assessed. since / until: as --since / --until.
    All scans are read (no severity-total skipping). log receives progress lines (None for quiet).

    Returns (scans, finding_rows, failures):
      scans         scan_row() of every scan in the tenant; "_read": True on the latest scans whose
                    findings were read in full
      finding_rows  finding_row() of every finding in those scans (Code Lines included)
      failures      (scope, detail) of every failed request; not empty means the data is incomplete
    Raises ExtractError (exit_code 2 for bad input, 1 when the token or the scan list cannot be read)."""
    now = now or utcnow()
    say = log or (lambda _msg: None)
    if policy is not None and policy not in POLICY_VALUES:
        raise ExtractError(f"policy must be one of {', '.join(POLICY_VALUES)}", 2)
    if rps <= 0:
        raise ExtractError("rps must be greater than 0", 2)
    filters = argparse.Namespace(
        asset=_as_list(asset), exclude_asset=_as_list(exclude_asset), scan_type=_as_list(scan_type),
        asset_type=_as_list(asset_type), scanned_by=_as_list(scanned_by), policy=policy, library=None,
        category=None, scan_id=None, finding_type=None, file=None, rule=None, finding_id=None, where=[],
        since=since, until=until)
    try:
        clauses = build_clauses(filters)
        start, end = parse_window(filters, now)
    except (ValueError, re.error, argparse.ArgumentTypeError) as exc:
        raise ExtractError(str(exc), 2) from None
    if ca_cert and not os.path.isfile(ca_cert):
        raise ExtractError(f"CA certificate not found: {ca_cert}", 2)
    hosts = argparse.Namespace(base_url=base_url, link_base=link_base, api_base=None, match_apps=False)
    endpoint_error = resolve_endpoints(hosts)
    if endpoint_error:
        raise ExtractError(endpoint_error, 2)

    tracker = Tracker()
    tokens = TokenProvider(minter or mint_principal_token)
    try:
        tokens.get()
    except Exception as exc:
        raise ExtractError(str(exc), 1) from exc
    client = Client(hosts.base_url, tokens, RateLimiter(rps), tracker, ca_cert, max_attempts, timeout)
    say("Fetching scan list...")
    try:
        raw = client.paginate(f"{client.base}/scans", "records", "scans")
    except FetchError as exc:
        raise ExtractError(str(exc), 1) from exc
    latest = latest_scan_ids(raw)
    scans = [scan_row(s, now, hosts.link_base, latest, {}) for s in raw]
    picked = [(s, r) for s, r in zip(raw, scans) if in_window(s, start, end) and all(c.test(r) for c in clauses)]
    keep_ids = latest_scan_ids([s for s, _ in picked])
    picked = [(s, r) for s, r in picked if str(s.get("scan_id") or "") in keep_ids]
    say(f"  {len(raw)} scans in tenant; reading the latest scan of {len(picked)} asset(s)")

    rows: list[dict] = []
    n = max(1, workers)
    with ThreadPoolExecutor(max_workers=n) as pool:
        results = bounded_map(pool, lambda sr: fetch_scan_findings(client, tracker, sr[0]), picked, 2 * n)
        for (scan, base), found in zip(picked, results):
            if found is None:
                continue
            for rec in found:
                try:
                    rows.append(finding_row(rec, base))
                except Exception as exc:
                    tracker.fail(f"normalise[{base.get('Asset Name')}]", f"{type(exc).__name__}: {exc}")
            base["_read"] = True
    return scans, rows, list(tracker.failures)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection from scanned content. A leading apostrophe is doubled
    so read_csv_file gives back the exact value."""
    if isinstance(value, str) and value[:1] == "'":
        return "'" + value
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\x0d"):
        try:
            float(value)
            return value
        except ValueError:
            return "'" + value
    return value


def partial_path(path: str) -> str:
    """'out.csv' -> 'out.partial.csv': where an incomplete run writes, so the last good file stays."""
    stem, ext = os.path.splitext(path)
    return f"{stem}.partial{ext}"


REPLACE_RETRY_DELAY = 1.0  # seconds between tries when the output file is locked (open in Excel)


class OutputLocked(PermissionError):
    """The output file could not be replaced (usually open in Excel); the data went to `path` instead."""

    def __init__(self, target: str, path: str, count: int) -> None:
        super().__init__(f"{target} is locked; wrote {path} instead")
        self.target, self.path, self.count = target, path, count


def replace_or_fallback(tmp: str, path: str) -> Optional[str]:
    """Move tmp onto path, retrying while the file is locked. Returns the fallback file used, if any."""
    for attempt in range(3):
        try:
            os.replace(tmp, path)
            return None
        except PermissionError:
            if attempt < 2:
                time.sleep(REPLACE_RETRY_DELAY)
    stem, ext = os.path.splitext(path)
    fallback = f"{stem}.{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}{ext}"
    os.replace(tmp, fallback)
    return fallback


def save_output(path: str, *args: Any, **kwargs: Any) -> tuple[int, str, bool]:
    """write_output that reports a locked file instead of failing. Returns (rows, file written, locked)."""
    try:
        return write_output(path, *args, **kwargs), path, False
    except OutputLocked as exc:
        print(f"\n  ! {exc.target} is open in another program (Excel?) and could not be replaced. "
              f"Wrote {exc.path} instead.")
        return exc.count, exc.path, True


def write_output(path: str, fmt: str, columns: list[str], rows: Iterable[dict], raw_cells: bool,
                 sheet: str = "Findings", xlsx_style: Optional[dict[str, Any]] = None) -> int:
    """Writes rows atomically as csv, json, jsonl or xlsx. xlsx_style (Excel only, optional):
    {"wrap": columns to wrap, "dates": columns holding YYYY-MM-DD dates,
     "fills": {column: {value: "RRGGBB"}} for bold, coloured cells}."""
    count = 0
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".iac_", suffix=".tmp", dir=folder)
    os.close(fd)
    try:
        if fmt == "xlsx":
            count = write_xlsx(tmp, columns, rows, sheet, xlsx_style)
        elif fmt == "csv":
            with open(tmp, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(columns)
                for row in rows:
                    w.writerow([row.get(c, "") if raw_cells else csv_safe(row.get(c, "")) for c in columns])
                    count += 1
        else:
            with open(tmp, "w", encoding="utf-8") as fh:
                if fmt == "json":
                    fh.write("[\n")
                for row in rows:
                    line = json.dumps({c: row.get(c, "") for c in columns}, ensure_ascii=False)
                    if fmt == "json":
                        fh.write(("," if count else "") + line + "\n")
                    else:
                        fh.write(line + "\n")
                    count += 1
                if fmt == "json":
                    fh.write("]\n")
        fallback = replace_or_fallback(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    if fallback:
        raise OutputLocked(path, fallback, count)
    return count


# ---------------------------------------------------------------------------
# Excel output (.xlsx, needs openpyxl)
# ---------------------------------------------------------------------------

XLSX_FONT = "Arial"
XLSX_MAX_ROWS = 1_048_576  # Excel sheet limit, header row included
XLSX_SEVERITY_FILL = {"Critical": ("C00000", "FFFFFF"), "High": ("FF7C80", "000000"),
                      "Medium": ("FFC000", "000000"), "Low": ("A9D08E", "000000"),
                      "Negligible": ("D9D9D9", "000000"), "Unknown": ("D9D9D9", "000000")}
XLSX_WRAP = {"Title", "Description", "Suggested Fix", "References"}


def xlsx_too_big(fmt: str, rows: int) -> Optional[str]:
    """Error message when `rows` data rows plus the header do not fit in one Excel sheet."""
    if fmt == "xlsx" and rows + 1 > XLSX_MAX_ROWS:
        return (f"{rows:,} rows do not fit in an Excel sheet (max {XLSX_MAX_ROWS - 1:,}). "
                "Write .csv, .json or .jsonl instead, or narrow the filters")
    return None


def require_openpyxl() -> Any:
    try:
        import openpyxl
    except ImportError:
        raise SystemExit("Excel files need openpyxl: pip install openpyxl")
    return openpyxl


def xlsx_value(value: Any, column: str, date_columns: Iterable[str] = ()) -> Any:
    """Cell value for Excel: real dates in date columns, text that is never run as a formula."""
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
    if value in (None, ""):
        return None
    if column in date_columns:
        if isinstance(value, (dt.date, dt.datetime)):
            return value
        try:
            return dt.date.fromisoformat(str(value).strip()[:10])
        except ValueError:
            pass
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    return ILLEGAL_CHARACTERS_RE.sub("", str(value))[:32767]


def write_xlsx(path: str, columns: list[str], rows: Iterable[dict], sheet: str,
               style: Optional[dict[str, Any]] = None) -> int:
    openpyxl = require_openpyxl()
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    style = style or {}
    wrap_cols = XLSX_WRAP | set(style.get("wrap") or ())
    date_cols = set(style.get("dates") or ())
    value_fills: dict[str, dict[str, str]] = style.get("fills") or {}
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = sheet
    fills: dict[str, Any] = {}
    fonts: dict[tuple, Any] = {}

    def fill(rgb: str) -> Any:  # one style object per colour, not one per cell
        if rgb not in fills:
            fills[rgb] = PatternFill("solid", start_color=rgb, end_color=rgb)
        return fills[rgb]

    def font(**kw: Any) -> Any:
        key = tuple(sorted(kw.items()))
        if key not in fonts:
            fonts[key] = Font(name=XLSX_FONT, **kw)
        return fonts[key]

    head_font = font(bold=True, color="FFFFFF")
    body_font = font()
    link_font = font(color="0563C1", underline="single")
    wrap = Alignment(wrap_text=True, vertical="top")
    top = Alignment(vertical="top")
    idx = {c: i + 1 for i, c in enumerate(columns)}
    widths = {c: min(max(len(c), 10), 40) for c in columns}

    head_align = Alignment(vertical="center", wrap_text=True)
    for c, i in idx.items():
        cell = ws.cell(row=1, column=i, value=c)
        cell.font = head_font
        cell.fill = fill("1F3864")
        cell.alignment = head_align
    count = 0
    for count, row in enumerate(rows, 1):
        r = count + 1
        if r > XLSX_MAX_ROWS:
            raise ValueError(f"more than {XLSX_MAX_ROWS - 1:,} rows do not fit in an Excel sheet; use CSV")
        for c, i in idx.items():
            raw = row.get(c, "")
            value = xlsx_value(raw, c, date_cols)
            cell = ws.cell(row=r, column=i, value=value)
            if isinstance(value, str) and value.startswith("="):
                cell.data_type = "s"  # scanned content must never become a formula
            cell.font = body_font
            cell.alignment = wrap if c in wrap_cols else top
            if value is not None:
                widths[c] = max(widths[c], min(len(str(raw)), 60))
            if c == "Veracode Link" and isinstance(value, str) and value.startswith("http"):
                cell.hyperlink = value
                cell.font = link_font
            elif c == "Severity" and value in XLSX_SEVERITY_FILL:
                bg, fg = XLSX_SEVERITY_FILL[value]
                cell.fill, cell.font = fill(bg), font(bold=True, color=fg)
            elif c in value_fills and isinstance(value, str) and value in value_fills[c]:
                cell.fill, cell.font = fill(value_fills[c][value]), font(bold=True)
            if c in date_cols:
                cell.number_format = "yyyy-mm-dd"

    last_row = max(count + 1, 2)
    for c, i in idx.items():
        letter = get_column_letter(i)
        ws.column_dimensions[letter].width = (min(widths[c], 50) if c in wrap_cols else widths[c]) + 2
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(columns))}{last_row}"
    ws.page_setup.orientation = "landscape"   # print: one page wide, header row on every page
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.page_setup.fitToWidth, ws.page_setup.fitToHeight = 1, 0
    ws.print_title_rows = "1:1"
    wb.save(path)
    return count


def order_columns(seen: Counter, base: list[str], keep_empty: bool, user_cols: Optional[list[str]]) -> list[str]:
    """Output columns: base order, then extra columns; empty ones dropped unless kept; or exactly --columns."""
    extra_cols = sorted(c for c in seen if c not in base and not c.startswith("_"))
    cols = [c for c in base + extra_cols if keep_empty or c in CORE_COLUMNS or seen.get(c)]
    if user_cols:
        chosen = []
        for want in user_cols:
            match = next((c for c in base + extra_cols if norm(c) == norm(want)), None)
            if match is None:
                raise SystemExit(f"--columns: unknown column '{want}'. Available: {', '.join(base + extra_cols)}")
            chosen.append(match)
        cols = chosen
    return cols


# ---------------------------------------------------------------------------
# Finding identity (Finding Key)
# ---------------------------------------------------------------------------

_RE_DIGEST = re.compile(r"@sha256:[0-9a-f]{16,}$", re.I)
_RE_LINE_NO = re.compile(r"^\s*\d+\s*[:|]\s?", re.M)
_RE_LINE_NO_LEGACY = re.compile(r"^\s*\d+\s*[:|]?\s?", re.M)  # also ate leading digits of the code itself


def stable_asset(name: Any, asset_type: Any) -> str:
    """Lower-case asset name. Images lose their tag and digest, so app:1.2 and app:1.3 match."""
    a = str(name or "").strip()
    if str(asset_type or "").strip().lower() == "image":
        a = _RE_DIGEST.sub("", a)
        head, sep, last = a.rpartition("/")
        a = head + sep + last.split(":", 1)[0]
    return a.lower()


def stable_path(path: Any) -> str:
    p = str(path or "").strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def code_hash(code: Any, legacy: bool = False) -> str:
    """Hash of the flagged code without whitespace or line numbers. The code itself is never stored.
    legacy=True reproduces the old hash (line-number prefix without a separator), to remap old keys."""
    if code in (None, "", [], {}):
        return ""
    parts: list[str] = []

    def collect(v: Any) -> None:
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, list):
            for x in v:
                collect(x)
        elif isinstance(v, dict):
            for k in sorted(v):
                collect(v[k])

    value: Any = code
    if isinstance(code, str):
        try:
            value = json.loads(code)
        except ValueError:
            value = (_RE_LINE_NO_LEGACY if legacy else _RE_LINE_NO).sub("", code)
    collect(value)
    compact = re.sub(r"\s+", "", "".join(parts))
    return hashlib.sha256(compact.encode()).hexdigest()[:16] if compact else ""


def mitigation_key(row: dict[str, Any], legacy: bool = False) -> str:
    """Finding Key: stays the same between scans (no line numbers, no image tags).
    The mk- prefix stops spreadsheets from turning it into a number. legacy=True gives the key
    older versions computed (only secrets with plain-text code lines differ)."""
    ftype = str(row.get("Finding Type") or "").strip().lower()
    low = lambda col: str(row.get(col) or "").strip().lower()  # noqa: E731
    path = stable_path(row.get("File Path"))
    parts = ["v1", stable_asset(row.get("Asset Name"), row.get("Asset Type")), ftype, low("Finding ID")]
    if ftype == "misconfiguration":
        parts += [low("Rule ID"), path, low("Resource")]
    elif ftype == "secret":
        parts += [low("Rule ID"), path, code_hash(row.get("Code Lines"), legacy)]
    elif ftype == "vulnerability":
        parts += [low("Library Name"), path]
    else:
        parts += [low("Rule ID"), path, low("Resource"), low("Library Name")]
    return "mk-" + hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:12]


def read_csv_file(path: str) -> list[dict[str, str]]:
    """Reads a CSV saved by this script or by Excel: UTF-8 or Windows encoding, comma or semicolon."""
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("cp1252", errors="replace")
    first = text.split("\n", 1)[0]
    delim = ";" if first.count(";") > first.count(",") else ","
    rows = []
    for r in csv.DictReader(io.StringIO(text, newline=""), delimiter=delim):
        rows.append({k: (v[1:] if isinstance(v, str) and len(v) > 1 and v[0] == "'" and v[1] in "'=+-@\t\r"
                         else (v or "")) for k, v in r.items() if k is not None})
    return rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Export Veracode Container / IaC / Secrets findings to CSV, JSON, JSONL or Excel (.xlsx).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""matching: plain text means "contains" (--asset payments). Add * or ? for a
          wildcard on the whole value (--asset "my-org/*"). re:<regex> for regex.
          Never case-sensitive. Commas mean OR. Different flags are ANDed.

examples:
  %(prog)s --asset "my-org/payments-*"
  %(prog)s --scan-type container --severity high+ --fixable
  %(prog)s --scan-type iac --type misconfiguration --file "*.tf"
  %(prog)s --type secret --since 30d
  %(prog)s --id CVE-2024-3094
  %(prog)s --library openssl --compact -o openssl.csv
  %(prog)s --list-scans -o scans.csv""")
    p.add_argument("-o", "--output",
                   help="Output file (default veracode_iac_findings.csv). "
                        "Format follows the extension unless --format is given.")
    p.add_argument("--format", choices=("csv", "json", "jsonl", "xlsx"), help="Force the format.")
    p.add_argument("--summary-csv", metavar="PATH", help="Also write a per-asset rollup CSV (Asset Name, Asset ID).")

    g = p.add_argument_group("scan filters (applied before findings are fetched)")
    g.add_argument("--asset", action="append", metavar="PATTERN",
                   help="Asset to include. Matches asset name, asset ID or source.")
    g.add_argument("--exclude-asset", action="append", metavar="PATTERN", help="Asset to exclude.")
    g.add_argument("--scan-type", action="append", metavar="LIST", help="e.g. container, iac")
    g.add_argument("--asset-type", action="append", metavar="LIST", help="image, repo, archive, directory")
    g.add_argument("--scanned-by", action="append", metavar="PATTERN", help="User that ran the scan.")
    g.add_argument("--policy", choices=list(POLICY_VALUES), help="Scan policy result.")
    g.add_argument("--scan-id", action="append", metavar="PATTERN", help="Specific scan, latest or not.")
    g.add_argument("--since", metavar="DATE|Nd",
                   help="Only scans on/after this (YYYY-MM-DD, YYYYMMDD, ISO datetime, 30d, 12h, 2w).")
    g.add_argument("--until", metavar="DATE|Nd", help="Only scans on/before this (a bare date is inclusive).")
    g.add_argument("--all-scans", action="store_true",
                   help="Every scan in history, not just the latest per asset. A finding appears once per scan.")
    g.add_argument("--latest-only", action="store_true",
                   help="Only the most recent scan per asset. This is the default; kept for compatibility.")
    g.add_argument("--track-history", action="store_true",
                   help="Fetch every scan to compute First Seen / Last Seen / Seen In Scans, "
                        "but only output findings from the latest scan per asset.")

    H = argparse.SUPPRESS
    g = p.add_argument_group("finding filters")
    g.add_argument("--severity", action="append", metavar="LEVELS",
                   help="'high+' for high and above, or a list: critical,high. "
                        "Levels: critical, high, medium, low, negligible, unknown.")
    g.add_argument("--min-severity", choices=list(SEVERITY_RANK), help=H)
    g.add_argument("--type", "--finding-type", dest="finding_type", action="append", metavar="TYPES",
                   help="vulnerability, misconfiguration, secret")
    g.add_argument("--id", "--cve", "--finding-id", dest="finding_id", action="append", metavar="TEXT",
                   help="CVE or finding ID, e.g. CVE-2024-3094 (exact match) or 'CVE-2024-*'.")
    g.add_argument("--library", action="append", metavar="TEXT",
                   help="Vulnerable library, e.g. openssl or 'log4j*@2.14*'.")
    g.add_argument("--file", action="append", metavar="TEXT", help="File path, e.g. '*.tf' or Dockerfile.")
    g.add_argument("--rule", action="append", metavar="TEXT", help="Rule ID.")
    g.add_argument("--category", action="append", metavar="TEXT", help="Finding category.")
    g.add_argument("--fixable", action="store_true", help="Only findings with a fix available.")
    g.add_argument("--cvss", "--min-cvss", dest="min_cvss", type=float, metavar="N",
                   help="CVSS of N or higher.")
    g.add_argument("--search", "--grep", dest="grep", metavar="TEXT",
                   help="Free text (or regex) across title, description, fix, IDs, library, "
                        "category, resource and file path.")
    g.add_argument("--where", action="append", metavar="COLUMN=TEXT", default=[],
                   help="Filter on any other output column. Use != to exclude. Repeatable.")

    g = p.add_argument_group("columns")
    g.add_argument("--columns", metavar="LIST", help="Comma-separated columns to output, in order.")
    g.add_argument("--compact", action="store_true",
                   help="Short developer view: " + ", ".join(COMPACT_COLUMNS) + ".")
    g.add_argument("--no-extra-columns", action="store_true",
                   help="Drop the 'Scan: x' / 'Finding: x' raw passthrough columns.")
    g.add_argument("--keep-empty-columns", action="store_true", help="Keep columns with no values.")
    g.add_argument("--match-apps", action="store_true",
                   help="Match asset names to application profiles to add Application, Business Unit, Teams.")
    g.add_argument("--no-csv-safe", action="store_true",
                   help="Do not prefix cells starting with = + - @ (formula-injection guard).")

    g = p.add_argument_group("modes")
    g.add_argument("--list-scans", action="store_true", help="Export the scan inventory only, no findings.")

    g = p.add_argument_group("connection")
    g.add_argument("--max-workers", type=int, default=4, help="Concurrent requests (default 4).")
    g.add_argument("--rps", type=float, default=2.0, help="Max requests per second (default 2).")
    g.add_argument("--no-server-search", action="store_true",
                   help="Download the full scan list and filter --asset locally instead of "
                        "using the API search.")
    g.add_argument("--fetch-empty-scans", action="store_true",
                   help="Also query scans whose severity totals say they have no matching findings.")
    g.add_argument("--max-attempts", type=int, default=6, help="Tries per request (default 6).")
    g.add_argument("--timeout", type=int, default=90, help="Seconds per request (default 90).")
    g.add_argument("--ca-cert", metavar="FILE", help="Custom CA bundle (.pem), e.g. behind SSL inspection.")
    g.add_argument("--base-url", default=os.environ.get("VERACODE_IAC_BASE_URL"),
                   help="Container scan query API base. Default: derived from the region of your API credentials "
                        "(US commercial or EU; required for FedRAMP).")
    g.add_argument("--link-base", default=os.environ.get("VERACODE_IAC_LINK_BASE"),
                   help="Base of the Veracode Link column. Default: derived like --base-url.")
    g.add_argument("--api-base", default=os.environ.get("VERACODE_API_BASE"),
                   help="Veracode REST API base for --match-apps. Default: derived like --base-url.")
    g.add_argument("--ignore-failures", action="store_true",
                   help="Exit 0 and replace the output even if some requests failed. Without it, an incomplete "
                        "run keeps the previous output and writes <name>.partial.<ext>.")
    args = p.parse_args(argv)
    if args.rps <= 0:
        p.error("--rps must be greater than 0")
    return args


def parse_severities(values: Optional[list[str]], minimum: Optional[str]) -> Optional[set[int]]:
    """'high+' / 'critical,high' -> set of allowed ranks. None means no severity filter."""
    tokens = [t.strip().lower() for v in values or [] for t in v.split(",") if t.strip()]
    if minimum:
        tokens.append(minimum + "+")
    if not tokens:
        return None
    allowed: set[int] = set()
    for tok in tokens:
        name = tok.rstrip("+")
        if name not in SEVERITY_RANK:
            raise ValueError(f"Unknown severity '{tok}'. Use: {', '.join(SEVERITY_RANK)} (add + for 'and above')")
        rank = SEVERITY_RANK[name]
        allowed.update(r for r in SEVERITY_LABEL if r >= rank) if tok.endswith("+") else allowed.add(rank)
    return allowed


def server_search_terms(clauses: list[Clause]) -> Optional[list[str]]:
    """Turn the first --asset filter into text for the API's own `search` parameter.

    The API search is plain text, so a wildcard pattern contributes its longest
    literal piece ("my-org/pay*" -> "my-org/pay"). The full pattern is still
    applied locally afterwards. Returns None when the list must be fetched whole.
    """
    for c in clauses:
        if c.column == "Asset Name" and c.also and not c.negate:
            terms: list[str] = []
            for pat in c.patterns:
                if pat.lower().startswith("re:"):
                    return None
                best = max((x for x in re.split(r"[*?]+", pat) if x), key=len, default="")
                if len(best) < 3:
                    return None
                if best.lower() not in (t.lower() for t in terms):
                    terms.append(best)
            return terms or None
    return None


def build_clauses(args: argparse.Namespace) -> list[Clause]:
    clauses: list[Clause] = []

    def add(column: str, values: Optional[list[str]], negate: bool = False) -> None:
        for v in values or []:
            clauses.append(Clause(column, v, negate))

    for v in args.asset or []:
        clauses.append(Clause("Asset Name", v, also=("Asset ID", "Scan Source")))
    for v in args.exclude_asset or []:
        clauses.append(Clause("Asset Name", v, negate=True, also=("Asset ID", "Scan Source")))
    add("Scan Type", args.scan_type)
    add("Asset Type", args.asset_type)
    add("Scanned By", args.scanned_by)
    if args.policy:
        clauses.append(Clause("Scan Policy Status", f"re:^{POLICY_VALUES[args.policy]}$"))
    for v in args.library or []:
        clauses.append(Clause("Library Name", v, also=("Library",)))
    add("Category", args.category)
    add("Scan ID", args.scan_id)
    add("Finding Type", args.finding_type)
    add("All File Paths", args.file)
    add("Rule ID", args.rule)
    for v in args.finding_id or []:  # a plain ID matches exactly; wildcards, re: or a list keep the usual rules
        plain = not (v.strip().lower().startswith("re:") or any(ch in v for ch in "*?,"))
        clauses.append(Clause("Finding ID", v, also=("CVE ID",), exact=plain))
    clauses.extend(Clause.parse(w) for w in args.where)
    return clauses


def parse_window(args: argparse.Namespace, now: dt.datetime) -> tuple[Optional[dt.datetime], Optional[dt.datetime]]:
    """--since / --until as datetimes. A bare --until date is inclusive."""
    since = parse_cutoff(args.since, now) if args.since else None
    until = parse_cutoff(args.until, now) if args.until else None
    if until and args.until and re.fullmatch(r"\d{4}-?\d{2}-?\d{2}", args.until.strip()):
        until += dt.timedelta(days=1)
    return since, until


def in_window(scan: dict, since: Optional[dt.datetime], until: Optional[dt.datetime]) -> bool:
    when = parse_when(scan.get("scanned_at"))
    if since and (not when or when < since):
        return False
    return not (until and (not when or when > until))


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def main(argv: Optional[list[str]] = None, minter: Callable[[], str] = mint_principal_token) -> int:
    args = parse_args(argv)
    map_credential_env()
    now = utcnow()
    args.output = args.output or "veracode_iac_findings.csv"
    try:
        clauses = build_clauses(args)
        since, until = parse_window(args, now)
        grep = None
        if args.grep:
            try:
                grep = re.compile(args.grep, re.I)
            except re.error:
                grep = re.compile(re.escape(args.grep), re.I)  # not a regex: treat as plain text
    except (ValueError, re.error, argparse.ArgumentTypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.latest_only and args.all_scans:
        print("error: --latest-only and --all-scans are mutually exclusive", file=sys.stderr)
        return 2
    # Default: latest scan per asset. --track-history and --scan-id need older scans too.
    latest_only = not (args.all_scans or args.track_history or args.scan_id)
    if args.ca_cert and not os.path.isfile(args.ca_cert):
        print(f"error: CA certificate not found: {args.ca_cert}", file=sys.stderr)
        return 2
    fmt = args.format or {".json": "json", ".jsonl": "jsonl", ".ndjson": "jsonl", ".xlsx": "xlsx"}.get(
        os.path.splitext(args.output)[1].lower(), "csv")
    try:
        ranks = parse_severities(args.severity, args.min_severity)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    user_cols = [c.strip() for c in args.columns.split(",") if c.strip()] if args.columns else None
    if args.compact and not user_cols and not args.list_scans:
        user_cols = list(COMPACT_COLUMNS)
    finding_base = BASE_COLUMNS
    if user_cols:  # catch typos before any request; 'Scan: x' / 'Finding: x' are checked once the data is in
        listing = SCAN_INVENTORY_COLUMNS + APP_COLUMNS if args.list_scans else finding_base
        dynamic = ("scan:",) if args.list_scans else ("scan:", "finding:")
        known = {norm(c) for c in listing}
        bad = [c for c in user_cols if norm(c) not in known and not c.lower().startswith(dynamic)]
        if bad:
            print(f"error: --columns: unknown column(s) {', '.join(repr(c) for c in bad)}. "
                  f"Available: {', '.join(listing)}", file=sys.stderr)
            return 2
    endpoint_error = resolve_endpoints(args)
    if endpoint_error:
        print(f"error: {endpoint_error}", file=sys.stderr)
        return 2

    tracker = Tracker()
    tokens = TokenProvider(minter)
    try:
        tokens.get()
    except Exception as exc:
        print(f"error: {exc}\nCheck API credentials and that the account can view Container/IaC scans.",
              file=sys.stderr)
        return 1
    client = Client(args.base_url, tokens, RateLimiter(args.rps), tracker,
                    args.ca_cert, args.max_attempts, args.timeout)

    # --- 1. Scan inventory ---------------------------------------------------
    print("Fetching scan list...")
    terms = None if args.no_server_search else server_search_terms(clauses)
    try:
        scans: list[dict] = []
        if terms:
            seen_ids: set[str] = set()
            for term in terms:
                hits = client.paginate(f"{client.base}/scans", "records", f"scans[search={term}]",
                                       {"search": term})
                print(f"  server-side search '{term}': {len(hits)} scans")
                for h in hits:
                    if str(h.get("scan_id")) not in seen_ids:
                        seen_ids.add(str(h.get("scan_id")))
                        scans.append(h)
            if not scans:
                print("  no server-side matches, falling back to the full scan list")
                terms = None
        if not terms:
            scans = client.paginate(f"{client.base}/scans", "records", "scans")
            print(f"  {len(scans)} scans in tenant")
    except FetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    latest = latest_scan_ids(scans)
    app_index = load_app_index(args.ca_cert, tracker, args.api_base) if args.match_apps else {}
    scan_rows = [(s, scan_row(s, now, args.link_base, latest, app_index)) for s in scans]
    if args.no_extra_columns:
        scan_rows = [(s, {k: v for k, v in r.items() if not k.startswith("Scan: ")}) for s, r in scan_rows]

    scan_keys = {k for _, r in scan_rows for k in r} | set(SCAN_INVENTORY_COLUMNS)
    scan_clauses = [c for c in clauses if c.resolve(scan_keys)]
    finding_clauses = [c for c in clauses if c not in scan_clauses]
    for c in scan_clauses:
        c.resolved = True

    selected: list[tuple[dict, dict]] = []
    for s, r in scan_rows:
        if not in_window(s, since, until):
            continue
        if all(c.test(r) for c in scan_clauses):
            selected.append((s, r))
    if latest_only:  # the latest scan per asset among those that passed the window and scan filters
        keep_ids = latest_scan_ids([s for s, _ in selected])
        selected = [(s, r) for s, r in selected if str(s.get("scan_id") or "") in keep_ids]
    selected.sort(key=lambda sr: (str(sr[1].get("Asset Name", "")).lower(), sr[1].get("Scan Date", "")),
                  reverse=False)
    assets = {str(r.get("Asset Name", "")).lower() for _, r in selected}
    print(f"  {len(selected)} scans across {len(assets)} assets after scan filters")

    if args.list_scans:
        seen = Counter(k for _, r in selected for k, v in r.items() if v not in ("", None))
        try:
            cols = order_columns(seen, SCAN_INVENTORY_COLUMNS + APP_COLUMNS, args.keep_empty_columns, user_cols)
        except SystemExit as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        too_big = xlsx_too_big(fmt, len(selected))
        if too_big:
            print(f"error: {too_big}", file=sys.stderr)
            return 2
        incomplete = bool(tracker.failures) and not args.ignore_failures
        out_path = partial_path(args.output) if incomplete else args.output
        n, out_path, locked = save_output(out_path, fmt, cols, (r for _, r in selected), args.no_csv_safe,
                                          sheet="Scans")
        print(f"\nWrote {n} scans to {out_path}")
        if incomplete:
            print(f"INCOMPLETE: {len(tracker.failures)} failure(s). {args.output} was not replaced; "
                  f"the partial export is in {out_path}")
        return 1 if (incomplete or locked) else 0

    # --- 2. Findings ---------------------------------------------------------
    # The scan list already carries per-severity totals, so scans that cannot
    # contain a matching finding are skipped without spending a request.
    skipped = 0
    if not args.fetch_empty_scans:
        wanted = [s for s, r in SEVERITY_RANK.items() if ranks is None or r in ranks]
        keep = []
        for scan, base in selected:
            hist = severity_histogram(scan)
            unknown = hist is not None and any(v for k, v in hist.items() if k not in SEVERITY_RANK)
            if hist is not None and not unknown and not any(hist.get(sev) for sev in wanted):
                skipped += 1
            else:
                keep.append((scan, base))
        selected = keep
        if skipped:
            print(f"  {skipped} scans skipped (scan totals show no matching findings)")

    def fetch(item: tuple[int, tuple[dict, dict]]) -> tuple[dict, Optional[list[dict]]]:
        idx, (scan, base) = item
        found = fetch_scan_findings(client, tracker, scan)
        if found is not None:
            print(f"  [{idx}/{len(selected)}] {scan.get('asset_name', 'Unknown')} ({base.get('Scan Date', '')}): "
                  f"{len(found)} findings")
        return base, found

    seen_cols: Counter = Counter()
    history: dict[str, list] = {}           # track key -> [first, last, scan count]
    by_sev: Counter = Counter()
    by_type: Counter = Counter()
    by_rule: Counter = Counter()
    per_asset: dict[str, Counter] = defaultdict(Counter)   # keyed by Asset ID (name when no ID)
    asset_names: dict[str, str] = {}
    asset_ids: dict[str, str] = {}
    total_raw = kept = 0
    grep_cols = ("Title", "Description", "Suggested Fix", "Rule ID", "Finding ID", "All File Paths",
                 "Library", "Category", "Resource")
    by_lib: Counter = Counter()
    fixable = 0

    spool = tempfile.NamedTemporaryFile("w+", encoding="utf-8", suffix=".jsonl", delete=False)
    try:
        print(f"\nFetching findings for {len(selected)} scans...")
        workers = max(1, args.max_workers)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for base, found in bounded_map(pool, fetch, enumerate(selected, 1), 2 * workers):
                is_latest = base.get("Is Latest Scan For Asset") == "true"
                tracked_here: set[str] = set()
                for raw in found or []:
                    total_raw += 1
                    try:
                        row = finding_row(raw, base)
                    except Exception as exc:
                        tracker.fail(f"normalise[{base.get('Asset Name')}]", f"{type(exc).__name__}: {exc}")
                        continue
                    if args.no_extra_columns:
                        row = {k: v for k, v in row.items() if not k.startswith("Finding: ")}
                    if ranks is not None and row["Severity Rank"] not in ranks:
                        continue
                    if not all(c.test(row) for c in finding_clauses):
                        continue
                    if args.fixable and row.get("Fix Available") != "true":
                        continue
                    if args.min_cvss is not None:
                        try:
                            if float(row.get("CVSS") or 0) < args.min_cvss:
                                continue
                        except (TypeError, ValueError):
                            continue
                    if grep and not any(grep.search(str(row.get(c, ""))) for c in grep_cols):
                        continue
                    tk, date = row["_track"], row.get("Scan Date", "")
                    h = history.setdefault(tk, [date, date, 0])
                    if date:
                        h[0] = min(h[0] or date, date)
                        h[1] = max(h[1], date)
                    if tk not in tracked_here:
                        tracked_here.add(tk)
                        h[2] += 1
                    if args.track_history and not is_latest:
                        continue
                    spool.write(json.dumps(row, ensure_ascii=False) + "\n")
                    kept += 1
                    seen_cols.update(k for k, v in row.items() if v not in ("", None))
                    by_sev[row["Severity"]] += 1
                    by_type[row["Finding Type"] or "(none)"] += 1
                    by_rule[row.get("Rule ID") or row.get("Finding ID") or "(none)"] += 1
                    if row.get("Library"):
                        by_lib[row["Library"]] += 1
                    is_fixable = row.get("Fix Available") == "true"
                    fixable += is_fixable
                    akey = str(row.get("Asset ID") or row.get("Asset Name", ""))
                    asset_names.setdefault(akey, str(row.get("Asset Name") or akey))
                    asset_ids.setdefault(akey, str(row.get("Asset ID") or ""))
                    a = per_asset[akey]
                    a["Fixable"] += is_fixable
                    a["Findings"] += 1
                    a[row["Severity"]] += 1
                    a["Type: " + (row["Finding Type"] or "(none)")] += 1
                    a["scan:" + str(row.get("Scan ID", ""))] = 1
        spool.flush()

        for col in ("First Seen", "Last Seen", "Seen In Scans"):
            seen_cols[col] = kept
        try:
            columns = order_columns(seen_cols, finding_base, args.keep_empty_columns, user_cols)
        except SystemExit as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        def rows() -> Iterable[dict]:
            spool.seek(0)
            for line in spool:
                row = json.loads(line)
                h = history.get(row.get("_track"), ["", "", 1])
                row["First Seen"], row["Last Seen"], row["Seen In Scans"] = h
                yield row

        too_big = xlsx_too_big(fmt, kept)
        if too_big:
            print(f"error: {too_big}. Nothing was written.", file=sys.stderr)
            return 2
        incomplete = bool(tracker.failures) and not args.ignore_failures
        out_path = partial_path(args.output) if incomplete else args.output
        written, out_path, locked = save_output(out_path, fmt, columns, rows(), args.no_csv_safe)
    finally:
        spool.close()
        os.remove(spool.name)

    if args.summary_csv:
        sev_cols = [SEVERITY_LABEL[r] for r in (5, 4, 3, 2, 1, 0)]
        type_cols = sorted({k for c in per_asset.values() for k in c if k.startswith("Type: ")})
        summary = []
        for key in sorted(per_asset, key=lambda k: (asset_names[k].lower(), k)):
            c = per_asset[key]
            summary.append({"Asset Name": asset_names[key], "Asset ID": asset_ids[key],
                            "Scans": sum(1 for k in c if k.startswith("scan:")),
                            "Findings": c["Findings"], "Fixable": c["Fixable"],
                            **{s: c[s] for s in sev_cols},
                            **{t: c[t] for t in type_cols}})
        summary_path = partial_path(args.summary_csv) if incomplete else args.summary_csv
        _, summary_path, summary_locked = save_output(
            summary_path, "csv", ["Asset Name", "Asset ID", "Scans", "Findings", "Fixable"] + sev_cols + type_cols,
            summary, args.no_csv_safe)
        locked = locked or summary_locked

    # --- 3. Report -----------------------------------------------------------
    print("\n" + "=" * 64)
    print(f"  Scans queried      : {len(selected)}" + (f"  ({skipped} skipped, nothing to fetch)" if skipped else ""))
    print(f"  Findings retrieved : {total_raw}")
    print(f"  Findings exported  : {written}  ->  {out_path}")
    if by_sev:
        print("  By severity        : " + ", ".join(
            f"{SEVERITY_LABEL[r]} {by_sev[SEVERITY_LABEL[r]]}" for r in (5, 4, 3, 2, 1, 0) if by_sev[SEVERITY_LABEL[r]]))
        print("  By type            : " + ", ".join(f"{k} {v}" for k, v in by_type.most_common()))
        print("  Top assets         : " + ", ".join(
            f"{asset_names[k]} ({v['Findings']})"
            for k, v in sorted(per_asset.items(), key=lambda kv: -kv[1]["Findings"])[:5]))
        print("  Top rules / IDs    : " + ", ".join(f"{k} ({v})" for k, v in by_rule.most_common(5)))
        if by_lib:
            print("  Top libraries      : " + ", ".join(f"{k} ({v})" for k, v in by_lib.most_common(5)))
        print(f"  Fix available      : {fixable}")
    if args.summary_csv:
        print(f"  Per-asset rollup   : {summary_path}")
    if tokens.refreshes:
        print(f"  Token refreshes    : {tokens.refreshes}")
    for c in clauses:
        if not c.resolved:
            print(f"  WARNING: filter '{c.source}' refers to a column that never appeared "
                  f"(check the column names in the README)")
    if tracker.failures:
        print(f"\n  INCOMPLETE: {len(tracker.failures)} failure(s):")
        for scope, detail in tracker.failures[:20]:
            print(f"    - {scope}: {detail[:160]}")
        if incomplete:
            print(f"  {args.output} was not replaced. The partial export is in {out_path}\n"
                  "  (use --ignore-failures to write the output anyway).")
    print("=" * 64)
    return 1 if (incomplete or locked) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted. Output file was not modified.", file=sys.stderr)
        sys.exit(130)
