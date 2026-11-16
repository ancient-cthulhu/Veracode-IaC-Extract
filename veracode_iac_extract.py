#!/usr/bin/env python3
"""Standalone Veracode Container / IaC / Secrets findings extractor.

Pulls scans and findings from the Veracode Container Security query API
(the same one the Platform UI uses), filters them, and writes a flat,
developer-friendly CSV / JSON / JSONL export.
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
                 sheet: str = "Findings") -> int:
    count = 0
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".iac_", suffix=".tmp", dir=folder)
    os.close(fd)
    try:
        if fmt == "xlsx":
            count = write_xlsx(tmp, columns, rows, sheet)
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
XLSX_STATUS_FILL = {"Mitigated": "C6EFCE", "Expiring": "FFEB9C", "Expired": "F8CBAD"}
XLSX_WRAP = {"Title", "Description", "Suggested Fix", "Mitigation Reason", "References"}
XLSX_DATE_COLUMNS = {"Mitigation Expires"}


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


def xlsx_value(value: Any, column: str) -> Any:
    """Cell value for Excel: real dates in date columns, text that is never run as a formula."""
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
    if value in (None, ""):
        return None
    if column in XLSX_DATE_COLUMNS:
        day, _ = parse_expiry(str(value)) if not isinstance(value, (dt.date, dt.datetime)) else (value, "")
        if day:
            return day
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    return ILLEGAL_CHARACTERS_RE.sub("", str(value))[:32767]


def write_xlsx(path: str, columns: list[str], rows: Iterable[dict], sheet: str) -> int:
    openpyxl = require_openpyxl()
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

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
            value = xlsx_value(raw, c)
            cell = ws.cell(row=r, column=i, value=value)
            if isinstance(value, str) and value.startswith("="):
                cell.data_type = "s"  # scanned content must never become a formula
            cell.font = body_font
            cell.alignment = wrap if c in XLSX_WRAP else top
            if value is not None:
                widths[c] = max(widths[c], min(len(str(raw)), 60))
            if c == "Veracode Link" and isinstance(value, str) and value.startswith("http"):
                cell.hyperlink = value
                cell.font = link_font
            elif c == "Severity" and value in XLSX_SEVERITY_FILL:
                bg, fg = XLSX_SEVERITY_FILL[value]
                cell.fill, cell.font = fill(bg), font(bold=True, color=fg)
            elif c == "Mitigation Status" and value in XLSX_STATUS_FILL:
                cell.fill, cell.font = fill(XLSX_STATUS_FILL[value]), font(bold=True)
            if c in XLSX_DATE_COLUMNS:
                cell.number_format = "yyyy-mm-dd"

    last_row = max(count + 1, 2)
    for c, i in idx.items():
        letter = get_column_letter(i)
        ws.column_dimensions[letter].width = (min(widths[c], 50) if c in XLSX_WRAP else widths[c]) + 2
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
# Finding identity and mitigation types
# ---------------------------------------------------------------------------
# Mitigations for these findings are not available on the Veracode Platform. The tracker keeps
# approved mitigations in mitigations.yml (see the Mitigation rules section below).

MITIGATION_TYPES = {
    "false-positive": "Not a real issue (Potential False Positive in Static Analysis).",
    "by-design": "Deliberate and approved, or the design already handles it (Mitigate by Design).",
    "network-environment": "A network control handles it: WAF, security group, private network.",
    "os-environment": "The OS or runtime handles it: hardened host, read-only file system, no shell.",
    "accept-risk": "The business accepts the risk for a limited time. Needs an expiry date.",
}
NOT_IN_EXPORT = "Not in export"  # status of carried-over rows in old tracking files (migration only)
EXPIRY_WARN_DAYS = 30
_RE_DIGEST = re.compile(r"@sha256:[0-9a-f]{16,}$", re.I)
_RE_LINE_NO = re.compile(r"^\s*\d+\s*[:|]\s?", re.M)
_RE_LINE_NO_LEGACY = re.compile(r"^\s*\d+\s*[:|]?\s?", re.M)  # also ate leading digits of the code itself
_RE_MKEY = re.compile(r"^mk-[0-9a-f]{12}$")


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


def parse_expiry(text: str) -> tuple[Optional[dt.date], str]:
    """YYYY-MM-DD, or a date a spreadsheet rewrote (31/12/2027, 12/31/2027) when it is unambiguous."""
    t = text.strip()
    m = re.fullmatch(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:[ T].*)?", t)
    if m:
        y, mo, d = map(int, m.groups())
    else:
        m = re.fullmatch(r"(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})(?: .*)?", t)
        if not m:
            return None, f"'{t}' is not a date. Use YYYY-MM-DD"
        a, b, y = map(int, m.groups())
        if a > 12 and b <= 12:
            d, mo = a, b
        elif b > 12 and a <= 12:
            mo, d = a, b
        elif a == b:
            d = mo = a
        else:
            return None, f"'{t}' could be day/month or month/day. Use YYYY-MM-DD"
    try:
        return dt.date(y, mo, d), ""
    except ValueError:
        return None, f"'{t}' is not a valid date"


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
# Findings tracker (--track DIR)
# ---------------------------------------------------------------------------
# DIR/findings.csv is the baseline: one row per open finding. DIR/fixed.csv logs the fixed ones.
# A finding is identified by its Asset ID plus its Finding Key (line-independent, see mitigation_key),
# so a moved line or a new image tag does not make it a new finding.

NEW, OPEN, REOPENED, ASSET_MISSING = "New", "Open", "Reopened", "Asset Missing"
ASSET_MISSING_DAYS = 30
TRACK_MITIGATION_COLUMNS = ["Mitigation Status", "Mitigation Type", "Mitigation Reason", "Mitigation Approved By",
                            "Mitigation Expires", "Mitigation Ref"]
TRACK_COLUMNS = ["Status", "Severity", "Finding Type", "Finding ID", "Title", "Asset Name", "Location",
                 "Fixed Versions", "First Seen", "Last Seen", "Days Open", *TRACK_MITIGATION_COLUMNS,
                 "Veracode Link", "Asset ID", "Finding Key", "Mitigation ID", "File Path", "Scan Type", "Scan ID",
                 "Scan Date", "Detected On", "Reopened On", "Asset Missing Since"]
FIXED_COLUMNS = ["Fixed On", "Fixed Reason", "Days Open", "Severity", "Finding Type", "Finding ID", "Title",
                 "Asset Name", "Location", "First Seen", "Last Seen", "Mitigation Status", "Mitigation ID",
                 "Veracode Link", "Asset ID", "Finding Key", "Fixed By Scan"]
TRACK_REJECTS = {"severity": "--severity", "min_severity": "--min-severity", "finding_type": "--type",
                 "finding_id": "--id", "library": "--library", "file": "--file", "rule": "--rule",
                 "category": "--category", "fixable": "--fixable", "min_cvss": "--cvss", "grep": "--search",
                 "where": "--where", "all_scans": "--all-scans", "track_history": "--track-history",
                 "scan_id": "--scan-id", "list_scans": "--list-scans", "columns": "--columns", "compact": "--compact",
                 "summary_csv": "--summary-csv", "match_apps": "--match-apps"}


def asset_key(asset_id: Any, name: Any) -> str:
    aid = str(asset_id or "").strip()
    return aid if aid else "name:" + str(name or "").strip().lower()


def finding_ident(row: dict[str, Any]) -> tuple[str, str]:
    return asset_key(row.get("Asset ID"), row.get("Asset Name")), str(row.get("Finding Key") or "")


def severity_rank(label: Any) -> int:
    return SEVERITY_RANK.get(str(label or "").strip().lower(), 0)


def day_of(value: Any) -> Optional[dt.date]:
    try:
        return dt.date.fromisoformat(str(value or "")[:10])
    except ValueError:
        return None


def tracker_row(row: dict[str, Any]) -> dict[str, Any]:
    """The tracker's compact view of a finding_row."""
    out = {c: row.get(c, "") for c in ("Severity", "Finding Type", "Finding ID", "Title", "Asset Name",
                                       "Fixed Versions", "Veracode Link", "Asset ID", "Finding Key", "File Path",
                                       "Scan Type", "Scan ID", "Scan Date")}
    out["Location"] = row.get("Location") or ""
    if str(row.get("Finding Type") or "").lower() == "vulnerability" and row.get("Library"):
        out["Location"] = row["Library"]
    out["_legacy"] = mitigation_key(row, legacy=True)
    return out


def sort_track_rows(rows: Iterable[dict]) -> list[dict]:
    return sorted(rows, key=lambda r: (-severity_rank(r.get("Severity")), str(r.get("Asset Name") or "").lower(),
                                       str(r.get("Finding Key") or ""), str(r.get("Asset ID") or "")))


def fixed_entry(old: dict[str, Any], fixed_on: str, reason: str, scan_id: str = "") -> dict[str, Any]:
    row = {c: old.get(c, "") for c in FIXED_COLUMNS}
    first, fixed = day_of(old.get("First Seen")), day_of(fixed_on)
    row.update({"Fixed On": fixed_on, "Fixed Reason": reason, "Fixed By Scan": scan_id,
                "Days Open": (fixed - first).days if first and fixed else ""})
    return row


def update_lifecycle(baseline: list[dict], fixed_log: list[dict], current: list[dict],
                     scanned: dict[tuple[str, str], tuple[str, str]], known_assets: set[str], today: dt.date,
                     seed: Optional[dict[str, str]] = None) -> tuple[list[dict], list[dict], Counter]:
    """Moves the baseline forward with this run's findings. Returns (open rows, newly fixed rows, counts).

    scanned: (asset key, scan type) -> (scan date, scan ID) for every scan read in full in this run.
    known_assets: asset keys of every scan in the tenant (to tell a deleted asset from a filtered one).
    seed: Finding Key -> First Seen, from a migrated tracking file."""
    today_s = today.isoformat()
    prev = {finding_ident(r): r for r in baseline}
    was_fixed = {finding_ident(r): r for r in fixed_log}
    counts: Counter = Counter()
    out: dict[tuple[str, str], dict] = {}
    for cur in sorted(current, key=lambda r: -severity_rank(r.get("Severity"))):
        ident = finding_ident(cur)
        if ident in out:
            continue
        legacy = (ident[0], str(cur.get("_legacy") or ""))
        old = prev.pop(ident, None)
        if old is None and legacy[1] and legacy != ident:
            old = prev.pop(legacy, None)  # baseline written before the code_hash fix
        row = dict(cur)
        seen = str(cur.get("Scan Date") or "")[:10] or today_s
        row["Last Seen"] = seen
        row["Asset Missing Since"] = ""
        if old is not None:
            for c in ("First Seen", "Detected On", "Reopened On"):
                row[c] = old.get(c, "")
            fresh = old.get("Status") in (NEW, REOPENED) and old.get("Detected On") == today_s
            row["Status"] = old["Status"] if fresh else OPEN
        elif ident in was_fixed or legacy in was_fixed:
            gone = was_fixed.get(ident) or was_fixed[legacy]
            row.update({"Status": REOPENED, "First Seen": gone.get("First Seen") or seen,
                        "Reopened On": today_s, "Detected On": today_s})
            counts["reopened"] += 1
        elif seed and (ident[1] in seed or legacy[1] in seed):
            row.update({"Status": OPEN, "First Seen": seed.get(ident[1]) or seed.get(legacy[1]) or seen,
                        "Detected On": ""})
            counts["seeded"] += 1
        else:
            row.update({"Status": NEW, "First Seen": seen, "Detected On": today_s})
            counts["new"] += 1
        out[ident] = row

    fixed_rows: list[dict] = []
    for ident, old in prev.items():
        akey = ident[0]
        stype = str(old.get("Scan Type") or "").lower()
        if stype:
            newer = scanned.get((akey, stype))
        else:  # no scan type recorded: only when every scan read for the asset is newer
            dates = [v for (a, _), v in scanned.items() if a == akey]
            newer = min(dates) if dates else None
        if newer and newer[0] > str(old.get("Scan Date") or ""):
            fixed_rows.append(fixed_entry(old, newer[0][:10], "fixed", newer[1]))
            counts["fixed"] += 1
            continue
        row = dict(old)
        if akey not in known_assets:
            since = old.get("Asset Missing Since") or today_s
            since_day = day_of(since) or today
            if (today - since_day).days >= ASSET_MISSING_DAYS:
                fixed_rows.append(fixed_entry(old, today_s, "asset-removed"))
                counts["removed"] += 1
                continue
            row["Status"], row["Asset Missing Since"] = ASSET_MISSING, since
        elif row.get("Status") == ASSET_MISSING:
            row["Status"], row["Asset Missing Since"] = OPEN, ""
        elif row.get("Status") in (NEW, REOPENED) and row.get("Detected On") != today_s:
            row["Status"] = OPEN
        out[ident] = row
    return sort_track_rows(out.values()), fixed_rows, counts


def refresh_days_open(rows: list[dict], today: dt.date) -> None:
    for row in rows:
        first = day_of(row.get("First Seen"))
        row["Days Open"] = (today - first).days if first else ""


def track_paths(folder: str) -> dict[str, str]:
    return {"findings": os.path.join(folder, "findings.csv"), "fixed": os.path.join(folder, "fixed.csv"),
            "run": os.path.join(folder, "last-run.json")}


def load_track_files(paths: dict[str, str]) -> tuple[list[dict], list[dict], Optional[str]]:
    """(baseline, fixed log, error). Missing files are empty: the first run creates them."""
    out = []
    for name in ("findings", "fixed"):
        path = paths[name]
        rows: list[dict] = []
        if os.path.exists(path):
            try:
                rows = read_csv_file(path)
            except (OSError, csv.Error) as exc:
                return [], [], f"cannot read {path}: {exc}"
            if rows and "Finding Key" not in rows[0]:
                return [], [], f"{path} has no Finding Key column; it was not written by --track"
        out.append(rows)
    return out[0], out[1], None


def read_json_file(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def atomic_write_text(path: str, text: str) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".iac_", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def github_output(**values: Any) -> None:
    """Step outputs for GitHub Actions (only our own computed values, never user text)."""
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            for k, v in values.items():
                fh.write(f"{k}={v}\n")


def step_summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")


def merge_fixed(fixed_log: list[dict], new_rows: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for row in fixed_log + new_rows:
        key = (str(row.get("Asset ID") or ""), str(row.get("Finding Key") or ""), str(row.get("Fixed On") or ""))
        if key not in seen:
            seen.add(key)
            out.append(row)
    return out


def track_totals(rows: list[dict]) -> Counter:
    c: Counter = Counter()
    for r in rows:
        ms = r.get("Mitigation Status") or ""
        if ms in ("Mitigated", "Expiring"):
            c["mitigated"] += 1
        else:
            c[str(r.get("Severity") or "Unknown")] += 1
        if ms == "Expiring":
            c["expiring"] += 1
        if ms == "Expired":
            c["expired"] += 1
        if r.get("Status") in (NEW, REOPENED):
            c["new today"] += 1
    return c


def write_track_outputs(paths: dict[str, str], rows: list[dict], fixed_all: list[dict]) -> Optional[str]:
    """Writes findings.csv and fixed.csv (each atomically). Returns an error message or None."""
    try:
        write_output(paths["findings"], "csv", TRACK_COLUMNS, rows, raw_cells=False)
        write_output(paths["fixed"], "csv", FIXED_COLUMNS, fixed_all, raw_cells=False)
    except OutputLocked as exc:
        os.remove(exc.path)
        return f"{exc.target} is locked by another program"
    except OSError as exc:
        return f"cannot write the tracking files: {exc}"
    return None


def finish_track(args: argparse.Namespace, paths: dict[str, str], rows: list[dict], fixed_log: list[dict],
                 fixed_new: list[dict], counts: Counter, run_info: dict, now: dt.datetime,
                 rules: Optional["Rules"] = None, notes: Optional[list[str]] = None) -> int:
    today = now.date()
    for row in rows:
        if rules:
            rules.apply(row)
        else:
            clear_mitigation(row)
    refresh_days_open(rows, today)
    fixed_all = merge_fixed(fixed_log, fixed_new)
    err = write_track_outputs(paths, rows, fixed_all)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    run_info = dict(run_info, updated=now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    atomic_write_text(paths["run"], json.dumps(run_info, indent=2, sort_keys=True) + "\n")
    dashboard = args.dashboard or os.path.join(os.path.dirname(os.path.abspath(args.track)), "FINDINGS.md")
    repo_url = resolve_repo_url(args.repo_url)
    if args.repo_url and not repo_url:
        print("  WARNING: --repo-url must look like https://github.com/<org>/<repo>; Mitigate links left out")
    rel = os.path.relpath(os.path.abspath(args.track), os.path.dirname(os.path.abspath(dashboard)))
    atomic_write_text(dashboard, render_dashboard(rows, fixed_all, run_info, now, repo_url, rel))
    t = track_totals(rows)
    sev = ", ".join(f"{SEVERITY_LABEL[r]} {t[SEVERITY_LABEL[r]]}" for r in (5, 4, 3, 2, 1, 0)
                    if t[SEVERITY_LABEL[r]])
    lines = [f"New {counts['new']}, reopened {counts['reopened']}, fixed {counts['fixed']}"
             + (f", asset removed {counts['removed']}" if counts["removed"] else ""),
             f"Open (not mitigated): {sev or 'none'}",
             f"Mitigated {t['mitigated']}, expiring {t['expiring']}, expired {t['expired']}"]
    print("\n" + "\n".join("  " + ln for ln in lines))
    for msg in (notes or [])[:10]:
        print(f"  NOTE: {msg}")
    print(f"\nWrote {len(rows)} open finding(s) to {paths['findings']}")
    step_summary("### Veracode findings tracker\n\n" + "\n".join(f"- {ln}" for ln in lines))
    github_output(new=counts["new"], reopened=counts["reopened"], fixed=counts["fixed"] + counts["removed"],
                  open=len(rows))
    return 0


def clear_mitigation(row: dict[str, Any]) -> None:
    for c in TRACK_MITIGATION_COLUMNS + ["Mitigation ID"]:
        row[c] = ""


# FINDINGS.md: the dashboard GitHub shows next to the code. Every value is escaped with md_safe.
DASHBOARD_LIMIT = 500_000
DASHBOARD_ROWS = 300
_RE_REPO_URL = re.compile(r"^https://[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def resolve_repo_url(explicit: Optional[str]) -> str:
    """https://github.com/<org>/<repo> from --repo-url or GitHub Actions; '' when unknown (no Mitigate links)."""
    url = explicit or ""
    if not url and os.environ.get("GITHUB_REPOSITORY"):
        url = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/") + "/" + \
            os.environ["GITHUB_REPOSITORY"]
    url = url.strip().rstrip("/")
    return url if _RE_REPO_URL.match(url) else ""


def mitigate_url(repo_url: str, row: dict[str, Any]) -> str:
    """Link to the mitigation request issue form, pre-filled with this finding."""
    from urllib.parse import quote, urlencode
    if not repo_url:
        return ""
    fid, asset = str(row.get("Finding ID") or ""), str(row.get("Asset Name") or "")
    params = {"template": "mitigation.yml", "title": f"Mitigate: {fid} in {asset}"[:200],
              "finding_key": row.get("Finding Key") or "", "finding_id": fid[:200], "asset": asset[:300]}
    return f"{repo_url}/issues/new?{urlencode(params, quote_via=quote)}"


def dashboard_table(columns: list[str], rows: list[dict], cell: Callable[[dict, str], str], budget: int,
                    more_note: str) -> tuple[list[str], int]:
    """Markdown table lines, at most DASHBOARD_ROWS rows and `budget` characters."""
    if not rows:
        return ["None."], 5
    lines = ["| " + " | ".join(columns) + " |", "|" + " --- |" * len(columns)]
    used = sum(len(x) + 1 for x in lines)
    shown = 0
    for r in rows[:DASHBOARD_ROWS]:
        line = "| " + " | ".join(cell(r, c) for c in columns) + " |"
        if used + len(line) + 1 > budget:
            break
        lines.append(line)
        used += len(line) + 1
        shown += 1
    if shown < len(rows):
        note = f"\n_Showing {shown} of {len(rows)}. {more_note}_"
        lines.append(note)
        used += len(note) + 1
    return lines, used


def render_dashboard(rows: list[dict], fixed_all: list[dict], run_info: dict, now: dt.datetime,
                     repo_url: str, track_rel: str = "tracking") -> str:
    track_rel = track_rel.replace("\\", "/").strip("/")
    track_rel = track_rel if re.fullmatch(r"[A-Za-z0-9_./-]+", track_rel) else "tracking"
    today = now.date()
    t = track_totals(rows)
    fixed_on = [(day_of(r.get("Fixed On")), r) for r in fixed_all]
    recent = sorted(((d, r) for d, r in fixed_on if d and 0 <= (today - d).days <= 30),
                    key=lambda dr: (dr[0], severity_rank(dr[1].get("Severity"))), reverse=True)
    days = sorted(int(r["Days Open"]) for r in rows if str(r.get("Days Open", "")).lstrip("-").isdigit())
    median = "" if not days else (days[len(days) // 2] if len(days) % 2 else
                                  (days[len(days) // 2 - 1] + days[len(days) // 2]) / 2)
    if isinstance(median, float) and median.is_integer():
        median = int(median)
    assets = run_info.get("assets", len({finding_ident(r)[0] for r in rows}))
    last = "never (offline only)"
    if run_info.get("run"):
        last = (f"{str(run_info['run']).replace('T', ' ').rstrip('Z')} UTC, +{run_info.get('new', 0)} new, "
                f"{run_info.get('reopened', 0)} reopened, -{int(run_info.get('fixed', 0)) + int(run_info.get('removed', 0))}"
                " fixed")
    out = ["# Veracode findings", "",
           f"Last updated: {now.strftime('%Y-%m-%d %H:%M')} UTC · Assets tracked: {md_safe(assets)} · "
           f"Last run: {md_safe(last)}", "",
           "_Generated by the tracker workflow; do not edit. All open findings are in "
           "[tracking/findings.csv](tracking/findings.csv), fixed ones in [tracking/fixed.csv](tracking/fixed.csv)._"
           .replace("tracking/", track_rel + "/"),
           "", "| Critical | High | Medium | Low | Mitigated | Expiring (≤30d) | Expired | New today | Fixed (7d) "
           "| Fixed (30d) | Median days open |",
           "|" + " --- |" * 11,
           f"| {t['Critical']} | {t['High']} | {t['Medium']} | {t['Low']} | {t['mitigated']} | {t['expiring']} | "
           f"{t['expired']} | {t['new today']} | {sum(1 for d, _ in recent if (today - d).days <= 7)} | "
           f"{len(recent)} | {median} |", ""]
    if not repo_url:
        out += ["_Mitigate links are off: run in GitHub Actions or pass --repo-url._", ""]

    def cell(r: dict, c: str) -> str:
        if c == "Title":
            return md_safe(r.get("Title"), 80)
        if c == "Mitigation":
            st = r.get("Mitigation Status") or ""
            if not st:
                return ""
            ref = r.get("Mitigation Ref") or ""
            mid = md_link(md_safe(r.get("Mitigation ID")), ref) or md_safe(r.get("Mitigation ID"))
            return f"{md_safe(st)} ({md_safe(r.get('Mitigation Type'))}, {mid})"
        if c == "Links":
            links = [md_link("Veracode", r.get("Veracode Link"))]
            if r.get("Mitigation Status") != "Mitigated":
                links.append(md_link("Mitigate", mitigate_url(repo_url, r)))
            return " ".join(x for x in links if x)
        if c == "Asset":
            return md_safe(r.get("Asset Name"), 120)
        return md_safe(r.get(c), 160)

    open_rows = [r for r in rows if r.get("Mitigation Status") not in ("Mitigated", "Expiring")]
    sections = [
        ("New since last run", ["Status", "Severity", "Finding ID", "Title", "Asset", "Location", "Days Open",
                                "Mitigation", "Links"], [r for r in rows if r.get("Status") in (NEW, REOPENED)]),
        ("Expiring or expired mitigations", ["Severity", "Finding ID", "Title", "Asset", "Mitigation Expires",
                                             "Mitigation", "Links"],
         [r for r in rows if r.get("Mitigation Status") in ("Expiring", "Expired")]),
        ("Open findings", ["Severity", "Finding ID", "Title", "Asset", "Location", "Days Open", "Mitigation",
                           "Links"], open_rows),
        ("Fixed in the last 30 days", ["Fixed On", "Severity", "Finding ID", "Title", "Asset", "Location",
                                       "Days Open", "Fixed Reason"], [r for _, r in recent]),
    ]
    used = sum(len(x) + 1 for x in out)
    for i, (title, cols, srows) in enumerate(sections):
        budget = (DASHBOARD_LIMIT - used - 2000) // (len(sections) - i)
        lines, n = dashboard_table(cols, srows, cell, budget,
                                   f"Full list in {track_rel}/" + ("fixed.csv" if i == 3 else "findings.csv") + ".")
        out += [f"## {title} ({len(srows)})", ""] + lines + [""]
        used += n + len(title) + 20
    return "\n".join(out)


def run_track(args: argparse.Namespace, now: dt.datetime, minter: Callable[[], str]) -> int:
    paths = track_paths(args.track)
    baseline, fixed_log, err = load_track_files(paths)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    rules, notes = None, []
    if args.mitigations:
        rules, notes, rc = load_rules_for_run(args.mitigations, now.date())
        if rules is None:
            return rc
    if args.offline:  # refresh the derived columns only; no Veracode access
        return finish_track(args, paths, sort_track_rows(baseline), fixed_log, [], Counter(),
                            read_json_file(paths["run"]), now, rules, notes)
    bad = [flag for attr, flag in TRACK_REJECTS.items() if getattr(args, attr, None) not in (None, False, [])]
    if bad:
        print(f"error: --track cannot be combined with {', '.join(bad)}: findings filtered out would look fixed. "
              "Use scan filters (--asset, --scan-type, --asset-type, ...) only", file=sys.stderr)
        return 2
    try:
        clauses = build_clauses(args)
        since, until = parse_window(args, now)
    except (ValueError, re.error, argparse.ArgumentTypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.ca_cert and not os.path.isfile(args.ca_cert):
        print(f"error: CA certificate not found: {args.ca_cert}", file=sys.stderr)
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
        print(f"error: {exc}\nNothing was changed.", file=sys.stderr)
        return 1
    client = Client(args.base_url, tokens, RateLimiter(args.rps), tracker, args.ca_cert, args.max_attempts,
                    args.timeout)
    print("Fetching scan list...")
    try:
        scans = client.paginate(f"{client.base}/scans", "records", "scans")
    except FetchError as exc:
        print(f"error: {exc}\nNothing was changed.", file=sys.stderr)
        return 1
    latest = latest_scan_ids(scans)
    selected = [(s, r) for s, r in ((s, scan_row(s, now, args.link_base, latest, {})) for s in scans)
                if in_window(s, since, until) and all(c.test(r) for c in clauses)]
    keep_ids = latest_scan_ids([s for s, _ in selected])
    selected = [(s, r) for s, r in selected if str(s.get("scan_id") or "") in keep_ids]
    print(f"  {len(scans)} scans in tenant; reading the latest scan of {len(selected)} asset(s)")

    current: list[dict] = []
    full: list[dict] = []
    scanned: dict[tuple[str, str], tuple[str, str]] = {}
    workers = max(1, args.max_workers)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = bounded_map(pool, lambda sb: fetch_scan_findings(client, tracker, sb[0]), selected, 2 * workers)
        for (scan, base), found in zip(selected, results):
            if found is None:
                continue
            for raw in found:
                try:
                    fr = finding_row(raw, base)
                    current.append(tracker_row(fr))
                    if args.output:  # never the raw code: it can hold the secret itself
                        full.append({k: v for k, v in fr.items() if k != "Code Lines"})
                except Exception as exc:
                    tracker.fail(f"normalise[{base.get('Asset Name')}]", f"{type(exc).__name__}: {exc}")
            akey = asset_key(scan.get("asset_id"), scan.get("asset_name"))
            scanned[(akey, str(scan.get("scan_type") or "").lower())] = (str(base.get("Scan Date") or ""),
                                                                          str(scan.get("scan_id") or ""))
    if tracker.failures:
        print(f"\nINCOMPLETE: {len(tracker.failures)} failure(s):", file=sys.stderr)
        for scope, detail in tracker.failures[:20]:
            print(f"  - {scope}: {detail[:160]}", file=sys.stderr)
        print("Nothing was changed: findings are never marked fixed from partial data.", file=sys.stderr)
        return 1
    known = {asset_key(s.get("asset_id"), s.get("asset_name")) for s in scans} | \
        {asset_key("", s.get("asset_name")) for s in scans}
    seed: Optional[dict[str, str]] = None
    rules_path = args.mitigations or "mitigations.yml"
    old_file = args.migrate or os.path.join(os.path.dirname(os.path.abspath(args.track)), OLD_TRACKING_FILE)
    if args.migrate or (os.path.exists(old_file) and not os.path.exists(paths["findings"])):
        seed, err = migrate_old_file(old_file, rules_path, now.date())
        if err:
            print(f"error: {err}\nNothing was changed.", file=sys.stderr)
            return 2
    if (args.mitigations and os.path.exists(rules_path) and remap_legacy_rules(rules_path, current)) \
            or seed is not None:
        rules, more, rc = load_rules_for_run(rules_path, now.date())
        if rules is None:
            return rc
        notes = more
    rows, fixed_new, counts = update_lifecycle(baseline, fixed_log, current, scanned, known, now.date(), seed)
    run_info = {"run": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "assets": len({a for a, _ in scanned}),
                **{k: counts[k] for k in ("new", "reopened", "fixed", "removed")}}
    rc = finish_track(args, paths, rows, fixed_log, fixed_new, counts, run_info, now, rules, notes)
    if rc == 0 and args.output:
        rc = write_track_report(args, rows, full)
    return rc


def write_track_report(args: argparse.Namespace, rows: list[dict], full: list[dict]) -> int:
    """-o with --track: every current finding with all its columns plus Status and Mitigation (no Code Lines)."""
    by_ident = {finding_ident(r): r for r in rows}
    seen: Counter = Counter()
    for fr in full:
        t = by_ident.get(finding_ident(fr), {})
        for c in ["Status", "First Seen", "Last Seen"] + EXPORT_MITIGATION_COLUMNS:
            fr[c] = t.get(c, "")
        seen.update(k for k, v in fr.items() if v not in ("", None))
    fmt = args.format or {".json": "json", ".jsonl": "jsonl", ".ndjson": "jsonl", ".xlsx": "xlsx"}.get(
        os.path.splitext(args.output)[1].lower(), "csv")
    too_big = xlsx_too_big(fmt, len(full))
    if too_big:
        print(f"error: {too_big}", file=sys.stderr)
        return 2
    base = ["Status", "Mitigation Status"] + [c for c in BASE_COLUMNS if c not in ("Code Lines", "Seen In Scans")] \
        + EXPORT_MITIGATION_COLUMNS[1:]
    columns = order_columns(seen, base, args.keep_empty_columns, None)
    full.sort(key=lambda r: (-int(r.get("Severity Rank") or 0), str(r.get("Asset Name") or "").lower()))
    n, path, locked = save_output(args.output, fmt, columns, full, args.no_csv_safe)
    print(f"Wrote {n} finding(s) to {path}")
    return 1 if locked else 0


# ---------------------------------------------------------------------------
# Mitigation rules (mitigations.yml)
# ---------------------------------------------------------------------------
# Approved mitigations live in mitigations.yml: a list of rules recorded by the approval workflow or
# added through a pull request. A rule matches findings by Finding ID / CVE / Finding Key, optionally
# narrowed to assets and files. Mitigations affect the tracker and exports only, not the Veracode Platform.

RULE_FIELDS = ("id", "finding", "asset", "file", "type", "reason", "approved_by", "approved_on", "expires", "ref",
               "requested_by", "notes", "allow_broad")
RULE_REQUIRED = ("id", "finding", "type", "reason", "approved_by")
RULE_PATTERNS = ("finding", "asset", "file")
RULE_TEXT_MAX = 2000
RULE_PATTERN_MAX = 300
EXPORT_MITIGATION_COLUMNS = TRACK_MITIGATION_COLUMNS + ["Mitigation ID"]
_RE_RULE_ID = re.compile(r"^M-(\d{4,})$")
_RE_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RE_UNPRINTABLE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029\ufeff\ufffe\uffff\ud800-\udfff]")
_GLOBS: dict[str, Any] = {}


def require_yaml() -> Any:
    try:
        import yaml
    except ImportError:
        raise SystemExit("mitigations.yml needs PyYAML: pip install PyYAML")
    return yaml


def glob_match(pattern: str, value: Any) -> bool:
    """Whole-value match, case-insensitive. * is any text, ? one character; nothing else is special."""
    rx = _GLOBS.get(pattern)
    if rx is None:
        rx = _GLOBS[pattern] = re.compile("".join(
            ".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pattern.strip()), re.I | re.S)
    return bool(rx.fullmatch(str(value or "").strip()))


def is_broad(pattern: str) -> bool:
    return not pattern.replace("*", "").replace("?", "").strip()


def rule_date(value: Any) -> tuple[Optional[dt.date], str]:
    if isinstance(value, dt.datetime):
        return value.date(), ""
    if isinstance(value, dt.date):
        return value, ""
    text = str(value).strip()
    if not _RE_ISO_DATE.match(text):
        return None, f"'{text[:40]}' is not a date. Use YYYY-MM-DD"
    try:
        return dt.date.fromisoformat(text), ""
    except ValueError:
        return None, f"'{text}' is not a valid date"


def validate_rules(data: Any, today: dt.date) -> tuple[list[dict], list[str], list[str]]:
    """Normalises the parsed YAML. Returns (entries, errors, warnings). Every mapping that has an id is
    returned (with _valid False when it has problems) so a diff can still show it."""
    if data is None:
        data = []
    if not isinstance(data, list):
        return [], ["the file must be a list of entries, each starting with '- id:'"], []
    entries: list[dict] = []
    errors: list[str] = []
    warnings: list[str] = []
    ids: dict[str, int] = {}
    for n, item in enumerate(data, 1):
        if not isinstance(item, dict):
            errors.append(f"entry {n}: must be a mapping (id: ..., finding: ..., ...)")
            continue
        raw_id = item.get("id")
        where = f"entry {n}" + (f" ({raw_id})" if isinstance(raw_id, str) and raw_id.strip() else "")
        problems: list[str] = []
        for key in item:
            if key not in RULE_FIELDS:
                problems.append(f"unknown key '{str(key)[:40]}'. Allowed: {', '.join(RULE_FIELDS)}")
        e: dict[str, Any] = {"_n": n, "_where": where}
        for f in RULE_FIELDS:
            v = item.get(f)
            if f == "allow_broad":
                if v is not None and not isinstance(v, bool):
                    problems.append("allow_broad must be true or false")
                e[f] = v is True
                continue
            if v is None:
                e[f] = ""
            elif isinstance(v, (dt.date, dt.datetime)):
                e[f] = (v.date() if isinstance(v, dt.datetime) else v).isoformat()
            elif isinstance(v, (str, int, float)) and not isinstance(v, bool):
                e[f] = str(v).strip()
            else:
                problems.append(f"{f} must be text")
                e[f] = ""
            limit = RULE_PATTERN_MAX if f in RULE_PATTERNS or f in ("id", "approved_by", "requested_by", "ref") \
                else RULE_TEXT_MAX
            if len(e[f]) > limit:
                problems.append(f"{f} is longer than {limit} characters")
            if f in RULE_PATTERNS and ("\n" in e[f] or "\r" in e[f]):
                problems.append(f"{f} must be one line")
        for f in RULE_REQUIRED:
            if not e[f]:
                problems.append(f"{f} is required")
        if e["id"]:
            if not _RE_RULE_ID.match(e["id"]):
                problems.append(f"id '{e['id'][:40]}' must look like M-0001")
            elif e["id"] in ids:
                problems.append(f"duplicate id {e['id']} (also entry {ids[e['id']]})")
            else:
                ids[e["id"]] = n
        if e["type"] and e["type"] not in MITIGATION_TYPES:
            problems.append(f"type '{e['type'][:40]}' must be one of {', '.join(MITIGATION_TYPES)}")
        e["_expires"] = None
        for f in ("expires", "approved_on"):
            if e[f]:
                day, err = rule_date(item.get(f))
                if err:
                    problems.append(f"{f}: {err}")
                else:
                    e[f] = day.isoformat()
                    if f == "expires":
                        e["_expires"] = day
        if e["type"] == "accept-risk" and not e["expires"]:
            problems.append("accept-risk needs expires (YYYY-MM-DD)")
        if e["finding"] and is_broad(e["finding"]) and all(not e[f] or is_broad(e[f]) for f in ("asset", "file")) \
                and not e["allow_broad"]:
            problems.append("finding matches everything and there is no asset or file scope. Narrow it, or add "
                            "allow_broad: true if this is intended")
        if e["ref"].lower().startswith("http") and not e["ref"].startswith("https://"):
            problems.append("ref must be an https:// link or plain text")
        e["_valid"] = not problems
        errors += [f"{where}: {p}" for p in problems]
        if e["_expires"] and e["_expires"] < today and not problems:
            warnings.append(f"{where}: expired on {e['_expires']}; the findings count as open again. "
                            "Renew it or remove the entry")
        entries.append(e)
    return entries, errors, warnings


def load_rules(path: str, today: dt.date) -> tuple[list[dict], list[str], list[str]]:
    """Reads and validates mitigations.yml. A missing file is an empty list."""
    if not os.path.exists(path):
        return [], [], []
    yaml = require_yaml()
    try:
        with open(path, encoding="utf-8-sig") as fh:
            data = yaml.safe_load(fh)
    except (OSError, UnicodeDecodeError) as exc:
        return [], [f"cannot read {path}: {exc}"], []
    except yaml.YAMLError as exc:
        return [], [f"{path} is not valid YAML: {str(exc)[:300]}"], []
    return validate_rules(data, today)


class Rules:
    def __init__(self, entries: list[dict], today: dt.date) -> None:
        self.entries = [e for e in entries if e.get("_valid")]
        self.today = today

    def status(self, e: dict) -> str:
        exp = e.get("_expires")
        if exp and exp < self.today:
            return "Expired"
        if exp and (exp - self.today).days <= EXPIRY_WARN_DAYS:
            return "Expiring"
        return "Mitigated"

    def match(self, row: dict[str, Any]) -> Optional[dict]:
        """The first rule that matches and has not expired; else the first expired one."""
        expired = None
        for e in self.entries:
            if rule_matches(e, row):
                if self.status(e) != "Expired":
                    return e
                expired = expired or e
        return expired

    def apply(self, row: dict[str, Any]) -> str:
        """Fills the Mitigation columns. Returns the Mitigation Status ('' when not mitigated)."""
        e = self.match(row)
        if e is None:
            clear_mitigation(row)
            return ""
        st = self.status(e)
        row.update({"Mitigation Status": st, "Mitigation Type": e["type"], "Mitigation Reason": e["reason"],
                    "Mitigation Approved By": e["approved_by"], "Mitigation Expires": e["expires"],
                    "Mitigation Ref": e["ref"] if e["ref"].startswith("https://") else e["id"],
                    "Mitigation ID": e["id"]})
        return st


def rule_matches(e: dict, row: dict[str, Any]) -> bool:
    if not any(glob_match(e["finding"], row.get(c)) for c in ("Finding ID", "Finding Key", "CVE ID", "_legacy")
               if row.get(c)):
        return False
    if e["asset"] and not any(glob_match(e["asset"], row.get(c)) for c in ("Asset Name", "Asset ID")):
        return False
    if e["file"] and not any(glob_match(e["file"], row.get(c)) for c in ("File Path", "Location") if row.get(c)):
        return False
    return True


def load_rules_for_run(path: str, today: dt.date, must_exist: bool = False) -> tuple[Optional[Rules], list[str], int]:
    """(rules, warnings, exit code). rules is None when the run must stop."""
    if must_exist and not os.path.exists(path):
        print(f"error: {path} not found", file=sys.stderr)
        return None, [], 2
    try:
        entries, errors, warnings = load_rules(path, today)
    except SystemExit as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None, [], 2
    if errors:
        for msg in errors:
            print(f"error: {path} {msg}", file=sys.stderr)
        print(f"Nothing was changed. Fix {path} (see --check-mitigations) and run again.", file=sys.stderr)
        return None, [], 2
    return Rules(entries, today), warnings, 0


# Markdown for pull request comments, issue comments and FINDINGS.md. Everything that came from a
# scan, a file or a person goes through md_safe: no HTML, no comments, no mentions, no table breaks.
REPORT_LIMIT = 60_000
_RE_MD_SPECIAL = re.compile(r"([\\`*_\[\]~|])")


def md_safe(value: Any, limit: Optional[int] = None) -> str:
    s = "" if value is None else str(value)
    s = _RE_UNPRINTABLE.sub(" ", s.replace("\r\n", " ").replace("\r", " ").replace("\n", " ").replace("\t", " "))
    while "<!--" in s or "-->" in s:
        s = s.replace("<!--", "").replace("-->", "")
    if limit and len(s) > limit:
        s = s[:limit - 1].rstrip() + "…"
    s = html.escape(s, quote=False)
    s = _RE_MD_SPECIAL.sub(r"\\\1", s)
    return s.replace("@", "&#64;")


def md_link(text: str, url: Any) -> str:
    """[text](url) for https links only; the URL is percent-encoded so it cannot break the Markdown."""
    u = str(url or "").strip()
    if not u.startswith("https://"):
        return ""
    from urllib.parse import quote
    return f"[{text}]({quote(u, safe=':/?#=&%~.-_+,;!$*')})"


def severity_counts(rows: Iterable[dict]) -> str:
    c = Counter(str(r.get("Severity") or "Unknown") for r in rows)
    total = sum(c.values())
    if not total:
        return "0"
    parts = ", ".join(f"{SEVERITY_LABEL[r]} {c[SEVERITY_LABEL[r]]}" for r in (5, 4, 3, 2, 1, 0)
                      if c[SEVERITY_LABEL[r]])
    return f"{total} ({parts})"


DIFF_FIELDS = ("finding", "asset", "file", "type", "reason", "approved_by", "expires")
OTHER_FIELDS = ("notes", "ref", "requested_by", "approved_on", "allow_broad")


def rule_changes(base: list[dict], new: list[dict]) -> list[tuple[str, Optional[dict], Optional[dict]]]:
    def key(e: dict) -> str:
        return e["id"] or f"(entry {e['_n']})"
    b = {key(e): e for e in base}
    n = {key(e): e for e in new}
    out: list[tuple[str, Optional[dict], Optional[dict]]] = []
    for k, cur in n.items():
        old = b.get(k)
        if old is None:
            out.append(("Added", None, cur))
        elif any(old[f] != cur[f] for f in DIFF_FIELDS + OTHER_FIELDS):
            out.append(("Changed", old, cur))
    out += [("Removed", old, None) for k, old in b.items() if k not in n]
    return out


def rule_report(path: str, entries: list[dict], errors: list[str], warnings: list[str], base: list[dict],
                baseline: Optional[list[dict]]) -> str:
    """Markdown for the pull request comment, capped at REPORT_LIMIT characters."""
    valid = sum(1 for e in entries if e["_valid"])
    head = ["## Veracode mitigations", "",
            f"**{md_safe(path)}: {len(errors)} problem(s). Fix them before merging.**" if errors
            else f"**{md_safe(path)}: {valid} rule(s), all valid.**", "",
            "### Changes compared with the base branch", ""]
    changes = rule_changes(base, entries)
    cols = ["Change", "ID", "Finding", "Asset", "File", "Type", "Reason", "Approved By", "Expires", "Other"]
    if baseline is not None:
        cols.append("Open findings matched")
    rows: list[str] = []
    for change, old, cur in changes:
        e = cur or old
        assert e is not None

        def cell(f: str) -> str:
            if change == "Changed" and old and cur and old[f] != cur[f]:
                return f"~~{md_safe(old[f], 200) or '(empty)'}~~ {md_safe(cur[f], 200) or '(empty)'}"
            return md_safe(e[f], 200)
        other = []
        for f in OTHER_FIELDS:
            if change == "Changed" and old and cur and old[f] != cur[f]:
                other.append(f"{f}: ~~{md_safe(old[f], 80) or '(empty)'}~~ {md_safe(cur[f], 80) or '(empty)'}")
            elif change == "Added" and e[f] not in ("", False):
                other.append(f"{f}: {md_safe(e[f], 80)}")
        cells = [change, md_safe(e["id"] or "(no id)", 40)] + [cell(f) for f in DIFF_FIELDS] + ["; ".join(other)]
        if baseline is not None:
            cells.append(severity_counts(r for r in baseline if rule_matches(e, r)) if cur and cur["finding"]
                         else "")
        rows.append("| " + " | ".join(cells) + " |")
    tail: list[str] = []
    if errors:
        tail += ["", "### Problems", ""] + [f"- {md_safe(m, 500)}" for m in errors[:200]]
        if len(errors) > 200:
            tail.append(f"- ...and {len(errors) - 200} more")
    if warnings:
        tail += ["", "### Warnings", ""] + [f"- {md_safe(m, 500)}" for m in warnings[:100]]
    tail_text = "\n".join(tail)[:REPORT_LIMIT // 3]
    budget = REPORT_LIMIT - len(tail_text) - 500
    body: list[str] = []
    if rows:
        body = ["| " + " | ".join(cols) + " |", "|" + " --- |" * len(cols)]
        used = sum(len(x) + 1 for x in head + body)
        for i, r in enumerate(rows):
            if used + len(r) + 1 > budget:
                body.append(f"\n_{len(rows) - i} more change(s) not shown. Run --check-mitigations locally "
                            "for the full list._")
                break
            body.append(r)
            used += len(r) + 1
    else:
        body = ["No mitigation changes."]
    return ("\n".join(head + body) + "\n" + tail_text + "\n")[:REPORT_LIMIT]


def check_mitigations(path: str, against: Optional[str] = None, track_dir: Optional[str] = None) -> int:
    """--check-mitigations: validate mitigations.yml and list its rules. No Veracode access.
    With --against BASE: Markdown of the rules added, changed or removed, for a pull request comment.
    With --track DIR: also how many open findings in DIR/findings.csv each added or changed rule matches."""
    if not os.path.exists(path):
        print(f"error: {path} not found", file=sys.stderr)
        return 2
    today = utcnow().date()
    try:
        entries, errors, warnings = load_rules(path, today)
    except SystemExit as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if against is not None:
        base: list[dict] = []
        if os.path.exists(against) and os.path.getsize(against):
            base, _, _ = load_rules(against, today)
        baseline = None
        if track_dir:
            fpath = track_paths(track_dir)["findings"]
            baseline = read_csv_file(fpath) if os.path.exists(fpath) else []
        print(rule_report(path, entries, errors, warnings, base, baseline))
        return 2 if errors else 0
    for e in entries:
        if not e["_valid"]:
            continue
        scope = "".join(f", {f} {e[f]}" for f in ("asset", "file") if e[f])
        extra = f", expires {e['expires']}" if e["expires"] else ""
        print(f"OK       {e['id']} {e['finding']}{scope}: {e['type']}, approved by {e['approved_by']}{extra}. "
              f"{e['reason']}")
    for msg in errors:
        print(f"ERROR    {msg}")
    for msg in warnings:
        print(f"WARNING  {msg}")
    if errors:
        print(f"\n{path}: {len(errors)} problem(s). Fix them before merging.")
        return 2
    print(f"{path}: {sum(1 for e in entries if e['_valid'])} rule(s), all valid.")
    return 0


# ---------------------------------------------------------------------------
# Approving a mitigation request issue (--approve-issue)
# ---------------------------------------------------------------------------
# The approval workflow passes the issue (as JSON in a file, never through the shell) when an
# approver adds the `approved` label. The issue body is the Markdown GitHub renders from the issue
# form: "### <field label>" followed by the value.

ISSUE_FORM_FIELDS = {"Finding Key": "finding_key", "Finding ID": "finding_id", "Asset": "asset", "File": "file",
                     "Type": "type", "Reason": "reason", "Expires": "expires", "Notes / ticket": "notes"}
NO_RESPONSE = "_No response_"
NOT_APPROVER = 3  # exit code: the person who added the label is not in MITIGATION_APPROVERS
MITIGATIONS_HEADER = ("# Approved mitigations for the Veracode findings tracker. See docs/MITIGATIONS.md.\n"
                      "# The approval workflow appends entries here; you can also add or remove them in a pull "
                      "request.\n")
_RE_LOGIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}(\[bot\])?$")
_RE_ISSUE_URL = re.compile(r"^https://[^\s/]+/[^\s/]+/[^\s/]+/issues/\d+$")


def parse_issue_form(body: Any) -> tuple[dict[str, str], list[str]]:
    """Issue-form Markdown -> {field id: value}. A field heading that appears twice is an error (someone
    typed '### Type' inside another answer)."""
    text = str(body or "").replace("\x0d\n", "\n").replace("\x0d", "\n")
    values: dict[str, str] = {}
    errors: list[str] = []
    current: Optional[str] = None
    buf: list[str] = []

    def flush() -> None:
        if current is not None and current not in values:
            value = "\n".join(buf).strip()
            values[current] = "" if value == NO_RESPONSE else value

    for line in text.split("\n"):
        hit = re.fullmatch(r"###[ \t]+(.+?)[ \t]*", line)
        if hit and hit.group(1) in ISSUE_FORM_FIELDS:
            flush()
            current, buf = ISSUE_FORM_FIELDS[hit.group(1)], []
            if current in values:
                errors.append(f"the section '{hit.group(1)}' appears more than once")
            continue
        if current is not None:
            buf.append(line)
    flush()
    return values, errors


def parse_approvers(text: Optional[str]) -> set[str]:
    return {x.lstrip("@").lower() for x in re.split(r"[\s,]+", text or "") if x.strip().lstrip("@")}


def next_rule_id(entries: list[dict]) -> str:
    nums = [int(mt.group(1)) for e in entries if (mt := _RE_RULE_ID.match(str(e.get("id") or "")))]
    return f"M-{max(nums, default=0) + 1:04d}"


def yaml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, dt.date):
        return v.isoformat()
    return json.dumps(_RE_UNPRINTABLE.sub(" ", str(v)), ensure_ascii=False)  # a JSON string is valid YAML


def render_rule(entry: dict[str, Any]) -> str:
    lines = [f"- id: {entry['id']}"]
    for k in RULE_FIELDS[1:]:
        v = entry.get(k)
        if v not in (None, "", False):
            lines.append(f"  {k}: {v if k == 'type' else yaml_value(v)}")
    return "\n".join(lines) + "\n"


def append_rules(path: str, new: list[dict[str, Any]], today: dt.date) -> Optional[str]:
    """Appends entries to mitigations.yml as text (comments and layout stay) and writes it atomically.
    Returns an error message, or None."""
    yaml = require_yaml()
    text = MITIGATIONS_HEADER
    if os.path.exists(path):
        with open(path, encoding="utf-8-sig") as fh:
            text = fh.read()
    try:
        current = yaml.safe_load(text) or []
    except yaml.YAMLError as exc:
        return f"{path} is not valid YAML: {str(exc)[:200]}"
    if not current:  # "[]" (the template's empty list) cannot be followed by block entries
        text = re.sub(r"(?m)^[ \t]*\[[ \t]*\][ \t]*(#.*)?$\n?", "", text)
    if text and not text.endswith("\n"):
        text += "\n"
    text += "".join(render_rule(e) for e in new)
    try:
        entries, errors, _ = validate_rules(yaml.safe_load(text), today)
    except yaml.YAMLError as exc:
        return f"{path} could not be extended ({str(exc)[:200]}). Rewrite it as a block list ('- id: ...')"
    tail = entries[-len(new):] if new else []
    if errors or len(tail) != len(new) or any(
            got[k] != str(want.get(k) or "") for got, want in zip(tail, new)
            for k in ("id", "finding", "asset", "file", "reason", "approved_by", "notes", "ref")):
        return f"{path} could not be extended safely: " + "; ".join(errors[:5])
    atomic_write_text(path, text)
    return None


def approve_issue(issue_path: str, rules_path: str, approver: Optional[str], approvers: Optional[str],
                  today: dt.date, track_dir: Optional[str] = None) -> int:
    """--approve-issue: turn an approved mitigation request issue into a mitigations.yml entry.
    Exit 0 recorded (or already recorded), 2 invalid request, 3 not an approver."""
    def fail(msgs: list[str], code: int = 2) -> int:
        for msg in msgs:  # the workflow posts these on the issue: keep them Markdown-safe
            print(f"- {md_safe(msg, 500)}", file=sys.stderr)
        return code

    login = (approver or "").strip()
    if not _RE_LOGIN.match(login):
        return fail(["--approver must be the GitHub login of the person who added the label"])
    allowed = parse_approvers(approvers)
    if not allowed:
        return fail(["the repository variable MITIGATION_APPROVERS is empty, so nobody can approve"], NOT_APPROVER)
    if login.lower() not in allowed:
        return fail([f"{login} is not an approver (repository variable MITIGATION_APPROVERS)"], NOT_APPROVER)
    try:
        with open(issue_path, encoding="utf-8") as fh:
            issue = json.load(fh)
    except (OSError, ValueError) as exc:
        return fail([f"cannot read the issue JSON: {exc}"])
    if not isinstance(issue, dict):
        return fail(["the issue JSON must be an object"])
    if str(issue.get("state") or "open").lower() != "open":
        return fail(["the issue is closed; reopen it to approve"])
    url = str(issue.get("url") or "")
    if not _RE_ISSUE_URL.match(url):
        return fail(["the issue JSON has no valid url"])
    author = issue.get("author") if isinstance(issue.get("author"), dict) else {}
    requested_by = str(author.get("login") or "")
    try:
        entries, errors, _ = load_rules(rules_path, today)
    except SystemExit as exc:
        return fail([str(exc)])
    if errors:
        return fail([f"{rules_path} has problems; fix them first:"] + errors[:20])
    done = next((e for e in entries if e["ref"] == url), None)
    if done:
        print(f"Already recorded as {done['id']}")
        github_output(id=done["id"], matches=count_matches(done, track_dir))
        return 0

    fields, problems = parse_issue_form(issue.get("body"))
    f = {k: _RE_UNPRINTABLE.sub(" ", fields.get(k, "")).strip() for k in ISSUE_FORM_FIELDS.values()}
    key = f["finding_key"].lower()
    if not _RE_MKEY.match(key):
        problems.append("Finding Key must look like mk-0123456789ab (use the Mitigate link in FINDINGS.md)")
    for k in ("finding_key", "finding_id", "asset", "file", "expires"):
        if "\n" in f[k]:
            problems.append(f"{k.replace('_', ' ')} must be one line")
    wider = any(ch in f["asset"] for ch in "*?") or bool(f["file"])
    if wider and not f["finding_id"]:
        problems.append("Finding ID is required when Asset has a wildcard or File is set")
    mtype = (f["type"].split() or [""])[0].lower()
    if f["expires"]:
        day, err = rule_date(f["expires"])
        if err:
            problems.append(f"Expires: {err}")
        elif day and day < today:
            problems.append(f"Expires: {day} is in the past")
    entry = {"id": next_rule_id(entries), "finding": f["finding_id"] if wider else key, "asset": f["asset"],
             "file": f["file"], "type": mtype, "reason": f["reason"], "approved_by": login, "approved_on": today,
             "expires": f["expires"], "ref": url, "requested_by": requested_by, "notes": f["notes"]}
    _, errs, _ = validate_rules([{k: v for k, v in entry.items() if v not in ("", None)}], today)
    problems += [e.split(": ", 1)[1] for e in errs]
    if problems:
        return fail(problems)
    err = append_rules(rules_path, [entry], today)
    if err:
        return fail([err])
    n = count_matches(entry, track_dir)
    print(f"Approved as {entry['id']}, applied to {n} finding(s)")
    github_output(id=entry["id"], matches=n)
    return 0


def count_matches(entry: dict[str, Any], track_dir: Optional[str]) -> int:
    """Open findings in DIR/findings.csv that the rule matches (0 without a baseline)."""
    if not track_dir:
        return 0
    path = track_paths(track_dir)["findings"]
    if not os.path.exists(path):
        return 0
    e = {k: str(entry.get(k) or "") for k in RULE_PATTERNS}
    return sum(1 for r in read_csv_file(path) if rule_matches(e, r))


# ---------------------------------------------------------------------------
# Migration from the old tracking CSV (veracode-findings.csv, --mitigations FILE.csv in older versions)
# ---------------------------------------------------------------------------

OLD_TRACKING_FILE = "veracode-findings.csv"


def migrate_old_file(path: str, rules_path: str, today: dt.date) -> tuple[Optional[dict[str, str]], Optional[str]]:
    """Turns every mitigated row of an old tracking CSV into a mitigations.yml entry (finding = its key,
    ref 'migrated') and returns {Finding Key: First Seen} to seed the baseline. Running it twice adds nothing.
    Returns (seed, error)."""
    if not os.path.exists(path):
        return None, f"{path} not found"
    try:
        old = read_csv_file(path)
    except (OSError, csv.Error) as exc:
        return None, f"cannot read {path}: {exc}"
    if old and "Mitigation Key" not in old[0]:
        return None, f"{path} has no Mitigation Key column; it is not an old tracking file"
    try:
        entries, errors, _ = load_rules(rules_path, today)
    except SystemExit as exc:
        return None, str(exc)
    if errors:
        return None, f"{rules_path} has problems; fix them first: " + "; ".join(errors[:5])
    done = {e["finding"].lower() for e in entries if e["ref"] == "migrated"}
    seed: dict[str, str] = {}
    new: list[dict[str, Any]] = []
    problems: list[str] = []
    next_n = int(next_rule_id(entries)[2:])
    for line, row in enumerate(old, 2):
        key = str(row.get("Mitigation Key") or "").strip().lower()
        valid_key = bool(_RE_MKEY.match(key))
        if valid_key and row.get("Mitigation Status") != NOT_IN_EXPORT:
            first = day_of(row.get("First Seen") or row.get("Scan Date"))
            seed[key] = first.isoformat() if first else ""
        mtype = str(row.get("Mitigation Type") or "").strip().lower()
        if not mtype:
            continue
        where = f"{path} row {line} ({row.get('Finding ID') or key or '?'})"
        if not valid_key:
            problems.append(f"{where}: Mitigation Key is missing or changed")
            continue
        if key in done:
            continue
        expires = str(row.get("Mitigation Expires") or "").strip()
        if expires:
            day, err = parse_expiry(expires)
            if err:
                problems.append(f"{where}: Mitigation Expires: {err}")
                continue
            expires = day.isoformat() if day else ""
        entry = {"id": f"M-{next_n:04d}", "finding": key, "type": mtype,
                 "reason": str(row.get("Mitigation Reason") or "").strip(),
                 "approved_by": str(row.get("Mitigation Approved By") or "").strip(), "expires": expires,
                 "notes": str(row.get("Mitigation Notes") or "").strip(), "ref": "migrated"}
        _, errs, _ = validate_rules([{k: v for k, v in entry.items() if v}], today)
        if errs:
            problems += [f"{where}: {e.split(': ', 1)[1]}" for e in errs]
            continue
        new.append(entry)
        done.add(key)
        next_n += 1
    if problems:
        return None, "cannot migrate the old tracking file:\n  " + "\n  ".join(problems[:50])
    if new:
        err = append_rules(rules_path, new, today)
        if err:
            return None, err
    print(f"Migrated {len(new)} mitigation(s) from {path} to {rules_path}"
          + (f" ({new[0]['id']} to {new[-1]['id']})" if new else "")
          + f"; {len(seed)} finding(s) keep their First Seen. {path} is no longer used and can be deleted.")
    return seed, None


def remap_legacy_rules(rules_path: str, current: list[dict]) -> bool:
    """Rules written with a Finding Key from before the code_hash fix get the current key. True if changed."""
    legacy = {str(r.get("_legacy")): str(r.get("Finding Key")) for r in current
              if r.get("_legacy") and r.get("_legacy") != r.get("Finding Key")}
    if not legacy:
        return False
    with open(rules_path, encoding="utf-8-sig") as fh:
        text = fh.read()
    changed = text
    for old, new in legacy.items():
        changed = re.sub(rf"(?i)\b{re.escape(old)}\b", new, changed)
    if changed == text:
        return False
    atomic_write_text(rules_path, changed)
    print(f"Updated old Finding Keys in {rules_path} to the current ones")
    return True


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

    g = p.add_argument_group("findings tracker (see README.md)")
    g.add_argument("--track", metavar="DIR",
                   help="Update the findings baseline in DIR (findings.csv, fixed.csv): New, Open, Reopened and "
                        "Fixed findings of the latest scan per asset. Scan filters apply; finding filters are "
                        "refused. Any failed request changes nothing (exit 1).")
    g.add_argument("--offline", action="store_true",
                   help="With --track: refresh Days Open and the Mitigation columns from the existing baseline, "
                        "without calling Veracode.")
    g.add_argument("--dashboard", metavar="FILE",
                   help="With --track: where to write the Markdown dashboard (default FINDINGS.md next to DIR).")
    g.add_argument("--repo-url", metavar="URL",
                   help="With --track: https://github.com/<org>/<repo>, for the Mitigate links in the dashboard. "
                        "Default: from GITHUB_SERVER_URL and GITHUB_REPOSITORY in GitHub Actions.")
    g.add_argument("--migrate", metavar="OLD_CSV",
                   help="With --track: copy the mitigations of an old tracking CSV (veracode-findings.csv) into "
                        "--mitigations and keep its First Seen dates. Done automatically on the first run when "
                        f"{OLD_TRACKING_FILE} sits next to DIR.")

    g = p.add_argument_group("mitigations (see docs/MITIGATIONS.md)")
    g.add_argument("--mitigations", metavar="FILE",
                   help="Mitigation rules file (mitigations.yml). Adds the Mitigation columns (Status, Type, "
                        "Reason, Approved By, Expires, Ref) to an export or to --track.")
    g.add_argument("--check-mitigations", metavar="FILE",
                   help="Validate and list the rules in this mitigations.yml, then exit (0 valid, 2 invalid). "
                        "No Veracode access needed.")
    g.add_argument("--against", metavar="BASE",
                   help="With --check-mitigations: print Markdown of the rules added, changed or removed compared "
                        "with BASE (for pull requests). Add --track DIR to show how many open findings in "
                        "DIR/findings.csv each rule matches.")
    g.add_argument("--approve-issue", metavar="ISSUE_JSON",
                   help="Record an approved mitigation request: read the issue (JSON with number, title, body, "
                        "url, author, from the approval workflow), validate it and append the next M-NNNN entry "
                        "to --mitigations. Exit 2 if invalid, 3 if --approver is not in MITIGATION_APPROVERS.")
    g.add_argument("--approver", metavar="LOGIN",
                   help="With --approve-issue: GitHub login that added the approved label. Must be listed in the "
                        "MITIGATION_APPROVERS environment variable (comma or space separated).")

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
    now = utcnow()
    if args.offline and not args.track:
        print("error: --offline needs --track DIR", file=sys.stderr)
        return 2
    if args.against and not args.check_mitigations:
        print("error: --against needs --check-mitigations FILE", file=sys.stderr)
        return 2
    if args.check_mitigations:
        return check_mitigations(args.check_mitigations, args.against, args.track)
    if args.approve_issue:
        if not args.mitigations:
            print("error: --approve-issue needs --mitigations FILE", file=sys.stderr)
            return 2
        return approve_issue(args.approve_issue, args.mitigations, args.approver,
                             os.environ.get("MITIGATION_APPROVERS"), now.date(), args.track)
    if args.track:
        return run_track(args, now, minter)
    rules: Optional[Rules] = None
    mitigation_notes: list[str] = []
    if args.mitigations:
        rules, mitigation_notes, rc = load_rules_for_run(args.mitigations, now.date(), must_exist=True)
        if rules is None:
            return rc
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
        if rules:
            user_cols = ["Mitigation Status"] + user_cols + EXPORT_MITIGATION_COLUMNS[1:]
    finding_base = (["Mitigation Status"] + BASE_COLUMNS + EXPORT_MITIGATION_COLUMNS[1:]) if rules else BASE_COLUMNS
    mit_status: Counter = Counter()
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
                    if rules:
                        rules.apply(row)  # before filters, so --where "Mitigation Status=..." works
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
                    if rules:
                        mit_status[row["Mitigation Status"] or "Not mitigated"] += 1
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
        if rules:
            for col in EXPORT_MITIGATION_COLUMNS:
                seen_cols[col] += 1

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
    if rules:
        print("  Mitigation status  : " + ", ".join(
            f"{k} {mit_status[k]}" for k in ("Not mitigated", "Mitigated", "Expiring", "Expired")))
        for msg in mitigation_notes[:10]:
            print(f"  NOTE: {msg}")
        if len(mitigation_notes) > 10:
            print(f"  NOTE: ...and {len(mitigation_notes) - 10} more (run --check-mitigations)")
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
