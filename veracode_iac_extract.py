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
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterable, Optional

import requests
from requests.adapters import HTTPAdapter

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_IAC_BASE = "https://ui.analysiscenter.veracode.com/container-scan-query/v1"
DEFAULT_LINK_BASE = "https://web.analysiscenter.veracode.com/app/container-iac-scans"
APPLICATIONS_URL = "https://api.veracode.com/appsec/v1/applications"
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
        self._tokens = rps
        self._last = time.monotonic()
        self._pause_until = 0.0
        self._lock = threading.Lock()

    def pause(self, seconds: float) -> None:
        with self._lock:
            self._pause_until = max(self._pause_until, time.monotonic() + seconds)

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                if now < self._pause_until:
                    wait = self._pause_until - now
                else:
                    self._tokens = min(self._rps, self._tokens + (now - self._last) * self._rps)
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
                        return resp.json()
                    except ValueError as exc:
                        raise FetchError(f"{scope}: invalid JSON ({exc})") from exc
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
                try:
                    retry_after = max(0.0, float(resp.headers.get("Retry-After", "")))
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
            out.extend(batch)
            prev = batch
            total_pages = (data.get("pagination") or {}).get("total_pages")
            expected = (data.get("pagination") or {}).get("total_elements")
            if isinstance(total_pages, (int, float)):
                if page >= int(total_pages) - 1:
                    break
            elif len(batch) < PAGE_LIMIT:
                break
            if not batch:
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
    """'30d', '12h', '2w' (relative) or an ISO date / datetime."""
    m = re.fullmatch(r"(\d+)([hdw])", value.strip().lower())
    if m:
        unit = {"h": "hours", "d": "days", "w": "weeks"}[m.group(2)]
        return now - dt.timedelta(**{unit: int(m.group(1))})
    d = parse_when(value)
    if not d:
        raise argparse.ArgumentTypeError(f"Unrecognised date '{value}'. Use YYYY-MM-DD or e.g. 30d")
    return d


def norm(name: str) -> str:
    return _RE_NORM.sub("", name.lower())


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------

def compile_pattern(pat: str) -> Callable[[str], bool]:
    """Plain text = contains. With * or ? = whole-value wildcard. 're:<regex>' = regex.
    Always case-insensitive."""
    pat = pat.strip()
    if pat.lower().startswith("re:"):
        rx = re.compile(pat[3:], re.I)
        return lambda s: bool(rx.search(s))
    if not any(ch in pat for ch in "*?"):
        needle = pat.lower()
        return lambda s: needle in s.lower()
    rx = re.compile(fnmatch.translate(pat), re.I)
    return lambda s: bool(rx.match(s))


class Clause:
    """COLUMN=pat1,pat2 (any of) or COLUMN!=pat1,pat2 (none of)."""

    def __init__(self, column: str, patterns: str, negate: bool = False, source: str = "",
                 also: tuple[str, ...] = ()) -> None:
        self.column = column
        self.also = also
        self.key = norm(column)
        self.negate = negate
        self.source = source or f"{column}{'!=' if negate else '='}{patterns}"
        self.patterns = split_patterns(patterns)
        self.matchers = [compile_pattern(p) for p in self.patterns]
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

def scan_row(scan: dict, now: dt.datetime, link_base: str, latest_ids: set[str],
             app_index: dict[str, dict]) -> dict[str, Any]:
    consumed: set[str] = set()
    row: dict[str, Any] = {}
    for col, names in SCAN_FIELDS.items():
        row[col] = flat(pick(scan, names))
        consumed.update(n for n in names if n in scan)
    hist = scan.get("severity_histogram")
    if isinstance(hist, dict):
        consumed.add("severity_histogram")
        for sev, col in HISTOGRAM_COLUMNS.items():
            row[col] = hist.get(sev, 0) or 0
        row["Scan Total Findings"] = sum(v for v in hist.values() if isinstance(v, (int, float)))
    when = parse_when(scan.get("scanned_at"))
    row["Scan Date"] = when.strftime("%Y-%m-%dT%H:%M:%SZ") if when else flat(scan.get("scanned_at"))
    row["Scan Age Days"] = (now - when).days if when else ""
    sid = str(scan.get("scan_id") or "")
    row["Is Latest Scan For Asset"] = "true" if sid in latest_ids else "false"
    row["Veracode Link"] = f"{link_base}/{sid}/summary" if sid else ""
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
    row["Finding Key"] = hashlib.sha1("\x1f".join(ident + [str(start)]).encode()).hexdigest()[:16]
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


def load_app_index(ca_cert: Optional[str], tracker: Tracker) -> dict[str, dict]:
    """Optional: map asset names to application profiles (name match, case-insensitive)."""
    from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
    s = make_session(ca_cert)
    s.auth = RequestsAuthPluginVeracodeHMAC()
    index: dict[str, dict] = {}
    page = 0
    try:
        while True:
            r = s.get(APPLICATIONS_URL, params={"page": page, "size": 500}, timeout=120)
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
    """Neutralise spreadsheet formula injection from scanned content."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        try:
            float(value)
            return value
        except ValueError:
            return "'" + value
    return value


def write_output(path: str, fmt: str, columns: list[str], rows: Iterable[dict], raw_cells: bool) -> int:
    count = 0
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".iac_", suffix=".tmp", dir=folder)
    os.close(fd)
    try:
        if fmt == "csv":
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
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return count


def order_columns(seen: Counter, base: list[str], keep_empty: bool, user_cols: Optional[list[str]]) -> list[str]:
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
# Mitigations (only with --mitigations or --check-mitigations)
# ---------------------------------------------------------------------------
# Mitigations for these findings are not yet available on the Veracode Platform.
# Until they are, they are tracked in the export CSV itself: people fill in the
# Mitigation columns, and the next run carries them onto the fresh findings by key.

MITIGATION_TYPES = {
    "false-positive": "Not a real issue (Potential False Positive in Static Analysis).",
    "by-design": "Deliberate and approved, or the design already handles it (Mitigate by Design).",
    "network-environment": "A network control handles it: WAF, security group, private network.",
    "os-environment": "The OS or runtime handles it: hardened host, read-only file system, no shell.",
    "accept-risk": "The business accepts the risk for a limited time. Needs Mitigation Expires.",
}
# Columns people fill in. Status and Key are written by the script.
MITIGATION_INPUT = ["Mitigation Type", "Mitigation Reason", "Mitigation Approved By", "Mitigation Expires",
                    "Mitigation Notes"]
MITIGATION_COLUMNS = ["Mitigation Status"] + MITIGATION_INPUT + ["Mitigation Key"]
NOT_IN_EXPORT = "Not in export"
EXPIRY_WARN_DAYS = 30
_RE_DIGEST = re.compile(r"@sha256:[0-9a-f]{16,}$", re.I)
_RE_LINE_NO = re.compile(r"^\s*\d+\s*[:|]?\s?", re.M)
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


def code_hash(code: Any) -> str:
    """Hash of the flagged code without whitespace or line numbers. The code itself is never stored."""
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
            value = _RE_LINE_NO.sub("", code)
    collect(value)
    compact = re.sub(r"\s+", "", "".join(parts))
    return hashlib.sha256(compact.encode()).hexdigest()[:16] if compact else ""


def mitigation_key(row: dict[str, Any]) -> str:
    """ID that stays the same between scans: no line numbers, no image tags.
    The mk- prefix stops spreadsheets from turning it into a number."""
    ftype = str(row.get("Finding Type") or "").strip().lower()
    low = lambda col: str(row.get(col) or "").strip().lower()  # noqa: E731
    path = stable_path(row.get("File Path"))
    parts = ["v1", stable_asset(row.get("Asset Name"), row.get("Asset Type")), ftype, low("Finding ID")]
    if ftype == "misconfiguration":
        parts += [low("Rule ID"), path, low("Resource")]
    elif ftype == "secret":
        parts += [low("Rule ID"), path, code_hash(row.get("Code Lines"))]
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
        rows.append({k: (v[1:] if isinstance(v, str) and len(v) > 1 and v[0] == "'" and v[1] in "=+-@\t\r"
                         else (v or "")) for k, v in r.items() if k is not None})
    return rows


def load_mitigations(path: str, today: dt.date) -> tuple[dict[str, dict], dict[str, dict], list[str], list[str]]:
    """Reads the Mitigation columns of a previous export.
    Returns (mitigation per key, the row each came from, errors, notes). A missing file is not an error."""
    if not os.path.exists(path):
        return {}, {}, [], [f"{path} did not exist yet, so every finding is Open. "
                            "Fill in the Mitigation columns to mitigate."]
    try:
        rows = read_csv_file(path)
    except (OSError, csv.Error) as exc:
        return {}, {}, [f"cannot read {path}: {exc}"], []
    if rows and "Mitigation Key" not in rows[0]:
        return {}, {}, [f"{path} has no Mitigation Key column. Use a CSV written with --mitigations"], []
    by_key: dict[str, dict] = {}
    source: dict[str, dict] = {}
    line_of: dict[str, int] = {}
    errors: list[str] = []
    notes: list[str] = []
    for line, row in enumerate(rows, 2):
        vals = {c: str(row.get(c) or "").strip() for c in MITIGATION_INPUT}
        if not any(vals.values()):
            continue
        where = f"line {line} ({row.get('Finding ID') or row.get('Mitigation Key') or '?'})"
        key = str(row.get("Mitigation Key") or "").strip()
        problems = []
        if not _RE_MKEY.match(key):
            problems.append("Mitigation Key is missing or changed. Do not edit it")
        mtype = vals["Mitigation Type"].lower()
        if not mtype:
            problems.append("set Mitigation Type, or clear the other Mitigation columns")
        elif mtype not in MITIGATION_TYPES:
            problems.append(f"Mitigation Type must be one of {', '.join(MITIGATION_TYPES)}")
        for col in ("Mitigation Reason", "Mitigation Approved By"):
            if not vals[col]:
                problems.append(f"{col} is required")
        expires = None
        if vals["Mitigation Expires"]:
            expires, err = parse_expiry(vals["Mitigation Expires"])
            if err:
                problems.append(f"Mitigation Expires: {err}")
        elif mtype == "accept-risk":
            problems.append("accept-risk needs Mitigation Expires")
        if problems:
            errors += [f"{where}: {p}" for p in problems]
            continue
        mit = {"Mitigation Type": mtype, "Mitigation Reason": vals["Mitigation Reason"],
               "Mitigation Approved By": vals["Mitigation Approved By"],
               "Mitigation Expires": expires.isoformat() if expires else "",
               "Mitigation Notes": vals["Mitigation Notes"], "_expires": expires}
        if key in by_key:
            if {k: v for k, v in by_key[key].items() if not k.startswith("_")} != \
                    {k: v for k, v in mit.items() if not k.startswith("_")}:
                errors.append(f"{where}: same Mitigation Key as line {line_of[key]} but a different mitigation. "
                              "Make them match or clear one")
            continue
        by_key[key], source[key], line_of[key] = mit, row, line
        if expires and expires < today:
            notes.append(f"{where} expired on {expires}: the finding is open again. Renew or fix it")
        elif expires and (expires - today).days <= EXPIRY_WARN_DAYS:
            notes.append(f"{where} expires on {expires}")
    return by_key, source, errors, notes


class MitigationSet:
    def __init__(self, by_key: dict[str, dict], source: dict[str, dict], today: dt.date) -> None:
        self.by_key = by_key
        self.source = source
        self.today = today
        self.seen: set[str] = set()

    def apply(self, row: dict[str, Any]) -> str:
        """Adds the Mitigation columns to a fresh finding. Returns Open, Mitigated or Expired."""
        key = mitigation_key(row)
        mit = self.by_key.get(key)
        status = "Open"
        if mit:
            self.seen.add(key)
            status = "Expired" if mit["_expires"] and mit["_expires"] < self.today else "Mitigated"
        row["Mitigation Status"] = status
        for col in MITIGATION_INPUT:
            row[col] = mit[col] if mit else ""
        row["Mitigation Key"] = key
        return status

    def not_in_export(self) -> list[dict[str, Any]]:
        """Mitigated rows from the previous file whose finding is not in this export (fixed, or
        filtered out). Kept so the mitigation is not lost if the finding comes back."""
        return [dict(self.source[k], **{"Mitigation Status": NOT_IN_EXPORT})
                for k in self.by_key if k not in self.seen]


def check_mitigations(path: str) -> int:
    """--check-mitigations: validate the Mitigation columns and exit. No Veracode access needed."""
    if not os.path.exists(path):
        print(f"error: {path} not found", file=sys.stderr)
        return 2
    by_key, _, errors, notes = load_mitigations(path, dt.datetime.now(dt.timezone.utc).date())
    for msg in errors:
        print(f"ERROR  {msg}")
    for msg in notes:
        print(f"NOTE   {msg}")
    if errors:
        print(f"\n{path}: {len(errors)} problem(s). Fix them before merging.")
        return 2
    print(f"{path}: {len(by_key)} mitigated finding(s), all valid.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Export Veracode Container / IaC / Secrets findings to CSV, JSON or JSONL.",
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
                   help="Output file (default veracode_iac_findings.csv, or the --mitigations file). "
                        "Format follows the extension unless --format is given.")
    p.add_argument("--format", choices=("csv", "json", "jsonl"))
    p.add_argument("--summary-csv", metavar="PATH", help="Also write a per-asset rollup CSV.")

    g = p.add_argument_group("scan filters (applied before findings are fetched)")
    g.add_argument("--asset", action="append", metavar="PATTERN",
                   help="Asset to include. Matches asset name, asset ID or source.")
    g.add_argument("--exclude-asset", action="append", metavar="PATTERN", help="Asset to exclude.")
    g.add_argument("--scan-type", action="append", metavar="LIST", help="e.g. container, iac")
    g.add_argument("--asset-type", action="append", metavar="LIST", help="image, repo, archive, directory")
    g.add_argument("--scanned-by", action="append", metavar="PATTERN", help="User that ran the scan.")
    g.add_argument("--policy", choices=list(POLICY_VALUES), help="Scan policy result.")
    g.add_argument("--scan-id", action="append", metavar="PATTERN")
    g.add_argument("--since", metavar="DATE|Nd", help="Only scans on/after this (YYYY-MM-DD, 30d, 12h, 2w).")
    g.add_argument("--until", metavar="DATE|Nd", help="Only scans on/before this.")
    g.add_argument("--latest-only", action="store_true",
                   help="Only the most recent scan per asset (current state, fewest API calls).")
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
                   help="CVE or finding ID, e.g. CVE-2024-3094 or 'CVE-2024-*'.")
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

    g = p.add_argument_group("mitigations (see MITIGATIONS.md)")
    g.add_argument("--mitigations", metavar="FILE.csv",
                   help="Track mitigations in this CSV: read the Mitigation columns filled in by people, "
                        "then write the fresh export back to it with the mitigations carried over.")
    g.add_argument("--check-mitigations", metavar="FILE.csv",
                   help="Only validate the Mitigation columns of this CSV and exit. No Veracode access needed.")

    g = p.add_argument_group("connection")
    g.add_argument("--max-workers", type=int, default=4)
    g.add_argument("--rps", type=float, default=2.0, help="Max requests per second (default 2).")
    g.add_argument("--no-server-search", action="store_true",
                   help="Download the full scan list and filter --asset locally instead of "
                        "using the API search.")
    g.add_argument("--fetch-empty-scans", action="store_true",
                   help="Also query scans whose severity totals say they have no matching findings.")
    g.add_argument("--max-attempts", type=int, default=6)
    g.add_argument("--timeout", type=int, default=90)
    g.add_argument("--ca-cert", help="Custom CA bundle (.pem), e.g. behind SSL inspection.")
    g.add_argument("--base-url", default=os.environ.get("VERACODE_IAC_BASE_URL", DEFAULT_IAC_BASE),
                   help="Container scan query API base (override for non-US regions).")
    g.add_argument("--link-base", default=os.environ.get("VERACODE_IAC_LINK_BASE", DEFAULT_LINK_BASE))
    g.add_argument("--ignore-failures", action="store_true", help="Exit 0 even if some requests failed.")
    return p.parse_args(argv)


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
    add("Finding ID", args.finding_id)
    clauses.extend(Clause.parse(w) for w in args.where)
    return clauses


def main(argv: Optional[list[str]] = None, minter: Callable[[], str] = mint_principal_token) -> int:
    args = parse_args(argv)
    now = dt.datetime.now(dt.timezone.utc)
    if args.check_mitigations:
        return check_mitigations(args.check_mitigations)
    mitigations: Optional[MitigationSet] = None
    mitigation_notes: list[str] = []
    writes_back = False
    if args.mitigations:
        if not args.mitigations.lower().endswith(".csv"):
            print("error: --mitigations needs a .csv file", file=sys.stderr)
            return 2
        args.output = args.output or args.mitigations
        writes_back = os.path.abspath(args.output) == os.path.abspath(args.mitigations)
        if writes_back and args.format not in (None, "csv"):
            print("error: the --mitigations file is written back as CSV; drop --format or use -o", file=sys.stderr)
            return 2
        by_key, source, errors, mitigation_notes = load_mitigations(args.mitigations, now.date())
        if errors:
            for msg in errors:
                print(f"error: {args.mitigations} {msg}", file=sys.stderr)
            print(f"Nothing was changed. Fix {args.mitigations} and run again.", file=sys.stderr)
            return 2
        mitigations = MitigationSet(by_key, source, now.date())
    args.output = args.output or "veracode_iac_findings.csv"
    try:
        clauses = build_clauses(args)
        since = parse_cutoff(args.since, now) if args.since else None
        until = parse_cutoff(args.until, now) if args.until else None
        if until and args.until and re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.until.strip()):
            until += dt.timedelta(days=1)  # make a bare date inclusive
        grep = None
        if args.grep:
            try:
                grep = re.compile(args.grep, re.I)
            except re.error:
                grep = re.compile(re.escape(args.grep), re.I)  # not a regex: treat as plain text
    except (ValueError, re.error, argparse.ArgumentTypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.latest_only and args.track_history:
        print("error: --latest-only and --track-history are mutually exclusive", file=sys.stderr)
        return 2
    if args.ca_cert and not os.path.isfile(args.ca_cert):
        print(f"error: CA certificate not found: {args.ca_cert}", file=sys.stderr)
        return 2
    fmt = args.format or {".json": "json", ".jsonl": "jsonl", ".ndjson": "jsonl"}.get(
        os.path.splitext(args.output)[1].lower(), "csv")
    try:
        ranks = parse_severities(args.severity, args.min_severity)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    user_cols = [c.strip() for c in args.columns.split(",") if c.strip()] if args.columns else None
    if args.compact and not user_cols and not args.list_scans:
        user_cols = list(COMPACT_COLUMNS)
        if mitigations:
            user_cols = ["Mitigation Status"] + user_cols + MITIGATION_COLUMNS[1:]
    if user_cols and writes_back:  # never drop the columns people fill in
        have = {norm(c) for c in user_cols}
        if norm("Mitigation Status") not in have:
            user_cols = ["Mitigation Status"] + user_cols
        user_cols += [c for c in MITIGATION_COLUMNS[1:] if norm(c) not in have]
    finding_base = (["Mitigation Status"] + BASE_COLUMNS + MITIGATION_COLUMNS[1:]) if mitigations else BASE_COLUMNS
    mit_status: Counter = Counter()

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
    app_index = load_app_index(args.ca_cert, tracker) if args.match_apps else {}
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
        when = parse_when(s.get("scanned_at"))
        if since and (not when or when < since):
            continue
        if until and (not when or when > until):
            continue
        if args.latest_only and r["Is Latest Scan For Asset"] != "true":
            continue
        if all(c.test(r) for c in scan_clauses):
            selected.append((s, r))
    selected.sort(key=lambda sr: (str(sr[1].get("Asset Name", "")).lower(), sr[1].get("Scan Date", "")),
                  reverse=False)
    assets = {str(r.get("Asset Name", "")).lower() for _, r in selected}
    print(f"  {len(selected)} scans across {len(assets)} assets after scan filters")

    if args.list_scans:
        seen = Counter(k for _, r in selected for k, v in r.items() if v not in ("", None))
        cols = order_columns(seen, SCAN_INVENTORY_COLUMNS + [c for c in BASE_COLUMNS if c.startswith(("Application", "Business", "Teams"))],
                             args.keep_empty_columns, user_cols)
        n = write_output(args.output, fmt, cols, (r for _, r in selected), args.no_csv_safe)
        print(f"\nWrote {n} scans to {args.output}")
        return 0 if (not tracker.failures or args.ignore_failures) else 1

    # --- 2. Findings ---------------------------------------------------------
    # The scan list already carries per-severity totals, so scans that cannot
    # contain a matching finding are skipped without spending a request.
    skipped = 0
    if not args.fetch_empty_scans:
        wanted = [s for s, r in SEVERITY_RANK.items() if ranks is None or r in ranks]
        keep = []
        for scan, base in selected:
            hist = scan.get("severity_histogram")
            if isinstance(hist, dict) and not any(hist.get(sev) for sev in wanted):
                skipped += 1
            else:
                keep.append((scan, base))
        selected = keep
        if skipped:
            print(f"  {skipped} scans skipped (scan totals show no matching findings)")

    def fetch(item: tuple[int, tuple[dict, dict]]) -> tuple[dict, Optional[list[dict]]]:
        idx, (scan, base) = item
        sid, name = scan.get("scan_id"), scan.get("asset_name", "Unknown")
        if not sid:
            tracker.fail(f"scan[{name}]", "record has no scan_id")
            return base, None
        try:
            found = client.paginate(f"{client.base}/scans/{sid}/findings", "findings",
                                    f"findings[{name}:{sid}]", {"sort": "severity", "direction": "desc"})
        except FetchError as exc:
            tracker.fail(f"findings[{name}:{sid}]", str(exc))
            return base, None
        print(f"  [{idx}/{len(selected)}] {name} ({base.get('Scan Date', '')}): {len(found)} findings")
        return base, found

    seen_cols: Counter = Counter()
    history: dict[str, list] = {}           # track key -> [first, last, scan count]
    by_sev: Counter = Counter()
    by_type: Counter = Counter()
    by_rule: Counter = Counter()
    per_asset: dict[str, Counter] = defaultdict(Counter)
    total_raw = kept = 0
    grep_cols = ("Title", "Description", "Suggested Fix", "Rule ID", "Finding ID", "All File Paths",
                 "Library", "Category", "Resource")
    by_lib: Counter = Counter()
    fixable = 0

    spool = tempfile.NamedTemporaryFile("w+", encoding="utf-8", suffix=".jsonl", delete=False)
    try:
        print(f"\nFetching findings for {len(selected)} scans...")
        with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as pool:
            for base, found in pool.map(fetch, enumerate(selected, 1)):
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
                    if mitigations:
                        mitigations.apply(row)  # before filters, so --where "Mitigation Status=..." works
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
                    if mitigations:
                        mit_status[row["Mitigation Status"]] += 1
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
                    a = per_asset[str(row.get("Asset ID") or row.get("Asset Name", ""))]
                    a["Fixable"] += is_fixable
                    a["Findings"] += 1
                    a[row["Severity"]] += 1
                    a["Type: " + (row["Finding Type"] or "(none)")] += 1
                    a["scan:" + str(row.get("Scan ID", ""))] = 1
        spool.flush()
        carried = mitigations.not_in_export() if (mitigations and writes_back) else []
        for row in carried:
            seen_cols.update(k for k, v in row.items() if v not in ("", None))
        if mitigations:
            for col in MITIGATION_COLUMNS:
                seen_cols[col] += 1
            mit_status[NOT_IN_EXPORT] = len(carried)

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
            yield from carried

        written = write_output(args.output, fmt, columns, rows(), args.no_csv_safe)
    finally:
        spool.close()
        os.remove(spool.name)

    if args.summary_csv:
        sev_cols = [SEVERITY_LABEL[r] for r in (5, 4, 3, 2, 1, 0)]
        type_cols = sorted({k for c in per_asset.values() for k in c if k.startswith("Type: ")})
        summary = []
        for name in sorted(per_asset, key=str.lower):
            c = per_asset[name]
            summary.append({"Asset": name, "Scans": sum(1 for k in c if k.startswith("scan:")),
                            "Findings": c["Findings"], "Fixable": c["Fixable"],
                            **{s: c[s] for s in sev_cols},
                            **{t: c[t] for t in type_cols}})
        write_output(args.summary_csv, "csv", ["Asset", "Scans", "Findings", "Fixable"] + sev_cols + type_cols,
                     summary, args.no_csv_safe)

    # --- 3. Report -----------------------------------------------------------
    print("\n" + "=" * 64)
    print(f"  Scans queried      : {len(selected)}" + (f"  ({skipped} skipped, nothing to fetch)" if skipped else ""))
    print(f"  Findings retrieved : {total_raw}")
    print(f"  Findings exported  : {written}  ->  {args.output}")
    if by_sev:
        print("  By severity        : " + ", ".join(
            f"{SEVERITY_LABEL[r]} {by_sev[SEVERITY_LABEL[r]]}" for r in (5, 4, 3, 2, 1, 0) if by_sev[SEVERITY_LABEL[r]]))
        print("  By type            : " + ", ".join(f"{k} {v}" for k, v in by_type.most_common()))
        print("  Top assets         : " + ", ".join(
            f"{k} ({v['Findings']})" for k, v in sorted(per_asset.items(), key=lambda kv: -kv[1]["Findings"])[:5]))
        print("  Top rules / IDs    : " + ", ".join(f"{k} ({v})" for k, v in by_rule.most_common(5)))
        if by_lib:
            print("  Top libraries      : " + ", ".join(f"{k} ({v})" for k, v in by_lib.most_common(5)))
        print(f"  Fix available      : {fixable}")
    if args.summary_csv:
        print(f"  Per-asset rollup   : {args.summary_csv}")
    if mitigations:
        print(f"  Mitigation status  : Open {mit_status['Open']}, Mitigated {mit_status['Mitigated']}, "
              f"Expired {mit_status['Expired']}, {NOT_IN_EXPORT} {mit_status[NOT_IN_EXPORT]}")
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
    print("=" * 64)
    return 0 if (not tracker.failures or args.ignore_failures) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted. Output file was not modified.", file=sys.stderr)
        sys.exit(130)
