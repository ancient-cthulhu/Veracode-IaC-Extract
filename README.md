# Veracode IaC / Container / Secrets Findings Extract

English | [Español](docs/es/README.md)

Exports Veracode Container Security findings (container images, IaC, secrets) to CSV, JSON, JSONL or Excel,
one row per finding, with filters.

To track findings over time and approve mitigations, see [Veracode-IaC-Mitigation-Tracker](https://github.com/ancient-cthulhu/Veracode-IaC-Mitigation-Tracker).

## Requirements

- Python 3.9 or later
- `pip install -r requirements.txt` (requests, veracode-api-signing, veracode-api-py; openpyxl for Excel `.xlsx` output)
- Veracode API credentials in `~/.veracode/credentials`, or in the environment variables `VERACODE_API_ID` and
  `VERACODE_API_KEY` (`VERACODE_API_KEY_ID` / `VERACODE_API_KEY_SECRET` are also accepted)
- Account with the Reviewer role that can see Container and IaC scans

## Quick Start

```bash
python veracode_iac_extract.py                # latest scan per asset -> veracode_iac_findings.csv
python veracode_iac_extract.py --compact      # 14-column developer view
python veracode_iac_extract.py --list-scans   # scan inventory only, no findings
python veracode_iac_extract.py --all-scans    # every scan in history, one row per finding per scan
```

Each run ends with a summary: scans queried, findings exported, counts by severity and type, and any
failed requests.

## Usage

```bash
# Repos and orgs
python veracode_iac_extract.py --asset "my-org/payments-api"
python veracode_iac_extract.py --asset "my-org/*" --exclude-asset "sandbox,archived"

# Scan and asset type
python veracode_iac_extract.py --scan-type container
python veracode_iac_extract.py --asset-type image --asset "registry.acme.com/*"

# What to fix first
python veracode_iac_extract.py --severity high+ --fixable --compact

# Finding types
python veracode_iac_extract.py --type misconfiguration --file "*.tf"
python veracode_iac_extract.py --type secret --since 30d

# Are we affected?
python veracode_iac_extract.py --id CVE-2024-3094
python veracode_iac_extract.py --library "log4j*" --severity critical,high

# Policy, activity, reporting
python veracode_iac_extract.py --policy failed --list-scans -o failed_scans.csv
python veracode_iac_extract.py --all-scans --since 2026-09-01 --until 2026-09-30
python veracode_iac_extract.py --scanned-by ci_pipeline_user
python veracode_iac_extract.py --summary-csv per_asset.csv

# Any output column
python veracode_iac_extract.py --where "Scan Policy Status!=passed" --where "Provider=AWS"
```

### Matching rules (all text filters)

| Value | Matches |
| --- | --- |
| `payments` | Contains "payments" |
| `my-org/*` | Wildcard on the whole value (`*` any text, `?` one character) |
| `a,b` | a or b |
| `re:^prod-` | Regular expression |

Never case-sensitive. Different flags combine with AND.

### Scan filters (applied before findings are fetched)

| Flag | Values |
| --- | --- |
| `--asset`, `--exclude-asset` | Asset name, asset ID or source |
| `--scan-type` | `container`, `iac` |
| `--asset-type` | `image`, `repo`, `archive`, `directory` |
| `--policy` | `failed`, `passed`, `not-assessed` |
| `--scanned-by` | User that ran the scan |
| `--since`, `--until` | `YYYY-MM-DD`, `YYYYMMDD`, ISO datetime, or relative: `12h`, `30d`, `2w`. A bare `--until` date includes that day |
| `--all-scans` | Every scan in history instead of only the latest per asset (the default) |
| `--latest-only` | Only the latest scan per asset. The default; kept for compatibility |
| `--track-history` | Fetch every scan to fill First Seen, Last Seen, Seen In Scans; output only the latest scan per asset |
| `--scan-id` | Specific scan, latest or not |

### Finding filters (applied after download)

| Flag | Values |
| --- | --- |
| `--severity` | `high+` (that level and above) or a list: `critical,high` |
| `--type` (`--finding-type`) | `vulnerability`, `misconfiguration`, `secret` |
| `--id` (`--cve`, `--finding-id`) | CVE or finding ID. A single plain ID matches exactly (`CVE-2024-3094` not `CVE-2024-30940`); wildcards, `re:` and comma lists follow the matching rules |
| `--library` | Name or `name@version` |
| `--file` | File path |
| `--rule`, `--category` | Rule ID, finding category |
| `--fixable` | Only findings with a fix available |
| `--cvss N` (`--min-cvss`) | CVSS of N or higher |
| `--search` (`--grep`) | Free text or regex across title, description, fix, IDs, library, category, resource, file path |
| `--where "COL=text"` | Any output column. `!=` excludes. Repeatable |

### Output

| Flag | Effect |
| --- | --- |
| `-o FILE` | Output file (default `veracode_iac_findings.csv`). Extension sets the format: `.csv`, `.json`, `.jsonl`, `.xlsx` |
| `--format` | Force `csv`, `json`, `jsonl` or `xlsx` regardless of extension |
| `--compact` | Asset Name, Scan Type (`container`, `iac`), Asset Type (`image`, `repo`, `archive`, `directory`), Severity, CVSS, Finding Type, Finding ID, Title, Library, Fixed Versions, Location, Suggested Fix, Scan Date, Veracode Link |
| `--columns "A,B,C"` | Choose and order columns. Unknown names stop the run before any request (exit 2) |
| `--summary-csv FILE` | Per-asset rollup (Asset Name, Asset ID): scans, findings, fixable, counts by severity and type |
| `--list-scans` | Scan inventory only |
| `--match-apps` | Add Application Name, Application GUID, Business Unit, Teams where the asset name matches an application profile |
| `--keep-empty-columns` | Keep columns that are empty for the whole export (dropped by default) |
| `--no-extra-columns` | Drop the `Scan: <field>` / `Finding: <field>` passthrough columns |
| `--no-csv-safe` | Do not prefix cells starting with `=`, `+`, `-`, `@` with `'` |

### Columns (full export)

| Group | Columns |
| --- | --- |
| What | Severity, Severity Rank (5 critical to 0 unknown), CVSS, Exploitability Score, Impact Score, Finding Type, Finding ID, CVE ID, Rule ID, Category, Title, Description, References, Finding Policy Status |
| Where | Asset Name, Asset ID, Asset Type, Scan Type, Scan Source, Location (`path:line` or `path:start-end`), File Path, Start Line, End Line, All File Paths, Code Lines, Provider, Service, Resource, Image Tags, Image Distro, Image Hash, Image Labels, Layer IDs |
| Fix | Library (`name@version`), Library Name, Library Version, Fix Available (blank when no library), Fix State, Fixed Versions, Suggested Fix |
| Scan | Scan ID, Scan Date, Scan Age Days, Scan Duration, Scan Status, Scanned By, Policy Name, Policy ID, Scan Policy Status, Scan Total Findings, Scan Critical/High/Medium/Low/Negligible/Unknown, Veracode Link |
| History | Finding Key, Is Latest Scan For Asset, First Seen, Last Seen, Seen In Scans |

API fields not listed appear as `Scan: <field>` or `Finding: <field>` columns.

Excel output (`.xlsx`) has a frozen, filterable header, severity colours, clickable Veracode Link, and prints
one page wide. Cells are always text, never formulas. `--list-scans` writes a `Scans` sheet. An export over
Excel's 1,048,575-row limit stops with exit 2 before writing; use CSV for it.

## Configuration

| Setting | Default | Purpose |
| --- | --- | --- |
| `--base-url` / `VERACODE_IAC_BASE_URL` | From the credentials' region (US commercial or EU) | Container scan query API. Required for FedRAMP |
| `--link-base` / `VERACODE_IAC_LINK_BASE` | From the credentials' region | Base of the Veracode Link column |
| `--api-base` / `VERACODE_API_BASE` | From the credentials' region | REST API used by `--match-apps` |
| `--ca-cert FILE` | system CAs | Corporate CA bundle (SSL inspection) |
| `--rps` | 2 | Max requests per second, shared by all workers |
| `--max-workers` | 4 | Concurrent requests |
| `--max-attempts` | 6 | Tries per request |
| `--timeout` | 90 | Seconds per request |
| `--no-server-search` | off | Filter `--asset` locally instead of with the API search |
| `--fetch-empty-scans` | off | Also query scans whose severity totals show no matching findings |
| `--ignore-failures` | off | Exit 0 and replace the output even if some requests failed |

## Important Notes

- `--asset` is filtered server side; scan filters run before any findings are requested. Finding filters run after download.
- Scans whose severity totals cannot match are skipped: with `--severity critical`, scans with zero criticals are never fetched. Use `--fetch-empty-scans` to override.
- On HTTP 429 every worker pauses and honours `Retry-After` (capped at 90 seconds).
- `Finding Key` (`mk-` and 12 hex characters) ignores line numbers and image tags (`app:1.2` and `app:1.3` share keys). It changes when the file is moved or renamed, the resource is renamed, or a secret's value changes.
- **Only the latest scan per asset is exported by default.** `--since` / `--until` then keep the latest scans in that window; add `--all-scans` for every scan in a period. `--latest-only` is still accepted and does nothing extra.
- First Seen / Last Seen / Seen In Scans only cover the scans fetched in that run.
- The output file is replaced only when the run finishes. If some requests failed, the previous file is kept and the partial export goes to `<name>.partial.<ext>` (exit 1); `--ignore-failures` writes the output anyway.
- If the output file is open in another program (Excel), the run retries briefly, then writes `<name>.<YYYYmmdd-HHMMSS>.<ext>` next to it and exits 1.

## Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Complete |
| 1 | Incomplete: some requests failed (listed in the summary), or the output file was locked |
| 2 | Bad arguments |
| 130 | Interrupted |

## Library API

Other scripts can import the file instead of running it. The supported names are the ones in `__all__`;
`__version__` is the release.

```python
import veracode_iac_extract as vx

scans, rows, failures = vx.collect_latest(asset="my-org/*", scan_type="iac")
```

```python
collect_latest(base_url=None, link_base=None, *, asset=None, exclude_asset=None, scan_type=None,
               asset_type=None, scanned_by=None, policy=None, since=None, until=None, workers=4, rps=2.0,
               max_attempts=6, timeout=90, ca_cert=None, minter=None, now=None, log=print)
```

It reads every finding of the latest scan of each asset that passes the scan filters. The filter arguments take
the same values as the flags (a pattern or a list of patterns). No scan is skipped and nothing is written.

| Returned | Content |
| --- | --- |
| `scans` | One row per scan in the tenant, with the scan columns of the export. `"_read": True` on the scans whose findings were read in full |
| `rows` | One row per finding of those scans, with the export columns (Code Lines included) |
| `failures` | `(scope, detail)` for every failed request. Not empty means the data is incomplete |

It raises `ExtractError`: `exit_code` 2 for bad input, 1 when the token or the scan list cannot be read.
`base_url` and `link_base` come from the credentials' region unless given (required for FedRAMP).

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Authentication error at start | Check credentials, the Reviewer role, and access to Container/IaC scans |
| TLS or certificate errors | `--ca-cert corp.pem` |
| FedRAMP tenant | `--base-url` (or `VERACODE_IAC_BASE_URL`), `--link-base`, and `--api-base` with `--match-apps` |
| A filter returns nothing | Retry with `--no-server-search`, then compare the value with `--list-scans` output |
| `refers to a column that never appeared` | The `--where` column does not exist in this export; check the column names above |

## Related Documentation

- [Veracode-IaC-Mitigation-Tracker](https://github.com/ancient-cthulhu/Veracode-IaC-Mitigation-Tracker): findings tracker with mitigations, built on this script
