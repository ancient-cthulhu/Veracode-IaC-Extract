# Veracode IaC / Container / Secrets Findings Extract

English | [Español](README.es.md)

Exports Veracode Container Security findings (container images, IaC, secrets) to CSV, JSON, JSONL or Excel,
one row per finding, with filters. It also runs a findings tracker in a GitHub repository, with mitigations.

## Findings tracker (recommended)

A private repository that keeps the state of every finding over time, like Static Analysis findings on the
Veracode Platform, and records approved mitigations. It runs in GitHub Actions; nothing to install.

### Setup

1. **Use this template > Create a new repository**, and make it private.
2. Settings > Secrets and variables > Actions: add the secrets `VERACODE_API_KEY_ID` and
   `VERACODE_API_KEY_SECRET`.
3. In the same place, add the variable `MITIGATION_APPROVERS`: the GitHub logins that can approve mitigations,
   comma or space separated. Optional: the variable `VERACODE_TRACK_ARGS` with scan filters, for example
   `--asset my-org/*`.

The first run is the next day at 05:23 UTC, or now from Actions > Veracode findings tracker > Run workflow.

### What runs every day

[veracode-tracker.yml](.github/workflows/veracode-tracker.yml) reads the latest scan of every asset and commits
`Daily findings: +N new, -M fixed` with:

| File | Content |
| --- | --- |
| `FINDINGS.md` | Dashboard: totals, new findings, expiring mitigations, open findings, fixed in the last 30 days. Each finding has a Veracode link and a Mitigate link |
| `tracking/findings.csv` | Every open finding: status, severity, location, First Seen, Days Open, mitigation |
| `tracking/fixed.csv` | Every fixed finding, with Fixed On and Days Open |
| `mitigations.yml` | Approved mitigations (see [MITIGATIONS.md](MITIGATIONS.md)) |

The run also attaches a full Excel report (artifact `veracode-findings`, kept 30 days; no code lines). If any
request fails, nothing changes and an issue labelled `tracker-failure` is opened; it closes after the next
successful run. If branch protection rejects the push, the update goes to the branch `tracking`.

### Statuses

| Status | Meaning |
| --- | --- |
| New | First seen in this run. Shown as Open from the next day |
| Open | Still present in the latest scan |
| Reopened | Was fixed and came back. Keeps its original First Seen |
| Asset Missing | The asset is no longer in Veracode. After 30 days the finding moves to `fixed.csv` as `asset-removed` |
| Fixed | Missing from a newer scan of its asset. Removed from `findings.csv` and logged in `fixed.csv` |

A finding is marked fixed only when its asset was scanned again. Findings of assets that were filtered out or
not rescanned stay as they are.

### Mitigation requests

1. In `FINDINGS.md`, click **Mitigate** on the finding. GitHub opens a pre-filled issue: pick the type, write the
   reason (and the expiry date for `accept-risk`), submit.
2. An approver adds the label `approved`.
3. The workflow records the mitigation in `mitigations.yml` (`M-0001`, `M-0002`, ...), updates the dashboard,
   comments and closes the issue. If the request is invalid or the person is not an approver, it comments why
   and removes the label.

Mitigation Status: `Mitigated`, `Expiring` (30 days or less left), `Expired` (counts as open again), or empty.
Details, editing `mitigations.yml` directly, and revoking: [MITIGATIONS.md](MITIGATIONS.md).

### Tracker flags

| Flag | Effect |
| --- | --- |
| `--track DIR` | Update `DIR/findings.csv`, `DIR/fixed.csv` and the dashboard from the latest scan of every asset. Scan filters apply; finding filters are refused. Any failed request changes nothing (exit 1) |
| `--offline` | With `--track`: refresh Days Open, the Mitigation columns and the dashboard without calling Veracode |
| `--mitigations FILE` | The rules file, `mitigations.yml` |
| `--dashboard FILE` | Dashboard path (default `FINDINGS.md` next to `DIR`) |
| `--repo-url URL` | `https://github.com/<org>/<repo>` for the Mitigate links. In GitHub Actions it is detected |
| `--migrate OLD_CSV` | Copy the mitigations of an old tracking CSV into `mitigations.yml`. Automatic on the first run when `veracode-findings.csv` sits next to `DIR` |
| `-o FILE` | With `--track`: also write every current finding with all columns, Status and Mitigation (no Code Lines) |

Run it locally: `python veracode_iac_extract.py --track tracking --mitigations mitigations.yml`.

## Requirements

- Python 3.9 or later (CI uses 3.12)
- `pip install -r requirements.txt` (requests, veracode-api-signing, veracode-api-py, PyYAML for `mitigations.yml`; openpyxl for Excel `.xlsx` output)
- Veracode API credentials in `~/.veracode/credentials`, or `VERACODE_API_KEY_ID` and `VERACODE_API_KEY_SECRET`
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
| `--mitigations FILE` | Add the Mitigation columns (Status, Type, Reason, Approved By, Expires, Ref, ID) from `mitigations.yml` |
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
| Tracking | Finding Key, Is Latest Scan For Asset, First Seen, Last Seen, Seen In Scans |

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
| 2 | Bad arguments, invalid `mitigations.yml`, or invalid mitigation request |
| 3 | `--approve-issue`: the person who added the label is not in `MITIGATION_APPROVERS` |
| 130 | Interrupted |

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Authentication error at start | Check credentials, the Reviewer role, and access to Container/IaC scans |
| TLS or certificate errors | `--ca-cert corp.pem` |
| FedRAMP tenant | `--base-url` (or `VERACODE_IAC_BASE_URL`), `--link-base`, and `--api-base` with `--match-apps` |
| A filter returns nothing | Retry with `--no-server-search`, then compare the value with `--list-scans` output |
| `refers to a column that never appeared` | The `--where` column does not exist in this export; check the column names above |

## Related Documentation

- [MITIGATIONS.md](MITIGATIONS.md): requesting, approving, editing and revoking mitigations; `mitigations.yml` fields
