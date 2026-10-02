# Veracode IaC / Container / Secrets Findings Extract

Export Veracode Container Security findings (container images, IaC, secrets) to CSV, JSON
or JSONL, with filters.

```bash
python veracode_iac_extract.py --asset "my-org/*" --severity high+ --compact
```

The tool outputs:

- One row per finding, with file and line, library and fix version, and a link back to the Platform
- Filters for asset, scan type, severity, finding type, CVE, library, file and more
- Asset filtering done server side, so large tenants are not downloaded in full
- A run that either completes or tells you exactly what is missing

## Install

```bash
pip install requests veracode-api-signing veracode-api-py
```

| Requirement | Detail |
| --- | --- |
| Credentials | Standard Veracode API credentials in `~/.veracode/credentials`, or `VERACODE_API_KEY_ID` and `VERACODE_API_KEY_SECRET` |
| Role | Reviewer |

## Quick start

```bash
python veracode_iac_extract.py                # everything -> veracode_iac_findings.csv
python veracode_iac_extract.py --compact      # same, short developer view
python veracode_iac_extract.py --list-scans   # what has been scanned, no findings
```

## Recipes

### By repo or org

```bash
# One repo
python veracode_iac_extract.py --asset "my-org/payments-api"

# Every repo in an org
python veracode_iac_extract.py --asset "my-org/*"

# Several patterns
python veracode_iac_extract.py --asset "my-org/payments-*,my-org/billing-*"

# An org, minus sandboxes and archived repos
python veracode_iac_extract.py --asset "my-org/*" --exclude-asset "sandbox,archived"
```

### By scan or asset type

```bash
# Container images only
python veracode_iac_extract.py --scan-type container

# IaC only
python veracode_iac_extract.py --scan-type iac

# Images from one registry
python veracode_iac_extract.py --asset-type image --asset "registry.acme.com/*"

# Repos and directories
python veracode_iac_extract.py --asset-type repo,directory
```

### What to fix first

```bash
# High and critical, with a fix available
python veracode_iac_extract.py --severity high+ --fixable --compact

# Container vulnerabilities at CVSS 9 or above that can be patched
python veracode_iac_extract.py --scan-type container --cvss 9 --fixable
```

### By finding type

```bash
# Terraform misconfigurations
python veracode_iac_extract.py --type misconfiguration --file "*.tf"

# Dockerfile and Kubernetes misconfigurations
python veracode_iac_extract.py --type misconfiguration --file "Dockerfile,*.yaml,*.yml"

# Leaked secrets
python veracode_iac_extract.py --type secret

# Secrets found in the last 30 days of scans
python veracode_iac_extract.py --type secret --since 30d
```

### "Are we affected?"

```bash
# A specific CVE
python veracode_iac_extract.py --id CVE-2024-3094

# A library
python veracode_iac_extract.py --library openssl

# A library family, serious findings only
python veracode_iac_extract.py --library "log4j*" --severity critical,high
```

### Policy, activity and reporting

```bash
# Findings from scans that failed policy
python veracode_iac_extract.py --policy failed

# Just the list of failed scans
python veracode_iac_extract.py --policy failed --list-scans -o failed_scans.csv

# Last 7 days
python veracode_iac_extract.py --since 7d

# A date range
python veracode_iac_extract.py --since 2026-09-01 --until 2026-09-30

# One user's scans, for example the CI account
python veracode_iac_extract.py --scanned-by ci_pipeline_user

# Per-asset rollup for management
python veracode_iac_extract.py --summary-csv per_asset.csv
```

## How matching works

One rule for every text filter.

| You type | It matches |
| --- | --- |
| `payments` | Anything **containing** "payments" |
| `my-org/*` | Wildcard on the whole value. `*` is any text, `?` is one character |
| `a,b` | a **or** b |
| `re:^prod-` | Regular expression |

Matching is never case-sensitive. Using several flags together means **and**.

## Filter reference

### Which scans

| Flag | Example | Meaning |
| --- | --- | --- |
| `--asset` | `"my-org/*"` | Asset name, asset ID or source |
| `--exclude-asset` | `sandbox` | Leave these out |
| `--scan-type` | `container` | `container`, `iac` |
| `--asset-type` | `image` | `image`, `repo`, `archive`, `directory` |
| `--policy` | `failed` | `failed`, `passed`, `not-assessed` |
| `--scanned-by` | `ci_user` | User that ran the scan |
| `--since`, `--until` | `30d`, `2026-09-01` | Scan date. Relative forms: `12h`, `30d`, `2w` |
| `--latest-only` | | Only the newest scan per asset |
| `--scan-id` | `2357847` | A specific scan |

### Which findings

| Flag | Example | Meaning |
| --- | --- | --- |
| `--severity` | `high+`, `critical,high` | `+` means "and above" |
| `--type` | `secret` | `vulnerability`, `misconfiguration`, `secret` |
| `--id` | `CVE-2024-3094` | CVE or finding ID |
| `--library` | `openssl` | Vulnerable library, by name or `name@version` |
| `--file` | `"*.tf"` | File path |
| `--fixable` | | Only findings with a fix available |
| `--cvss` | `7` | CVSS of 7 or higher |
| `--search` | `"public bucket"` | Free text across title, description, fix, IDs, library and path |
| `--rule` | `"CIS-DI-*"` | Rule ID |
| `--category` | `Passwords` | Finding category |

### Anything else

`--where "COLUMN=text"` filters on any column in the output. Use `!=` to exclude. Repeat it to
combine.

```bash
python veracode_iac_extract.py --where "Service=s3"
python veracode_iac_extract.py --where "Scan Policy Status!=passed" --where "Provider=AWS"
```

## Output

| Flag | Meaning |
| --- | --- |
| `-o FILE` | Output file. The extension picks the format: `.csv` (default), `.json`, `.jsonl` |
| `--compact` | Short developer view, 12 columns |
| `--columns "A,B,C"` | Choose and order columns yourself |
| `--summary-csv FILE` | Per-asset rollup: scans, findings, fixable, counts by severity and type |
| `--list-scans` | Export the scan inventory only, no findings |
| `--match-apps` | Add Application Name, Business Unit and Teams where the asset name matches an application profile |
| `--track-history` | Fill First Seen, Last Seen and Seen In Scans from every scan, but output only the latest scan per asset |

Columns that are empty for the whole export are left out. `--keep-empty-columns` keeps them.

CSV cells that begin with `=`, `+`, `-` or `@` are prefixed with `'` so a spreadsheet does not
run them as formulas. `--no-csv-safe` turns this off.

## Columns

### Compact view (`--compact`)

| Column | What it tells you |
| --- | --- |
| Asset Name | Which repo or image |
| Severity | Critical, High, Medium, Low, Negligible, Unknown |
| CVSS | Score, where the finding has one |
| Finding Type | Vulnerability, Misconfiguration or Secret |
| Finding ID | CVE or rule identifier |
| Title | Short name of the finding |
| Library | `name@version` of the vulnerable library |
| Fixed Versions | Versions that fix it |
| Location | `path:line` |
| Suggested Fix | Remediation text |
| Scan Date | When the scan ran |
| Veracode Link | Opens the scan in the Platform |

### Full export

#### What is it

| Column | Notes |
| --- | --- |
| Severity | Critical to Unknown |
| Severity Rank | 5 (critical) to 0 (unknown), for sorting |
| CVSS, Exploitability Score, Impact Score | |
| Finding Type | Vulnerability, Misconfiguration, Secret |
| Finding ID, CVE ID, Rule ID, Category | |
| Title, Description, References | |
| Finding Policy Status | |

#### Where is it

| Column | Notes |
| --- | --- |
| Asset Name, Asset ID, Asset Type | |
| Scan Type, Scan Source | |
| Location | `path:line` or `path:start-end` |
| File Path, Start Line, End Line | |
| All File Paths | Every path, when a finding has more than one |
| Code Lines | |
| Provider, Service, Resource | Cloud misconfigurations |
| Image Tags, Image Distro, Image Hash, Image Labels, Layer IDs | Container images |

#### How to fix it

| Column | Notes |
| --- | --- |
| Library | `name@version` |
| Library Name, Library Version | |
| Fix Available | `true` or `false`. Blank for findings with no library |
| Fix State, Fixed Versions | |
| Suggested Fix | |

#### About the scan

| Column | Notes |
| --- | --- |
| Scan ID, Scan Date, Scan Age Days | |
| Scan Duration, Scan Status, Scanned By | |
| Policy Name, Policy ID, Scan Policy Status | |
| Scan Total Findings | |
| Scan Critical, High, Medium, Low, Negligible, Unknown | Totals for the whole scan |
| Veracode Link | Opens the scan in the Platform |

#### Tracking

| Column | Notes |
| --- | --- |
| Finding Key | Stable ID for a finding. Use it to diff two exports |
| Is Latest Scan For Asset | |
| First Seen, Last Seen, Seen In Scans | Computed across the scans fetched in this run |

Any field the API returns that is not listed above still appears, as a `Scan: <field>` or
`Finding: <field>` column. `--no-extra-columns` drops those.

## Performance and API load

| What | How |
| --- | --- |
| Asset filter | `--asset` is filtered **server side**. `--asset "my-org/*"` only downloads scans matching `my-org/`, not the whole tenant |
| Scan filters | Scan type, asset type, date and policy are applied to the scan list before any findings are requested |
| Empty scans | Scans whose severity totals show nothing relevant are skipped. With `--severity critical`, a scan with zero criticals is never fetched |
| Rate | 2 requests per second across 4 workers |
| Throttling | On a 429 every worker pauses and the server's `Retry-After` is honoured |
| Finding filters | `--type`, `--id`, `--library`, `--file` and the rest are applied after download |

| Flag | Default | Meaning |
| --- | --- | --- |
| `--rps` | 2 | Maximum requests per second |
| `--max-workers` | 4 | Concurrent requests |
| `--max-attempts` | 6 | Retries per request |
| `--timeout` | 90 | Seconds per request |
| `--no-server-search` | off | Download the full scan list and filter `--asset` locally |
| `--fetch-empty-scans` | off | Also query scans whose totals show no matching findings |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Complete |
| 1 | Incomplete. Some requests failed and are listed in the summary |
| 2 | Bad arguments |
| 130 | Interrupted |

The output file is only replaced when a run finishes, so a failed run never leaves a
half-written file. `--ignore-failures` forces exit 0.

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| Authentication error at start | Check the API credentials, and that the account has the Reviewer role and can see Container and IaC scans in the Platform |
| TLS or certificate errors | Behind SSL inspection, pass your corporate bundle: `--ca-cert corp.pem` |
| Tenant is not in the US commercial region | Point the script at your region with `--base-url` or `VERACODE_IAC_BASE_URL` |
| A filter returns nothing | Run the same command with `--no-server-search` to rule out the server-side search, then check the value against `--list-scans` |
| "refers to a column that never appeared" | The `--where` column name does not exist in this export. Column names are listed under [Columns](#columns) |
