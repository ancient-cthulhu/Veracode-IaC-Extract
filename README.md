# Veracode IaC / Container / Secrets Findings Extract

Exports Veracode Container Security findings (container images, IaC, secrets) to CSV, JSON
or JSONL, with filters so each team gets only what it owns.

## Setup

```bash
pip install requests veracode-api-signing veracode-api-py
```

Uses your normal Veracode API credentials (`~/.veracode/credentials` or the
`VERACODE_API_KEY_ID` / `VERACODE_API_KEY_SECRET` environment variables). The account
needs the Reviewer role.

## Quick start

```bash
python veracode_iac_extract.py                    # everything -> veracode_iac_findings.csv
python veracode_iac_extract.py --compact          # same, short developer view
python veracode_iac_extract.py --list-scans       # what has been scanned, no findings
```

## Common requests

**One repo, or every repo in an org**
```bash
python veracode_iac_extract.py --asset "my-org/payments-api"
python veracode_iac_extract.py --asset "my-org/*"
python veracode_iac_extract.py --asset "my-org/payments-*,my-org/billing-*"
python veracode_iac_extract.py --asset "my-org/*" --exclude-asset "sandbox,archived"
```

**Only container images, or only IaC**
```bash
python veracode_iac_extract.py --scan-type container
python veracode_iac_extract.py --scan-type iac
python veracode_iac_extract.py --asset-type image --asset "registry.acme.com/*"
```

**What a dev team should fix first**
```bash
python veracode_iac_extract.py --severity high+ --fixable --compact
python veracode_iac_extract.py --scan-type container --cvss 9 --fixable
```

**Terraform / Kubernetes / Dockerfile misconfigurations**
```bash
python veracode_iac_extract.py --type misconfiguration --file "*.tf"
python veracode_iac_extract.py --type misconfiguration --file "Dockerfile,*.yaml,*.yml"
```

**Leaked secrets**
```bash
python veracode_iac_extract.py --type secret
python veracode_iac_extract.py --type secret --since 30d
```

**"Are we affected by this CVE / this library?"**
```bash
python veracode_iac_extract.py --id CVE-2024-3094
python veracode_iac_extract.py --library openssl
python veracode_iac_extract.py --library "log4j*" --severity critical,high
```

**Recent activity, or one person's scans**
```bash
python veracode_iac_extract.py --since 7d
python veracode_iac_extract.py --since 2026-09-01 --until 2026-09-30
python veracode_iac_extract.py --scanned-by ci_pipeline_user
```

**Management rollup**
```bash
python veracode_iac_extract.py --summary-csv per_asset.csv
```

**Other formats**
```bash
python veracode_iac_extract.py -o findings.json
python veracode_iac_extract.py -o findings.jsonl
```

## How matching works

One rule for every text filter:

| You type | It matches |
|---|---|
| `payments` | anything **containing** "payments" |
| `my-org/*` | wildcard on the whole value (`*` any text, `?` one character) |
| `a,b` | a **or** b |
| `re:^prod-` | regular expression |

Never case-sensitive. Using several flags together means **and**.

## Filters

### Which scans

| Flag | Example | Meaning |
|---|---|---|
| `--asset` | `"my-org/*"` | Asset name, asset ID or source |
| `--exclude-asset` | `sandbox` | Leave these out |
| `--scan-type` | `container` | `container` or `iac` |
| `--asset-type` | `image` | e.g. `image`, `repository`, `directory` |
| `--scanned-by` | `ci_user` | User that ran the scan |
| `--since` / `--until` | `30d`, `2026-09-01` | Scan date. Relative: `12h`, `30d`, `2w` |
| `--latest-only` | | Only the newest scan per asset |

### Which findings

| Flag | Example | Meaning |
|---|---|---|
| `--severity` | `high+` or `critical,high` | `+` means "and above" |
| `--type` | `secret` | `vulnerability`, `misconfiguration`, `secret` |
| `--id` | `CVE-2024-3094` | CVE or finding ID |
| `--library` | `openssl` | Vulnerable library (name or `name@version`) |
| `--file` | `"*.tf"` | File path |
| `--fixable` | | Only findings with a fix available |
| `--cvss` | `7` | CVSS of 7 or higher |
| `--search` | `"public bucket"` | Free text across title, description, fix, IDs, library and path |

Less common: `--rule`, `--category`, `--scan-id`, and `--where "COLUMN=text"` to filter on
any column in the output (`--where "Service=s3"`, `--where "Scan Policy Status!=passed"`).

## Columns

`--compact` gives the short developer view:

> Asset Name, Severity, CVSS, Finding Type, Finding ID, Title, Library, Fixed Versions,
> Location, Suggested Fix, Scan Date, Veracode Link

The default export has everything. Columns that are empty for the whole export are left out.

**What is it**
- `Severity`, `Severity Rank` (5 critical to 0 unknown), `CVSS`, `Exploitability Score`, `Impact Score`
- `Finding Type`, `Finding ID`, `CVE ID`, `Rule ID`, `Category`
- `Title`, `Description`, `References`, `Finding Policy Status`

**Where is it**
- `Asset Name`, `Asset ID`, `Asset Type`, `Scan Type`, `Scan Source`
- `Location` (`path:line`), `File Path`, `Start Line`, `End Line`, `All File Paths`, `Code Lines`
- `Provider`, `Service`, `Resource` (cloud misconfigurations)
- `Image Tags`, `Image Distro`, `Image Hash`, `Image Labels`, `Layer IDs` (container images)

**How to fix it**
- `Library` (`name@version`), `Library Name`, `Library Version`
- `Fix Available` (true / false), `Fix State`, `Fixed Versions`, `Suggested Fix`

**About the scan**
- `Scan ID`, `Scan Date`, `Scan Age Days`, `Scan Duration`, `Scan Status`, `Scanned By`
- `Policy Name`, `Policy ID`, `Scan Policy Status`
- `Scan Total Findings`, `Scan Critical`, `Scan High`, `Scan Medium`, `Scan Low`, `Scan Negligible`, `Scan Unknown`
- `Veracode Link` (opens the scan in the Platform)

**Tracking**
- `Finding Key`: stable ID for a finding. Use it to diff two exports.
- `Is Latest Scan For Asset`, `First Seen`, `Last Seen`, `Seen In Scans`

Pick your own with `--columns "Asset Name,Severity,Title,Location"`. Add
`--match-apps` to include Application Name, Business Unit and Teams where the asset name
matches an application profile.

## API load

- One request lists every scan. Asset, scan type and date filters are applied to that list,
  so only matching scans are queried for findings.
- Scans whose severity totals show nothing relevant are skipped without a request. With
  `--severity critical`, a scan with zero criticals is never fetched.
- Requests are capped at 2 per second across 4 workers. On a 429 every worker pauses and
  the server's `Retry-After` is honoured.

Tune with `--rps` and `--max-workers`. Use `--ca-cert corp.pem` behind SSL inspection.

Finding-level filters (`--type`, `--id`, `--library`, `--file`, ...) are applied after
download, because this API has no documented filter parameters.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Complete |
| 1 | Incomplete, some requests failed (listed in the summary) |
| 2 | Bad arguments |
| 130 | Interrupted |

The output file is only replaced when a run finishes, so a failed run never leaves a
half-written file.
