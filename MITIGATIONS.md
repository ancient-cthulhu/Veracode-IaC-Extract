# Mitigations

English | [Español](MITIGATIONS.es.md)

Mitigations for Container, IaC and Secrets findings are not yet available on the Veracode Platform. With
`--mitigations`, the export itself tracks them: the repo keeps `veracode-findings.csv` (GitHub shows it as a
table), people edit it offline in a locked Excel copy, and every run carries the mitigations onto the fresh
findings.

> **Never edit `Mitigation Key` or `Mitigation Status`.** The script sets both. The key links each row to its
> finding on the next run; if it changes, the mitigation is lost. In the Excel copy both are locked.

## Requirements

- Everything in [README.md](README.md#requirements)
- `pip install openpyxl` for the Excel copy

## Quick Start

1. Get the latest findings into the tracking CSV (created on the first run):

   ```bash
   python veracode_iac_extract.py --compact --mitigations veracode-findings.csv
   ```

   Or download the `veracode-findings` artifact of the latest [GitHub Action](#github-action) run (CSV and Excel).

2. Make the Excel copy, offline:

   ```bash
   python veracode_iac_extract.py --convert veracode-findings.csv veracode-findings.xlsx
   ```

3. Open `veracode-findings.xlsx`. On each row to mitigate, fill in the yellow cells; nothing else can be edited:

   | Mitigation Type | Mitigation Reason | Mitigation Approved By | Mitigation Expires | Mitigation Notes |
   | --- | --- | --- | --- | --- |
   | accept-risk (dropdown) | Bucket serves the public status page through CloudFront | lead@acme.com | 2027-11-09 | CHG-4411 |

4. Turn it back into the CSV. This validates every mitigation and refreshes `Mitigation Status`:

   ```bash
   python veracode_iac_extract.py --convert veracode-findings.xlsx veracode-findings.csv
   # Wrote 4 rows (1 mitigated finding(s)) to veracode-findings.csv
   ```

5. Commit `veracode-findings.csv` in a pull request. The pull request gets a comment like this:

   | Change | Finding | Asset | Type | Reason | Approved By | Expires | Notes |
   | --- | --- | --- | --- | --- | --- | --- | --- |
   | Added | AVD-AWS-0086 | acme/payments-infra | by-design | Public status page via CloudFront | lead@acme.com | | CHG-4411 |
   | Changed | AVD-AWS-0089 | acme/sandbox-dev | accept-risk | Sandbox rebuilt nightly | lead@acme.com | ~~2027-02-01~~ 2027-05-01 | |
   | Removed | aws-access-token | acme/payments-infra | false-positive | AWS example key in a test | lead@acme.com | | |

Example: [examples/veracode-findings.example.csv](examples/veracode-findings.example.csv) (one mitigation,
every column filled).

## The Excel copy

| Feature | Effect |
| --- | --- |
| Protected sheet | Only the yellow Mitigation cells can be edited. Key, Status and finding data are locked. Filtering still works |
| Mitigation Type | Dropdown with the five types; other values are rejected |
| Mitigation Expires | Accepts dates only; shown as `YYYY-MM-DD` |
| Header notes and cell prompts | Explain each Mitigation column when selected |
| How to use sheet | Steps, an example row, types and statuses |
| Formatting | Status and severity colours, frozen header, filters, clickable Veracode Link, prints one page wide |

The protection has no password. It prevents mistakes, not deliberate changes (Review > Unprotect Sheet).
Do not commit the `.xlsx`; it is in `.gitignore`.

## Usage

```bash
# Refresh the tracking CSV from Veracode (reads it, then writes it back)
python veracode_iac_extract.py --compact --mitigations veracode-findings.csv

# CSV -> Excel and back, offline
python veracode_iac_extract.py --convert veracode-findings.csv veracode-findings.xlsx
python veracode_iac_extract.py --convert veracode-findings.xlsx veracode-findings.csv

# Validate and list every mitigation, offline
python veracode_iac_extract.py --check-mitigations veracode-findings.csv

# What changed compared with another version (Markdown, as in the pull request comment)
python veracode_iac_extract.py --check-mitigations veracode-findings.csv --against old.csv

# Only what still needs fixing, to a separate file (the tracking file is not changed)
python veracode_iac_extract.py --compact --mitigations veracode-findings.csv \
  --where "Mitigation Status!=Mitigated" -o to-fix.xlsx
```

## Configuration

### Flags

| Flag | Effect |
| --- | --- |
| `--mitigations FILE` | Read mitigations from `FILE` (`.csv` or `.xlsx`), then write the fresh export back to it. `-o` writes elsewhere instead |
| `--convert IN OUT` | Convert between `.csv` and `.xlsx`, offline. Validates mitigations and refreshes Mitigation Status; writes nothing if invalid |
| `--check-mitigations FILE` | Validate and list every mitigation, offline: exit 0 valid, 2 invalid |
| `--against BASE` | With `--check-mitigations`: Markdown table of mitigations added, changed or removed compared with `BASE` |

### Columns added

| Column | Filled by | Notes |
| --- | --- | --- |
| Mitigation Status | Script | First column. Do not edit |
| Mitigation Type | You | One of the types below |
| Mitigation Reason | You | Required |
| Mitigation Approved By | You | Required |
| Mitigation Expires | You | `YYYY-MM-DD`. Required for `accept-risk` |
| Mitigation Notes | You | Optional (ticket, change number) |
| Mitigation Key | Script | Last column. Do not edit |

### Types (same as Static Analysis)

| Type | Use when | Static Analysis name |
| --- | --- | --- |
| `false-positive` | Finding is not real | Potential False Positive |
| `by-design` | Setting is deliberate and approved | Mitigate by Design |
| `network-environment` | A network control blocks it (WAF, security group, private network) | Mitigate by Network Environment |
| `os-environment` | OS or runtime blocks it (hardened host, read-only file system, no shell) | Mitigate by OS Environment |
| `accept-risk` | Business accepts the risk; needs Mitigation Expires | Accept the Risk |

### Statuses

| Mitigation Status | Meaning |
| --- | --- |
| Open | Not mitigated |
| Mitigated | Mitigated and not expired |
| Expired | Mitigation Expires has passed; counts as open |
| Not in export | Mitigated, but the finding was not in the last export (fixed, or filtered out). Kept so the mitigation returns if the finding does. Delete the row when no longer needed |

## GitHub Action

[.github/workflows/veracode-iac-findings.yml](.github/workflows/veracode-iac-findings.yml):

| Trigger | Job | Result |
| --- | --- | --- |
| Daily, 04:23 UTC, or Actions > Veracode IaC findings > Run workflow | `export` | Refreshes `veracode-findings.csv` from the repo's copy and attaches it, plus the Excel copy, as artifact `veracode-findings` |
| Pull request changing `veracode-findings.csv` | `check-mitigations` | Comments the table of changes on the pull request (updated on each push), adds it to the job summary, and fails if any mitigation is invalid |

The Action does not commit. Commit the CSV yourself through a pull request.

Setup:

1. Add repository secrets `VERACODE_API_KEY_ID` and `VERACODE_API_KEY_SECRET`.
2. Optional: require the `check-mitigations` check before merging.
3. Optional: repository variable `VERACODE_EXTRACT_ARGS` with filters added to every run, for example `--asset my-org/*`.

Pull requests from forks get a read-only token, so they get the job summary but no comment.

## Important Notes

- **The tool does not enforce approval.** `Mitigation Approved By` is free text; anyone who can change the CSV can mitigate anything. Decide how approvals are controlled, for example a CODEOWNERS entry for `veracode-findings.csv` plus branch protection requiring that review.
- **Use `--compact` for the file you commit.** The full export includes `Code Lines`, which can contain the secret itself.
- **Mitigations do not change the Veracode Platform**, including policy results.
- `Mitigation Key` ignores line numbers and image tags (`app:1.2` and `app:1.3` share keys). It changes when the file is moved or renamed, the resource is renamed, or a secret's value changes: the old row becomes `Not in export` and the finding appears as a new `Open` row. Copy the Mitigation columns to the new row.
- Rows with the same key (for example the same image under two tags) share one mitigation; fill in any one of them.
- Use the same filters on every run. Open findings excluded by a filter are dropped from the file; mitigated ones are kept as `Not in export`.
- Invalid Mitigation columns stop `--mitigations` and `--convert` with exit code 2 and leave the files unchanged.
- The CSV can also be edited directly in Excel. Files saved with `;` separators or Windows encoding are read correctly, and rewritten dates (for example `31/12/2027`) are accepted when unambiguous.
- The run summary lists mitigations that have expired or expire within 30 days.

## Troubleshooting

| Message | Fix |
| --- | --- |
| `Nothing was changed. Fix veracode-findings.csv and run again.` / `Nothing was written.` | Run `--check-mitigations`; it lists each problem by row number |
| `Excel files need openpyxl` | `pip install openpyxl` |
| `Mitigation Key is missing or changed. Do not edit it` | Restore the key from the previous file, or redo the row from a fresh export |
| `has no Mitigation Key column` | The file was not written with `--mitigations`; run Quick Start step 1 |
| `same Mitigation Key as row N but a different mitigation` | Make both rows match, or clear one |
| `could be day/month or month/day. Use YYYY-MM-DD` | The CSV was edited directly; retype the date as `YYYY-MM-DD`, or edit through the Excel copy |
