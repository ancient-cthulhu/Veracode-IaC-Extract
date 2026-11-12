# Mitigations

English | [Español](MITIGATIONS.es.md)

Mitigations for Container, IaC and Secrets findings are not yet available on the Veracode Platform. With
`--mitigations`, the export itself is where mitigations are tracked: fill in the Mitigation columns, and the
next run carries them onto the fresh findings. One file, kept in this repo.

> **Never edit `Mitigation Key` or `Mitigation Status`.** The script sets both. The key links each row to its
> finding on the next run; if it changes, the mitigation is lost. In the Excel file both are locked.

## Requirements

- Everything in [README.md](README.md#requirements)
- `pip install openpyxl` for `.xlsx` (recommended). `.csv` needs nothing extra.

## Quick Start

1. Create the tracking workbook (every finding starts `Open`):

   ```bash
   python veracode_iac_extract.py --compact --mitigations veracode-findings.xlsx
   ```

2. Open `veracode-findings.xlsx`. On each row to mitigate, fill in the yellow columns; nothing else can be
   edited:

   | Mitigation Type | Mitigation Reason | Mitigation Approved By | Mitigation Expires | Mitigation Notes |
   | --- | --- | --- | --- | --- |
   | accept-risk (dropdown) | Bucket serves the public status page through CloudFront | lead@acme.com | 2027-11-09 | CHG-4411 |

   See [examples/veracode-findings.example.xlsx](examples/veracode-findings.example.xlsx).

3. Validate, then commit the file through a pull request:

   ```bash
   python veracode_iac_extract.py --check-mitigations veracode-findings.xlsx
   ```

   ```text
   OK     row 2 (AVD-AWS-0086) acme/payments-infra: accept-risk, approved by lead@acme.com, expires 2027-11-09, notes: CHG-4411. Bucket serves the public status page through CloudFront
   veracode-findings.xlsx: 1 mitigated finding(s), all valid.
   ```

4. Run step 1 again. The file is rewritten with the latest findings and the mitigations carried over:

   ```text
     Mitigation status  : Open 3, Mitigated 1, Expired 0, Not in export 0
   ```

## The Excel file

| Feature | Effect |
| --- | --- |
| Protected sheet | Only the yellow Mitigation cells can be edited. Key, Status and finding data are locked. Filtering still works |
| Mitigation Type | Dropdown with the five types; other values are rejected |
| Mitigation Expires | Accepts dates only; shown as `YYYY-MM-DD` |
| Header notes and cell prompts | Explain each Mitigation column when selected |
| How to use sheet | Steps, an example row, types and statuses |
| Formatting | Status and severity colours, frozen header, filters, clickable Veracode Link, prints one page wide |

The protection has no password. It prevents mistakes, not deliberate changes (Review > Unprotect Sheet).

## Usage

```bash
# Refresh the tracking file (reads it, then writes it back)
python veracode_iac_extract.py --compact --mitigations veracode-findings.xlsx

# Only what still needs fixing, to a separate file (the tracking file is not changed)
python veracode_iac_extract.py --compact --mitigations veracode-findings.xlsx \
  --where "Mitigation Status!=Mitigated" -o to-fix.xlsx

# Validate and list every mitigation (no Veracode access needed)
python veracode_iac_extract.py --check-mitigations veracode-findings.xlsx
```

`.csv` works the same way (`--mitigations veracode-findings.csv`), without the Excel features.

## Configuration

### Flags

| Flag | Effect |
| --- | --- |
| `--mitigations FILE` | `.xlsx` or `.csv`. Read mitigations from the file, then write the export back to it. `-o` writes elsewhere instead |
| `--check-mitigations FILE` | Validate the Mitigation columns, list every mitigation, and exit: 0 valid, 2 invalid |

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
| Not in export | Mitigated, but the finding was not in this export (fixed, or filtered out). Kept so the mitigation returns if the finding does. Delete the row when no longer needed |

## GitHub Action

[.github/workflows/veracode-iac-findings.yml](.github/workflows/veracode-iac-findings.yml):

| Trigger | Job | Result |
| --- | --- | --- |
| Daily, 04:23 UTC, or Actions > Veracode IaC findings > Run workflow | `export` | Reads `veracode-findings.xlsx` from the repo and attaches the refreshed file as artifact `veracode-findings` |
| Pull request changing `veracode-findings.xlsx` | `check-mitigations` | Fails if the Mitigation columns are invalid; its log lists every mitigation for the reviewer |

The Action does not commit. To mitigate: download the artifact, fill in the yellow columns, and commit it as
`veracode-findings.xlsx` through a pull request.

Setup:

1. Add repository secrets `VERACODE_API_KEY_ID` and `VERACODE_API_KEY_SECRET`.
2. Optional: require the `check-mitigations` check before merging.
3. Optional: repository variable `VERACODE_EXTRACT_ARGS` with filters added to every run, for example `--asset my-org/*`.

## Important Notes

- **The tool does not enforce approval.** `Mitigation Approved By` is free text; anyone who can change the file can mitigate anything. Decide how approvals are controlled, for example a CODEOWNERS entry for the tracking file plus branch protection requiring that review.
- **Pull request diffs of `.xlsx` files are not readable.** Reviewers read the `check-mitigations` log instead. Use `.csv` if you want line-by-line diffs.
- **Use `--compact` for a file you commit.** The full export includes `Code Lines`, which can contain the secret itself.
- **Mitigations do not change the Veracode Platform**, including policy results.
- `Mitigation Key` ignores line numbers and image tags (`app:1.2` and `app:1.3` share keys). It changes when the file is moved or renamed, the resource is renamed, or a secret's value changes: the old row becomes `Not in export` and the finding appears as a new `Open` row. Copy the Mitigation columns to the new row.
- Rows with the same key (for example the same image under two tags) share one mitigation; fill in any one of them.
- Use the same filters on every run. Open findings excluded by a filter are dropped from the file; mitigated ones are kept as `Not in export`.
- Invalid Mitigation columns stop the run with exit code 2 and leave the file unchanged.
- CSV files saved by Excel with `;` separators or Windows encoding are read correctly. Rewritten dates (for example `31/12/2027`) are accepted when unambiguous.
- The run summary lists mitigations that have expired or expire within 30 days.

## Troubleshooting

| Message | Fix |
| --- | --- |
| `Nothing was changed. Fix veracode-findings.xlsx and run again.` | Run `--check-mitigations`; it lists each problem by row number |
| `Excel files need openpyxl` | `pip install openpyxl` |
| `Mitigation Key is missing or changed. Do not edit it` | Restore the key from the previous file, or redo the row from a fresh export |
| `has no Mitigation Key column` | The file was not written with `--mitigations`; run step 1 to create it |
| `same Mitigation Key as row N but a different mitigation` | Make both rows match, or clear one |
| `could be day/month or month/day. Use YYYY-MM-DD` | CSV only: retype the date as `YYYY-MM-DD` |
