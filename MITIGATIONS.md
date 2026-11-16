# Mitigations

English | [Español](MITIGATIONS.es.md)

Mitigations for Container, IaC and Secrets findings are not available on the Veracode Platform. The findings
tracker (see [README.md](README.md#findings-tracker-recommended)) keeps the approved ones in `mitigations.yml`
and shows them in `FINDINGS.md`, `tracking/findings.csv` and exports.

## Request and approve

1. **Request.** In `FINDINGS.md`, click **Mitigate** on the finding. GitHub opens the *Mitigation request* issue
   form with the Finding Key, Finding ID and Asset filled in. Pick the type, write the reason, add the expiry date
   for `accept-risk`, and submit. You can also open the form from Issues > New issue and copy the Finding Key from
   `tracking/findings.csv`.
2. **Approve.** An approver reviews the issue and adds the label `approved`. Approvers are the GitHub logins in the
   repository variable `MITIGATION_APPROVERS` (Settings > Secrets and variables > Actions > Variables), comma or
   space separated.
3. **Recorded.** [veracode-mitigation.yml](.github/workflows/veracode-mitigation.yml) checks the approver and the
   form, appends the next entry (`M-0001`, `M-0002`, ...) to `mitigations.yml`, refreshes the Mitigation columns
   and `FINDINGS.md` without calling Veracode, commits `Approve mitigation M-000N (#issue)`, comments
   "Approved as M-000N, applied to N finding(s)" and closes the issue.

| Situation | Result |
| --- | --- |
| The person who added the label is not an approver | Label removed, comment "@login is not an approver" |
| The form is invalid (bad key, type or date, missing reason, expiry in the past) | Label removed, comment with the problems. Edit the issue and add the label again |
| The issue was edited after the label was added | Label removed. Review it and add the label again |
| Rejecting | Close the issue without the label |

### Scope of a request

| Asset field | File field | The rule mitigates |
| --- | --- | --- |
| Unchanged (as filled in by the link) | Empty | This finding only (`finding` is its Finding Key) |
| With a wildcard, for example `acme/payments-*` | Any | This Finding ID on every matching asset |
| Any | A path pattern, for example `modules/status/*` | This Finding ID in matching files |

A rule that matches everything (`finding: "*"` with no asset or file) is refused.

## mitigations.yml

The template starts with an empty list (`[]`). Entries look like this
([examples/mitigations.example.yml](examples/mitigations.example.yml)):

```yaml
- id: M-0001
  finding: AVD-AWS-0086
  asset: acme/payments-*
  file: modules/status/*
  type: accept-risk
  reason: Public status page served through CloudFront
  approved_by: lead-dev
  approved_on: 2026-11-15
  expires: 2027-11-09
  ref: https://github.com/acme/veracode-findings/issues/12
```

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | `M-` and at least 4 digits, unique. The workflow assigns the next free number |
| `finding` | Yes | Finding ID, CVE or Finding Key (`mk-...`). `*` and `?` are wildcards; the whole value must match; not case-sensitive |
| `asset` | No | Asset Name or Asset ID, with wildcards |
| `file` | No | File Path or Location, with wildcards |
| `type` | Yes | One of the types below |
| `reason` | Yes | Why the finding needs no fix |
| `approved_by` | Yes | The approver. The workflow writes the GitHub login |
| `approved_on` | No | `YYYY-MM-DD`. Set by the workflow |
| `expires` | For `accept-risk` | `YYYY-MM-DD`. From the day after, the finding counts as open again |
| `ref` | No | Issue link (set by the workflow), `migrated`, or any text |
| `requested_by` | No | Issue author. Set by the workflow |
| `notes` | No | Ticket or change number |
| `allow_broad` | No | `true` to allow a rule that matches every finding |

When several rules match a finding, the first one in the file that has not expired wins.

### Types (same as Static Analysis)

| Type | Use when | Static Analysis name |
| --- | --- | --- |
| `false-positive` | Finding is not real | Potential False Positive |
| `by-design` | Setting is deliberate and approved | Mitigate by Design |
| `network-environment` | A network control blocks it (WAF, security group, private network) | Mitigate by Network Environment |
| `os-environment` | OS or runtime blocks it (hardened host, read-only file system, no shell) | Mitigate by OS Environment |
| `accept-risk` | Business accepts the risk; needs `expires` | Accept the Risk |

### Mitigation Status

| Value | Meaning |
| --- | --- |
| `Mitigated` | A rule matches and has not expired |
| `Expiring` | It expires in 30 days or less. Listed in `FINDINGS.md` |
| `Expired` | The expiry date has passed. Counts as open; listed in `FINDINGS.md` with a Mitigate link to renew |
| (empty) | Not mitigated |

## Edit, renew, revoke

- **Edit or add directly:** change `mitigations.yml` in a pull request. The `check` job validates the file and
  comments a table of the rules added, changed or removed, with how many open findings each one matches. The
  check runs the script from the base branch, so a pull request cannot change how it is checked. It fails when the
  file is invalid; make it a required check.
- **Renew:** change `expires` in a pull request, or request again from the Mitigate link.
- **Revoke:** delete the entry in a pull request. The next run (or the next approval) shows the findings as not
  mitigated.

Check locally, without Veracode access:

```bash
python veracode_iac_extract.py --check-mitigations mitigations.yml
python veracode_iac_extract.py --check-mitigations mitigations.yml --against old.yml --track tracking   # PR table
python veracode_iac_extract.py -o findings.csv --mitigations mitigations.yml   # export with Mitigation columns
```

| Flag | Effect |
| --- | --- |
| `--mitigations FILE` | Apply the rules in `FILE` to `--track` or to an export |
| `--check-mitigations FILE` | Validate and list the rules: exit 0 valid, 2 invalid. Unknown keys, missing fields, bad types or dates and duplicate ids are errors; an expiry in the past is a warning |
| `--against BASE` | With `--check-mitigations`: Markdown table of the changes compared with `BASE` (capped at 60,000 characters) |
| `--track DIR` | With `--against`: count the open findings in `DIR/findings.csv` that each rule matches |
| `--approve-issue FILE` | Used by the workflow: turn the issue JSON in `FILE` into an entry. Exit 2 invalid, 3 not an approver |
| `--approver LOGIN` | With `--approve-issue`: who added the label. Checked against `MITIGATION_APPROVERS` |

## Security notes

- Only people who can add labels (triage access or more) can trigger an approval, and only logins in
  `MITIGATION_APPROVERS` are accepted. Changing that variable needs admin access.
- Protect `mitigations.yml` and `.github/` with [CODEOWNERS](.github/CODEOWNERS) and branch protection. Direct
  edits by people with write access are possible otherwise.
- The issue text never reaches a shell: the workflow passes it to the script as a JSON file. The issue is read
  from the label event, and the approval is refused if the issue was edited afterwards.
- Every value shown in comments and in `FINDINGS.md` is escaped: no HTML, no hidden comments, no @mentions, no
  table breaks.
- The daily job and the approval job share one concurrency group, so they never write at the same time.

## Limitations

- Mitigations affect the tracker and the exports only. They do not change the Veracode Platform, policy results
  or pipeline gates.
- A Finding Key changes when the file is moved or renamed, the resource is renamed, or a secret's value changes.
  The finding then shows as New; request the mitigation again, or use a rule by Finding ID with an asset or file
  scope.

## Moving from the CSV tracking file

Older versions kept mitigations in `veracode-findings.csv` (`--mitigations FILE.csv`, `--convert`). On the
first `--track` run, if `veracode-findings.csv` is next to the `tracking` folder (or with
`--migrate FILE`), every mitigated row becomes a `mitigations.yml` entry (`finding` = its key, `ref: migrated`)
and the findings keep their First Seen date. The old file is not used after that and can be deleted. Invalid
rows stop the run with exit 2 and change nothing.
