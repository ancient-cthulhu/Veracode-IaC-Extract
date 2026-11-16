# Mitigations

English | [Español](MITIGATIONS.es.md)

The Veracode Platform has no mitigations for Container, IaC and Secrets findings. The
[findings tracker](README.md#findings-tracker-recommended) records them in `mitigations.yml` and shows them in
`FINDINGS.md`, `tracking/findings.csv` and every export.

## Request and approve

1. **Request.** In `FINDINGS.md`, click **Mitigate** on the finding. A pre-filled issue opens. Pick the type, write
   the reason, add an expiry date (required for `accept-risk`) and submit.
2. **Approve.** An approver (a login in the variable `MITIGATION_APPROVERS`) adds the label `approved`.
3. **Done.** The bot adds the next entry (`M-0001`, `M-0002`, ...) to `mitigations.yml`, updates the dashboard,
   comments "Approved as M-0001, applied to 1 finding(s)" and closes the issue.

| Situation | Result |
| --- | --- |
| The label was added by someone who is not an approver | Label removed, with a comment |
| The form is invalid (missing reason, bad type or date) | Label removed, with the problems listed. Fix the issue and label it again |
| The issue was edited after the label | Label removed. Review it and label it again |
| Reject | Close the issue without the label |

### Scope

| Asset field | File field | Mitigates |
| --- | --- | --- |
| As filled in by the link | Empty | This finding only |
| Wildcard, for example `acme/payments-*` | Any | This Finding ID on every matching asset |
| Any | Path pattern, for example `modules/status/*` | This Finding ID in matching files |

## mitigations.yml

```yaml
- id: M-0001
  finding: AVD-AWS-0086
  asset: acme/payments-*
  type: accept-risk
  reason: Public status page served through CloudFront
  approved_by: lead-dev
  approved_on: 2026-11-15
  expires: 2027-11-09
  ref: https://github.com/acme/veracode-findings/issues/12
```

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | `M-0001` style, unique |
| `finding` | Yes | Finding ID, CVE or Finding Key (`mk-...`). `*` and `?` wildcards, whole value, not case-sensitive |
| `asset` | No | Asset Name or Asset ID, wildcards allowed |
| `file` | No | File path, wildcards allowed |
| `type` | Yes | See below |
| `reason` | Yes | Why no fix is needed |
| `approved_by` | Yes | Approver |
| `approved_on`, `requested_by`, `ref` | No | Set by the bot (`ref` is the issue link) |
| `expires` | For `accept-risk` | `YYYY-MM-DD`. From the next day the finding counts as open |
| `notes` | No | Ticket or change number |
| `allow_broad` | No | `true` to allow a rule that matches every finding |

If several rules match, the first unexpired one in the file wins. More examples:
[examples/mitigations.example.yml](examples/mitigations.example.yml).

| Type | Use when |
| --- | --- |
| `false-positive` | The finding is not real |
| `by-design` | The setting is deliberate and approved |
| `network-environment` | A network control blocks it (WAF, security group, private network) |
| `os-environment` | The OS or runtime blocks it (hardened host, read-only file system) |
| `accept-risk` | The business accepts the risk until `expires` |

| Mitigation Status | Meaning |
| --- | --- |
| `Mitigated` | A rule matches and has not expired |
| `Expiring` | Expires in 30 days or less |
| `Expired` | Past `expires`; counts as open. Renew from the Mitigate link |

## Edit, renew, revoke

Change `mitigations.yml` in a pull request: edit or add a rule, extend `expires`, or delete an entry to revoke it.
The pull request gets a comment listing the rules added, changed or removed and how many open findings each one
matches, and the check fails if the file is invalid. Make it a required check.

```bash
python veracode_iac_extract.py --check-mitigations mitigations.yml                  # validate
python veracode_iac_extract.py -o findings.csv --mitigations mitigations.yml        # export with mitigations
```

## Security

- Only logins in `MITIGATION_APPROVERS` can approve; changing the variable needs admin access.
- Protect `mitigations.yml` and `.github/` with [CODEOWNERS](.github/CODEOWNERS) and branch protection.
- Issue text never reaches a shell, and everything shown in comments and `FINDINGS.md` is escaped.
- The pull request check runs the script from the base branch, so a pull request cannot change its own check.

## Limitations

- Mitigations apply to the tracker and exports only, not to the Veracode Platform, policies or pipeline gates.
- A Finding Key changes when the file or resource is renamed or a secret's value changes. The finding then shows
  as New; mitigate it again, or use a rule by Finding ID with an asset or file scope.

## Existing veracode-findings.csv

If a `veracode-findings.csv` with mitigations sits next to the `tracking` folder, the first run copies its
mitigations into `mitigations.yml` (`ref: migrated`) and keeps each finding's First Seen. The CSV can then be
deleted.
