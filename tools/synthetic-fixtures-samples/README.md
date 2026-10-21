# Synthetic fixture samples

This folder holds real, checked-in output from
[`../New-ADSecurityAuditSyntheticFixtures.ps1`](../New-ADSecurityAuditSyntheticFixtures.ps1) -
four tiers of synthetic `AD_Security_Audit_*.json` findings (25%/50%/75%/100%
of every Issue this project can currently detect), plus the HTML and CSV
reports rebuilt from each one. They were generated and verified by actually
running the tool (PowerShell 7.6.6), not hand-written - see `v1.30.3` in
[CHANGELOG.md](../../CHANGELOG.md) for the validation pass that produced
them, including a real bug the first run of this tool caught (every
synthetic finding sharing one `Category`, which silently saturated the
scoring model - see that entry before assuming any output number here is
self-evidently correct without reading how it's computed).

**These are reference samples, not a live test suite.** They prove report
*rendering* works end-to-end (JSON → score → HTML → CSV, correct category
grouping, correct narrative-text backfill) as of the date they were
generated. They do **not** prove any check's *detection logic* is correct
against a real domain - that's what the Pester suite (`tests/`) and, more
importantly, an actual audit run are for.

## What's here

| File pattern | What it is |
|---|---|
| `AD_Security_Audit_<tier>.json` | The synthetic findings export for that tier - what `Start-ADSecurityAudit` would have written |
| `AD_Security_Score_<tier>.json` | The score sidecar for that tier (`TotalScore`, `MaturityLevel`, `CategoryScores`, ...) |
| `AD_Security_Audit_<tier>.html` | The HTML report rebuilt from the JSON via `Export-ADSecurityReportHTMLFromJson` |
| `AD_Security_Audit_<tier>.csv` | The flat findings CSV rebuilt via `Export-ADSecurityReportCSVFromJson` |
| `AD_Security_Audit_<tier>-coverage.csv` | The accompanying Test Coverage CSV (a single explanatory row here, since synthetic runs have no real coverage sidecar - this is expected, not a bug) |

Every finding's `Description`/`Impact`/`Remediation` is explicitly prefixed
`"[SYNTHETIC TEST DATA]"` and `Details.Synthetic = true` - open any HTML
file and this is obvious at a glance, so nobody mistakes one of these for a
real audit result.

## Regenerating these samples

From the repo root, with a real PowerShell (5.1+ or 7+) available:

```powershell
./tools/New-ADSecurityAuditSyntheticFixtures.ps1 `
    -OutputPath ./tools/synthetic-fixtures-samples `
    -GenerateReports
```

This overwrites the timestamped files it produces by default; if you want
to replace the checked-in reference copies above, rename the new output to
match the stable `<type>_<tier>.<ext>` pattern used here (the tool itself
always writes a timestamp in the filename, by design, so ad-hoc runs never
collide with each other or with these committed samples).

## Why this exists: validating a new check before it ships

This tool's real value isn't the four sample reports above - it's the
**workflow** for catching the kind of gap this project has repeatedly
shipped and then had to patch (a missing `Scoring.ps1` entry, a missing
`FindingNarrativeLibrary.ps1` entry, a check with zero Pester coverage, a
category/severity choice that behaves unexpectedly once it hits the actual
scoring model). Run this checklist whenever a new check is added, **before**
it ships:

1. **Confirm the new `Issue` string has a `Scoring.ps1` entry.**
   ```powershell
   . ./src/Common.ps1; . ./src/Scoring.ps1
   $Script:ADFindingMetadataMap.ContainsKey('Your New Issue String Here')
   ```
   `$false` here means the finding will silently score as `Weight = 0` /
   `Unknown technique` at runtime instead of throwing - exactly the kind of
   gap that shipped twice in this project's history before being caught by
   a manual full-codebase audit. Don't rely on manual inspection catching
   it again; check it directly.

2. **Confirm it has a `FindingNarrativeLibrary.ps1` entry** (or that
   `tools/Build-ADFindingNarrativeLibrary.ps1` has been re-run since the
   new check was added - see that tool's own `-WhatIf` mode for a
   conflict-checking dry run first).

3. **Regenerate the synthetic fixtures** (command above) and confirm:
   - The new Issue actually appears in the tier(s) its severity puts it in
     (check the JSON, or just search the HTML for its name).
   - Its `Category` in the rendered HTML matches what you expect - a new
     check accidentally reusing an existing `$finding.Category` string
     (typo, copy-paste) will silently merge into that category's score
     instead of standing on its own, which is easy to miss by eye but
     obvious once you diff `CategoryScores` in the score sidecar JSON
     before/after.
   - The score sidecar's `CategoryScores` moved in the direction you'd
     expect for the category the new check belongs to.

4. **Write (or extend) a Pester test for the new check specifically** -
   this tool proves rendering, not detection logic; a real Pester test
   with mocked AD cmdlets is still what actually exercises the check's own
   conditional logic (see `tests/AdminSDAudits.Tests.ps1`,
   `tests/LapsAudits.Tests.ps1`, or `tests/ReplicationAudits.Tests.ps1` for
   the pattern to follow, including the SID-vs-`"DOMAIN\name"` identity
   gotcha noted in each of those files' own header comments).

5. **Run the full Pester suite** (`Invoke-Pester ./tests/`) if a Pester
   installation is available in your environment - this generator and its
   samples do not replace that, they cover the one thing Pester's mocked
   unit tests structurally can't: what the *rendered report* actually
   looks like once real scoring/narrative-backfill/category-grouping runs
   against it.

None of this replaces testing against a real (or lab) Active Directory
environment for the check's actual detection logic - see the project's own
"Lab Test Notes" convention in each `files/NN-*.md` feature-request doc for
that half of validation.
