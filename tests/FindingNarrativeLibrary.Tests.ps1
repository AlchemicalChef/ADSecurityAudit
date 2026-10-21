#Requires -Modules Pester
<#
    Guards against exactly the failure mode a generated/derived data file
    like src/FindingNarrativeLibrary.ps1 invites: someone edits a check's
    EstimatedEffort/KnownRisks/BackupRollback/OperationalNotes text in
    src/*.ps1 (or adds/renames an Issue) and forgets to re-run
    tools/Build-ADFindingNarrativeLibrary.ps1, so the checked-in library
    silently starts serving STALE "current guidance" text for offline JSON
    report recreation (Merge-ADFindingNarrativeGaps / Export-
    ADSecurityReportHTMLFromJson) - the exact kind of duplication-drift
    risk this file exists to eliminate for report CONSUMERS, but which the
    library ITSELF is still vulnerable to relative to its own source of
    truth if regeneration is skipped.

    This test re-runs the same extraction the build script performs, byte-
    for-byte, and asserts it matches the checked-in
    src/FindingNarrativeLibrary.ps1 exactly. If a PR changes narrative text
    in a check but doesn't regenerate the library, this test fails with a
    clear message telling the author to run the build script - CI (or a
    local test run) catches the drift before it ships, rather than a
    report reader silently getting stale backfilled guidance months later
    with no way to know it happened.

    Run from the repo root:  Invoke-Pester ./tests/FindingNarrativeLibrary.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    $libraryPath = Join-Path $root 'src/FindingNarrativeLibrary.ps1'
    $buildScriptPath = Join-Path $root 'tools/Build-ADFindingNarrativeLibrary.ps1'
}

Describe 'FindingNarrativeLibrary.ps1 is in sync with its source' {

    It 'the build script and the checked-in file both exist' {
        Test-Path $libraryPath | Should -BeTrue -Because 'src/FindingNarrativeLibrary.ps1 should be checked in, not generated at runtime'
        Test-Path $buildScriptPath | Should -BeTrue
    }

    It 'regenerating the library from current source produces byte-identical output to the checked-in file' {
        # Regenerate into a scratch location - never overwrite the real
        # checked-in file as a side effect of running tests.
        $scratchPath = Join-Path $TestDrive 'FindingNarrativeLibrary.regenerated.ps1'

        & $buildScriptPath -SourceRoot $root -OutputPath $scratchPath -Confirm:$false | Out-Null

        Test-Path $scratchPath | Should -BeTrue -Because 'the build script should have written a fresh copy to the scratch path'

        $checkedIn   = Get-Content -Path $libraryPath -Raw
        $regenerated = Get-Content -Path $scratchPath -Raw

        if ($checkedIn -ne $regenerated) {
            # A plain "should be" failure here just prints two large blobs -
            # find and report the first differing line instead, so the
            # failure message actually tells you where to look.
            $checkedInLines   = $checkedIn -split "`n"
            $regeneratedLines = $regenerated -split "`n"
            $maxLines = [Math]::Max($checkedInLines.Count, $regeneratedLines.Count)
            $firstDiffLine = -1
            for ($i = 0; $i -lt $maxLines; $i++) {
                $a = if ($i -lt $checkedInLines.Count) { $checkedInLines[$i] } else { '<end of file>' }
                $b = if ($i -lt $regeneratedLines.Count) { $regeneratedLines[$i] } else { '<end of file>' }
                if ($a -ne $b) { $firstDiffLine = $i + 1; break }
            }
            throw "src/FindingNarrativeLibrary.ps1 is OUT OF SYNC with the src/*.ps1 it's extracted from (first differing line: $firstDiffLine of $maxLines). A check's EstimatedEffort/KnownRisks/BackupRollback/OperationalNotes text (or Issue name) changed without regenerating the library. Run: pwsh ./tools/Build-ADFindingNarrativeLibrary.ps1  then commit the result."
        }

        $checkedIn | Should -BeExactly $regenerated
    }

    It 'every Issue key in the library actually exists as a literal Issue string somewhere in src/*.ps1 (catches renamed/removed Issues left stale in the library)' {
        . $libraryPath
        $allSource = Get-ChildItem -Path (Join-Path $root 'src') -Filter '*.ps1' |
            Where-Object { $_.Name -ne 'FindingNarrativeLibrary.ps1' } |
            ForEach-Object { Get-Content -Path $_.FullName -Raw } |
            Out-String

        $orphaned = @($Script:ADFindingNarrativeLibrary.Keys | Where-Object {
            $escaped = [regex]::Escape($_)
            $allSource -notmatch "'$escaped'" -and $allSource -notmatch "`"$escaped`""
        })

        $orphaned | Should -BeNullOrEmpty -Because "these library entries no longer match any Issue string in src/*.ps1 - the check was likely renamed or removed; re-run tools/Build-ADFindingNarrativeLibrary.ps1: $($orphaned -join ', ')"
    }

    It 'captures both variants of a conditionally-named Issue (e.g. "$finding.Issue = if (...) { ... } else { ... }"), each with its own distinct paired text' {
        <#
            Regression coverage for a reported gap: "User Account with SPN
            (Kerberoasting Risk)" / "Privileged Account with SPN
            (Kerberoasting Risk)" (UserAudits.ps1) sets Issue AND
            EstimatedEffort/KnownRisks/BackupRollback all via
            "if ($isPrivileged) { 'A' } else { 'B' }" - a pattern the
            plain-literal extractor (Get-ADQuotedFieldValue) doesn't
            match at all, so this Issue previously had NO library entry,
            leaving those fields permanently blank when recreating a
            report from an export that predates them. Fixed via
            Get-ADConditionalFieldBranches in the build script, pairing
            each field's if/else branches positionally with Issue's own.
        #>
        . $libraryPath
        $priv = $Script:ADFindingNarrativeLibrary['Privileged Account with SPN (Kerberoasting Risk)']
        $nonPriv = $Script:ADFindingNarrativeLibrary['User Account with SPN (Kerberoasting Risk)']

        $priv | Should -Not -BeNullOrEmpty
        $nonPriv | Should -Not -BeNullOrEmpty
        $priv.EstimatedEffort | Should -Not -BeNullOrEmpty
        $nonPriv.EstimatedEffort | Should -Not -BeNullOrEmpty
        # The two variants must have genuinely DIFFERENT text (proves the
        # branches were paired correctly, not both accidentally getting
        # the same branch's text).
        $priv.KnownRisks | Should -Not -Be $nonPriv.KnownRisks
        $priv.KnownRisks | Should -Match 'privileged'
        $nonPriv.KnownRisks | Should -Not -Match 'privileged access directly'
    }
}
