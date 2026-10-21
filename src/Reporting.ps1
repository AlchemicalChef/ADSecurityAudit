function Format-ADFindingDetectedDate {
    <#
    .SYNOPSIS
        Formats a finding's DetectedDate for display, tolerating a missing/
        $null value instead of throwing.
    .DESCRIPTION
        FIXED (reported): DetectedDate.ToString('yyyy-MM-dd HH:mm') was
        called directly inline. On a live [ADSecurityFinding] this always
        works (the class always sets it at construction), but a finding
        loaded from an older JSON export that predates DetectedDate being
        added to the schema deserializes with no DetectedDate property at
        all - PSCustomObject property access then returns $null, and
        calling .ToString() on $null throws "You cannot call a method on
        a null-valued expression." for every single such finding, visibly
        on the console, while the "Detected:" field itself silently
        rendered blank regardless (the error was non-fatal to the overall
        report, just noisy and wrong-looking).
    .PARAMETER DetectedDate
        The finding's DetectedDate. May be $null, a [datetime], or (from
        some JSON round-trips) a date-like [string].
    .OUTPUTS
        [string]
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        $DetectedDate
    )
    if ($null -eq $DetectedDate -or $DetectedDate -eq '') {
        return 'Unknown (not present in this export)'
    }
    if ($DetectedDate -is [datetime]) {
        return $DetectedDate.ToString('yyyy-MM-dd HH:mm')
    }
    # ConvertFrom-Json can hand back a date as a string rather than
    # [datetime] depending on PowerShell version/format; try to parse it
    # before giving up, so a well-formed date string still displays
    # nicely rather than falling through to the raw string as-is.
    $parsed = $null
    if ([datetime]::TryParse($DetectedDate, [ref]$parsed)) {
        return $parsed.ToString('yyyy-MM-dd HH:mm')
    }
    return [string]$DetectedDate
}

function Export-ADSecurityReportHTMLFromJson {
    <#
    .SYNOPSIS
        Recreates the main HTML audit report from a previously-exported
        AD_Security_Audit_<timestamp>.json findings file, with no live
        Active Directory access.
    .DESCRIPTION
        Start-ADSecurityAudit's HTML report (Export-ADSecurityReportHTML) is
        normally built once, in-memory, at the end of a live run - it needs
        Findings plus several run-time-only values (Domain, Summary,
        Duration, PrivilegedUsers) that Start-ADSecurityAudit never persists to disk
        on their own. Only two files survive a run for later offline use:
        the flat findings export (AD_Security_Audit_<timestamp>.json) and,
        optionally, its AD_Security_Score_<timestamp>.json sidecar.

        This function is the "I only kept/have the JSON, not the original
        HTML" recovery path: point it at a findings export (or a folder -
        same newest-file resolution idiom as Get-ADRetestComparison's
        -BaselinePath/-RetestPath) and it rebuilds the HTML report from
        that alone. Because most of Export-ADSecurityReportHTML's other
        inputs simply don't exist in the findings JSON, this comes with
        real, spelled-out gaps versus the original report - see LIMITATIONS
        below. If you still have the original HTML, that one file has
        everything and this function has nothing to add for it.

        If a sibling AD_Security_TestCoverage_<timestamp>.json sidecar
        exists next to the findings file (same naming convention as the
        Score sidecar - written automatically by a live/snapshot run),
        its contents populate the recreated report's "Test Coverage"
        section too (see Get-ADTestCoverageSidecar). An export that
        predates coverage tracking simply omits that section.

        The risk score shown is always freshly RECOMPUTED from the
        findings via Get-ADRiskScore, never read back from a score sidecar
        (same "never trust a stored sidecar score" philosophy as
        Get-ADRetestComparison) - so a JSON export originally scored under
        an older module version is rescored under whatever version you run
        this function with.
    .PARAMETER FindingsPath
        Either an explicit AD_Security_Audit_<timestamp>.json file, or a
        folder to search for the newest one (same resolution idiom as
        Get-ADRetestComparison's -BaselinePath/-RetestPath).
    .PARAMETER OutputPath
        Path to write the recreated HTML report to - either an exact
        file path, or a folder (an auto-named
        "AD_Security_Audit_<timestamp>-recreated.html" is created inside
        it, timestamp matched to the findings export being rebuilt from;
        deliberately not the same name a live run would use for that
        timestamp, so pointing this at the same folder the original
        report already lives in can't silently overwrite it).
    .PARAMETER Domain
        Not present in the findings JSON (the ADSecurityFinding schema
        doesn't carry a Domain field - see the note in
        ForestConsolidation.ps1). Defaults to a clearly-labeled placeholder;
        pass the actual domain name if you know it, so the recreated report
        doesn't read as if the domain were unknown at scan time.
    .PARAMETER Duration
        Not present in the findings JSON (Start-ADSecurityAudit only times
        a run in-memory). Defaults to zero; the recreated report's SCAN
        DURATION will read as "0 seconds" unless you supply the real value.
    .OUTPUTS
        None. Writes the HTML file to -OutputPath.
    .EXAMPLE
        Export-ADSecurityReportHTMLFromJson -FindingsPath "C:\Reports\AD_Security_Audit_2026-08-01_00-00-00.json" `
            -OutputPath "C:\Reports\AD_Security_Audit_2026-08-01_00-00-00-recreated.html" `
            -Domain "contoso.com"
    .EXAMPLE
        # Folder form - picks the newest AD_Security_Audit_*.json in it:
        Export-ADSecurityReportHTMLFromJson -FindingsPath "C:\Reports" -OutputPath "C:\Reports\recreated.html"
    .EXAMPLE
        # Folder form for BOTH arguments - resolves the newest export and
        # writes an auto-named "...-recreated.html" into the given folder:
        Export-ADSecurityReportHTMLFromJson -FindingsPath "C:\Reports" -OutputPath "C:\Reports"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FindingsPath,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [string]$Domain = 'Unknown (recreated from JSON export - Domain was not persisted in AD_Security_Audit_*.json)',

        [Parameter()]
        [timespan]$Duration = [timespan]::Zero
    )

    $findingsFile = Resolve-ADRetestReportFile -Path $FindingsPath
    $OutputPath = Resolve-ADRebuiltReportOutputPath -OutputPath $OutputPath -FindingsFile $findingsFile -Extension 'html'

    try {
        $findings = @(Get-Content -Path $findingsFile.FullName -Raw | ConvertFrom-Json)
    }
    catch {
        throw "Failed to parse findings export '$($findingsFile.FullName)': $_"
    }

    # Defensive flatten, same reasoning as Get-ADRetestComparison - a no-op
    # for a normal, already-flat export. @() wrap is load-bearing for a
    # genuinely empty (zero-finding) export - see
    # ConvertTo-ADFlatFindingsArray's own docs.
    $findings = @(ConvertTo-ADFlatFindingsArray -Findings $findings)

    # Reported gap: a report recreated from an older JSON export was
    # missing the "Estimated Effort" / "Known Risks" / "Backup / Rollback"
    # / "Operational Notes" sections entirely for any finding whose export
    # predates those fields, with no indication anything was missing - it
    # just silently read as a thinner report than a fresh run would
    # produce. Backfills those fields (and MITRE/ANSSI/Weight) from
    # current guidance where the loaded finding is missing them and a
    # library entry exists; never overwrites real data the export already
    # had. See Merge-ADFindingNarrativeGaps's own docs for exactly what
    # this does and doesn't do.
    $backfilledCount = Merge-ADFindingNarrativeGaps -Findings $findings
    $runScopeNotes = @(Get-ADRunScopeNotes)
    if ($backfilledCount -gt 0) {
        $runScopeNotes += [PSCustomObject]@{
            Category = 'Recreated From JSON'
            Message  = "This report was recreated from a JSON findings export, not from a live/snapshot run. $backfilledCount finding(s) in this export were missing supporting information (Estimated Effort / Known Risks / Backup-Rollback / Operational Notes) that the current module version normally provides - this typically happens when the export predates that field being added, or predates that specific finding's current wording. Those sections were backfilled with CURRENT guidance for the finding's Issue type where available; this is representative guidance, not necessarily an exact reproduction of what the original run's module version would have shown. Any finding that still shows one of these sections missing has no current guidance available to backfill from."
        }
    }

    Write-Verbose "Recomputing risk score for the recreated report under the current Get-ADRiskScore mapping table (never the original sidecar value, if one exists)..."
    $riskScore = Get-ADRiskScore -Findings $findings

    # Reported gap: neither this recreated report nor a live one gave any
    # indication of which checks did NOT run (excluded, or attempted and
    # failed) or which ran and found nothing. For a live/snapshot run,
    # Main.ps1 now writes this alongside the findings JSON as
    # AD_Security_TestCoverage_<timestamp>.json; pick it up here by the
    # same sibling-filename convention the Score sidecar already uses, if
    # it exists. An export from before this tracking existed (or one
    # where the sidecar wasn't kept alongside the findings file) simply
    # has no Test Coverage section - Get-ADTestCoverageSidecar returns an
    # empty array for that case, not an error.
    # @(...) wrapping here is load-bearing, not decorative: when
    # Get-ADTestCoverageSidecar returns @() (no sidecar found), PowerShell
    # represents that as an internal "nothing" value that compares equal
    # to $null but wraps to a genuinely empty array under @(). Passing
    # that value across ANOTHER function's parameter boundary (-TestCoverage
    # below, and again inside Export-ADSecurityReportHTML) normalizes it to
    # a real $null - and @($null).Count is 1, not 0. Without this @()
    # here, a findings export with no coverage sidecar rendered a "Test
    # Coverage" section claiming "0 check(s) tracked" instead of omitting
    # the section entirely as intended.
    $testCoverage = @(Get-ADTestCoverageSidecar -FindingsFile $findingsFile)

    # Requested: make it explicit, in the report itself, when a JSON
    # export has no coverage information because it predates the feature
    # entirely - not just silently omit the Test Coverage section, which
    # reads ambiguously (did nothing get excluded/fail, or was coverage
    # simply never recorded for this run?). Test coverage tracking was
    # introduced in module v1.24.0 (AD_Security_TestCoverage_*.json first
    # written by Main.ps1 at that version) - an export from a version
    # before that, or the rare case where the sidecar file itself was
    # lost/not kept alongside the findings JSON, has NO data on which
    # checks ran, passed, failed, or were excluded for this specific run.
    # That's a real, total blank for the whole run - not "some checks
    # were untested" (which is what an empty/zero Test Coverage section
    # could otherwise be misread as).
    if ($testCoverage.Count -eq 0) {
        $runScopeNotes += [PSCustomObject]@{
            Category = 'Test Coverage Not Available'
            Message  = "No test coverage information is available for this run - this report cannot say which checks ran, passed, failed, or were excluded. Test coverage tracking was introduced in module version 1.24.0; this export either predates that version, or its AD_Security_TestCoverage_<timestamp>.json sidecar was not kept alongside the findings JSON being recreated from. This is a limitation of the export itself, not evidence that every check ran cleanly - if you need coverage information for this run, it does not exist and cannot be reconstructed from the findings alone."
        }
    }

    # Mirrors Main.ps1's own $summary construction exactly, so the recreated
    # report's Executive Summary counts match what a live run would have shown.
    $summary = @{
        Critical = @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
        High     = @($findings | Where-Object { $_.Severity -eq 'High' }).Count
        Medium   = @($findings | Where-Object { $_.Severity -eq 'Medium' }).Count
        Low      = @($findings | Where-Object { $_.Severity -eq 'Low' }).Count
    }

    Write-Verbose "Recreating HTML report from '$($findingsFile.FullName)' ($($findings.Count) finding(s))..."
    Export-ADSecurityReportHTML -Findings $findings -OutputPath $OutputPath -Domain $Domain -Summary $summary `
        -Duration $Duration -RiskScore $riskScore `
        -PrivilegedUsers $null -RunScopeNotes $runScopeNotes -TestCoverage $testCoverage

    Write-Verbose "Recreated HTML report written to '$OutputPath'."
}

function Export-ADSecurityReportCSVFromJson {
    <#
    .SYNOPSIS
        Recreates the flat findings CSV (and, if a coverage sidecar is
        available, a Test Coverage CSV alongside it) from a previously-
        exported AD_Security_Audit_<timestamp>.json findings file, with no
        live Active Directory access.
    .DESCRIPTION
        Reported gap: Export-ADSecurityReportHTMLFromJson existed to
        rebuild the HTML report from an old JSON export, but there was no
        equivalent for the CSV - so a CSV regenerated by hand (or not
        regenerated at all) could silently drift out of date relative to
        the JSON it's meant to be a flat view of, with no supported way
        to bring it back in sync short of re-running the whole audit.

        This function is that equivalent: point it at a findings export
        (or a folder - same newest-file resolution idiom as
        Get-ADRetestComparison's -BaselinePath/-RetestPath and
        Export-ADSecurityReportHTMLFromJson's -FindingsPath) and it writes
        a fresh AD_Security_Audit_<timestamp>-recreated.csv using
        ConvertTo-ADFindingsCsvRows - the SAME column-construction
        function Start-ADSecurityAudit's live export uses (Common.ps1),
        so this can never independently drift from the live CSV's column
        list. Supporting-information fields
        (EstimatedEffort/KnownRisks/BackupRollback/OperationalNotes) and
        MITRE/ANSSI/Weight metadata are backfilled the same way as the
        HTML rebuild path (Merge-ADFindingNarrativeGaps) before being
        written, so an old export's CSV benefits from the same "current
        guidance" backfill as its HTML counterpart, not a lesser version
        of it.

        If a sibling AD_Security_TestCoverage_<timestamp>.json sidecar
        exists next to the findings file, this ALSO writes a
        <OutputPath>-coverage.csv alongside the findings CSV, using the
        exact same rows Main.ps1's live export writes to
        AD_Security_TestCoverage_<timestamp>.csv. An export that predates
        coverage tracking (module v1.24.0) still gets a
        <OutputPath>-coverage.csv, but with a single explanatory row
        (Status = 'NotAvailable') instead of real per-check data - made
        visible in the output artifact itself, not just a verbose log
        line, since a genuinely-missing file is easy to read as "the tool
        forgot" rather than "no data exists for this run".
    .PARAMETER FindingsPath
        Either an explicit AD_Security_Audit_<timestamp>.json file, or a
        folder to search for the newest one.
    .PARAMETER OutputPath
        Path to write the recreated findings CSV to - either an exact
        file path, or a folder (an auto-named
        "AD_Security_Audit_<timestamp>-recreated.csv" is created inside
        it, timestamp matched to the findings export being rebuilt from;
        deliberately not the same name a live run would use for that
        timestamp, so pointing this at the same folder the original
        report already lives in can't silently overwrite it). If a
        test-coverage sidecar is found, a second file is written
        alongside it with "-coverage" inserted before the extension
        (e.g. "recreated.csv" -> "recreated-coverage.csv").
    .OUTPUTS
        None. Writes the CSV file(s) to disk.
    .EXAMPLE
        Export-ADSecurityReportCSVFromJson -FindingsPath "C:\Reports\AD_Security_Audit_2026-08-01_00-00-00.json" `
            -OutputPath "C:\Reports\AD_Security_Audit_2026-08-01_00-00-00-recreated.csv"
    .EXAMPLE
        # Folder form - picks the newest AD_Security_Audit_*.json in it:
        Export-ADSecurityReportCSVFromJson -FindingsPath "C:\Reports" -OutputPath "C:\Reports\recreated.csv"
    .EXAMPLE
        # Folder form for BOTH arguments - resolves the newest export and
        # writes an auto-named "...-recreated.csv" into the given folder:
        Export-ADSecurityReportCSVFromJson -FindingsPath "C:\Reports" -OutputPath "C:\Reports"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FindingsPath,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $findingsFile = Resolve-ADRetestReportFile -Path $FindingsPath
    $OutputPath = Resolve-ADRebuiltReportOutputPath -OutputPath $OutputPath -FindingsFile $findingsFile -Extension 'csv'

    try {
        $findings = @(Get-Content -Path $findingsFile.FullName -Raw | ConvertFrom-Json)
    }
    catch {
        throw "Failed to parse findings export '$($findingsFile.FullName)': $_"
    }

    # Same defensive flatten + narrative/metadata backfill as
    # Export-ADSecurityReportHTMLFromJson, so the two rebuild paths never
    # show different "current guidance" text for the same underlying
    # export - see Merge-ADFindingNarrativeGaps's own docs. @() wrap is
    # load-bearing for a genuinely empty export - see
    # ConvertTo-ADFlatFindingsArray's own docs.
    $findings = @(ConvertTo-ADFlatFindingsArray -Findings $findings)
    $backfilledCount = Merge-ADFindingNarrativeGaps -Findings $findings
    if ($backfilledCount -gt 0) {
        Write-Verbose "Export-ADSecurityReportCSVFromJson: backfilled supporting-information fields on $backfilledCount finding(s) from current guidance before writing the CSV (see Merge-ADFindingNarrativeGaps)."
    }

    Write-Verbose "Recreating findings CSV from '$($findingsFile.FullName)' ($($findings.Count) finding(s))..."
    ConvertTo-ADFindingsCsvRows -Findings $findings | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Verbose "Recreated findings CSV written to '$OutputPath'."

    $testCoverage = @(Get-ADTestCoverageSidecar -FindingsFile $findingsFile)
    if ($testCoverage.Count -gt 0) {
        $coverageOutputPath = [System.IO.Path]::Combine(
            [System.IO.Path]::GetDirectoryName($OutputPath),
            ([System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '-coverage' + [System.IO.Path]::GetExtension($OutputPath))
        )
        $testCoverage | Sort-Object TestName | ForEach-Object {
            [PSCustomObject]@{
                TestName     = $_.TestName | ConvertTo-SafeCsvValue
                Status       = $_.Status
                FindingCount = $_.FindingCount
                ErrorMessage = $_.ErrorMessage | ConvertTo-SafeCsvValue
            }
        } | Export-Csv -Path $coverageOutputPath -NoTypeInformation -Encoding UTF8
        Write-Verbose "Recreated test coverage CSV written to '$coverageOutputPath'."
    }
    else {
        # Requested: make this visible in the actual output artifact, not
        # just -Verbose logging someone has to remember to check. Writes
        # the coverage CSV anyway, but with a single explanatory row
        # (Status = 'NotAvailable', clearly distinct from the real
        # Completed/Failed/Excluded values) instead of leaving the
        # coverage CSV entirely absent - a missing file next to one that
        # DOES have a "-coverage.csv" sibling for other exports is easy
        # to overlook as "the tool forgot" rather than "no data exists for
        # this run". Same version-boundary explanation as the HTML
        # rebuild path's Run Scope Note (see Export-ADSecurityReportHTMLFromJson).
        $coverageOutputPath = [System.IO.Path]::Combine(
            [System.IO.Path]::GetDirectoryName($OutputPath),
            ([System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '-coverage' + [System.IO.Path]::GetExtension($OutputPath))
        )
        [PSCustomObject]@{
            TestName     = '(no coverage data for this run)'
            Status       = 'NotAvailable'
            FindingCount = ''
            ErrorMessage = 'Test coverage tracking was introduced in module version 1.24.0. This export either predates that version, or its AD_Security_TestCoverage_<timestamp>.json sidecar was not kept alongside the findings JSON being recreated from. This is a limitation of the export itself, not evidence that every check ran cleanly.' | ConvertTo-SafeCsvValue
        } | Export-Csv -Path $coverageOutputPath -NoTypeInformation -Encoding UTF8
        Write-Verbose "Export-ADSecurityReportCSVFromJson: no test coverage sidecar found for '$($findingsFile.Name)' - wrote a coverage CSV with a single explanatory 'NotAvailable' row instead of real per-check data."
    }
}

function Export-ADSecurityReportHTML {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Findings,
        
        [Parameter(Mandatory)]
        [string]$OutputPath,
        
        [Parameter(Mandatory)]
        [string]$Domain,
        
        [Parameter(Mandatory)]
        [hashtable]$Summary,
        
        [Parameter(Mandatory)]
        [timespan]$Duration,
        
        [Parameter()]
        [array]$PrivilegedUsers = $null,

        [Parameter()]
        [PSCustomObject]$RiskScore = $null,

        # General-purpose "this check ran, but against a narrower/
        # different target than its normal assumption" notes
        # (Get-ADRunScopeNotes). So far, populated only when -Server named
        # an explicit, non-PDC Domain Controller and a "PDC-only" check
        # (Test-ADMachineAccountQuota, Test-ADDomainSecurity) ran against
        # it directly. Rendered as a "Run Scope Information" section.
        [Parameter()]
        [array]$RunScopeNotes = @(),

        # Reported gap: neither the HTML nor CSV report gave any
        # indication of which checks did NOT run (excluded via
        # -IncludeTests/-ExcludeTests, or attempted and failed - console-
        # only Write-Warning before this, invisible once you're reading
        # the report later) or which ran and found nothing (a clean
        # result was indistinguishable from "never ran" from the findings
        # list alone). Each entry: TestName, Status ('Completed' |
        # 'Failed' | 'Excluded'), FindingCount, ErrorMessage. Populated by
        # Main.ps1 for a live/snapshot run (covers every entry in
        # $allTests, not just the ones that ran), or recovered from the
        # AD_Security_TestCoverage_<timestamp>.json sidecar by
        # Export-ADSecurityReportHTMLFromJson if that sidecar sits next
        # to the findings JSON being recreated from. Renders a "Test
        # Coverage" section when non-empty; omitted (with a note as to
        # why) when this module version's export predates coverage
        # tracking.
        [Parameter()]
        [array]$TestCoverage = @()
    )
    
    # Second layer of defense (see ConvertTo-ADNormalizedTestCoverage's
    # own docs, Common.ps1) in case -TestCoverage is ever passed directly
    # with a malformed "columnar" shape - e.g. a future caller that
    # doesn't go through Get-ADTestCoverageSidecar, which already applies
    # this same repair for the JSON-rebuild paths.
    $TestCoverage = ConvertTo-ADNormalizedTestCoverage -Coverage $TestCoverage

    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Group findings by severity
    $criticalFindings = $Findings | Where-Object { $_.Severity -eq 'Critical' } | Sort-Object Category
    $highFindings = $Findings | Where-Object { $_.Severity -eq 'High' } | Sort-Object Category
    $mediumFindings = $Findings | Where-Object { $_.Severity -eq 'Medium' } | Sort-Object Category
    $lowFindings = $Findings | Where-Object { $_.Severity -eq 'Low' } | Sort-Object Category
    # Defensive catch-all: every check in this module currently only ever
    # assigns Critical/High/Medium/Low (confirmed by a full source audit),
    # but Get-ADRiskScore already has its own silent fallback for anything
    # else (Scoring.ps1's "default { $sevCounts.Info++ }") - a finding
    # with an unexpected Severity value (a typo, a future check, or a
    # custom finding fed in from outside this module) would still be
    # scored and still appear in the JSON/CSV exports (neither of which
    # filter by severity at all), but would have been completely INVISIBLE
    # in the HTML report - no section anywhere would ever render it, with
    # no warning that anything was missing. Route it into its own section
    # instead of letting it silently disappear, and warn so this is loud
    # rather than silent if it's ever hit.
    $otherFindings = @($Findings | Where-Object { $_.Severity -notin @('Critical', 'High', 'Medium', 'Low') } | Sort-Object Category)
    if ($otherFindings.Count -gt 0) {
        Write-Warning "Export-ADSecurityReportHTML: $($otherFindings.Count) finding(s) have an unexpected Severity value (not Critical/High/Medium/Low) and would have been invisible in the HTML report's severity sections - rendering them in a separate 'Other / Unclassified Severity' section instead. Affected Issue(s): $(($otherFindings | Select-Object -ExpandProperty Issue -Unique) -join '; ')"
    }

    # Computed early (rather than where it's rendered, further down) so the
    # v1.20.1 sticky nav bar can know up front whether a Control Paths link
    # is warranted.
    $controlPathFindings = @($Findings | Where-Object { $_.Category -eq 'Attack Paths' } | Sort-Object -Property @{Expression = { $_.SeverityLevel }; Descending = $true })
    
    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }

    # v1.20.1: sticky mini table-of-contents - only link to sections that
    # will actually render for this run, so it's never a dead link.
    $navLinks = New-Object System.Collections.ArrayList
    [void]$navLinks.Add(@{ Href = '#'; Label = 'Executive Summary' })
    if (@($TestCoverage).Count -gt 0) { [void]$navLinks.Add(@{ Href = '#test-coverage'; Label = 'Test Coverage' }) }
    if ($Findings.Count -gt 0) { [void]$navLinks.Add(@{ Href = '#priority-remediation'; Label = 'Prioritized Remediation' }) }
    if ($RiskScore) { [void]$navLinks.Add(@{ Href = '#risk-score'; Label = 'Risk Score &amp; Maturity' }) }
    if ($controlPathFindings.Count -gt 0) { [void]$navLinks.Add(@{ Href = '#control-paths'; Label = 'Control Paths' }) }
    if ($criticalFindings) { [void]$navLinks.Add(@{ Href = '#critical-findings'; Label = 'Critical' }) }
    if ($highFindings) { [void]$navLinks.Add(@{ Href = '#high-findings'; Label = 'High' }) }
    if ($mediumFindings) { [void]$navLinks.Add(@{ Href = '#medium-findings'; Label = 'Medium' }) }
    if ($lowFindings) { [void]$navLinks.Add(@{ Href = '#low-findings'; Label = 'Low' }) }
    if ($otherFindings.Count -gt 0) { [void]$navLinks.Add(@{ Href = '#other-findings'; Label = 'Other' }) }
    $navLinksHtml = ($navLinks | ForEach-Object { "<a href=`"$($_.Href)`">$($_.Label)</a>" }) -join "`n            "

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Security Assessment Report - $(HtmlEncode $Domain)</title>
    <style>
        :root {
            --font-sans: -apple-system, "Segoe UI", system-ui, Roboto, Helvetica, Arial, sans-serif;
            --font-mono: 'Consolas', 'SFMono-Regular', Menlo, Monaco, monospace;
            --bg: #f4f6f8;
            --surface: #ffffff;
            --ink: #1f2937;
            --ink-muted: #5b6472;
            --border: #e2e6ea;
            --brand: #1f4e79;
            --critical: #b3261e;
            --critical-bg: #fdf1f0;
            --high: #c8590b;
            --high-bg: #fdf5ec;
            --medium: #8a6200;
            --medium-bg: #fdf8ec;
            --low: #5b6472;
            --low-bg: #f4f5f6;
            --good: #1a7f4e;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: var(--font-sans); line-height: 1.6; color: var(--ink); background: var(--bg); padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: var(--surface); padding: 30px; box-shadow: 0 1px 3px rgba(15,23,42,0.08); border-radius: 8px; border: 1px solid var(--border); }
        h1 { color: var(--ink); border-bottom: 3px solid var(--brand); padding-bottom: 15px; margin-bottom: 20px; font-size: 1.7em; }
        h2 { color: var(--ink); margin-top: 30px; margin-bottom: 15px; padding: 10px 14px; background: var(--bg); border-left: 4px solid var(--brand); }
        h3 { color: var(--ink-muted); margin-top: 20px; margin-bottom: 10px; }
        .header-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 30px; padding: 20px; background: var(--bg); border-radius: 5px; border: 1px solid var(--border); }
        .header-info div { padding: 10px; }
        .header-info strong { display: block; color: var(--ink-muted); font-size: 0.9em; margin-bottom: 5px; }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .summary-card { display: block; padding: 22px; border-radius: 8px; text-align: center; text-decoration: none; border: 1px solid var(--border); border-top: 4px solid transparent; background: var(--surface); transition: transform 0.15s ease, box-shadow 0.15s ease; }
        .summary-card:hover { transform: translateY(-2px); box-shadow: 0 4px 10px rgba(15,23,42,0.08); }
        .summary-card-empty { cursor: default; opacity: 0.6; }
        .summary-card-empty:hover { transform: none; box-shadow: none; }
        .summary-card .count { font-size: 2.6em; font-weight: 700; margin-bottom: 6px; color: var(--ink); }
        .summary-card .label { font-size: 0.95em; text-transform: uppercase; letter-spacing: 1px; color: var(--ink-muted); font-weight: 600; }
        .critical-card { border-top-color: var(--critical); }
        .critical-card .count { color: var(--critical); }
        .high-card { border-top-color: var(--high); }
        .high-card .count { color: var(--high); }
        .medium-card { border-top-color: var(--medium); }
        .medium-card .count { color: var(--medium); }
        .low-card { border-top-color: var(--low); }
        .low-card .count { color: var(--low); }
        .finding { margin-bottom: 15px; padding: 20px; border-radius: 5px; border-left: 5px solid; background: var(--surface); border: 1px solid var(--border); border-left-width: 5px; }
        .finding.critical { border-left-color: var(--critical); background: var(--critical-bg); }
        .finding.high { border-left-color: var(--high); background: var(--high-bg); }
        .finding.medium { border-left-color: var(--medium); background: var(--medium-bg); }
        .finding.low { border-left-color: var(--low); background: var(--low-bg); }
        details.finding { padding: 0; }
        details.finding[open] { padding-bottom: 5px; }
        details.finding > summary { list-style: none; cursor: pointer; padding: 20px; }
        details.finding > summary::-webkit-details-marker { display: none; }
        details.finding > summary::before { content: '\25B8'; display: inline-block; margin-right: 10px; color: var(--ink-muted); transition: transform 0.15s ease; }
        details.finding[open] > summary::before { transform: rotate(90deg); }
        .finding-body { padding: 0 20px 15px; }
        .section-toolbar { display: flex; justify-content: flex-end; gap: 10px; margin: -8px 0 10px; }
        .toggle-all-btn { background: var(--bg); border: 1px solid var(--border); color: var(--ink); padding: 5px 12px; border-radius: 4px; font-size: 0.85em; cursor: pointer; }
        .toggle-all-btn:hover { background: #e8ebee; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 10px; }
        .finding-title { font-size: 1.3em; font-weight: 600; color: var(--ink); display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
        .count-badge { display: inline-block; background: var(--bg); color: var(--ink); font-size: 0.6em; font-weight: 700; padding: 3px 10px; border-radius: 12px; vertical-align: middle; letter-spacing: 0.3px; border: 1px solid var(--border); }
        .finding-instance-list { list-style: none; border-top: 1px solid var(--border); margin-top: 5px; max-height: 420px; overflow-y: auto; }
        .finding-instance { padding: 10px 0; border-bottom: 1px solid var(--border); }
        .finding-instance:last-child { border-bottom: none; }
        .finding-instance-object { font-weight: 600; color: var(--ink); font-family: var(--font-mono); font-size: 13px; word-break: break-word; }
        .meta-code { font-family: var(--font-mono); font-size: 13px; color: var(--ink); word-break: break-word; }
        .finding-instance-desc { color: var(--ink-muted); margin-top: 4px; line-height: 1.5; }
        .finding-instance-date { color: var(--ink-muted); font-size: 0.8em; margin-top: 4px; }
        .severity-badge { padding: 6px 15px; border-radius: 20px; font-weight: 700; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; color: #fff; }
        .severity-critical { background: var(--critical); }
        .severity-high { background: var(--high); }
        .severity-medium { background: var(--medium); }
        .severity-low { background: var(--low); }
        .finding-meta { display: flex; gap: 20px; margin-bottom: 15px; font-size: 0.9em; color: var(--ink-muted); flex-wrap: wrap; }
        .finding-meta span { display: flex; align-items: center; }
        .finding-meta strong { margin-right: 5px; color: var(--ink); }
        .finding-section { margin: 15px 0; padding: 15px; background: var(--surface); border-radius: 4px; border: 1px solid var(--border); }
        .finding-section h4 { color: var(--ink-muted); margin-bottom: 10px; font-size: 1em; text-transform: uppercase; letter-spacing: 0.5px; }
        .finding-section p { color: var(--ink); line-height: 1.7; }
        .privileged-users-table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; }
        .privileged-users-table th { background: var(--brand); color: #fff; padding: 12px; text-align: left; font-weight: 600; }
        .privileged-users-table td { padding: 10px; border-bottom: 1px solid var(--border); }
        .privileged-users-table tr:nth-child(even) { background: var(--bg); }
        .privileged-users-table tr:hover { background: #eaf1f8; }
        .status-enabled { color: var(--good); font-weight: bold; }
        .status-disabled { color: var(--critical); font-weight: bold; }
        .footer { margin-top: 50px; padding-top: 20px; border-top: 2px solid var(--border); text-align: center; color: var(--ink-muted); font-size: 0.9em; }
        .warning-box { background: #fdf8ec; border-left: 4px solid var(--medium); padding: 15px; margin: 20px 0; border-radius: 4px; }
        .warning-box p { color: #6b4e00; margin: 5px 0; }

        /* Risk score, maturity & category visuals - inline hand-built SVG, no chart library, no CDN */
        .scoring-grid { display: grid; grid-template-columns: minmax(260px, 1fr) minmax(260px, 1fr); gap: 20px; margin: 20px 0; }
        @media (max-width: 700px) { .scoring-grid { grid-template-columns: 1fr; } }
        .score-panel, .maturity-panel { padding: 25px; border-radius: 8px; background: var(--bg); border: 1px solid var(--border); }
        .gauge-wrap { display: flex; align-items: center; justify-content: center; gap: 20px; flex-wrap: wrap; }
        .gauge-svg-wrap { position: relative; width: 160px; height: 160px; flex: none; }
        .gauge-svg-wrap svg { width: 100%; height: 100%; }
        .gauge-center { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
        .gauge-center .num { font-size: 2.3em; font-weight: 700; color: var(--ink); line-height: 1; }
        .gauge-center .of { font-size: 0.85em; color: var(--ink-muted); }
        .score-meta { color: var(--ink); }
        .score-meta .hint { font-size: 0.85em; color: var(--ink-muted); margin-top: 8px; }
        .maturity-stepper { display: flex; gap: 6px; margin-top: 14px; flex-wrap: wrap; }
        .maturity-chip { flex: 1; min-width: 88px; padding: 8px 6px; border-radius: 4px; background: var(--surface); border: 1px solid var(--border); color: var(--ink-muted); font-size: 0.78em; text-align: center; }
        .maturity-chip .lvl { display: block; font-weight: 700; font-size: 1.15em; }
        .maturity-chip.reached { background: #eaf5ef; border-color: var(--good); color: var(--good); }
        .maturity-chip.current { background: var(--brand); border-color: var(--brand); color: #fff; }
        .maturity-head { font-size: 2.2em; font-weight: 700; color: var(--ink); }
        .maturity-head small { font-size: 0.45em; color: var(--ink-muted); font-weight: normal; }
        .mitre-table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.9em; }
        .mitre-table th { background: var(--brand); color: #fff; padding: 10px; text-align: left; }
        .mitre-table td { padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
        .mitre-table tr:nth-child(even) { background: var(--bg); }
        .mitre-id { font-family: var(--font-mono); font-size: 13px; color: var(--brand); font-weight: 600; }
        .mitre-bar-cell { display: flex; align-items: center; gap: 8px; }
        .mitre-bar-track { display: block; width: 100px; height: 10px; background: var(--border); border-radius: 5px; overflow: hidden; flex: none; }
        .mitre-bar-fill { display: block; height: 100%; background: var(--brand); border-radius: 5px; }
        .tag-mitre { font-family: var(--font-mono); font-size: 12px; background: #eaf2f8; color: #2471a3; padding: 2px 6px; border-radius: 3px; }
        .tag-anssi { font-family: var(--font-mono); font-size: 12px; background: #f4ecf7; color: #6c3483; padding: 2px 6px; border-radius: 3px; }

        /* v1.20.2: one shared style for path/command-style code content
           (currently just the control-path hop chain), so it reads as a
           distinct "code block" rather than a plain paragraph that happens
           to use a monospace font. Same --font-mono/size as the inline
           mono elements above, for a consistent code type scale throughout. */
        .code-block { font-family: var(--font-mono); font-size: 13px; line-height: 1.6; color: var(--ink); background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; word-break: break-word; }

        /* Prioritized remediation order */
        .priority-list { list-style: none; margin: 15px 0; }
        .priority-item { display: grid; grid-template-columns: 34px 1fr auto; align-items: center; gap: 14px; padding: 12px 14px; border: 1px solid var(--border); border-radius: 6px; margin-bottom: 8px; background: var(--surface); }
        .priority-rank { font-weight: 700; color: var(--ink-muted); font-size: 1.2em; text-align: center; }
        .priority-item a { color: var(--ink); text-decoration: none; font-weight: 600; }
        .priority-item a:hover { text-decoration: underline; }
        .priority-cat { color: var(--ink-muted); font-size: 0.85em; font-weight: 400; display: block; margin-top: 2px; }

        /* Control path diagram */
        .control-path-diagram { margin: 10px 0 4px; }
        .control-path-diagram svg { width: 100%; height: auto; max-width: 640px; display: block; }

        /* v1.20.2: without an explicit max-width, this SVG's viewBox
           (700 units wide) stretched to fill the full container width
           (~1300px+), inflating every font-size/stroke in it by ~1.9x -
           this is why "Risk by Category" text rendered oversized relative
           to the rest of the report. Capping at 700px keeps 1 viewBox unit
           equal to 1 real pixel, matching the size the text was authored at. */
        .category-bars-svg svg { width: 100%; height: auto; max-width: 700px; display: block; }

        @media print {
            body { background: white; padding: 0; }
            .container { box-shadow: none; border: none; }
            .toggle-all-btn { display: none; }
            .no-print { display: none !important; }
            .report-nav { position: static !important; }
        }

        /* v1.20.1: severity dots replacing emoji on section headings - a
           solid color square carries the same at-a-glance severity cue
           without relying on emoji glyph support/rendering consistency. */
        .sev-dot { display: inline-block; width: 11px; height: 11px; border-radius: 2px; margin-right: 10px; vertical-align: middle; }
        .sev-dot-critical { background: var(--critical); }
        .sev-dot-high { background: var(--high); }
        .sev-dot-medium { background: var(--medium); }
        .sev-dot-low { background: var(--low); }

        /* v1.20.1: sticky mini table-of-contents so a leadership reader can
           jump straight to the risk picture and an IT reader can jump
           straight to evidence, without scrolling or using find-in-page. */
        .report-nav { position: sticky; top: 0; z-index: 10; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; margin-bottom: 20px; display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
        .report-nav-links { display: flex; gap: 4px; flex-wrap: wrap; flex: 1; }
        .report-nav a { color: var(--ink); text-decoration: none; font-size: 0.85em; font-weight: 600; padding: 6px 10px; border-radius: 4px; }
        .report-nav a:hover { background: var(--bg); }
        .print-btn { background: var(--brand); color: #fff; border: none; padding: 8px 14px; border-radius: 4px; font-size: 0.85em; font-weight: 600; cursor: pointer; flex: none; }
        .print-btn:hover { background: #163d5f; }

        /* v1.20.1: divider between the leadership-facing front section
           (Executive Summary through Control Paths) and the full technical
           finding-by-finding detail that follows. */
        .section-divider { margin: 40px 0 10px; border: none; border-top: 2px solid var(--border); }
        .section-divider-label { text-align: center; margin-top: -13px; }
        .section-divider-label span { background: var(--surface); padding: 0 16px; color: var(--ink-muted); font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 700; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Active Directory Security Assessment Report</h1>
        
        <div class="warning-box">
            <p><strong>CONFIDENTIAL SECURITY REPORT</strong></p>
            <p>This report contains sensitive security information about your Active Directory environment. Handle with care and share only with authorized personnel.</p>
        </div>
$(if (@($RunScopeNotes).Count -gt 0) {
@"
        <div class="warning-box" style="background:#eef3fb; border-color:#2f5fa8;">
            <p><strong>RUN SCOPE INFORMATION</strong> - $(@($RunScopeNotes).Count) note(s) about how this run was scoped that may affect how to read specific findings below.</p>
            <table class="mitre-table">
                <tr><th>Category</th><th>Note</th></tr>
$(($RunScopeNotes | Sort-Object Category | ForEach-Object {
    "                <tr><td>$(HtmlEncode $_.Category)</td><td>$(HtmlEncode $_.Message)</td></tr>"
}) -join "`n")
            </table>
        </div>
"@
})
$(if (@($TestCoverage).Count -gt 0) {
    $tcSorted = @($TestCoverage | Sort-Object TestName)
    if ($tcSorted.Count -eq 0) {
        # Safety net: $TestCoverage had entries, but Sort-Object somehow
        # produced none (e.g. every entry's TestName came back $null,
        # which Sort-Object -Property silently drops rather than erroring
        # on). Rendering nothing here would otherwise look identical to
        # the intentional "Test Coverage Not Available" note elsewhere -
        # this is a DIFFERENT, unexpected case (coverage data existed but
        # something about its shape broke rendering), so it gets its own
        # explicit, honest message instead of a table with a header row
        # and no data, or silently vanishing.
@"
        <div class="warning-box" style="background:#fdf8ec; border-color:#8a6200;" id="test-coverage">
            <p><strong>TEST COVERAGE</strong> - $(@($TestCoverage).Count) coverage entry(ies) were present for this run, but could not be rendered as a per-check list (their data did not match the expected shape even after automatic repair). This is unexpected - if you can, please keep the raw AD_Security_TestCoverage_*.json for this run so the cause can be investigated.</p>
        </div>
"@
    }
    else {
    $tcCompleted = @($tcSorted | Where-Object { $_.Status -eq 'Completed' })
    $tcPassed = @($tcCompleted | Where-Object { $_.FindingCount -eq 0 })
    $tcWithFindings = @($tcCompleted | Where-Object { $_.FindingCount -gt 0 })
    $tcFailed = @($tcSorted | Where-Object { $_.Status -eq 'Failed' })
    $tcExcluded = @($tcSorted | Where-Object { $_.Status -eq 'Excluded' })
    $tcUntested = $tcFailed.Count + $tcExcluded.Count
@"
        <details class="warning-box" style="background:#f2f7ee; border-color:#3f7d3f;" id="test-coverage">
            <summary style="cursor:pointer; margin:-4px -4px 0 -4px; padding:4px;"><strong>TEST COVERAGE</strong> - $($tcSorted.Count) check(s) tracked for this run: <strong>$($tcPassed.Count) passed clean</strong> (ran, found nothing), $($tcWithFindings.Count) found issue(s), and <strong>$tcUntested untested</strong> ($($tcFailed.Count) failed, $($tcExcluded.Count) excluded). Click to expand the full per-check list.</summary>
            <p style="margin-top:10px;">"Passed clean" means the check actually ran and found nothing to report - not that it wasn't checked; "untested" checks (failed or excluded) contributed zero findings either way and should not be read as clean.</p>
            <table class="mitre-table">
                <tr><th>Check</th><th>Status</th><th>Findings</th><th>Detail</th></tr>
$(($tcSorted | ForEach-Object {
    # Deliberately NOT using $_ inside the switch clause bodies below:
    # `switch` rebinds $_ within its own clauses to the value currently
    # being matched (here, the STRING $_.Status, e.g. "Completed") - not
    # the original piped object. $_.FindingCount inside a switch clause
    # would silently resolve against that string instead (no error, just
    # $null), always taking the "0 findings" branch and always rendering
    # the ErrorMessage/TestName columns blank regardless of the real
    # data. Capturing the object into $entry first and reading BOTH the
    # switch subject and every field off $entry avoids the rebind.
    $entry = $_
    $statusBadge = switch ($entry.Status) {
        'Completed' {
            if ($entry.FindingCount -gt 0) { '<span style="background:#c8590b;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.85em;">COMPLETED</span>' }
            else { '<span style="background:#3f7d3f;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.85em;">CLEAN</span>' }
        }
        'Failed' { '<span style="background:#b3261e;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.85em;">FAILED</span>' }
        'Excluded' { '<span style="background:#5b6472;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.85em;">EXCLUDED</span>' }
        default { HtmlEncode $entry.Status }
    }
    $detail = switch ($entry.Status) {
        'Failed' { HtmlEncode $entry.ErrorMessage }
        'Excluded' { 'Not run for this scan (see -IncludeTests/-ExcludeTests used for this run).' }
        default { '&nbsp;' }
    }
    "                <tr><td>$(HtmlEncode $entry.TestName)</td><td>$statusBadge</td><td>$($entry.FindingCount)</td><td>$detail</td></tr>"
}) -join "`n")
            </table>
            <p style="margin-top:10px; font-size:0.9em; color:#5b6472;">"Excluded" checks were deliberately left out of this run's scope; "Failed" checks were attempted but errored before producing a result (see Detail) and contributed zero findings either way - neither should be read as "checked and clean".</p>
        </details>
"@
    }
})
        
        <div class="header-info">
            <div><strong>DOMAIN</strong><span style="font-size: 1.2em; color: #1f2937;">$(HtmlEncode $Domain)</span></div>
            <div><strong>REPORT DATE</strong><span style="font-size: 1.2em; color: #1f2937;">$reportDate</span></div>
            <div><strong>SCAN DURATION</strong><span style="font-size: 1.2em; color: #1f2937;">$([math]::Round($Duration.TotalSeconds, 2)) seconds</span></div>
            <div><strong>TOTAL FINDINGS</strong><span style="font-size: 1.2em; color: #1f2937;">$($Findings.Count)</span></div>
        </div>

        <nav class="report-nav no-print" aria-label="Report sections">
            <div class="report-nav-links">
            $navLinksHtml
            </div>
            <button type="button" class="print-btn" onclick="window.print()">Print / Save as PDF</button>
        </nav>

        <h2 id="executive-summary">Executive Summary</h2>
        <div class="summary-cards">
            <a class="summary-card critical-card$(if (-not $criticalFindings) { ' summary-card-empty' })" href="$(if ($criticalFindings) { '#critical-findings' } else { '#' })">
                <div class="count">$($Summary.Critical)</div>
                <div class="label">Critical</div>
            </a>
            <a class="summary-card high-card$(if (-not $highFindings) { ' summary-card-empty' })" href="$(if ($highFindings) { '#high-findings' } else { '#' })">
                <div class="count">$($Summary.High)</div>
                <div class="label">High</div>
            </a>
            <a class="summary-card medium-card$(if (-not $mediumFindings) { ' summary-card-empty' })" href="$(if ($mediumFindings) { '#medium-findings' } else { '#' })">
                <div class="count">$($Summary.Medium)</div>
                <div class="label">Medium</div>
            </a>
            <a class="summary-card low-card$(if (-not $lowFindings) { ' summary-card-empty' })" href="$(if ($lowFindings) { '#low-findings' } else { '#' })">
                <div class="count">$($Summary.Low)</div>
                <div class="label">Low</div>
            </a>
        </div>
"@

    # --- Prioritized Remediation Order ---
    # Presentation-only: sorts the *already computed* findings/category scores;
    # no new scoring logic. Severity first (worst first), then that finding's
    # category sub-score (worst category first) as a tie-breaker, then the
    # number of affected objects. Links each item to its full evidence in the
    # severity-grouped sections below via a stable per-finding anchor id.
    $priorityCategoryScores = if ($RiskScore -and $RiskScore.CategoryScores) { $RiskScore.CategoryScores } else { @() }
    $priorityListHtml = Get-ADPriorityListHTML -Findings $Findings -CategoryScores $priorityCategoryScores -Top 10
    if ($priorityListHtml) {
        $html += @"
        <h2 id="priority-remediation">Prioritized Remediation Order</h2>
        <p style="color:#5b6472; margin-bottom: 10px;">The findings below are ranked worst-first - by severity, then by how risky their category is overall - as a starting work order. This is a starting point for planning, not a replacement for reviewing every finding.</p>
$priorityListHtml
"@
    }

    # --- Risk score, ANSSI maturity & MITRE ATT&CK summary (v1.2.0) ---
    if ($RiskScore) {
        $score = [int]$RiskScore.TotalScore
        # Color the gauge by severity band (higher = worse) - same bands used
        # for the category bars below, so the palette only has to be learned once.
        $gaugeColor = if ($score -ge 75) { '#b3261e' }
                      elseif ($score -ge 50) { '#c8590b' }
                      elseif ($score -ge 25) { '#8a6200' }
                      else { '#1a7f4e' }

        $maturityLevel = [int]$RiskScore.MaturityLevel
        $gaugeSvg = Get-ADSvgGauge -Score $score -Color $gaugeColor

        $html += @"
        <h2 id="risk-score">Risk Score &amp; Maturity</h2>
        <div class="scoring-grid">
            <div class="score-panel">
                <h3>Global Risk Score</h3>
                <div class="gauge-wrap">
                    $gaugeSvg
                    <div class="score-meta">
                        <p><strong>$($RiskScore.FindingCount)</strong> findings scored.</p>
                        <p>Higher is worse. The global score equals the worst category's score - a category is only ever as strong as its weakest one - similar in spirit to PingCastle's approach.</p>
                        <p class="hint">Each category's score approaches 100 as findings accumulate, using diminishing returns per finding (a single Critical won't max out a category by itself). Raw weighted points across all findings: $($RiskScore.WeightedPoints)</p>
                    </div>
                </div>
            </div>
            <div class="maturity-panel">
                <h3>ANSSI Maturity Level</h3>
                <div class="maturity-head">$maturityLevel <small>/ 5</small></div>
                <p style="color:#1f2937; margin: 6px 0 4px;">$(HtmlEncode $RiskScore.MaturityLabel)</p>
                <div class="maturity-stepper">
"@
        foreach ($lvl in 1..5) {
            $cls = 'maturity-chip'
            if ($lvl -eq $maturityLevel) { $cls = 'maturity-chip current' }
            elseif ($lvl -lt $maturityLevel) { $cls = 'maturity-chip reached' }
            $labelMap = @{
                1 = 'Critical gaps'
                2 = 'Partial hygiene'
                3 = 'Standard hardening'
                4 = 'Advanced hardening'
                5 = 'Optimal'
            }
            $html += @"
                    <div class="$cls"><span class="lvl">$lvl</span><span>$($labelMap[$lvl])</span></div>
"@
        }
        $html += @"
                </div>
                <p class="hint" style="font-size:0.85em; color:#5b6472; margin-top:10px;">A single Level&nbsp;1 finding caps maturity at Level&nbsp;1. Lower level = more critical hygiene gaps remain.</p>
            </div>
        </div>
"@

        # Per-category sub-score bars - rendered as one inline SVG chart
        # (worst category first, same severity-band coloring as the gauge).
        if ($RiskScore.CategoryScores -and $RiskScore.CategoryScores.Count -gt 0) {
            $categoryBarsSvg = Get-ADSvgCategoryBars -CategoryScores $RiskScore.CategoryScores
            $html += @"
        <h3>Risk by Category</h3>
        <div class="category-bars-svg" style="margin: 10px 0 20px;">
$categoryBarsSvg
        </div>
"@
        }

        # MITRE ATT&CK technique summary
        if ($RiskScore.MitreSummary -and $RiskScore.MitreSummary.Count -gt 0) {
            $mitreMaxCount = ($RiskScore.MitreSummary | Measure-Object -Property Count -Maximum).Maximum
            if ($mitreMaxCount -le 0) { $mitreMaxCount = 1 }
            $html += @"
        <h3>MITRE ATT&amp;CK Technique Summary</h3>
        <div style="overflow-x: auto;">
            <table class="mitre-table">
                <thead><tr><th>Technique</th><th>Name</th><th>Findings</th></tr></thead>
                <tbody>
"@
            foreach ($t in $RiskScore.MitreSummary) {
                $barPct = [math]::Round(($t.Count / $mitreMaxCount) * 100, 0)
                $html += @"
                    <tr>
                        <td class="mitre-id">$(HtmlEncode $t.Technique)</td>
                        <td>$(HtmlEncode $t.Name)</td>
                        <td><div class="mitre-bar-cell"><span class="mitre-bar-track"><span class="mitre-bar-fill" style="width: $barPct%;"></span></span><span>$($t.Count)</span></div></td>
                    </tr>
"@
            }
            $html += @"
                </tbody>
            </table>
        </div>
"@
        }
    }

    if ($PrivilegedUsers -and $PrivilegedUsers.Count -gt 0) {
        $html += @"
        <h2>Privileged Users Summary</h2>
        <p style="margin-bottom: 15px; color: #5b6472;">The following $($PrivilegedUsers.Count) user accounts have membership in one or more privileged groups. Review these accounts regularly to ensure appropriate access levels.</p>
        <div style="overflow-x: auto;">
            <table class="privileged-users-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Display Name</th>
                        <th>Enabled</th>
                        <th>Privileged Groups</th>
                        <th>Password Last Set</th>
                        <th>Last Logon</th>
                        <th>Security Flags</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($user in ($PrivilegedUsers | Sort-Object -Property @{Expression={$_.PrivilegedGroups.Count}; Descending=$true}, SamAccountName)) {
            $enabledClass = if ($user.Enabled) { 'status-enabled' } else { 'status-disabled' }
            $enabledText = if ($user.Enabled) { 'Yes' } else { 'No' }
            
            $securityFlags = @()
            if ($user.PasswordNeverExpires) { $securityFlags += 'Pwd Never Expires' }
            if ($user.DoesNotRequirePreAuth) { $securityFlags += 'No PreAuth' }
            if ($user.TrustedForDelegation) { $securityFlags += 'Delegation' }
            if ($user.HasSPN) { $securityFlags += "SPN($($user.SPNCount))" }
            $flagsText = if ($securityFlags.Count -gt 0) { HtmlEncode ($securityFlags -join ', ') } else { '-' }
            
            $passwordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'Never' }
            $lastLogon = if ($user.LastLogonDate) { $user.LastLogonDate.ToString('yyyy-MM-dd') } else { 'Never' }
            
            $html += @"
                    <tr>
                        <td><strong>$(HtmlEncode $user.SamAccountName)</strong></td>
                        <td>$(HtmlEncode $user.DisplayName)</td>
                        <td class="$enabledClass">$enabledText</td>
                        <td style="font-size: 0.85em;">$(HtmlEncode $user.PrivilegedGroupsString)</td>
                        <td>$passwordLastSet</td>
                        <td>$lastLogon</td>
                        <td style="font-size: 0.85em;">$flagsText</td>
                    </tr>
"@
        }
        
        $html += @"
                </tbody>
            </table>
        </div>
"@
    }

    # --- Control paths to Tier-0 (v1.16.0) ---
    if ($controlPathFindings.Count -gt 0) {
        $html += @"
        <h2 id="control-paths">Control Paths to Tier-0</h2>
        <p style="color:#5b6472; margin-bottom: 15px;">Chained group-membership, ACL, and ownership relationships that let a non-privileged principal reach a Tier-0 object (Domain Admins/DCs/AdminSDHolder/domain head). No single hop here need look critical on its own - see each finding below for full remediation guidance.</p>
"@
        foreach ($cp in $controlPathFindings) {
            $sevClass = $cp.Severity.ToLower()
            # Test-ADFindingDetailsKey, not a bare .Details.ContainsKey():
            # the latter only exists on a real Hashtable, which Details
            # always is during a live run - but NOT after a JSON
            # round-trip (Export-ADSecurityReportHTMLFromJson), where
            # ConvertFrom-Json turns Details into a PSCustomObject
            # instead. See Test-ADFindingDetailsKey's own docs (Common.ps1)
            # for the reported "does not contain a method named
            # 'ContainsKey'" error this fixes.
            $hopChain = if ($cp.Details -and (Test-ADFindingDetailsKey -Details $cp.Details -Key 'HopChain')) { HtmlEncode "$($cp.Details.HopChain)" } else { HtmlEncode $cp.AffectedObject }
            $diagramSvg = ''
            if ($cp.Details -and (Test-ADFindingDetailsKey -Details $cp.Details -Key 'Source') -and (Test-ADFindingDetailsKey -Details $cp.Details -Key 'Target')) {
                $diagramColor = if ($sevClass -eq 'critical') { '#b3261e' } else { '#c8590b' }
                $hopCountForDiagram = if (Test-ADFindingDetailsKey -Details $cp.Details -Key 'HopCount') { [int]$cp.Details.HopCount } else { 1 }
                $diagramSvg = Get-ADSvgControlPathDiagram -Source "$($cp.Details.Source)" -Target "$($cp.Details.Target)" -HopCount $hopCountForDiagram -Color $diagramColor
            }
            $html += @"
        <div class="finding $sevClass" style="border-left-width: 5px;">
            <div class="finding-header">
                <div class="finding-title">$(HtmlEncode $cp.Issue)</div>
                <span class="severity-badge severity-$sevClass">$($cp.Severity)</span>
            </div>
$diagramSvg
            <div class="finding-section">
                <h4>Hop Chain</h4>
                <p class="code-block">$hopChain</p>
            </div>
        </div>
"@
        }
    }

    # Add findings by severity
    if ($criticalFindings -or $highFindings -or $mediumFindings -or $lowFindings) {
        $html += @"
        <hr class="section-divider">
        <div class="section-divider-label"><span>Technical Findings - Full Detail</span></div>
"@
    }
    if ($criticalFindings) {
        $html += @"
    <h2 id="critical-findings"><span class="sev-dot sev-dot-critical"></span>Critical Severity Findings</h2>
    <div class="section-toolbar">
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('critical-findings', true)">Expand All</button>
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('critical-findings', false)">Collapse All</button>
    </div>
    <div id="critical-findings-body">
"@
        $groups = @($criticalFindings | Group-Object -Property Category, Issue)
        foreach ($group in $groups) {
            $html += Get-FindingHTML -FindingGroup $group.Group
        }
        $html += "    </div>"
    }
    
    if ($highFindings) {
        $html += @"
    <h2 id="high-findings"><span class="sev-dot sev-dot-high"></span>High Severity Findings</h2>
    <div class="section-toolbar">
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('high-findings', true)">Expand All</button>
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('high-findings', false)">Collapse All</button>
    </div>
    <div id="high-findings-body">
"@
        $groups = @($highFindings | Group-Object -Property Category, Issue)
        foreach ($group in $groups) {
            $html += Get-FindingHTML -FindingGroup $group.Group
        }
        $html += "    </div>"
    }
    
    if ($mediumFindings) {
        $html += @"
    <h2 id="medium-findings"><span class="sev-dot sev-dot-medium"></span>Medium Severity Findings</h2>
    <div class="section-toolbar">
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('medium-findings', true)">Expand All</button>
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('medium-findings', false)">Collapse All</button>
    </div>
    <div id="medium-findings-body">
"@
        $groups = @($mediumFindings | Group-Object -Property Category, Issue)
        foreach ($group in $groups) {
            $html += Get-FindingHTML -FindingGroup $group.Group
        }
        $html += "    </div>"
    }
    
    if ($lowFindings) {
        $html += @"
    <h2 id="low-findings"><span class="sev-dot sev-dot-low"></span>Low Severity Findings</h2>
    <div class="section-toolbar">
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('low-findings', true)">Expand All</button>
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('low-findings', false)">Collapse All</button>
    </div>
    <div id="low-findings-body">
"@
        $groups = @($lowFindings | Group-Object -Property Category, Issue)
        foreach ($group in $groups) {
            $html += Get-FindingHTML -FindingGroup $group.Group
        }
        $html += "    </div>"
    }

    if ($otherFindings.Count -gt 0) {
        $html += @"
    <h2 id="other-findings"><span class="sev-dot" style="background:#5b6472;"></span>Other / Unclassified Severity Findings</h2>
    <p style="color:#5b6472; font-size:0.9em; margin-top:-8px;">These findings have a Severity value other than Critical/High/Medium/Low - see the console warning from this run for which check(s) produced them. They are NOT missing findings; they are shown here specifically so an unexpected severity value can never make a finding disappear from this report.</p>
    <div class="section-toolbar">
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('other-findings', true)">Expand All</button>
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('other-findings', false)">Collapse All</button>
    </div>
    <div id="other-findings-body">
"@
        $groups = @($otherFindings | Group-Object -Property Category, Issue)
        foreach ($group in $groups) {
            $html += Get-FindingHTML -FindingGroup $group.Group
        }
        $html += "    </div>"
    }
    
    $html += @"
        <div class="footer">
            <p><strong>Generated by ADSecurityAudit Module v$($script:ModuleVersion)</strong></p>
            <p>This report should be treated as confidential and shared only with authorized personnel.</p>
            <p>Review findings, prioritize remediation by severity, and implement security best practices.</p>
        </div>
    </div>
    <script>
        // Expand All / Collapse All toggles a section's <details> elements.
        // Each finding is a native <details>, collapsed by default; this
        // just flips the `open` attribute on every one inside the section.
        function setSectionFindings(sectionId, isOpen) {
            var container = document.getElementById(sectionId + '-body');
            if (!container) { return; }
            var items = container.querySelectorAll('details.finding');
            for (var i = 0; i < items.length; i++) {
                items[i].open = isOpen;
            }
        }
    </script>
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

#region Report visual components (v1.20.0)
# Presentation-only helpers: each renders an already-computed value
# (RiskScore fields, Finding fields) as inline SVG or HTML. None of these
# perform any new scoring, detection, or AD query - see Feature 16
# (html-report-visual-overhaul) for the design rationale. No chart library
# or external asset is used anywhere in this region.

function Get-ADFindingAnchorId {
    <#
    .SYNOPSIS
        Builds a stable, URL-safe anchor id for a Category+Issue pair so the
        Prioritized Remediation Order list can link straight to a finding's
        full evidence in the severity-grouped sections below it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Category,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Issue
    )
    $slug = ("$Category-$Issue").ToLower()
    $slug = [System.Text.RegularExpressions.Regex]::Replace($slug, '[^a-z0-9]+', '-')
    $slug = $slug.Trim('-')
    if ([string]::IsNullOrEmpty($slug)) { $slug = 'finding' }
    return "finding-$slug"
}

function Get-ADTruncateLabel {
    <#
    .SYNOPSIS
        Truncates a label to approximately fit a fixed-width SVG <text>
        element (which doesn't wrap or measure itself). A character-count
        approximation, not exact - intended to stop egregious overflow, not
        guarantee pixel-perfect fit for every font/browser.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][int]$MaxChars
    )
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    if ($Text.Length -le $MaxChars) { return $Text }
    if ($MaxChars -le 1) { return $Text.Substring(0, [Math]::Max($MaxChars, 0)) }
    return $Text.Substring(0, $MaxChars - 1).TrimEnd() + [char]0x2026
}

function Get-ADSvgGauge {
    <#
    .SYNOPSIS
        Renders a 0-100 score as a self-contained inline SVG ring gauge: two
        <circle> elements (a light track and a colored progress ring) using
        stroke-dasharray for the arc length. No canvas, no chart library.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Score,
        [Parameter(Mandatory)][string]$Color
    )
    $clamped = [math]::Max(0, [math]::Min(100, $Score))
    $radius = 70
    $circumference = [math]::Round(2 * [math]::PI * $radius, 2)
    $dash = [math]::Round($circumference * ($clamped / 100.0), 2)
    $gap = [math]::Round($circumference - $dash, 2)
    return @"
<div class="gauge-svg-wrap">
    <svg viewBox="0 0 160 160" role="img" aria-label="Risk score $clamped out of 100">
        <circle cx="80" cy="80" r="$radius" fill="none" stroke="#e2e6ea" stroke-width="14" />
        <circle cx="80" cy="80" r="$radius" fill="none" stroke="$Color" stroke-width="14"
                stroke-linecap="round" stroke-dasharray="$dash $gap"
                transform="rotate(-90 80 80)" />
    </svg>
    <div class="gauge-center">
        <div class="num">$clamped</div>
        <div class="of">/ 100</div>
    </div>
</div>
"@
}

function Get-ADSvgCategoryBars {
    <#
    .SYNOPSIS
        Renders per-category risk sub-scores (already sorted worst-first by
        the caller) as a single horizontal inline SVG bar chart, using the
        same severity-band coloring as the global gauge.
    .NOTES
        Category name labels are drawn as SVG <text> at a fixed font size and
        are not measured/wrapped - very long category names may visually
        crowd the bar for that row. Acceptable for the category names in use
        today; revisit if a much longer category name is introduced.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$CategoryScores
    )
    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }
    function Get-BandColor([int]$s) {
        if ($s -ge 75) { return '#b3261e' }
        elseif ($s -ge 50) { return '#c8590b' }
        elseif ($s -ge 25) { return '#8a6200' }
        else { return '#1a7f4e' }
    }

    $rowHeight  = 34
    $chartWidth = 700
    $labelWidth = 230
    $barAreaW   = $chartWidth - $labelWidth - 60
    $height     = ($rowHeight * @($CategoryScores).Count) + 10

    $rowsSvg = ''
    $y = 4
    foreach ($cat in $CategoryScores) {
        $score = [int]$cat.Score
        $barW  = [math]::Round(($score / 100.0) * $barAreaW, 1)
        if ($barW -lt 2 -and $score -gt 0) { $barW = 2 }
        $color = Get-BandColor $score
        # ~7.2px/char at this font-size; reserve room for the " (NN)" suffix
        # so the finding count is never the part that gets truncated.
        $maxCategoryChars = [math]::Max(8, [math]::Floor($labelWidth / 7.2) - 6)
        $categoryLabel = Get-ADTruncateLabel -Text "$($cat.Category)" -MaxChars $maxCategoryChars
        $fullLabelForTitle = HtmlEncode "$($cat.Category) ($($cat.Findings) finding$(if ($cat.Findings -ne 1) { 's' }))"
        $label = HtmlEncode "$categoryLabel ($($cat.Findings))"
        $textY = $y + 20
        $numX  = $labelWidth + $barAreaW + 10
        $rowsSvg += @"
    <g><title>$fullLabelForTitle</title>
    <text x="0" y="$textY" font-size="12.5" fill="#1f2937" font-family="-apple-system,Segoe UI,sans-serif">$label</text>
    <rect x="$labelWidth" y="$y" width="$barAreaW" height="22" rx="4" fill="#e2e6ea" />
    <rect x="$labelWidth" y="$y" width="$barW" height="22" rx="4" fill="$color" />
    <text x="$numX" y="$textY" font-size="13" font-weight="700" fill="#1f2937" font-family="-apple-system,Segoe UI,sans-serif">$score</text>
    </g>

"@
        $y += $rowHeight
    }

    return @"
<svg viewBox="0 0 $chartWidth $height" role="img" aria-label="Risk score by category">
$rowsSvg
</svg>
"@
}

function Get-ADSvgControlPathDiagram {
    <#
    .SYNOPSIS
        Renders a simplified 3-node diagram (source -> N hops -> Tier-0
        target) for a single control-path finding. This is an at-a-glance
        summary, not a replacement for the full hop-by-hop chain, which
        remains available as text (Details.HopChain) directly below it.
    .NOTES
        Source/Target labels are drawn as fixed-size SVG <text> and are not
        measured or truncated - very long object names may overflow their box
        visually. The authoritative text remains the hop-chain paragraph
        below the diagram.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][int]$HopCount,
        [Parameter(Mandatory)][string]$Color
    )
    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }
    # ~7.5px/char at this font-size against a ~200px usable box width.
    $maxNodeChars = 26
    $srcFull = HtmlEncode $Source
    $tgtFull = HtmlEncode $Target
    $srcLabel = HtmlEncode (Get-ADTruncateLabel -Text $Source -MaxChars $maxNodeChars)
    $tgtLabel = HtmlEncode (Get-ADTruncateLabel -Text $Target -MaxChars $maxNodeChars)
    $hopLabel = if ($HopCount -eq 1) { '1 hop' } else { "$HopCount hops" }

    return @"
        <div class="control-path-diagram">
        <svg viewBox="0 0 640 90" role="img" aria-label="$srcFull to $tgtFull via $hopLabel">
            <g><title>$srcFull</title>
            <rect x="4" y="24" width="220" height="42" rx="6" fill="#f4f6f8" stroke="#e2e6ea" />
            <text x="114" y="50" font-size="13" text-anchor="middle" fill="#1f2937" font-family="-apple-system,Segoe UI,sans-serif">$srcLabel</text>
            </g>
            <line x1="228" y1="45" x2="404" y2="45" stroke="$Color" stroke-width="3" />
            <polygon points="404,38 418,45 404,52" fill="$Color" />
            <text x="316" y="34" font-size="12" text-anchor="middle" fill="$Color" font-weight="700" font-family="-apple-system,Segoe UI,sans-serif">$hopLabel</text>
            <g><title>$tgtFull</title>
            <rect x="418" y="24" width="218" height="42" rx="6" fill="#fdf1f0" stroke="$Color" />
            <text x="527" y="50" font-size="13" text-anchor="middle" fill="#1f2937" font-weight="700" font-family="-apple-system,Segoe UI,sans-serif">$tgtLabel</text>
            </g>
        </svg>
        </div>
"@
}

function Get-ADPriorityListHTML {
    <#
    .SYNOPSIS
        Builds the "Prioritized Remediation Order" list: the existing
        findings, grouped and sorted worst-first (by severity, then by that
        finding's category risk score, then by affected-object count), linked
        to their full evidence via Get-ADFindingAnchorId. No new scoring.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Findings,
        [Parameter()][array]$CategoryScores = @(),
        [Parameter()][int]$Top = 10
    )
    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }

    if (-not $Findings -or @($Findings).Count -eq 0) { return '' }

    $catScoreMap = @{}
    foreach ($c in $CategoryScores) { $catScoreMap[$c.Category] = [int]$c.Score }

    $groups = @($Findings | Group-Object -Property Category, Issue)
    $ranked = foreach ($g in $groups) {
        $first = $g.Group[0]
        $catScore = if ($catScoreMap.ContainsKey($first.Category)) { $catScoreMap[$first.Category] } else { 0 }
        [PSCustomObject]@{
            Category      = $first.Category
            Issue         = $first.Issue
            Severity      = $first.Severity
            SeverityLevel = [int]$first.SeverityLevel
            CategoryScore = $catScore
            Count         = $g.Count
            AnchorId      = Get-ADFindingAnchorId -Category $first.Category -Issue $first.Issue
        }
    }
    $ranked = @($ranked | Sort-Object -Property SeverityLevel, CategoryScore, Count -Descending | Select-Object -First $Top)
    if ($ranked.Count -eq 0) { return '' }

    $rank = 0
    $items = foreach ($r in $ranked) {
        $rank++
        $sevClass = $r.Severity.ToLower()
        $objWord = if ($r.Count -eq 1) { 'object' } else { 'objects' }
        @"
    <li class="priority-item">
        <span class="priority-rank">$rank</span>
        <a href="#$($r.AnchorId)">$(HtmlEncode $r.Issue)<span class="priority-cat">$(HtmlEncode $r.Category) &middot; $($r.Count) affected $objWord</span></a>
        <span class="severity-badge severity-$sevClass">$($r.Severity)</span>
    </li>
"@
    }
    return @"
<ol class="priority-list">
$($items -join "`n")
</ol>
"@
}

#endregion

function Get-FindingHTML {
    [CmdletBinding()]
    param(
        # One or more findings sharing the same Category + Issue (and, since
        # they came from the same severity bucket, the same Severity too).
        # Grouping happens in the caller via `Group-Object -Property
        # Category, Issue`; this function renders either the original
        # single-item layout (Count -eq 1, unchanged from prior versions)
        # or a consolidated layout with one shared Impact/Remediation and a
        # list of every affected object underneath (Count -gt 1), instead
        # of duplicating the same finding once per affected object.
        [Parameter(Mandatory)]
        [array]$FindingGroup
    )
    
    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }
    
    $FindingGroup = @($FindingGroup)
    $first = $FindingGroup[0]
    $count = $FindingGroup.Count

    $severityClass = $first.Severity.ToLower()
    $impact = HtmlEncode $first.Impact
    $remediation = HtmlEncode $first.Remediation
    $issue = HtmlEncode $first.Issue
    $category = HtmlEncode $first.Category
    $anchorId = Get-ADFindingAnchorId -Category $first.Category -Issue $first.Issue

    # Defensive fallback: every field below should be populated by the audit
    # module that raised the finding, but a blank paragraph in the report is
    # confusing, so show an explicit placeholder instead of nothing.
    if ([string]::IsNullOrWhiteSpace($impact))      { $impact      = 'Not specified for this finding.' }
    if ([string]::IsNullOrWhiteSpace($remediation)) { $remediation = 'Not specified for this finding.' }
    $remediation = $remediation -replace "`r`n", '<br>' -replace "`n", '<br>'

    # Change-management enrichment (v1.24.0) - EstimatedEffort/KnownRisks/
    # BackupRollback are shown once per finding group (they're identical for
    # every item, keyed on Category+Issue like MitreTechnique/AnssiControl
    # above); OperationalNotes is genuinely optional and omitted entirely
    # when blank, per Finding-Enrichment-Prompt.md ("omit this field
    # entirely if there is nothing genuinely additive to say").
    $estimatedEffort  = HtmlEncode $first.EstimatedEffort
    $knownRisks       = HtmlEncode $first.KnownRisks
    $backupRollback   = HtmlEncode $first.BackupRollback
    $operationalNotes = HtmlEncode $first.OperationalNotes
    $enrichmentHtml = ''
    if (-not [string]::IsNullOrWhiteSpace($estimatedEffort) -or
        -not [string]::IsNullOrWhiteSpace($knownRisks) -or
        -not [string]::IsNullOrWhiteSpace($backupRollback)) {
        $opNotesHtml = ''
        if (-not [string]::IsNullOrWhiteSpace($operationalNotes)) {
            $opNotesHtml = @"
                <div class="finding-section">
                    <h4>Operational Notes</h4>
                    <p>$operationalNotes</p>
                </div>
"@
        }
        $enrichmentHtml = @"
                <div class="finding-section">
                    <h4>Estimated Effort</h4>
                    <p>$estimatedEffort</p>
                </div>
                <div class="finding-section">
                    <h4>Known Risks</h4>
                    <p>$knownRisks</p>
                </div>
                <div class="finding-section">
                    <h4>Backup / Rollback</h4>
                    <p>$backupRollback</p>
                </div>
$opNotesHtml
"@
    }
    # Optional metadata tags (v1.2.0) - these come from the shared Issue ->
    # MITRE/ANSSI mapping, so they're identical across every item in the
    # group; render once from the first item rather than once per object.
    $metaTags = ''
    if (-not [string]::IsNullOrEmpty($first.MitreTechnique)) {
        $metaTags += "<span><strong>MITRE:</strong> <span class=`"tag-mitre`">$(HtmlEncode $first.MitreTechnique)</span></span>"
    }
    if (-not [string]::IsNullOrEmpty($first.AnssiControl)) {
        $metaTags += "<span><strong>ANSSI:</strong> <span class=`"tag-anssi`">$(HtmlEncode $first.AnssiControl)</span></span>"
    }

    # Rendered as a native <details>/<summary> element so every finding is
    # collapsed by default and expandable with no JS required for the basic
    # interaction; the per-section Expand All/Collapse All buttons toggle the
    # `open` attribute on these elements (see setSectionFindings in the
    # footer script).
    if ($count -eq 1) {
        # Single affected object: same layout used since earlier versions,
        # including the finding's own specific Description text.
        $description = HtmlEncode $first.Description
        $affectedObject = HtmlEncode $first.AffectedObject
        if ([string]::IsNullOrWhiteSpace($description))    { $description = 'Not specified for this finding.' }
        if ([string]::IsNullOrWhiteSpace($affectedObject))  { $affectedObject = 'N/A' }
        # Some findings (e.g. Domain Admin Equivalence, ESC4) build a
        # newline-separated bullet list into Description instead of one
        # long semicolon-joined sentence; convert those to <br> the same
        # way Remediation already is, so the bullets actually break onto
        # separate lines instead of running together in the <p>.
        $description = $description -replace "`r`n", '<br>' -replace "`n", '<br>'

        return @"
        <details class="finding $severityClass" id="$anchorId">
            <summary>
                <div class="finding-header">
                    <div class="finding-title">$issue</div>
                    <span class="severity-badge severity-$severityClass">$($first.Severity)</span>
                </div>
            </summary>
            <div class="finding-body">
                <div class="finding-meta">
                    <span><strong>Category:</strong> $category</span>
                    <span><strong>Affected Object:</strong> <span class="meta-code">$affectedObject</span></span>
                    <span><strong>Detected:</strong> $(Format-ADFindingDetectedDate $first.DetectedDate)</span>
                    $metaTags
                </div>
                <div class="finding-section">
                    <h4>Description</h4>
                    <p>$description</p>
                </div>
                <div class="finding-section">
                    <h4>Impact</h4>
                    <p>$impact</p>
                </div>
                <div class="finding-section">
                    <h4>Remediation</h4>
                    <p>$remediation</p>
                </div>
$enrichmentHtml
            </div>
        </details>
"@
    }

    # Multiple affected objects for the same Category+Issue: one
    # consolidated block. Impact/Remediation/MITRE/ANSSI are shown once
    # (they're the same for every item, coming from the shared Issue -> 
    # metadata mapping); each object keeps its own specific Description
    # (which typically bakes in the exact principal/SID/rights/etc.) and
    # its own detection timestamp in the list below.
    $instanceItems = foreach ($f in ($FindingGroup | Sort-Object AffectedObject)) {
        $objDesc = HtmlEncode $f.Description
        $objName = HtmlEncode $f.AffectedObject
        if ([string]::IsNullOrWhiteSpace($objDesc)) { $objDesc = 'Not specified for this finding.' }
        if ([string]::IsNullOrWhiteSpace($objName)) { $objName = 'N/A' }
        $objDesc = $objDesc -replace "`r`n", '<br>' -replace "`n", '<br>'
        @"
                    <li class="finding-instance">
                        <div class="finding-instance-object">$objName</div>
                        <div class="finding-instance-desc">$objDesc</div>
                        <div class="finding-instance-date">Detected: $(Format-ADFindingDetectedDate $f.DetectedDate)</div>
                    </li>
"@
    }
    $instanceItemsHtml = $instanceItems -join "`n"

    return @"
        <details class="finding $severityClass" id="$anchorId">
            <summary>
                <div class="finding-header">
                    <div class="finding-title">$issue <span class="count-badge">$count objects</span></div>
                    <span class="severity-badge severity-$severityClass">$($first.Severity)</span>
                </div>
            </summary>
            <div class="finding-body">
                <div class="finding-meta">
                    <span><strong>Category:</strong> $category</span>
                    $metaTags
                </div>
                <div class="finding-section">
                    <h4>Impact</h4>
                    <p>$impact</p>
                </div>
                <div class="finding-section">
                    <h4>Remediation</h4>
                    <p>$remediation</p>
                </div>
$enrichmentHtml
                <div class="finding-section">
                    <h4>Affected Objects ($count)</h4>
                    <ul class="finding-instance-list">
$instanceItemsHtml
                    </ul>
                </div>
            </div>
        </details>
"@
}

#endregion

