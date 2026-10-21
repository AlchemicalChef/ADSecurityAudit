#region Retest / Configuration-Maturity Delta Comparison (offline, file-based)
#
# This is a POST-PROCESSING feature, not a live-AD detection module. It
# performs NO LDAP/AD queries, uses NO credentials, and requires NO network
# access to any domain controller. It reads two of this module's own prior
# exports (AD_Security_Audit_<timestamp>.json, produced by an existing
# Start-ADSecurityAudit run - a pre-remediation baseline and a post-
# remediation retest of the SAME domain) and produces a structured delta:
# new / resolved / still-open / changed findings, score delta, per-category
# delta, and maturity delta.
#
# Its only hard contract dependency is the finding schema and the
# Get-ADRiskScore/Set-ADFindingMetadata output contract (src/Scoring.ps1,
# shipped since v1.2.0). It does not depend on which detection modules
# produced the underlying findings.
#
# SCORING ACROSS RUNS: both runs are recomputed through the CURRENT
# Get-ADRiskScore/Set-ADFindingMetadata, ignoring each run's originally-
# stored score sidecar values. If the baseline and retest were captured
# under different module versions, the mapping table in Scoring.ps1 may
# have changed between them - comparing stored scores directly would blend
# "posture changed" with "the ruler changed". Recomputing both against one,
# current ruler keeps the comparison apples-to-apples. Each run's own
# recorded ModuleVersion (from its score sidecar, when present) is still
# surfaced in BaselineMeta/RetestMeta for context.
#
# This feature is NOT registered in Main.ps1's $allTests - it isn't a
# per-domain live-AD check, it's a standalone command run after two
# Start-ADSecurityAudit runs of the same domain already exist (the same
# pattern as Get-ADForestConsolidation / Export-ADControlPathGraphBloodHound).

function Resolve-ADRetestReportFile {
    <#
    .SYNOPSIS
        Resolves a -BaselinePath/-RetestPath argument (an explicit
        AD_Security_Audit_<timestamp>.json file, or a folder to search for
        the newest one) to a single findings-export file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path)) {
        throw "Path not found: $Path"
    }

    $item = Get-Item -Path $Path
    if ($item.PSIsContainer) {
        $candidates = @(Get-ChildItem -Path $Path -Filter 'AD_Security_Audit_*.json' -File |
            Sort-Object -Property LastWriteTime -Descending)
        if ($candidates.Count -eq 0) {
            throw "No 'AD_Security_Audit_*.json' findings export found under '$Path'."
        }
        return $candidates[0]
    }
    elseif ($item.Name -like 'AD_Security_Audit_*.json') {
        return $item
    }
    else {
        throw "'$Path' is not a recognized 'AD_Security_Audit_*.json' export, nor a folder containing one."
    }
}

function Get-ADRetestSidecarMeta {
    <#
    .SYNOPSIS
        Reads a findings export's sibling AD_Security_Score_*.json sidecar,
        if present, purely for informational context (ModuleVersion,
        GeneratedDate, and the originally-stored TotalScore/MaturityLevel).
        Never used as the authoritative score - see the module-level header
        comment above on recomputation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$FindingsFile
    )

    $scoreName = $FindingsFile.Name -replace '^AD_Security_Audit_', 'AD_Security_Score_'
    $scorePath = Join-Path -Path $FindingsFile.DirectoryName -ChildPath $scoreName

    $meta = [PSCustomObject]@{
        Path                  = $FindingsFile.FullName
        ScorePath             = $null
        ModuleVersion         = $null
        GeneratedDate         = $null
        OriginalTotalScore    = $null
        OriginalMaturityLevel = $null
    }

    if (Test-Path -Path $scorePath) {
        try {
            $sc = Get-Content -Path $scorePath -Raw | ConvertFrom-Json
            $meta.ScorePath = $scorePath
            if ($sc.PSObject.Properties.Name -contains 'ModuleVersion') { $meta.ModuleVersion = $sc.ModuleVersion }
            # Normalized through ConvertTo-ADFriendlyDateText (Common.ps1) so
            # this renders as a clean date even against an older score
            # sidecar written before GeneratedDate was stored as a string
            # (see Scoring.ps1) - otherwise the header shows the raw
            # "@{value=...; DisplayHint=2; DateTime=...}" PowerShell dump.
            if ($sc.PSObject.Properties.Name -contains 'GeneratedDate') { $meta.GeneratedDate = ConvertTo-ADFriendlyDateText -Value $sc.GeneratedDate }
            if ($sc.PSObject.Properties.Name -contains 'TotalScore') { $meta.OriginalTotalScore = $sc.TotalScore }
            if ($sc.PSObject.Properties.Name -contains 'MaturityLevel') { $meta.OriginalMaturityLevel = $sc.MaturityLevel }
        }
        catch {
            Write-Warning "Could not parse score sidecar '$scorePath' for informational metadata (this does not block the comparison): $_"
        }
    }

    return $meta
}

function Get-ADRetestComparison {
    <#
    .SYNOPSIS
        Offline, file-based comparison between two prior Start-ADSecurityAudit
        exports of the same domain (a pre-remediation baseline and a
        post-remediation retest).
    .DESCRIPTION
        Reads both runs' findings JSON, recomputes both through the CURRENT
        Get-ADRiskScore, matches findings across runs by
        Category+Issue+AffectedObject (Get-ADFindingMatchKey), and returns a
        structured delta object: new / resolved / still-open / changed
        findings, score delta, per-category delta, and maturity delta.

        Performs NO AD/LDAP queries, uses NO credentials, and needs NO
        network access to any domain controller - pure offline aggregation
        of exports this module already produces.
    .PARAMETER BaselinePath
        Either an explicit AD_Security_Audit_<timestamp>.json file, or a
        folder to search for the newest one (same idiom as
        Get-ADForestConsolidation's -ReportPath resolution).
    .PARAMETER RetestPath
        Same shape as -BaselinePath, for the later (retest) run.
    .PARAMETER ToJson
        Optional. Also persist the result to this path
        (AD_Retest_Comparison_<timestamp>.json convention).
    .PARAMETER RemediationStatePath
        Optional. Path to a remediation-state file (see RemediationState.ps1
        - Get-ADRemediationState/Set-ADRemediationState). When supplied,
        each StillOpenFinding and ChangedFinding is annotated with a
        RemediationState property (Status/Owner/Note/SetDate), so a retest
        report can visually separate "still open, actively being worked"
        from "still open, and that's a deliberate, accepted decision".
        Untracked findings (or when this parameter is omitted) default to
        Status = 'Open' with null Owner/Note/SetDate. This is purely an
        additive annotation step - it does not change the New/Resolved/
        StillOpen/Changed classification logic itself, and omitting this
        parameter behaves identically to before it existed.
    .OUTPUTS
        PSCustomObject: GeneratedDate, BaselineMeta, RetestMeta,
        BaselineScore, RetestScore, ScoreDelta, MaturityDelta,
        CategoryDeltas, SeverityCountDelta, NewFindings, ResolvedFindings,
        StillOpenFindings, ChangedFindings.
    .EXAMPLE
        Get-ADRetestComparison -BaselinePath .\Reports\Pre\ -RetestPath .\Reports\Post\ |
            Export-ADRetestComparisonHTML -OutputPath .\retest-report.html
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaselinePath,

        [Parameter(Mandatory)]
        [string]$RetestPath,

        [Parameter()]
        [string]$ToJson,

        [Parameter()]
        [string]$RemediationStatePath
    )

    Write-Verbose "Starting offline retest comparison (no AD queries)..."

    $baselineFile = Resolve-ADRetestReportFile -Path $BaselinePath
    $retestFile   = Resolve-ADRetestReportFile -Path $RetestPath

    try {
        $baselineFindings = @(Get-Content -Path $baselineFile.FullName -Raw | ConvertFrom-Json)
    }
    catch {
        throw "Failed to parse baseline findings export '$($baselineFile.FullName)': $_"
    }

    try {
        $retestFindings = @(Get-Content -Path $retestFile.FullName -Raw | ConvertFrom-Json)
    }
    catch {
        throw "Failed to parse retest findings export '$($retestFile.FullName)': $_"
    }

    # Defensive: flatten immediately after parsing, in case either export is
    # jagged (see ConvertTo-ADFlatFindingsArray in Common.ps1). Every
    # consumer below (Get-ADRiskScore, the key-building map) then only ever
    # sees real, individual finding objects - a no-op for a normal, already-
    # flat export. @() wrap is load-bearing for a genuinely empty (all
    # findings resolved) export - see ConvertTo-ADFlatFindingsArray's own
    # docs for why a plain assignment would otherwise silently produce a
    # real $null here, which then fails Get-ADRiskScore's Mandatory
    # -Findings parameter a few lines down with a binding error - confirmed
    # the hard way while testing the fully-resolved-retest scenario below.
    $baselineFindings = @(ConvertTo-ADFlatFindingsArray -Findings $baselineFindings)
    $retestFindings   = @(ConvertTo-ADFlatFindingsArray -Findings $retestFindings)

    $baselineMeta = Get-ADRetestSidecarMeta -FindingsFile $baselineFile
    $retestMeta   = Get-ADRetestSidecarMeta -FindingsFile $retestFile
    $baselineCoverage = @(Get-ADTestCoverageSidecar -FindingsFile $baselineFile)

    # Recompute BOTH runs through the current mapping table - see the
    # module-level header comment on why stored sidecar scores are never
    # used as authoritative here.
    Write-Verbose "Recomputing baseline and retest scores under the current Get-ADRiskScore mapping table..."
    $baselineScore = Get-ADRiskScore -Findings $baselineFindings
    $retestScore   = Get-ADRiskScore -Findings $retestFindings

    function ConvertTo-ADRetestKeyedMap {
        param([array]$Findings)
        $map = [ordered]@{}
        foreach ($f in $Findings) {
            $key = Get-ADFindingMatchKey -Category $f.Category -Issue $f.Issue -AffectedObject $f.AffectedObject
            if ($map.Contains($key)) {
                Write-Warning "Duplicate finding key encountered within a single run (keeping the first occurrence): $key"
                continue
            }
            $map[$key] = $f
        }
        return $map
    }

    $baselineMap = ConvertTo-ADRetestKeyedMap -Findings $baselineFindings
    $retestMap   = ConvertTo-ADRetestKeyedMap -Findings $retestFindings

    # Reported gap: a finding present in the baseline but absent from the
    # retest was ALWAYS classified as "Resolved" - with no consideration
    # of whether the check that would have produced it actually ran in
    # the retest. If that check was excluded (-ExcludeTests) or failed
    # (an exception, e.g. a permissions/connectivity error) during the
    # retest, every finding that check would have reported also
    # disappears from $retestMap - identically to genuine remediation, as
    # far as the key-based diff above can tell. That silently produces a
    # false "Resolved" claim for something that was simply never re-
    # checked - the one thing a retest comparison exists to verify.
    #
    # $retestCoverage is loaded to cross-reference: a "disappeared"
    # finding is only trusted as genuinely Resolved if its originating
    # check (Finding.TestName) is EITHER absent from coverage data
    # entirely (an old export predating TestName/coverage tracking, or a
    # custom/manually-added finding with no registered check - benefit of
    # the doubt, since there's no positive evidence of a problem) OR was
    # positively confirmed to have run (Status 'Completed') in the
    # retest. A TestName with a 'Failed' or 'Excluded' status in the
    # retest coverage moves that finding out of ResolvedFindings and into
    # the new UnconfirmedFindings bucket instead - disappeared, but for a
    # reason that has nothing to do with remediation.
    $retestCoverage = @(Get-ADTestCoverageSidecar -FindingsFile $retestFile)
    $retestCoverageByTestName = @{}
    foreach ($c in $retestCoverage) { $retestCoverageByTestName[$c.TestName] = $c }

    $newFindings      = @()
    $resolvedFindings = @()
    $unconfirmed      = @()
    $stillOpen        = @()
    $changed          = @()

    foreach ($key in $retestMap.Keys) {
        if (-not $baselineMap.Contains($key)) {
            $newFindings += $retestMap[$key]
        }
    }

    foreach ($key in $baselineMap.Keys) {
        if (-not $retestMap.Contains($key)) {
            $b = $baselineMap[$key]
            $testName = $b.TestName
            $coverageEntry = if ($testName) { $retestCoverageByTestName[$testName] } else { $null }
            if ($coverageEntry -and $coverageEntry.Status -in @('Failed', 'Excluded')) {
                $unconfirmed += [PSCustomObject]@{
                    Key      = $key
                    Finding  = $b
                    TestName = $testName
                    Reason   = if ($coverageEntry.Status -eq 'Failed') {
                        "The '$testName' check failed during the retest ($($coverageEntry.ErrorMessage)) - this finding's disappearance from the retest is NOT confirmed remediation, it simply was not re-checked."
                    }
                    else {
                        "The '$testName' check was excluded from the retest run (-ExcludeTests/-IncludeTests) - this finding's disappearance from the retest is NOT confirmed remediation, it simply was not re-checked."
                    }
                }
            }
            else {
                $resolvedFindings += $b
            }
            continue
        }

        $b = $baselineMap[$key]
        $r = $retestMap[$key]
        $sevChanged = ($b.Severity -ne $r.Severity) -or ([int]$b.SeverityLevel -ne [int]$r.SeverityLevel) -or ([int]$b.Weight -ne [int]$r.Weight)
        if ($sevChanged) {
            $changed += [PSCustomObject]@{
                Key             = $key
                BaselineFinding = $b
                RetestFinding   = $r
            }
        }
        else {
            $stillOpen += $r
        }
    }

    # --- Optional remediation-state annotation (additive only; does not
    # change the New/Resolved/StillOpen/Changed classification above). ---
    if ($RemediationStatePath) {
        Write-Verbose "Annotating Still Open / Changed findings from remediation state: $RemediationStatePath"
        $remediationState = Get-ADRemediationState -StatePath $RemediationStatePath
        $remediationByKey = @{}
        foreach ($entry in $remediationState.Entries) {
            $remediationByKey[$entry.Key] = $entry
        }

        function Add-ADRemediationStateAnnotation {
            param([Parameter(Mandatory)][object]$Finding, [hashtable]$ByKey)
            $key = Get-ADFindingMatchKey -Category $Finding.Category -Issue $Finding.Issue -AffectedObject $Finding.AffectedObject
            $tracked = $ByKey[$key]
            $stateObj = if ($tracked) {
                [PSCustomObject]@{ Status = $tracked.Status; Owner = $tracked.Owner; Note = $tracked.Note; SetDate = $tracked.SetDate }
            }
            else {
                [PSCustomObject]@{ Status = 'Open'; Owner = $null; Note = $null; SetDate = $null }
            }
            Add-Member -InputObject $Finding -MemberType NoteProperty -Name 'RemediationState' -Value $stateObj -Force
        }

        foreach ($f in $stillOpen) { Add-ADRemediationStateAnnotation -Finding $f -ByKey $remediationByKey }
        foreach ($c in $changed) { Add-ADRemediationStateAnnotation -Finding $c.RetestFinding -ByKey $remediationByKey }
        # Unconfirmed findings are, functionally, still-open-but-uncertain -
        # a human's prior AcceptedRisk/InProgress decision on one is just as
        # relevant here as for StillOpenFindings.
        foreach ($u in $unconfirmed) { Add-ADRemediationStateAnnotation -Finding $u.Finding -ByKey $remediationByKey }
    }

    # Per-category deltas across every category present in either run.
    $baselineCatByName = @{}
    foreach ($c in $baselineScore.CategoryScores) { $baselineCatByName[$c.Category] = [int]$c.Score }
    $retestCatByName = @{}
    foreach ($c in $retestScore.CategoryScores) { $retestCatByName[$c.Category] = [int]$c.Score }
    $allCategories = @(@($baselineCatByName.Keys) + @($retestCatByName.Keys) | Select-Object -Unique)

    $categoryDeltas = foreach ($cat in $allCategories) {
        $bScore = if ($baselineCatByName.ContainsKey($cat)) { $baselineCatByName[$cat] } else { 0 }
        $rScore = if ($retestCatByName.ContainsKey($cat)) { $retestCatByName[$cat] } else { 0 }
        [PSCustomObject]@{
            Category      = $cat
            BaselineScore = $bScore
            RetestScore   = $rScore
            Delta         = $rScore - $bScore
        }
    }
    $categoryDeltas = @($categoryDeltas | Sort-Object -Property Delta -Descending)

    $sevDelta = [PSCustomObject]@{
        Critical = [int]$retestScore.SeverityCounts.Critical - [int]$baselineScore.SeverityCounts.Critical
        High     = [int]$retestScore.SeverityCounts.High     - [int]$baselineScore.SeverityCounts.High
        Medium   = [int]$retestScore.SeverityCounts.Medium   - [int]$baselineScore.SeverityCounts.Medium
        Low      = [int]$retestScore.SeverityCounts.Low      - [int]$baselineScore.SeverityCounts.Low
        Info     = [int]$retestScore.SeverityCounts.Info     - [int]$baselineScore.SeverityCounts.Info
    }

    # General coverage-availability caveats - distinct from the specific
    # per-finding UnconfirmedFindings reclassification above, which only
    # fires when there IS coverage data and it POSITIVELY shows a
    # Failed/Excluded check. These cover the case where the cross-check
    # couldn't even be attempted: an export (either side) that predates
    # test coverage tracking (module v1.24.0) or is simply missing its
    # sidecar has NO data to catch a false "Resolved" claim with -
    # ResolvedFindings for that run falls back to the old, unverified
    # behavior, and a reader should know that, not assume the absence of
    # an UnconfirmedFindings entry means everything was cross-checked.
    $coverageCaveats = [System.Collections.Generic.List[string]]::new()
    if ($retestCoverage.Count -eq 0) {
        $coverageCaveats.Add("No test coverage data is available for the RETEST run - ResolvedFindings could not be cross-checked against which checks actually ran. A 'Resolved' finding in this comparison may reflect genuine remediation, or may simply mean the relevant check was not re-run; this cannot be distinguished without test coverage tracking (introduced in module version 1.24.0).")
    }
    if ($baselineCoverage.Count -eq 0) {
        $coverageCaveats.Add("No test coverage data is available for the BASELINE run. NewFindings in this comparison may be genuinely new, or may simply reflect a check that ran for the first time in the retest; this cannot be distinguished without test coverage tracking (introduced in module version 1.24.0).")
    }
    if ($unconfirmed.Count -gt 0) {
        $coverageCaveats.Add("$($unconfirmed.Count) finding(s) that disappeared between baseline and retest were reclassified from Resolved to UnconfirmedFindings, because the check that would have found them failed or was excluded during the retest - see UnconfirmedFindings for detail on each.")
    }

    $result = [PSCustomObject]@{
        # String, not a raw [datetime] - see the Scoring.ps1 comment on why;
        # this object can itself be written out via -ToJson below.
        GeneratedDate       = (Get-Date).ToString('o')
        BaselineMeta        = $baselineMeta
        RetestMeta          = $retestMeta
        BaselineScore       = $baselineScore
        RetestScore         = $retestScore
        ScoreDelta          = [int]$retestScore.TotalScore - [int]$baselineScore.TotalScore
        MaturityDelta       = [int]$retestScore.MaturityLevel - [int]$baselineScore.MaturityLevel
        CategoryDeltas      = $categoryDeltas
        SeverityCountDelta  = $sevDelta
        NewFindings         = @($newFindings)
        ResolvedFindings    = @($resolvedFindings)
        # New in v1.24.0, additive - findings that disappeared from the
        # retest but could NOT be trusted as resolved because their
        # originating check failed or was excluded during the retest (see
        # the classification loop above and each entry's own .Reason).
        # Older code that only reads ResolvedFindings/StillOpenFindings/
        # ChangedFindings/NewFindings is unaffected; it simply won't see
        # this bucket, the same as any other additive field in this
        # module's established contract.
        UnconfirmedFindings = @($unconfirmed)
        StillOpenFindings   = @($stillOpen)
        ChangedFindings     = @($changed)
        # New in v1.24.0, additive - general, comparison-level caveats
        # about what could and couldn't be cross-checked against test
        # coverage data. Empty array when both runs have full coverage
        # data and nothing needed reclassifying.
        CoverageCaveats     = @($coverageCaveats)
    }

    if ($ToJson) {
        try {
            $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $ToJson -Encoding UTF8
            Write-Verbose "Retest comparison written to $ToJson"
        }
        catch {
            Write-Warning "Failed to write -ToJson output to '$ToJson': $_"
        }
    }

    return $result
}

function Get-ADSvgCategoryDeltaBars {
    <#
    .SYNOPSIS
        Renders per-category baseline->retest score pairs as a paired inline
        SVG bar chart (a thin "baseline" bar above a "retest" bar per
        category), following the same no-chart-library / hand-built-SVG
        convention as Get-ADSvgCategoryBars. This is a sibling helper, not a
        modification of the single-value CategoryBars renderer, since a
        paired before/after bar per row is a different shape of chart.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$CategoryDeltas
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

    $rowHeight  = 46
    $chartWidth = 700
    $labelWidth = 200
    $barAreaW   = $chartWidth - $labelWidth - 70
    $height     = ($rowHeight * @($CategoryDeltas).Count) + 10

    $rowsSvg = ''
    $y = 4
    foreach ($cat in $CategoryDeltas) {
        $b = [int]$cat.BaselineScore
        $r = [int]$cat.RetestScore
        $bW = [math]::Round(($b / 100.0) * $barAreaW, 1)
        $rW = [math]::Round(($r / 100.0) * $barAreaW, 1)
        $bColor = Get-BandColor $b
        $rColor = Get-BandColor $r
        $maxChars = [math]::Max(8, [math]::Floor($labelWidth / 7.2) - 2)
        $label = HtmlEncode (Get-ADTruncateLabel -Text "$($cat.Category)" -MaxChars $maxChars)
        $fullLabel = HtmlEncode "$($cat.Category): baseline $b -> retest $r (delta $($cat.Delta))"
        $numX = $labelWidth + $barAreaW + 10
        $deltaSign = if ($cat.Delta -gt 0) { "+$($cat.Delta)" } else { "$($cat.Delta)" }
        # Lower score is better (0-100, higher = worse), so a negative delta
        # (score went down) is an improvement and colored with --good.
        $deltaColor = if ($cat.Delta -lt 0) { '#1a7f4e' } elseif ($cat.Delta -gt 0) { '#b3261e' } else { '#5b6472' }

        $rowsSvg += @"
    <g><title>$fullLabel</title>
    <text x="0" y="$($y + 24)" font-size="12.5" fill="#1f2937" font-family="-apple-system,Segoe UI,sans-serif">$label</text>
    <rect x="$labelWidth" y="$y" width="$barAreaW" height="14" rx="3" fill="#e2e6ea" />
    <rect x="$labelWidth" y="$y" width="$bW" height="14" rx="3" fill="$bColor" opacity="0.5" />
    <text x="$($labelWidth - 4)" y="$($y + 12)" font-size="9" text-anchor="end" fill="#7f8c8d">base</text>
    <rect x="$labelWidth" y="$($y + 18)" width="$barAreaW" height="14" rx="3" fill="#e2e6ea" />
    <rect x="$labelWidth" y="$($y + 18)" width="$rW" height="14" rx="3" fill="$rColor" />
    <text x="$($labelWidth - 4)" y="$($y + 30)" font-size="9" text-anchor="end" fill="#7f8c8d">now</text>
    <text x="$numX" y="$($y + 20)" font-size="13" font-weight="700" fill="$deltaColor" font-family="-apple-system,Segoe UI,sans-serif">$deltaSign</text>
    </g>

"@
        $y += $rowHeight
    }

    return @"
<svg viewBox="0 0 $chartWidth $height" role="img" aria-label="Category score delta, baseline vs retest">
$rowsSvg
</svg>
"@
}

function Get-ADRemediationAnnotatedFindingHTML {
    <#
    .SYNOPSIS
        Renders a Still-Open finding group (same Category+Issue) the same
        way Get-FindingHTML does, with an added remediation-status badge
        per affected object - reusing the existing severity-badge CSS
        pattern rather than inventing a new visual language.
    .DESCRIPTION
        Only used by Export-ADRetestComparisonHTML's Still Open section,
        and only when at least one finding in the comparison carries a
        RemediationState property (i.e. Get-ADRetestComparison was called
        with -RemediationStatePath). Untracked findings still render, with
        a default "Open" badge (Status = 'Open', no owner/note), so an
        untracked finding is visually distinguishable from a tracked
        AcceptedRisk/InProgress/Remediated one without looking broken.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$FindingGroup
    )

    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }
    function Get-RemediationBadgeHtml($finding) {
        $status = if ($finding.RemediationState -and $finding.RemediationState.Status) { [string]$finding.RemediationState.Status } else { 'Open' }
        $badgeClass = "remediation-badge remediation-$($status.ToLower())"
        $ownerText = ''
        if ($finding.RemediationState -and $finding.RemediationState.Owner) {
            $ownerText = " &middot; $(HtmlEncode $finding.RemediationState.Owner)"
        }
        return "<span class=`"$badgeClass`">$(HtmlEncode $status)$ownerText</span>"
    }

    $FindingGroup = @($FindingGroup)
    $first = $FindingGroup[0]
    $count = $FindingGroup.Count
    $severityClass = $first.Severity.ToLower()
    $issue = HtmlEncode $first.Issue
    $category = HtmlEncode $first.Category
    $anchorId = Get-ADFindingAnchorId -Category $first.Category -Issue $first.Issue

    $impact = HtmlEncode $first.Impact
    $remediation = HtmlEncode $first.Remediation
    if ([string]::IsNullOrWhiteSpace($impact)) { $impact = 'Not specified for this finding.' }
    if ([string]::IsNullOrWhiteSpace($remediation)) { $remediation = 'Not specified for this finding.' }
    $remediation = $remediation -replace "`r`n", '<br>' -replace "`n", '<br>'

    if ($count -eq 1) {
        $description = HtmlEncode $first.Description
        $affectedObject = HtmlEncode $first.AffectedObject
        if ([string]::IsNullOrWhiteSpace($description)) { $description = 'Not specified for this finding.' }
        if ([string]::IsNullOrWhiteSpace($affectedObject)) { $affectedObject = 'N/A' }
        $description = $description -replace "`r`n", '<br>' -replace "`n", '<br>'
        $badge = Get-RemediationBadgeHtml $first

        return @"
        <details class="finding $severityClass" id="$anchorId">
            <summary>
                <div class="finding-header">
                    <div class="finding-title">$issue</div>
                    <span class="severity-badge severity-$severityClass">$($first.Severity)</span>
                    $badge
                </div>
            </summary>
            <div class="finding-body">
                <div class="finding-meta">
                    <span><strong>Category:</strong> $category</span>
                    <span><strong>Affected Object:</strong> <span class="meta-code">$affectedObject</span></span>
                </div>
                <div class="finding-section"><h4>Description</h4><p>$description</p></div>
                <div class="finding-section"><h4>Impact</h4><p>$impact</p></div>
                <div class="finding-section"><h4>Remediation</h4><p>$remediation</p></div>
            </div>
        </details>
"@
    }

    $instanceItems = foreach ($f in ($FindingGroup | Sort-Object AffectedObject)) {
        $objDesc = HtmlEncode $f.Description
        $objName = HtmlEncode $f.AffectedObject
        if ([string]::IsNullOrWhiteSpace($objDesc)) { $objDesc = 'Not specified for this finding.' }
        if ([string]::IsNullOrWhiteSpace($objName)) { $objName = 'N/A' }
        $objDesc = $objDesc -replace "`r`n", '<br>' -replace "`n", '<br>'
        $badge = Get-RemediationBadgeHtml $f
        @"
                    <li class="finding-instance">
                        <div class="finding-instance-object">$objName $badge</div>
                        <div class="finding-instance-desc">$objDesc</div>
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
                <div class="finding-meta"><span><strong>Category:</strong> $category</span></div>
                <div class="finding-section"><h4>Impact</h4><p>$impact</p></div>
                <div class="finding-section"><h4>Remediation</h4><p>$remediation</p></div>
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

function Export-ADRetestComparisonHTML {
    <#
    .SYNOPSIS
        Renders a Get-ADRetestComparison result as a standalone HTML report
        with a togglable Current State / Delta View.
    .DESCRIPTION
        Reuses existing visual components rather than introducing new chart
        infrastructure: Get-FindingHTML, Get-ADSvgGauge, Get-ADSvgCategoryBars
        (all from Reporting.ps1), plus a new Get-ADSvgCategoryDeltaBars
        sibling helper for the paired baseline/retest category view.
    .PARAMETER Comparison
        The object returned by Get-ADRetestComparison.
    .PARAMETER OutputPath
        Path to write the HTML report to.
    .EXAMPLE
        Get-ADRetestComparison -BaselinePath .\Pre\ -RetestPath .\Post\ |
            Export-ADRetestComparisonHTML -OutputPath .\retest-report.html
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$Comparison,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    process {
    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }
    function Get-GaugeColor([int]$s) {
        if ($s -ge 75) { return '#b3261e' }
        elseif ($s -ge 50) { return '#c8590b' }
        elseif ($s -ge 25) { return '#8a6200' }
        else { return '#1a7f4e' }
    }

    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $baselineDateText = if ($Comparison.BaselineMeta.GeneratedDate) { $Comparison.BaselineMeta.GeneratedDate } else { 'unknown (no score sidecar found)' }
    $retestDateText   = if ($Comparison.RetestMeta.GeneratedDate) { $Comparison.RetestMeta.GeneratedDate } else { 'unknown (no score sidecar found)' }
    $baselineVerText  = if ($Comparison.BaselineMeta.ModuleVersion) { $Comparison.BaselineMeta.ModuleVersion } else { 'unknown' }
    $retestVerText    = if ($Comparison.RetestMeta.ModuleVersion) { $Comparison.RetestMeta.ModuleVersion } else { 'unknown' }

    # Finding-count context, mirroring TOTAL FINDINGS in the main report's
    # own header-info block (Reporting.ps1) - unlike GeneratedDate/
    # ModuleVersion these come from the recomputed score, not the sidecar,
    # so they're always available even when no sidecar exists.
    $baselineFindingsText = [int]$Comparison.BaselineScore.FindingCount
    $retestFindingsText   = [int]$Comparison.RetestScore.FindingCount

    $baselineGaugeColor = Get-GaugeColor([int]$Comparison.BaselineScore.TotalScore)
    $retestGaugeColor   = Get-GaugeColor([int]$Comparison.RetestScore.TotalScore)
    $baselineGaugeSvg = Get-ADSvgGauge -Score ([int]$Comparison.BaselineScore.TotalScore) -Color $baselineGaugeColor
    $retestGaugeSvg   = Get-ADSvgGauge -Score ([int]$Comparison.RetestScore.TotalScore) -Color $retestGaugeColor

    $scoreDelta = [int]$Comparison.ScoreDelta
    $scoreDeltaText = if ($scoreDelta -gt 0) { "+$scoreDelta" } else { "$scoreDelta" }
    $scoreDeltaColor = if ($scoreDelta -lt 0) { '#1a7f4e' } elseif ($scoreDelta -gt 0) { '#b3261e' } else { '#5b6472' }

    $maturityDelta = [int]$Comparison.MaturityDelta
    $maturityDeltaText = if ($maturityDelta -gt 0) { "+$maturityDelta" } else { "$maturityDelta" }
    $maturityDeltaColor = if ($maturityDelta -gt 0) { '#1a7f4e' } elseif ($maturityDelta -lt 0) { '#b3261e' } else { '#5b6472' }

    $categoryDeltaBarsSvg = ''
    if ($Comparison.CategoryDeltas -and @($Comparison.CategoryDeltas).Count -gt 0) {
        $categoryDeltaBarsSvg = Get-ADSvgCategoryDeltaBars -CategoryDeltas $Comparison.CategoryDeltas
    }
    $currentCategoryBarsSvg = ''
    if ($Comparison.RetestScore.CategoryScores -and @($Comparison.RetestScore.CategoryScores).Count -gt 0) {
        $currentCategoryBarsSvg = Get-ADSvgCategoryBars -CategoryScores $Comparison.RetestScore.CategoryScores
    }

    # --- Current State findings, grouped by severity then Category+Issue,
    # rendered with the same Get-FindingHTML consolidation Export-ADSecurityReportHTML uses. ---
    function Get-GroupedFindingsHtml($findings) {
        $groups = @($findings | Group-Object -Property Category, Issue)
        return (($groups | ForEach-Object { Get-FindingHTML -FindingGroup $_.Group }) -join "`n")
    }

    $retestFindingsAll = @()
    $retestFindingsAll += $Comparison.NewFindings
    $retestFindingsAll += $Comparison.StillOpenFindings
    $retestFindingsAll += ($Comparison.ChangedFindings | ForEach-Object { $_.RetestFinding })
    $currentCriticalHtml = Get-GroupedFindingsHtml (@($retestFindingsAll | Where-Object { $_.Severity -eq 'Critical' }))
    $currentHighHtml     = Get-GroupedFindingsHtml (@($retestFindingsAll | Where-Object { $_.Severity -eq 'High' }))
    $currentMediumHtml   = Get-GroupedFindingsHtml (@($retestFindingsAll | Where-Object { $_.Severity -eq 'Medium' }))
    $currentLowHtml      = Get-GroupedFindingsHtml (@($retestFindingsAll | Where-Object { $_.Severity -eq 'Low' }))

    # --- Delta View sections: New / Resolved / Still Open / Changed. ---
    $newHtml       = Get-GroupedFindingsHtml (@($Comparison.NewFindings))
    $resolvedHtml  = Get-GroupedFindingsHtml (@($Comparison.ResolvedFindings))

    # Still Open findings are rendered with Get-ADRemediationAnnotatedFindingHTML
    # instead of plain Get-FindingHTML whenever a RemediationState property is
    # present (i.e. -RemediationStatePath was supplied to Get-ADRetestComparison),
    # so a tracked AcceptedRisk/InProgress/Remediated finding is visually badged
    # apart from an untracked (default Open) one. Falls back to the plain
    # renderer when no findings carry that property, so this is a no-op when
    # remediation tracking isn't in use.
    $stillOpenFindingsArr = @($Comparison.StillOpenFindings)
    $hasRemediationState = @($stillOpenFindingsArr | Where-Object { $_.PSObject.Properties.Name -contains 'RemediationState' }).Count -gt 0
    if ($hasRemediationState) {
        $stillOpenGroups = @($stillOpenFindingsArr | Group-Object -Property Category, Issue)
        $stillOpenHtml = (($stillOpenGroups | ForEach-Object { Get-ADRemediationAnnotatedFindingHTML -FindingGroup $_.Group }) -join "`n")
    }
    else {
        $stillOpenHtml = Get-GroupedFindingsHtml $stillOpenFindingsArr
    }

    $changedHtml = ($Comparison.ChangedFindings | ForEach-Object {
        $b = $_.BaselineFinding
        $r = $_.RetestFinding
        @"
        <details class="finding $($r.Severity.ToLower())">
            <summary>
                <div class="finding-header">
                    <div class="finding-title">$(HtmlEncode $r.Issue)</div>
                    <span class="severity-badge severity-$($b.Severity.ToLower())">$(HtmlEncode $b.Severity)</span>
                    <span style="margin: 0 6px; color: var(--ink-muted);">&rarr;</span>
                    <span class="severity-badge severity-$($r.Severity.ToLower())">$(HtmlEncode $r.Severity)</span>
                </div>
            </summary>
            <div class="finding-body">
                <div class="finding-meta">
                    <span><strong>Category:</strong> $(HtmlEncode $r.Category)</span>
                    <span><strong>Affected Object:</strong> <span class="meta-code">$(HtmlEncode $r.AffectedObject)</span></span>
                </div>
                <div class="finding-section">
                    <h4>What Changed</h4>
                    <p>Severity/weight changed between baseline and retest: <strong>$(HtmlEncode $b.Severity)</strong> (weight $($b.Weight)) &rarr; <strong>$(HtmlEncode $r.Severity)</strong> (weight $($r.Weight)).</p>
                </div>
            </div>
        </details>
"@
    }) -join "`n"

    # --- Unconfirmed findings: disappeared from the retest, but their
    # originating check failed/was excluded so absence is NOT confirmed
    # remediation. Custom-rendered (not Get-GroupedFindingsHtml) so each
    # card can show WHY it's unconfirmed, same reasoning as the custom
    # $changedHtml block above.
    $unconfirmedHtml = (@($Comparison.UnconfirmedFindings) | ForEach-Object {
        $f = $_.Finding
        @"
        <details class="finding $($f.Severity.ToLower())">
            <summary>
                <div class="finding-header">
                    <div class="finding-title">$(HtmlEncode $f.Issue)</div>
                    <span class="severity-badge severity-$($f.Severity.ToLower())">$(HtmlEncode $f.Severity)</span>
                    <span style="margin-left:8px; background:#5b6472; color:#fff; padding:2px 8px; border-radius:10px; font-size:0.8em;">UNCONFIRMED</span>
                </div>
            </summary>
            <div class="finding-body">
                <div class="finding-meta">
                    <span><strong>Category:</strong> $(HtmlEncode $f.Category)</span>
                    <span><strong>Affected Object:</strong> <span class="meta-code">$(HtmlEncode $f.AffectedObject)</span></span>
                </div>
                <div class="finding-section">
                    <h4>Why This Isn't Confirmed Resolved</h4>
                    <p>$(HtmlEncode $_.Reason)</p>
                </div>
            </div>
        </details>
"@
    }) -join "`n"

    $coverageCaveatsHtml = ''
    if (@($Comparison.CoverageCaveats).Count -gt 0) {
        $coverageCaveatsHtml = @"
        <div class="warning-box" style="background:#f2f7ee; border-color:#3f7d3f;">
            <p><strong>COVERAGE CAVEATS</strong> - $(@($Comparison.CoverageCaveats).Count) note(s) about test coverage that affect how to read this comparison.</p>
            <ul>
$((@($Comparison.CoverageCaveats) | ForEach-Object { "                <li>$(HtmlEncode $_)</li>" }) -join "`n")
            </ul>
        </div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Retest / Maturity-Delta Comparison Report</title>
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
        .header-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 15px; margin-bottom: 20px; padding: 20px; background: var(--bg); border-radius: 5px; }
        .header-info div { padding: 10px; }
        .header-info strong { display: block; color: var(--ink-muted); font-size: 0.85em; margin-bottom: 5px; }
        .warning-box { background: var(--medium-bg); border-left: 4px solid var(--medium); padding: 15px; margin: 20px 0; border-radius: 4px; }
        .warning-box p { color: var(--medium); margin: 5px 0; }

        /* View toggle: plain [hidden]-attribute panels, tab-button styling
           matching ui/assets/styles.css's .tab-button rules. Per the v1.20.3
           CHANGELOG fix (the dashboard modal's [hidden] specificity bug),
           this explicit [hidden] override MUST come before any other
           .view-panel display rule so it wins the cascade. */
        .view-panel[hidden] { display: none; }
        .view-toggle { display: flex; gap: 8px; margin: 20px 0; border-bottom: 2px solid var(--border); }
        .tab-button { background: none; border: none; padding: 10px 18px; font-size: 0.95em; font-weight: 600; color: var(--ink-muted); cursor: pointer; border-bottom: 3px solid transparent; margin-bottom: -2px; }
        .tab-button.active { color: var(--brand); border-bottom-color: var(--brand); }
        .tab-button:hover { color: var(--brand); }

        .scoring-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin: 20px 0; }
        .score-panel { padding: 25px; border-radius: 8px; background: var(--bg); text-align: center; }
        .score-panel h3 { margin-bottom: 10px; color: var(--ink-muted); font-size: 0.95em; text-transform: uppercase; letter-spacing: 0.5px; }
        .gauge-svg-wrap { position: relative; width: 160px; height: 160px; margin: 0 auto; }
        .gauge-svg-wrap svg { width: 100%; height: 100%; }
        .gauge-center { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; }
        .gauge-center .num { font-size: 2.2em; font-weight: bold; color: var(--ink); line-height: 1; }
        .gauge-center .of { font-size: 0.85em; color: var(--ink-muted); }
        .delta-badge { display: inline-block; font-size: 1.6em; font-weight: 800; padding: 10px 20px; border-radius: 8px; background: var(--bg); margin-top: 10px; }
        .delta-panel { text-align: center; padding: 25px; border-radius: 8px; background: var(--bg); }
        .delta-panel h3 { margin-bottom: 10px; color: var(--ink-muted); font-size: 0.95em; text-transform: uppercase; letter-spacing: 0.5px; }

        details.finding { border: 1px solid var(--border); border-radius: 6px; margin-bottom: 10px; background: var(--surface); }
        details.finding.critical { border-left: 4px solid var(--critical); }
        details.finding.high { border-left: 4px solid var(--high); }
        details.finding.medium { border-left: 4px solid var(--medium); }
        details.finding.low { border-left: 4px solid var(--low); }
        details.finding { padding: 0; }
        details.finding[open] { padding-bottom: 5px; }
        details.finding > summary { list-style: none; cursor: pointer; padding: 16px 20px; }
        details.finding > summary::-webkit-details-marker { display: none; }
        details.finding > summary::before { content: '\25B8'; display: inline-block; margin-right: 10px; color: var(--ink-muted); transition: transform 0.15s ease; }
        details.finding[open] > summary::before { transform: rotate(90deg); }
        .finding-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
        .finding-title { font-weight: 600; }
        .finding-body { padding: 0 20px 16px 34px; }
        .finding-meta { display: flex; gap: 18px; flex-wrap: wrap; font-size: 0.88em; color: var(--ink-muted); margin-bottom: 10px; }
        .finding-section { margin-top: 10px; }
        .finding-section h4 { font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; color: var(--ink-muted); margin-bottom: 4px; }
        .meta-code { font-family: var(--font-mono); font-size: 13px; color: var(--ink); word-break: break-word; }
        .severity-badge { padding: 3px 10px; border-radius: 20px; font-weight: 700; font-size: 0.78em; text-transform: uppercase; letter-spacing: 0.5px; color: white; }
        .remediation-badge { padding: 3px 10px; border-radius: 20px; font-weight: 700; font-size: 0.78em; letter-spacing: 0.3px; color: white; margin-left: 4px; }
        .remediation-open { background: var(--low); }
        .remediation-acceptedrisk { background: #6b7fb0; }
        .remediation-inprogress { background: var(--high); }
        .remediation-remediated { background: var(--good); }
        .severity-critical { background: var(--critical); }
        .severity-high { background: var(--high); }
        .severity-medium { background: var(--medium); }
        .severity-low { background: var(--low); }
        .section-empty { color: var(--ink-muted); font-style: italic; padding: 10px 0; }
        .footer { margin-top: 50px; padding-top: 20px; border-top: 2px solid var(--border); text-align: center; color: var(--ink-muted); font-size: 0.9em; }
        @media print { body { background: white; padding: 0; } .container { box-shadow: none; } }
    </style>
</head>
<body>
    <div class="container">
        <h1>AD Retest / Maturity-Delta Comparison Report</h1>

        <div class="warning-box">
            <p><strong>CONFIDENTIAL SECURITY REPORT</strong> - offline comparison of two previously-exported ADSecurityAudit runs. No Active Directory queries were performed to produce this report. Both runs' scores were recomputed under the CURRENT scoring mapping table so the comparison stays apples-to-apples across module versions.</p>
        </div>

        <div class="header-info">
            <div><strong>BASELINE GENERATED</strong>$baselineDateText</div>
            <div><strong>BASELINE MODULE VERSION</strong>$baselineVerText</div>
            <div><strong>BASELINE FINDINGS</strong>$baselineFindingsText</div>
            <div><strong>RETEST GENERATED</strong>$retestDateText</div>
            <div><strong>RETEST MODULE VERSION</strong>$retestVerText</div>
            <div><strong>RETEST FINDINGS</strong>$retestFindingsText</div>
            <div><strong>REPORT GENERATED</strong>$reportDate</div>
        </div>

        <div class="view-toggle">
            <button type="button" class="tab-button active" data-view="current" onclick="setActiveView('current')">Current State</button>
            <button type="button" class="tab-button" data-view="delta" onclick="setActiveView('delta')">Delta View</button>
        </div>

        <section class="view-panel" data-view-panel="current">
            <h2>Risk Score &amp; Maturity (Retest / Current)</h2>
            <div class="scoring-grid">
                <div class="score-panel">
                    <h3>Risk Score</h3>
                    $retestGaugeSvg
                </div>
                <div class="score-panel">
                    <h3>ANSSI Maturity</h3>
                    <div style="font-size:2.2em; font-weight:bold;">$([int]$Comparison.RetestScore.MaturityLevel) <small style="font-size:0.5em; color:var(--ink-muted);">/ 5</small></div>
                    <p style="color:var(--ink-muted); margin-top:6px;">$(HtmlEncode $Comparison.RetestScore.MaturityLabel)</p>
                </div>
            </div>

            <h2>Risk by Category</h2>
            <div style="max-width:700px;">$currentCategoryBarsSvg</div>

            <h2>Findings - Critical</h2>
            $(if ($currentCriticalHtml) { $currentCriticalHtml } else { '<p class="section-empty">No Critical findings in the retest.</p>' })

            <h2>Findings - High</h2>
            $(if ($currentHighHtml) { $currentHighHtml } else { '<p class="section-empty">No High findings in the retest.</p>' })

            <h2>Findings - Medium</h2>
            $(if ($currentMediumHtml) { $currentMediumHtml } else { '<p class="section-empty">No Medium findings in the retest.</p>' })

            <h2>Findings - Low</h2>
            $(if ($currentLowHtml) { $currentLowHtml } else { '<p class="section-empty">No Low findings in the retest.</p>' })
        </section>

        <section class="view-panel" data-view-panel="delta" hidden>
            <h2>Score &amp; Maturity Delta</h2>
            <div class="scoring-grid">
                <div class="score-panel">
                    <h3>Baseline Score</h3>
                    $baselineGaugeSvg
                </div>
                <div class="score-panel">
                    <h3>Retest Score</h3>
                    $retestGaugeSvg
                </div>
                <div class="delta-panel">
                    <h3>Score Delta</h3>
                    <div class="delta-badge" style="color: $scoreDeltaColor;">$scoreDeltaText</div>
                    <p style="color:var(--ink-muted); margin-top:8px; font-size:0.85em;">Negative is improved (score is 0-100, higher = worse).</p>
                </div>
                <div class="delta-panel">
                    <h3>Maturity Delta</h3>
                    <div class="delta-badge" style="color: $maturityDeltaColor;">$maturityDeltaText</div>
                    <p style="color:var(--ink-muted); margin-top:8px; font-size:0.85em;">Positive is improved (1-5, higher = better).</p>
                </div>
            </div>

            <h2>Per-Category Delta (baseline vs retest)</h2>
            <div style="max-width:700px;">$categoryDeltaBarsSvg</div>

            $coverageCaveatsHtml

            <h2>New ($(@($Comparison.NewFindings).Count))</h2>
            $(if ($newHtml) { $newHtml } else { '<p class="section-empty">No new findings since the baseline.</p>' })

            <h2 style="border-left-color: var(--good);">Resolved ($(@($Comparison.ResolvedFindings).Count))</h2>
            $(if ($resolvedHtml) { $resolvedHtml } else { '<p class="section-empty">No findings were resolved between the baseline and the retest.</p>' })

            <h2 style="border-left-color: #5b6472;">Unconfirmed ($(@($Comparison.UnconfirmedFindings).Count))</h2>
            <p style="color:var(--ink-muted); font-size:0.9em; margin-top:-8px;">Disappeared from the retest, but the check that would have found them failed or was excluded - NOT confirmed as remediated.</p>
            $(if ($unconfirmedHtml) { $unconfirmedHtml } else { '<p class="section-empty">No findings were reclassified as unconfirmed - either every relevant check ran cleanly in the retest, or no coverage data was available to cross-check against (see Coverage Caveats above, if present).</p>' })

            <h2>Still Open ($(@($Comparison.StillOpenFindings).Count))</h2>
            $(if ($stillOpenHtml) { $stillOpenHtml } else { '<p class="section-empty">No unchanged still-open findings.</p>' })

            <h2>Changed ($(@($Comparison.ChangedFindings).Count))</h2>
            $(if ($changedHtml) { $changedHtml } else { '<p class="section-empty">No matched findings changed severity/weight between runs.</p>' })
        </section>

        <div class="footer">
            <p><strong>Generated by ADSecurityAudit Module v$($script:ModuleVersion) - Retest / Maturity-Delta Comparison</strong></p>
            <p>Pure offline aggregation of this module's own prior JSON exports. No Active Directory queries were performed to produce this report.</p>
        </div>
    </div>

    <script>
        function setActiveView(view) {
            document.querySelectorAll('.view-panel').forEach(function (panel) {
                panel.hidden = (panel.getAttribute('data-view-panel') !== view);
            });
            document.querySelectorAll('.tab-button').forEach(function (btn) {
                btn.classList.toggle('active', btn.getAttribute('data-view') === view);
            });
        }
    </script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Verbose "Retest comparison HTML report written to $OutputPath"
    }
}

#endregion
