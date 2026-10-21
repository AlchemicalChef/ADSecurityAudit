#region Remediation Burn-Down Projection (offline, file-based)
#
# This is a POST-PROCESSING feature, not a live-AD detection module. It
# performs NO LDAP/AD queries, uses NO credentials, and requires NO
# network access to any domain controller - the same posture as
# Get-ADForestConsolidation / Get-ADRetestComparison / Get-ADMaturityTrend.
# See files/26-remediation-burndown-projection.md.
#
# Combines two data sources that already exist independently but have
# never been connected: Get-ADRemediationState (per-finding Open/
# AcceptedRisk/InProgress/Remediated tracking, keyed by the same
# Category+Issue+AffectedObject key Get-ADRetestComparison already uses,
# via the shared Get-ADFindingMatchKey helper) and Get-ADMaturityTrend
# (the historical score/maturity series across a domain's prior runs).
# The result: a simple, honestly-caveated projection of when the domain's
# score/maturity would cross a target threshold if InProgress items get
# resolved at the pace the historical trend already shows.
#
# This feature is NOT registered in Main.ps1's $allTests - it isn't a
# per-domain live-AD check, it's a standalone command run after
# Start-ADSecurityAudit has already produced at least one export (and,
# for a meaningful historical rate, more than one), the same pattern as
# its sibling offline features.

function Get-ADRemediationBurndown {
    <#
    .SYNOPSIS
        Projects a domain's score/maturity trajectory if in-progress
        remediation completes at the pace the historical trend already
        shows.
    .DESCRIPTION
        1. Resolves the most recent AD_Security_Audit_<timestamp>.json
           under -ReportPath (reusing Resolve-ADRetestReportFile) and
           recomputes it through the CURRENT Get-ADRiskScore, exactly as
           Get-ADRetestComparison does, so the current score/weights are
           never taken from a possibly-stale stored sidecar.
        2. Reads -RemediationStatePath (Get-ADRemediationState) for
           current per-finding status, matched against the current
           findings by Get-ADFindingMatchKey.
        3. Builds a PROJECTED findings set with every InProgress-status
           finding removed (simulating full resolution) and recomputes
           IT through the same Get-ADRiskScore - this reuses this
           project's own real scoring math for the projection rather
           than a hand-rolled approximation.
        4. Reads the historical trend via Get-ADMaturityTrend and, only
           when the trend is Improving and -TargetScore/
           -TargetMaturityLevel was supplied, computes a rough calendar
           estimate of when that target would be crossed at the observed
           historical rate.
        5. AcceptedRisk entries are explicitly excluded from the
           projection (an accepted risk isn't expected to be resolved)
           but reported separately as a count.
    .PARAMETER ReportPath
        A folder to search for the newest AD_Security_Audit_<timestamp>.json
        (also used, unchanged, as -ReportPath for the historical
        Get-ADMaturityTrend series), or an explicit path to one.
    .PARAMETER RemediationStatePath
        Path to a remediation-state file (see RemediationState.ps1).
    .PARAMETER TargetScore
        Optional. If supplied (with the trend Improving), a rough
        calendar estimate of when this TotalScore would be reached is
        included.
    .PARAMETER TargetMaturityLevel
        Optional. Same as -TargetScore, for MaturityLevel instead.
    .PARAMETER ToJson
        Optional. Also persist the result to this path
        (AD_Remediation_Burndown_<timestamp>.json convention).
    .OUTPUTS
        PSCustomObject: GeneratedDate, CurrentScore, CurrentMaturityLevel,
        InProgressCount, InProgressWeight, AcceptedRiskCount,
        ProjectedScore, ProjectedMaturityLevel, HistoricalDirection,
        HistoricalRatePerDay, HistoricalMaturityRatePerDay, TargetScore,
        TargetMaturityLevel, EstimatedTargetDate,
        EstimatedMaturityTargetDate, UnmatchedInProgressKeys, Caveat.
    .EXAMPLE
        Get-ADRemediationBurndown -ReportPath .\Reports\ -RemediationStatePath .\AD_Remediation_State.json -TargetScore 20
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ReportPath,

        [Parameter(Mandatory)]
        [string]$RemediationStatePath,

        [Parameter()]
        [Nullable[int]]$TargetScore,

        [Parameter()]
        [Nullable[int]]$TargetMaturityLevel,

        [Parameter()]
        [string]$ToJson
    )

    Write-Verbose "Starting offline remediation burn-down projection (no AD queries)..."

    # -------------------------------------------------------------------
    # Step 1: current findings/score (most recent run).
    # -------------------------------------------------------------------
    $currentFile = Resolve-ADRetestReportFile -Path $ReportPath
    try {
        $currentFindings = @(Get-Content -Path $currentFile.FullName -Raw | ConvertFrom-Json)
    }
    catch {
        throw "Failed to parse findings export '$($currentFile.FullName)': $_"
    }
    $currentFindings = @(ConvertTo-ADFlatFindingsArray -Findings $currentFindings)
    $currentScore = Get-ADRiskScore -Findings $currentFindings

    # -------------------------------------------------------------------
    # Step 2: remediation state, matched to current findings by the same
    # Category+Issue+AffectedObject key Get-ADRetestComparison uses.
    # -------------------------------------------------------------------
    $remediationState = Get-ADRemediationState -StatePath $RemediationStatePath

    $findingsByKey = [ordered]@{}
    foreach ($f in $currentFindings) {
        $key = Get-ADFindingMatchKey -Category $f.Category -Issue $f.Issue -AffectedObject $f.AffectedObject
        if (-not $findingsByKey.Contains($key)) { $findingsByKey[$key] = $f }
    }

    $inProgressKeys   = [System.Collections.ArrayList]::new()
    $acceptedRiskKeys = [System.Collections.ArrayList]::new()
    $unmatchedInProgressKeys = [System.Collections.ArrayList]::new()

    foreach ($entry in @($remediationState.Entries)) {
        if (-not $entry.Key) { continue }
        switch ($entry.Status) {
            'InProgress' {
                if ($findingsByKey.Contains($entry.Key)) {
                    [void]$inProgressKeys.Add($entry.Key)
                }
                else {
                    # Tracked as in-progress, but no longer present in the
                    # current run (already resolved, or the finding text
                    # changed) - surfaced rather than silently ignored, so
                    # a reader can reconcile stale remediation-state
                    # entries.
                    [void]$unmatchedInProgressKeys.Add($entry.Key)
                }
            }
            'AcceptedRisk' {
                if ($findingsByKey.Contains($entry.Key)) { [void]$acceptedRiskKeys.Add($entry.Key) }
            }
        }
    }

    # -------------------------------------------------------------------
    # Step 3: projected findings set (every matched InProgress finding
    # removed, simulating full resolution), recomputed through the SAME
    # Get-ADRiskScore - reuses this project's own real scoring math for
    # the projection rather than a new approximation.
    # -------------------------------------------------------------------
    $inProgressKeySet = [System.Collections.Generic.HashSet[string]]::new([string[]]@($inProgressKeys))
    $projectedFindings = @($currentFindings | Where-Object {
        $k = Get-ADFindingMatchKey -Category $_.Category -Issue $_.Issue -AffectedObject $_.AffectedObject
        -not $inProgressKeySet.Contains($k)
    })
    $projectedScore = if ($projectedFindings.Count -gt 0) {
        Get-ADRiskScore -Findings $projectedFindings
    }
    else {
        # Get-ADRiskScore's own "no findings => clean" semantics: TotalScore
        # 0, MaturityLevel 5, matching how it treats a fully-clean category.
        [PSCustomObject]@{ TotalScore = 0; MaturityLevel = 5; MaturityLabel = 'Optimal'; CategoryScores = @() }
    }

    $inProgressWeight = 0
    foreach ($key in $inProgressKeys) {
        $f = $findingsByKey[$key]
        if ($f -and $f.PSObject.Properties.Name -contains 'Weight' -and $f.Weight) {
            $inProgressWeight += [int]$f.Weight
        }
    }

    # -------------------------------------------------------------------
    # Step 4: historical rate (from Get-ADMaturityTrend's own series and
    # direction classification - no new, inconsistent trend model).
    # -------------------------------------------------------------------
    $historicalDirection = 'InsufficientData'
    $historicalRatePerDay = $null
    $historicalMaturityRatePerDay = $null
    $estimatedTargetDate = $null
    $estimatedMaturityTargetDate = $null
    $trendMessageParts = @()

    try {
        $trend = Get-ADMaturityTrend -ReportPath $ReportPath
        $historicalDirection = $trend.OverallDirection

        if ($trend.RunCount -ge 2) {
            $firstRun = $trend.Series[0]
            $lastRun  = $trend.Series[-1]
            $elapsedDays = ([datetime]$lastRun.GeneratedDate - [datetime]$firstRun.GeneratedDate).TotalDays
            if ($elapsedDays -gt 0) {
                # Score: positive = improving (score falling) per day.
                $historicalRatePerDay = ([double]$firstRun.TotalScore - [double]$lastRun.TotalScore) / $elapsedDays
                # MaturityLevel: positive = improving (level rising, since
                # 1-5 is worst-to-best) per day - the OPPOSITE sign
                # direction from the score rate above, since the two
                # scales run in opposite directions (see
                # Get-ADMaturityTrendDirection's own doc comment on this).
                $historicalMaturityRatePerDay = ([double]$lastRun.MaturityLevel - [double]$firstRun.MaturityLevel) / $elapsedDays
            }

            $haveTarget = ($null -ne $TargetScore) -or ($null -ne $TargetMaturityLevel)

            if ($historicalDirection -eq 'Improving') {
                if ($null -ne $TargetScore -and $historicalRatePerDay -and $historicalRatePerDay -gt 0 -and $lastRun.TotalScore -gt $TargetScore) {
                    $daysToTarget = ([double]$lastRun.TotalScore - [double]$TargetScore) / $historicalRatePerDay
                    $estimatedTargetDate = (Get-Date).AddDays($daysToTarget).ToString('yyyy-MM-dd')
                }
                if ($null -ne $TargetMaturityLevel -and $historicalMaturityRatePerDay -and $historicalMaturityRatePerDay -gt 0 -and $lastRun.MaturityLevel -lt $TargetMaturityLevel) {
                    $daysToMaturityTarget = ([double]$TargetMaturityLevel - [double]$lastRun.MaturityLevel) / $historicalMaturityRatePerDay
                    $estimatedMaturityTargetDate = (Get-Date).AddDays($daysToMaturityTarget).ToString('yyyy-MM-dd')
                }
                if ($haveTarget -and -not $estimatedTargetDate -and -not $estimatedMaturityTargetDate) {
                    $trendMessageParts += 'A target was supplied and the historical trend is Improving, but the target has already been reached (or the relevant rate is zero) based on the most recent run - no future date to project.'
                }
            }
            elseif ($haveTarget) {
                $trendMessageParts += "A target was supplied, but the historical trend is '$historicalDirection' (not Improving), so no calendar estimate is projected - a target-crossing date can't be meaningfully estimated from a flat or regressing trend."
            }
        }
        else {
            $trendMessageParts += 'Fewer than two historical score sidecars were found - only the current-run InProgress projection is available; no historical rate or target-crossing estimate can be computed yet.'
        }
    }
    catch {
        Write-Verbose "Get-ADRemediationBurndown: could not compute historical trend (this is non-fatal - the InProgress projection above is still returned): $_"
        $trendMessageParts += "Historical trend unavailable: $_"
    }

    # -------------------------------------------------------------------
    # Step 5: honest, explicit caveat - matching Get-ADMaturityTrend's own
    # convention of surfacing data-quality caveats in its OUTPUT, not only
    # in documentation.
    # -------------------------------------------------------------------
    $caveatParts = @(
        'This is a rough linear projection from limited historical data, not a guarantee: it assumes every currently-InProgress finding is genuinely resolved, that remediation continues at the SAME pace as the historical average, and that no new findings are introduced in the meantime.'
    )
    if ($unmatchedInProgressKeys.Count -gt 0) {
        $caveatParts += "$($unmatchedInProgressKeys.Count) remediation-state entry/entries marked InProgress no longer match any finding in the current run (see UnmatchedInProgressKeys) - they were excluded from the weight sum above and may need reconciling in the remediation-state file."
    }
    $caveatParts += $trendMessageParts
    $caveat = $caveatParts -join ' '
    Write-Warning $caveat

    $result = [PSCustomObject]@{
        GeneratedDate           = (Get-Date).ToString('o')
        CurrentScore            = $currentScore.TotalScore
        CurrentMaturityLevel    = $currentScore.MaturityLevel
        InProgressCount         = $inProgressKeys.Count
        InProgressWeight        = $inProgressWeight
        AcceptedRiskCount       = $acceptedRiskKeys.Count
        ProjectedScore          = $projectedScore.TotalScore
        ProjectedMaturityLevel  = $projectedScore.MaturityLevel
        HistoricalDirection     = $historicalDirection
        HistoricalRatePerDay    = $historicalRatePerDay
        HistoricalMaturityRatePerDay = $historicalMaturityRatePerDay
        TargetScore             = $TargetScore
        TargetMaturityLevel     = $TargetMaturityLevel
        EstimatedTargetDate     = $estimatedTargetDate
        EstimatedMaturityTargetDate = $estimatedMaturityTargetDate
        UnmatchedInProgressKeys = @($unmatchedInProgressKeys)
        Caveat                  = $caveat
    }

    if ($ToJson) {
        try {
            $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $ToJson -Encoding UTF8
            Write-Verbose "Remediation burndown written to $ToJson"
        }
        catch {
            Write-Warning "Failed to write -ToJson output to '$ToJson': $_"
        }
    }

    return $result
}

#endregion
