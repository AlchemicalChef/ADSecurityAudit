#region Multi-run Maturity Trend History (offline, file-based)
#
# This is a POST-PROCESSING feature, not a live-AD detection module. It
# performs NO LDAP/AD queries, uses NO credentials, and requires NO network
# access to any domain controller. It reads ALL of a domain's historical
# AD_Security_Score_<timestamp>.json sidecars (however many exist - 3, 10,
# 50) and produces a chronological trend: score/maturity over time,
# per-category trend, and a simple Improving/Flat/Regressing direction
# indicator per category.
#
# RELATIONSHIP TO RETEST-COMPARISON (RetestComparison.ps1): that feature
# answers "exactly what changed between these two specific runs" - finding-
# level New/Resolved/StillOpen/Changed detail, two inputs. This feature
# answers "what's the trajectory over N runs" - score/maturity/category
# trend lines, no finding-level detail, N inputs. They are complementary,
# not redundant, and are deliberately NOT merged into one function -
# finding-level matching across many runs (rather than two) gets
# combinatorially messier for limited additional value at that granularity.
#
# NO RECOMPUTATION: unlike Get-ADRetestComparison, this reads each sidecar's
# OWN recorded TotalScore/MaturityLevel as they were computed at the time -
# a deliberate, OPPOSITE design choice from retest-comparison's "recompute
# both under current scoring" rule. The whole point here is seeing how the
# tool's own assessment evolved over the actual historical record, not
# re-litigating each run under today's mapping table. Each run's own
# recorded ModuleVersion is surfaced in the output/report specifically so a
# reader can attribute a score jump to "the tool changed" vs. "posture
# changed" by cross-referencing that column - do not assume this function
# handles version-skew the same way Get-ADRetestComparison does.
#
# This feature is NOT registered in Main.ps1's $allTests - standalone
# post-processing command, same posture as ForestConsolidation.ps1 and
# RetestComparison.ps1.

function Resolve-ADMaturityTrendScoreFiles {
    <#
    .SYNOPSIS
        Resolves a -ReportPath argument (a folder, or an explicit sidecar
        file) to every AD_Security_Score_<timestamp>.json file found.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ReportPath
    )

    if (-not (Test-Path -Path $ReportPath)) {
        throw "ReportPath not found: $ReportPath"
    }

    $item = Get-Item -Path $ReportPath
    if ($item.PSIsContainer) {
        return @(Get-ChildItem -Path $ReportPath -Filter 'AD_Security_Score_*.json' -Recurse -File)
    }
    elseif ($item.Name -like 'AD_Security_Score_*.json') {
        return @($item)
    }
    else {
        throw "'$ReportPath' is not a recognized 'AD_Security_Score_*.json' sidecar, nor a folder containing one."
    }
}

function Get-ADMaturityTrendDirection {
    <#
    .SYNOPSIS
        Simple, explainable first-vs-last classification with a tolerance
        band - deliberately NOT a statistical regression, consistent with
        this module's general preference for simple, auditable arithmetic
        (the same philosophy as Get-ADRiskScore's own diminishing-returns
        model rather than anything more elaborate).
    .DESCRIPTION
        Values are assumed to be "higher = worse" scores (0-100 risk score,
        or a per-category sub-score on the same scale), so a falling value
        is Improving and a rising value is Regressing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Values,

        [Parameter()]
        [int]$Tolerance = 5
    )

    if (@($Values).Count -lt 2) { return 'InsufficientData' }

    $first = [double]$Values[0]
    $last  = [double]$Values[-1]
    $delta = $last - $first

    if ($delta -le (0 - $Tolerance)) { return 'Improving' }
    elseif ($delta -ge $Tolerance) { return 'Regressing' }
    else { return 'Flat' }
}

function Get-ADMaturityTrend {
    <#
    .SYNOPSIS
        Offline, file-based multi-run maturity trend across all of a
        domain's historical AD_Security_Score_<timestamp>.json sidecars.
    .DESCRIPTION
        Discovers every AD_Security_Score_*.json under -ReportPath, sorts
        them chronologically by each sidecar's OWN recorded GeneratedDate
        (not filename, in case files were renamed/moved), and builds a
        score/maturity/per-category trend with a simple
        Improving/Flat/Regressing direction classification per category and
        overall.

        GeneratedDate was only added to Get-ADRiskScore's output in v1.21.0,
        so a score sidecar produced by an older module version won't have
        it. Rather than dropping that run from the trend, its date is
        ESTIMATED from the sidecar file's own last-write time instead, and
        that run is flagged (DateEstimated = $true on its Series entry, a
        note in the returned Message, and a visible flag on that row in
        Export-ADMaturityTrendHTML's per-run table) so an estimated date is
        never mistaken for the sidecar's real recorded generation time.

        Does NOT recompute scores under the current scoring mapping table -
        see the module-level header comment above for why this is the
        deliberate opposite of Get-ADRetestComparison's behavior.

        Performs NO AD/LDAP queries, uses NO credentials, and needs NO
        network access to any domain controller.
    .PARAMETER ReportPath
        A folder to search (recursively) for AD_Security_Score_*.json
        sidecars, or an explicit path to a single one.
    .PARAMETER ToJson
        Optional. Also persist the result to this path
        (AD_Maturity_Trend_<timestamp>.json convention), mirroring this
        module's other -ToJson features.
    .OUTPUTS
        PSCustomObject: GeneratedDate, RunCount, EstimatedDateCount,
        IncompleteCoverageCount, NoCoverageDataCount, DateRange, Series
        (each entry carries DateEstimated/CoverageAvailable/UntestedCount),
        CategoryTrends, OverallDirection, Message (non-null when fewer
        than two usable runs were found, and/or one or more runs used an
        estimated date, and/or one or more runs had incomplete/unavailable
        coverage data).
    .EXAMPLE
        Get-ADMaturityTrend -ReportPath .\Reports\ -Verbose |
            Export-ADMaturityTrendHTML -OutputPath .\maturity-trend.html
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ReportPath,

        [Parameter()]
        [string]$ToJson
    )

    Write-Verbose "Starting offline maturity trend history (no AD queries)..."

    $files = @(Resolve-ADMaturityTrendScoreFiles -ReportPath $ReportPath)
    if ($files.Count -eq 0) {
        throw "No 'AD_Security_Score_*.json' sidecars found under '$ReportPath'."
    }

    $runs = @()
    foreach ($f in $files) {
        try {
            $sc = Get-Content -Path $f.FullName -Raw | ConvertFrom-Json
        }
        catch {
            Write-Warning "Skipping unparsable score sidecar '$($f.FullName)': $_"
            continue
        }

        if (-not ($sc.PSObject.Properties.Name -contains 'TotalScore')) {
            Write-Warning "Skipping score sidecar missing the expected TotalScore field: '$($f.FullName)'"
            continue
        }

        # GeneratedDate was only added to Get-ADRiskScore's output in v1.21.0
        # (see Scoring.ps1) - a sidecar produced by an older module version
        # won't have it. Rather than dropping that run's history entirely,
        # fall back to the file's own last-write time and flag it as an
        # ESTIMATED date (DateEstimated = $true on the run/series entry, and
        # called out explicitly in the HTML report and the result's Message)
        # so nobody mistakes an estimate for the sidecar's real generation
        # time.
        $generatedDate = $null
        $dateEstimated = $false
        if (($sc.PSObject.Properties.Name -contains 'GeneratedDate') -and $sc.GeneratedDate) {
            try { $generatedDate = [datetime]$sc.GeneratedDate }
            catch {
                Write-Warning "Score sidecar has an unparsable GeneratedDate value - falling back to the file's last-write time as an ESTIMATED date instead: '$($f.FullName)'"
            }
        }
        if (-not $generatedDate) {
            $generatedDate = $f.LastWriteTime
            $dateEstimated = $true
            Write-Warning "Score sidecar has no GeneratedDate field (predates v1.21.0) - using the file's last-write time as an ESTIMATED date instead: '$($f.FullName)'"
        }

        # Reported gap: a run with several checks excluded/failed scores
        # BETTER than a fully-tested run purely because fewer checks means
        # fewer chances to find something - nothing here previously
        # distinguished "genuinely improved" from "checked less this
        # time". Same sibling-sidecar lookup Get-ADRetestComparison uses
        # (Get-ADTestCoverageSidecar, generalized to also accept a Score
        # sidecar - see its own docs), same "flag it on the run/series
        # entry, don't hide it" pattern already established here for
        # DateEstimated.
        $coverage = @(Get-ADTestCoverageSidecar -FindingsFile $f)
        $untestedCount = @($coverage | Where-Object { $_.Status -in @('Failed', 'Excluded') }).Count
        $coverageAvailable = $coverage.Count -gt 0

        $runs += [PSCustomObject]@{
            Path              = $f.FullName
            GeneratedDate     = $generatedDate
            DateEstimated     = $dateEstimated
            ModuleVersion     = if ($sc.PSObject.Properties.Name -contains 'ModuleVersion') { $sc.ModuleVersion } else { $null }
            TotalScore        = [int]$sc.TotalScore
            MaturityLevel     = [int]$sc.MaturityLevel
            MaturityLabel     = $sc.MaturityLabel
            CategoryScores    = @($sc.CategoryScores)
            CoverageAvailable = $coverageAvailable
            UntestedCount     = $untestedCount
        }
    }

    if ($runs.Count -eq 0) {
        throw "Found score sidecar(s) under '$ReportPath' but none were usable - see the warnings above."
    }

    # Chronological order by each sidecar's OWN recorded GeneratedDate (or the
    # estimated fallback above), never by filename (a file may have been
    # renamed or moved).
    $runs = @($runs | Sort-Object -Property GeneratedDate)

    $series = foreach ($r in $runs) {
        [PSCustomObject]@{
            # Stringified - $r.GeneratedDate is a real [datetime] here, but
            # $result (which this feeds) is round-tripped through -ToJson,
            # and a raw [datetime] would suffer the same ConvertTo-Json
            # expansion described in Scoring.ps1's GeneratedDate comment.
            GeneratedDate     = $r.GeneratedDate.ToString('o')
            DateEstimated     = $r.DateEstimated
            ModuleVersion     = $r.ModuleVersion
            TotalScore        = $r.TotalScore
            MaturityLevel     = $r.MaturityLevel
            CoverageAvailable = $r.CoverageAvailable
            UntestedCount     = $r.UntestedCount
        }
    }

    # Per-category trend: union of every category name across all runs; a
    # run with no findings in a given category contributes 0 for that point
    # (matches Get-ADRiskScore's own "no findings => clean" semantics).
    $allCategories = @($runs.CategoryScores.Category | Select-Object -Unique)
    $categoryTrends = foreach ($cat in $allCategories) {
        $catSeries = foreach ($r in $runs) {
            $c = @($r.CategoryScores) | Where-Object { $_.Category -eq $cat }
            $score = if ($c -and $c.Count -gt 0) { [int]$c[0].Score } else { 0 }
            [PSCustomObject]@{ GeneratedDate = $r.GeneratedDate.ToString('o'); Score = $score }
        }
        [PSCustomObject]@{
            Category  = $cat
            Series    = @($catSeries)
            Direction = Get-ADMaturityTrendDirection -Values @($catSeries.Score)
        }
    }
    $categoryTrends = @($categoryTrends | Sort-Object -Property Category)

    $overallDirection = Get-ADMaturityTrendDirection -Values @($runs.TotalScore)

    $messageParts = @()
    if ($runs.Count -eq 1) {
        $messageParts += 'Only one usable score sidecar was found under this ReportPath - no trend can be computed yet. Re-run Get-ADMaturityTrend once at least one more historical export is available.'
    }
    $estimatedRuns = @($runs | Where-Object { $_.DateEstimated })
    if ($estimatedRuns.Count -gt 0) {
        $estimatedFileList = ($estimatedRuns | ForEach-Object { $_.Path }) -join '; '
        $messageParts += "$($estimatedRuns.Count) of $($runs.Count) score sidecar(s) had no GeneratedDate field (predates v1.21.0) - their date was ESTIMATED from the file's last-write time instead: $estimatedFileList"
    }
    # Same reasoning as the DateEstimated caveat above, for a different
    # kind of "this run's number isn't quite what it looks like": a run
    # with untested (failed/excluded) checks scores BETTER than a fully-
    # tested run purely from checking less, not from genuine improvement.
    $incompleteCoverageRuns = @($runs | Where-Object { $_.CoverageAvailable -and $_.UntestedCount -gt 0 })
    if ($incompleteCoverageRuns.Count -gt 0) {
        $incompleteFileList = ($incompleteCoverageRuns | ForEach-Object { "$($_.Path) ($($_.UntestedCount) untested)" }) -join '; '
        $messageParts += "$($incompleteCoverageRuns.Count) of $($runs.Count) run(s) had one or more untested (failed/excluded) checks - their score may look better than a fully-tested run purely because fewer checks had a chance to find something, not because posture genuinely improved: $incompleteFileList"
    }
    $noCoverageDataRuns = @($runs | Where-Object { -not $_.CoverageAvailable })
    if ($noCoverageDataRuns.Count -gt 0 -and $noCoverageDataRuns.Count -lt $runs.Count) {
        $messageParts += "$($noCoverageDataRuns.Count) of $($runs.Count) run(s) have no test coverage data available (predates module version 1.24.0, or the coverage sidecar was not kept alongside the score sidecar) - whether those specific runs had untested checks cannot be determined."
    }
    $message = if ($messageParts.Count -gt 0) { $messageParts -join ' ' } else { $null }
    if ($message) { Write-Warning $message }

    $result = [PSCustomObject]@{
        # String, not a raw [datetime] - see Scoring.ps1's comment on why
        # (this object is itself written out via -ToJson below).
        GeneratedDate            = (Get-Date).ToString('o')
        RunCount                 = $runs.Count
        EstimatedDateCount       = $estimatedRuns.Count
        # New in v1.24.0, additive - see the CoverageAvailable/UntestedCount
        # comment above. IncompleteCoverageCount counts runs known (positive
        # coverage data) to have had untested checks; NoCoverageDataCount
        # counts runs where this couldn't be determined at all either way.
        IncompleteCoverageCount = $incompleteCoverageRuns.Count
        NoCoverageDataCount     = $noCoverageDataRuns.Count
        # Earliest/Latest stringified here too - $runs[].GeneratedDate is a
        # real [datetime] at this point (cast above), but this whole $result
        # object can be round-tripped through -ToJson, and a raw [datetime]
        # would suffer the same ConvertTo-Json expansion described above.
        DateRange           = [PSCustomObject]@{ Earliest = $runs[0].GeneratedDate.ToString('o'); Latest = $runs[-1].GeneratedDate.ToString('o') }
        Series              = @($series)
        CategoryTrends      = @($categoryTrends)
        OverallDirection    = $overallDirection
        Message             = $message
    }

    if ($ToJson) {
        try {
            $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $ToJson -Encoding UTF8
            Write-Verbose "Maturity trend written to $ToJson"
        }
        catch {
            Write-Warning "Failed to write -ToJson output to '$ToJson': $_"
        }
    }

    return $result
}

function Get-ADSvgTrendLine {
    <#
    .SYNOPSIS
        Renders a single numeric series over time as a hand-built inline SVG
        line chart (or a small sparkline variant) - no chart library, no
        CDN, matching this module's existing Get-ADSvgGauge/
        Get-ADSvgCategoryBars convention.
    .DESCRIPTION
        This is new time-series SVG territory: the existing gauge/bar
        helpers are single-value, not time-series, so this is a dedicated
        sibling helper rather than forcing them to do double duty.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Values,

        [Parameter()]
        [int]$Width = 700,

        [Parameter()]
        [int]$Height = 220,

        [Parameter()]
        [string]$Color = '#1f4e79',

        [Parameter()]
        [int]$MaxValue = 100,

        [Parameter()]
        [switch]$Sparkline,

        [Parameter()]
        [array]$PointLabels = @()
    )

    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }

    $values = @($Values | ForEach-Object { [double]$_ })
    $n = $values.Count
    if ($n -eq 0) {
        return "<svg viewBox=`"0 0 $Width $Height`" role=`"img`" aria-label=`"No data`"></svg>"
    }
    if ($n -eq 1) {
        # A single point can't drive an x-step; render it as a flat 2-point line.
        $values = @($values[0], $values[0])
        $n = 2
    }

    $padding = if ($Sparkline) { 3 } else { 30 }
    $plotW = $Width - ($padding * 2)
    $plotH = $Height - ($padding * 2)
    $stepX = $plotW / ($n - 1)

    function Get-ADTrendLineY {
        param([double]$Value, [int]$Padding, [int]$PlotHeight, [int]$Max)
        $clamped = [math]::Max(0, [math]::Min($Max, $Value))
        return $Padding + $PlotHeight - (($clamped / $Max) * $PlotHeight)
    }

    $points = for ($i = 0; $i -lt $n; $i++) {
        $x = [math]::Round($padding + ($i * $stepX), 1)
        $y = [math]::Round((Get-ADTrendLineY -Value $values[$i] -Padding $padding -PlotHeight $plotH -Max $MaxValue), 1)
        "$x,$y"
    }
    $pointsAttr = $points -join ' '

    $dotsSvg = ''
    $gridSvg = ''
    if (-not $Sparkline) {
        for ($i = 0; $i -lt $n; $i++) {
            $x = [math]::Round($padding + ($i * $stepX), 1)
            $y = [math]::Round((Get-ADTrendLineY -Value $values[$i] -Padding $padding -PlotHeight $plotH -Max $MaxValue), 1)
            $label = if (@($PointLabels).Count -gt $i) { HtmlEncode "$($PointLabels[$i])" } else { "$($values[$i])" }
            $dotsSvg += "<circle cx=`"$x`" cy=`"$y`" r=`"4`" fill=`"$Color`"><title>$label</title></circle>`n"
        }
        foreach ($gv in @(0, 25, 50, 75, 100)) {
            if ($gv -gt $MaxValue) { continue }
            $gy = [math]::Round((Get-ADTrendLineY -Value $gv -Padding $padding -PlotHeight $plotH -Max $MaxValue), 1)
            $gridSvg += "<line x1=`"$padding`" y1=`"$gy`" x2=`"$($Width - $padding)`" y2=`"$gy`" stroke=`"#e2e6ea`" stroke-width=`"1`" />`n"
            $gridSvg += "<text x=`"2`" y=`"$($gy + 4)`" font-size=`"10`" fill=`"#7f8c8d`">$gv</text>`n"
        }
    }

    $strokeWidth = if ($Sparkline) { 1.5 } else { 2.5 }

    return @"
<svg viewBox="0 0 $Width $Height" role="img" aria-label="Trend over $n runs">
$gridSvg
<polyline points="$pointsAttr" fill="none" stroke="$Color" stroke-width="$strokeWidth" stroke-linejoin="round" stroke-linecap="round" />
$dotsSvg
</svg>
"@
}

function Export-ADMaturityTrendHTML {
    <#
    .SYNOPSIS
        Renders a Get-ADMaturityTrend result as a standalone HTML report:
        a score/maturity line chart, per-category sparklines with a
        direction indicator, and a plain per-run table (including each
        run's ModuleVersion, so a reader can attribute a score jump to a
        tool change vs. an actual posture change).
    .PARAMETER Trend
        The object returned by Get-ADMaturityTrend.
    .PARAMETER OutputPath
        Path to write the HTML report to.
    .EXAMPLE
        Get-ADMaturityTrend -ReportPath .\Reports\ |
            Export-ADMaturityTrendHTML -OutputPath .\maturity-trend.html
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$Trend,

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

    $directionColors = @{
        Improving         = '#1a7f4e'
        Flat              = '#5b6472'
        Regressing        = '#b3261e'
        InsufficientData  = '#5b6472'
    }

    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $overallColor = $directionColors[[string]$Trend.OverallDirection]

    $scoreLineSvg = ''
    if (@($Trend.Series).Count -gt 0) {
        $labels = @($Trend.Series | ForEach-Object { "$(ConvertTo-ADFriendlyDateText -Value $_.GeneratedDate) - Score $($_.TotalScore)" })
        $scoreLineSvg = Get-ADSvgTrendLine -Values @($Trend.Series.TotalScore) -PointLabels $labels -Color '#1f4e79'
    }

    $messageHtml = ''
    if ($Trend.Message) {
        $messageHtml = "<div class=`"warning-box`"><p>$(HtmlEncode $Trend.Message)</p></div>"
    }

    $categoryRowsHtml = ($Trend.CategoryTrends | ForEach-Object {
        $spark = Get-ADSvgTrendLine -Values @($_.Series.Score) -Sparkline -Width 160 -Height 40 -Color '#1f4e79'
        $dirColor = $directionColors[[string]$_.Direction]
        @"
                    <tr>
                        <td>$(HtmlEncode $_.Category)</td>
                        <td style="width:170px;">$spark</td>
                        <td><span style="color:$dirColor; font-weight:700;">$($_.Direction)</span></td>
                    </tr>
"@
    }) -join "`n"

    $runRowsHtml = ($Trend.Series | ForEach-Object {
        $verText = if ($_.ModuleVersion) { HtmlEncode "$($_.ModuleVersion)" } else { 'unknown' }
        $dateCell = "$($_.GeneratedDate)"
        if ($_.DateEstimated) {
            $dateCell = "$($_.GeneratedDate) <span class=`"estimated-flag`" title=`"No GeneratedDate field in this sidecar (predates v1.21.0) - date estimated from the file's last-write time.`">&#9888; estimated</span>"
        }
        $coverageCell = if (-not $_.CoverageAvailable) {
            '<span class="estimated-flag" title="No test coverage sidecar for this run (predates module v1.24.0, or the sidecar was not kept alongside it) - untested checks, if any, cannot be determined.">&#9888; no data</span>'
        }
        elseif ($_.UntestedCount -gt 0) {
            "<span class=`"estimated-flag`" title=`"$($_.UntestedCount) check(s) failed or were excluded in this run - its score may look better than a fully-tested run purely from checking less, not genuine improvement.`">&#9888; $($_.UntestedCount) untested</span>"
        }
        else {
            '<span style="color:#3f7d3f;">&#10003; full</span>'
        }
        @"
                    <tr>
                        <td>$dateCell</td>
                        <td>$verText</td>
                        <td>$($_.TotalScore)</td>
                        <td>$($_.MaturityLevel)</td>
                        <td>$coverageCell</td>
                    </tr>
"@
    }) -join "`n"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Maturity Trend History Report</title>
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
            --good: #1a7f4e;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: var(--font-sans); line-height: 1.6; color: var(--ink); background: var(--bg); padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: var(--surface); padding: 30px; box-shadow: 0 1px 3px rgba(15,23,42,0.08); border-radius: 8px; border: 1px solid var(--border); }
        h1 { color: var(--ink); border-bottom: 3px solid var(--brand); padding-bottom: 15px; margin-bottom: 20px; font-size: 1.7em; }
        h2 { color: var(--ink); margin-top: 30px; margin-bottom: 15px; padding: 10px 14px; background: var(--bg); border-left: 4px solid var(--brand); }
        .header-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; padding: 20px; background: var(--bg); border-radius: 5px; }
        .header-info div { padding: 10px; }
        .header-info strong { display: block; color: var(--ink-muted); font-size: 0.85em; margin-bottom: 5px; }
        .warning-box { background: #fdf8ec; border-left: 4px solid #8a6200; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .warning-box p { color: #8a6200; margin: 5px 0; }
        .estimated-flag { display: inline-block; font-size: 0.78em; font-weight: 700; color: #8a6200; background: #fdf8ec; border: 1px solid #8a6200; border-radius: 10px; padding: 1px 8px; margin-left: 6px; cursor: help; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.9em; }
        th { background: var(--brand); color: white; padding: 10px 12px; text-align: left; font-weight: 600; }
        td { padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
        tr:nth-child(even) { background: var(--bg); }
        .footer { margin-top: 50px; padding-top: 20px; border-top: 2px solid var(--border); text-align: center; color: var(--ink-muted); font-size: 0.9em; }
        @media print { body { background: white; padding: 0; } .container { box-shadow: none; } }
    </style>
</head>
<body>
    <div class="container">
        <h1>AD Maturity Trend History Report</h1>

        <div class="header-info">
            <div><strong>RUNS IN TREND</strong>$($Trend.RunCount)</div>
            <div><strong>EARLIEST</strong>$(ConvertTo-ADFriendlyDateText -Value $Trend.DateRange.Earliest)</div>
            <div><strong>LATEST</strong>$(ConvertTo-ADFriendlyDateText -Value $Trend.DateRange.Latest)</div>
            <div><strong>OVERALL DIRECTION</strong><span style="color:$overallColor; font-weight:700;">$($Trend.OverallDirection)</span></div>
            <div><strong>REPORT GENERATED</strong>$reportDate</div>
        </div>

        $messageHtml

        <h2>Risk Score Over Time</h2>
        <div style="max-width:700px;">$scoreLineSvg</div>
        <p style="color:var(--ink-muted); font-size:0.85em; margin-top:6px;">Score is 0-100 (higher = worse), read straight from each run's own historical sidecar - not recomputed under the current scoring table. Hover a point for its date and score.</p>

        <h2>Per-Category Trend</h2>
        <div style="overflow-x: auto;">
            <table>
                <thead><tr><th>Category</th><th>Trend</th><th>Direction</th></tr></thead>
                <tbody>
$categoryRowsHtml
                </tbody>
            </table>
        </div>

        <h2>Per-Run Detail</h2>
        <div style="overflow-x: auto;">
            <table>
                <thead><tr><th>Generated</th><th>Module Version</th><th>Score</th><th>Maturity</th><th>Coverage</th></tr></thead>
                <tbody>
$runRowsHtml
                </tbody>
            </table>
        </div>
        <p style="color:var(--ink-muted); font-size:0.85em; margin-top:6px;">Module Version is shown for every run so a score jump can be attributed to a tool change (a different row's version) vs. an actual posture change (same version, different score). A row marked <span class="estimated-flag">&#9888; estimated</span> had no recorded GeneratedDate (its sidecar predates v1.21.0) - its date is estimated from the sidecar file's own last-write time, not read from the file's contents.</p>

        <div class="footer">
            <p><strong>Generated by ADSecurityAudit Module v$($script:ModuleVersion) - Maturity Trend History</strong></p>
            <p>Pure offline aggregation of this module's own prior JSON exports. No Active Directory queries were performed to produce this report. Scores shown are each run's own historical value, not recomputed under the current scoring table.</p>
        </div>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Verbose "Maturity trend HTML report written to $OutputPath"
    }
}

#endregion
