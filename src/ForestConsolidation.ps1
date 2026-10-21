#region Multi-Domain / Forest Consolidation (Step 16, offline, file-based)
#
# This is a POST-PROCESSING feature, not a live-AD detection module. It performs
# NO LDAP/AD queries, uses NO credentials, and requires NO network access to any
# domain controller. It reads two or more of this module's own prior exports
# (AD_Security_Audit_<timestamp>.json + AD_Security_Score_<timestamp>.json,
# produced by an existing Start-ADSecurityAudit run - one pair per domain) and
# rolls them up into a single forest-wide view, entirely offline.
#
# Its only hard contract dependency is step 01: the finding schema and the
# Get-ADRiskScore output shape (TotalScore, MaturityLevel, CategoryScores,
# SeverityCounts, etc.) that the score sidecar file already uses. It does not
# depend on which of steps 03-15's detection modules produced the underlying
# findings.
#
# NOTE ON DOMAIN NAMES: the ADSecurityFinding schema does not carry a Domain
# field (findings are per-run, and a run is already scoped to one domain), so
# this feature resolves a domain name for each report pair from, in order:
#   1. an explicit -DomainName array (must line up 1:1 with discovered pairs)
#   2. the per-domain subfolder a report pair lives in, if reports are
#      organized as <ReportPath>\<DomainName>\AD_Security_Audit_*.json
#   3. a synthetic "UnknownDomain-N" label, with a warning, so consolidation
#      still runs rather than failing outright
#
# This feature is NOT registered in Main.ps1's $allTests - it isn't a per-domain
# live-AD check, it's a standalone command run after one-or-more
# Start-ADSecurityAudit runs already exist (the same pattern as
# Export-ADControlPathGraphBloodHound).

function Get-ADForestConsolidation {
    <#
    .SYNOPSIS
        Offline, file-based consolidation of two or more ADSecurityAudit domain
        exports into a single forest-wide view.
    .DESCRIPTION
        Reads existing AD_Security_Audit_<timestamp>.json (findings) and
        AD_Security_Score_<timestamp>.json (score/maturity/MITRE sidecar) pairs
        produced by prior Start-ADSecurityAudit runs - one pair per domain - and
        builds:
          * a forest-wide score/maturity using the SAME worst-category (MAX)
            semantics as Get-ADRiskScore (the forest is only as strong as its
            weakest domain, not an average of all of them)
          * a per-category heatmap: the worst per-domain score for each audit
            category, so a category that's fine in one domain doesn't get
            diluted by an average with a domain where it's bad
          * a domain comparison table (finding counts by severity, worst-first)
          * cross-domain risk annotation: for each Domain-Trusts finding, or
            each Attack-Paths (Test-ADControlPaths) finding whose hop chain
            reaches into another domain, naming a target domain, if a report
            for that target domain is also present in the input set, its
            Details are annotated with the target domain's own
            TotalScore/MaturityLevel/MaturityLabel (files/27)
          * "not scanned this run" flags for any domain present in a prior
            consolidated run (-PriorConsolidationPath) but absent from this one

        This performs no AD/LDAP queries of any kind - it is pure offline file
        aggregation over this module's own prior JSON exports. A malformed or
        partial export produces a warning and that domain is skipped; it never
        crashes the whole consolidation.
    .PARAMETER ReportPath
        One or more paths: a folder to search recursively for
        AD_Security_Audit_*.json exports, and/or explicit paths to individual
        findings JSON files. Each findings file must have a sibling
        AD_Security_Score_*.json with the matching timestamp in the same folder
        (exactly what Start-ADSecurityAudit already writes side by side).
    .PARAMETER DomainName
        Optional. Explicit domain name per discovered report pair, in the same
        order as the pairs are discovered (sorted by full path). Only used when
        its count matches the number of discovered pairs exactly.
    .PARAMETER PriorConsolidationPath
        Optional. Path to a previous AD_Forest_Consolidation_<timestamp>.json.
        Any domain present there but missing from this run's input is flagged
        in MissingDomains as "not scanned this run" rather than silently
        dropped from history.
    .PARAMETER ToJson
        Optional. Also persist the consolidated result to this path.
    .OUTPUTS
        PSCustomObject: GeneratedDate, DomainCount, ForestScore,
        ForestMaturityLevel, ForestMaturityLabel, WorstDomain, Domains,
        CategoryHeatmap, DomainComparison, TrustRiskEnrichment, MissingDomains,
        IncompleteCoverageDomains, NoCoverageDataDomains.
        Additive-friendly shape - a later feature can extend it without
        breaking this one.
    .EXAMPLE
        Get-ADForestConsolidation -ReportPath .\Reports\ -Verbose |
            Export-ADForestConsolidationHTML -OutputPath .\forest-report.html
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$ReportPath,

        [Parameter()]
        [string[]]$DomainName,

        [Parameter()]
        [string]$PriorConsolidationPath,

        [Parameter()]
        [string]$ToJson
    )

    Write-Verbose "Starting offline forest consolidation (no AD queries)..."

    # --- Step 1: resolve input paths to a list of candidate findings files ---
    $findingsFiles = @()
    foreach ($p in $ReportPath) {
        if (-not (Test-Path -Path $p)) {
            Write-Warning "ReportPath entry not found, skipping: $p"
            continue
        }
        $item = Get-Item -Path $p
        if ($item.PSIsContainer) {
            $findingsFiles += Get-ChildItem -Path $p -Filter 'AD_Security_Audit_*.json' -Recurse -File
        }
        elseif ($item.Name -like 'AD_Security_Audit_*.json') {
            $findingsFiles += $item
        }
        else {
            Write-Warning "Not a recognized AD_Security_Audit_*.json export, skipping: $p"
        }
    }
    $findingsFiles = @($findingsFiles | Sort-Object -Property FullName -Unique)

    if ($findingsFiles.Count -eq 0) {
        throw "No 'AD_Security_Audit_*.json' findings exports found under the given -ReportPath."
    }

    # --- Step 2: pair each findings file with its score sidecar + resolve a domain name ---
    $pairs = @()
    for ($i = 0; $i -lt $findingsFiles.Count; $i++) {
        $ff = $findingsFiles[$i]
        $scoreName = $ff.Name -replace '^AD_Security_Audit_', 'AD_Security_Score_'
        $scorePath = Join-Path -Path $ff.DirectoryName -ChildPath $scoreName

        if (-not (Test-Path -Path $scorePath)) {
            Write-Warning "No matching score sidecar for '$($ff.FullName)' (expected '$scoreName' alongside it); skipping this domain export."
            continue
        }

        $resolvedName = $null
        if ($DomainName -and $DomainName.Count -eq $findingsFiles.Count) {
            $resolvedName = $DomainName[$i]
        }
        elseif ($ff.Directory.Name -and ($ReportPath -notcontains $ff.DirectoryName)) {
            # Organized as <ReportPath>\<DomainName>\AD_Security_Audit_*.json
            $resolvedName = $ff.Directory.Name
        }
        else {
            $resolvedName = "UnknownDomain-$($i + 1)"
            Write-Warning "Could not determine a domain name for '$($ff.FullName)' (the finding schema does not carry a Domain field); using '$resolvedName'. Pass -DomainName (one entry per discovered pair) to label domains explicitly."
        }

        $pairs += [PSCustomObject]@{
            DomainName   = $resolvedName
            FindingsPath = $ff.FullName
            ScorePath    = $scorePath
        }
    }

    if ($pairs.Count -eq 0) {
        throw "Found findings exports but none had a matching score sidecar file - nothing to consolidate."
    }

    # --- Step 3: deserialize each pair offline. No AD/network access here. ---
    $domains = @()
    foreach ($pair in $pairs) {
        try {
            $findingsRaw = Get-Content -Path $pair.FindingsPath -Raw | ConvertFrom-Json
            $scoreRaw    = Get-Content -Path $pair.ScorePath -Raw | ConvertFrom-Json
        }
        catch {
            Write-Warning "Skipping domain '$($pair.DomainName)': failed to parse JSON export ($_)."
            continue
        }

        if (-not ($scoreRaw.PSObject.Properties.Name -contains 'TotalScore')) {
            Write-Warning "Skipping domain '$($pair.DomainName)': score sidecar is missing the expected TotalScore field (see step 01's Get-ADRiskScore output contract)."
            continue
        }

        $findingsArray = @($findingsRaw)

        # Reported gap: a domain with several excluded/failed checks looks
        # "cleaner" (lower score) than a fully-tested domain purely from
        # checking less, not from genuinely better posture - the forest
        # heatmap and domain comparison table had no way to distinguish
        # the two. Same sibling-sidecar lookup used by
        # Get-ADRetestComparison/Get-ADMaturityTrend.
        $domainCoverage = @(Get-ADTestCoverageSidecar -FindingsFile (Get-Item -Path $pair.FindingsPath))
        $domainUntestedCount = @($domainCoverage | Where-Object { $_.Status -in @('Failed', 'Excluded') }).Count
        $domainCoverageAvailable = $domainCoverage.Count -gt 0

        $domains += [PSCustomObject]@{
            DomainName        = $pair.DomainName
            TotalScore        = [int]$scoreRaw.TotalScore
            MaturityLevel     = [int]$scoreRaw.MaturityLevel
            MaturityLabel     = $scoreRaw.MaturityLabel
            FindingCount      = if ($scoreRaw.PSObject.Properties.Name -contains 'FindingCount') { [int]$scoreRaw.FindingCount } else { $findingsArray.Count }
            SeverityCounts    = $scoreRaw.SeverityCounts
            CategoryScores    = @($scoreRaw.CategoryScores)
            Findings          = $findingsArray
            FindingsPath      = $pair.FindingsPath
            ScorePath         = $pair.ScorePath
            CoverageAvailable = $domainCoverageAvailable
            UntestedCount     = $domainUntestedCount
        }
    }

    if ($domains.Count -eq 0) {
        throw "No domain report pairs could be loaded - nothing to consolidate."
    }

    Write-Verbose "Loaded $($domains.Count) domain report(s): $($domains.DomainName -join ', ')"

    $maturityLabels = @{
        1 = 'Level 1 - Critical gaps (basic hygiene not met)'
        2 = 'Level 2 - Partial hygiene'
        3 = 'Level 3 - Standard hardening'
        4 = 'Level 4 - Advanced hardening'
        5 = 'Level 5 - Optimal'
    }

    # --- Step 4: forest-wide score & maturity - same worst-category / MAX
    # semantics as Get-ADRiskScore, applied at forest scope. Do NOT average. ---
    $forestScore = ($domains | Measure-Object -Property TotalScore -Maximum).Maximum
    $worstDomain = $domains | Sort-Object -Property TotalScore -Descending | Select-Object -First 1
    $forestMaturityLevel = ($domains | Measure-Object -Property MaturityLevel -Minimum).Minimum

    # --- Step 5: per-category forest heatmap - worst domain per category. ---
    $allCategories = @($domains.CategoryScores.Category | Select-Object -Unique)
    $heatmap = foreach ($cat in $allCategories) {
        $rows = foreach ($d in $domains) {
            $c = $d.CategoryScores | Where-Object { $_.Category -eq $cat }
            [PSCustomObject]@{ DomainName = $d.DomainName; Score = if ($c) { [int]$c.Score } else { 0 } }
        }
        $rows = @($rows | Sort-Object -Property Score -Descending)
        [PSCustomObject]@{
            Category    = $cat
            WorstDomain = $rows[0].DomainName
            WorstScore  = $rows[0].Score
            PerDomain   = $rows
        }
    }
    $heatmap = @($heatmap | Sort-Object -Property WorstScore -Descending)

    # --- Step 6: domain comparison table, worst-first. ---
    $comparison = foreach ($d in $domains) {
        $sev = $d.SeverityCounts
        [PSCustomObject]@{
            DomainName        = $d.DomainName
            TotalScore        = $d.TotalScore
            MaturityLevel     = $d.MaturityLevel
            Critical          = if ($sev -and $sev.PSObject.Properties.Name -contains 'Critical') { $sev.Critical } else { 0 }
            High              = if ($sev -and $sev.PSObject.Properties.Name -contains 'High') { $sev.High } else { 0 }
            Medium            = if ($sev -and $sev.PSObject.Properties.Name -contains 'Medium') { $sev.Medium } else { 0 }
            Low               = if ($sev -and $sev.PSObject.Properties.Name -contains 'Low') { $sev.Low } else { 0 }
            FindingCount      = $d.FindingCount
            CoverageAvailable = $d.CoverageAvailable
            UntestedCount     = $d.UntestedCount
        }
    }
    $comparison = @($comparison | Sort-Object -Property TotalScore, Critical, High -Descending)

    # --- Step 7: cross-domain risk annotation. Match a finding's target
    # domain (extracted per-category, see Get-ADForestConsolidationTargetDomain
    # below) against the domain names present in this input set. Annotate
    # in place when matched; leave unannotated (not an error) when the
    # target domain's own report isn't part of this consolidation.
    # Originally 'Domain Trusts' findings only; generalized
    # (files/27-cross-domain-risk-annotation-extension.md) into a shared
    # helper also applied to Test-ADControlPaths' 'Attack Paths' findings,
    # whose hop chain can reach into another domain in the same
    # consolidation run. Test-ADExchangeEscalation findings were
    # evaluated for applicability and found NOT applicable: per that
    # module's own header, it evaluates ACEs on the domain head and
    # AdminSDHolder strictly within a single domain's own boundary, and
    # never names a target domain in its finding output - there is
    # nothing for this annotation to attach to. ---
    $domainsByName = @{}
    foreach ($d in $domains) { $domainsByName[$d.DomainName] = $d }

    # Extracts the cross-domain target name a given finding names, or
    # $null if this finding/category doesn't name one. Kept as a single
    # function so the matching/annotation logic below never needs its own
    # per-category branch - only this extraction step does.
    function Get-ADForestConsolidationTargetDomain {
        param([Parameter(Mandatory)]$Finding)

        if ($Finding.Category -eq 'Domain Trusts') {
            if ($Finding.Details -and ($Finding.Details.PSObject.Properties.Name -contains 'Target') -and $Finding.Details.Target) {
                return [string]$Finding.Details.Target
            }
            elseif ($Finding.AffectedObject) {
                return [string]$Finding.AffectedObject
            }
            return $null
        }

        if ($Finding.Category -eq 'Attack Paths' -and $Finding.Details -and
            ($Finding.Details.PSObject.Properties.Name -contains 'TargetDN') -and $Finding.Details.TargetDN) {
            # TargetDN is a distinguished name (e.g.
            # "CN=X,OU=Y,DC=child,DC=contoso,DC=com"); the domain's own DN
            # form is exactly its DC= components joined with dots, which
            # is also how Get-ADDomain -Server ... .DistinguishedName's
            # own DC= components map back to a domain's DNSRoot/NetBIOS -
            # this consolidation's $domainsByName keys off DomainName, so
            # build the same dotted form here for the match below.
            $dcComponents = @([regex]::Matches("$($Finding.Details.TargetDN)", 'DC=([^,]+)', 'IgnoreCase') |
                ForEach-Object { $_.Groups[1].Value })
            if ($dcComponents.Count -gt 0) {
                return ($dcComponents -join '.')
            }
        }

        # Test-ADExchangeEscalation: intentionally not handled here - see
        # the comment above this function's block. Its findings never
        # name a cross-domain target (single-domain ACE reads only), so
        # there is nothing this helper could extract.
        return $null
    }

    $trustEnrichment = @()
    foreach ($d in $domains) {
        foreach ($finding in $d.Findings) {
            if ($finding.Category -notin @('Domain Trusts', 'Attack Paths')) { continue }

            $target = Get-ADForestConsolidationTargetDomain -Finding $finding
            if ([string]::IsNullOrEmpty($target)) { continue }

            # Case-insensitive match, tolerant of FQDN vs short-name mismatches
            # between a trust's Target and this consolidation's domain names.
            $matched = $domainsByName.Values | Where-Object {
                $_.DomainName -ieq $target -or $target -ilike "$($_.DomainName)*" -or $_.DomainName -ilike "$target*"
            } | Select-Object -First 1

            if ($matched) {
                if (-not $finding.Details) {
                    Add-Member -InputObject $finding -MemberType NoteProperty -Name 'Details' -Value ([PSCustomObject]@{}) -Force
                }
                Add-Member -InputObject $finding.Details -MemberType NoteProperty -Name 'TargetDomainScore' -Value $matched.TotalScore -Force
                Add-Member -InputObject $finding.Details -MemberType NoteProperty -Name 'TargetDomainMaturityLevel' -Value $matched.MaturityLevel -Force
                Add-Member -InputObject $finding.Details -MemberType NoteProperty -Name 'TargetDomainMaturityLabel' -Value $matched.MaturityLabel -Force

                $trustEnrichment += [PSCustomObject]@{
                    SourceDomain   = $d.DomainName
                    TargetDomain   = $matched.DomainName
                    Issue          = $finding.Issue
                    Severity       = $finding.Severity
                    TargetScore    = $matched.TotalScore
                    TargetMaturity = $matched.MaturityLabel
                    Annotated      = $true
                }
            }
            else {
                $trustEnrichment += [PSCustomObject]@{
                    SourceDomain   = $d.DomainName
                    TargetDomain   = $target
                    Issue          = $finding.Issue
                    Severity       = $finding.Severity
                    TargetScore    = $null
                    TargetMaturity = $null
                    Annotated      = $false
                }
            }
        }
    }

    # --- Step 8: flag domains present in a prior consolidated run but absent
    # from this one's input, rather than silently dropping them from history. ---
    $missingDomains = @()
    if ($PriorConsolidationPath) {
        if (Test-Path -Path $PriorConsolidationPath) {
            try {
                $prior = Get-Content -Path $PriorConsolidationPath -Raw | ConvertFrom-Json
                $priorNames = @($prior.Domains | ForEach-Object { $_.DomainName })
                $currentNames = @($domains.DomainName)
                foreach ($name in $priorNames) {
                    if ($currentNames -notcontains $name) {
                        $missingDomains += [PSCustomObject]@{
                            DomainName = $name
                            Status     = 'not scanned this run'
                            # Normalized (Common.ps1) so this renders as a clean
                            # date even against a prior consolidation JSON
                            # written before GeneratedDate was stored as a
                            # string - see the Scoring.ps1/RetestComparison.ps1
                            # comments on the same underlying issue.
                            LastSeen   = ConvertTo-ADFriendlyDateText -Value $prior.GeneratedDate
                        }
                    }
                }
            }
            catch {
                Write-Warning "Could not read prior consolidation at '$PriorConsolidationPath' for missing-domain comparison: $_"
            }
        }
        else {
            Write-Warning "PriorConsolidationPath '$PriorConsolidationPath' not found; skipping missing-domain comparison."
        }
    }

    # Same "flag it, don't hide it" reasoning as Get-ADMaturityTrend's
    # IncompleteCoverageCount/NoCoverageDataCount - a domain with untested
    # checks can look "cleaner" than a fully-tested one purely from
    # checking less, which would be a misleading signal in a forest-wide
    # comparison meant to find the WORST domain.
    $incompleteCoverageDomains = @($domains | Where-Object { $_.CoverageAvailable -and $_.UntestedCount -gt 0 })
    $noCoverageDataDomains = @($domains | Where-Object { -not $_.CoverageAvailable })

    $result = [PSCustomObject]@{
        # String, not a raw [datetime] - see Scoring.ps1's comment on why.
        GeneratedDate           = (Get-Date).ToString('o')
        DomainCount             = $domains.Count
        ForestScore             = [int]$forestScore
        ForestMaturityLevel     = [int]$forestMaturityLevel
        ForestMaturityLabel     = $maturityLabels[[int]$forestMaturityLevel]
        WorstDomain             = $worstDomain.DomainName
        Domains                 = $domains
        CategoryHeatmap         = $heatmap
        DomainComparison        = $comparison
        TrustRiskEnrichment     = @($trustEnrichment)
        MissingDomains          = @($missingDomains)
        # New in v1.24.0, additive - domain names (not counts, since a
        # forest is typically a much smaller N than a maturity trend's
        # run history, so naming them directly is more useful here) with
        # incomplete or unavailable test coverage data.
        # IncompleteCoverageDomains: coverage data exists and positively
        # shows one or more failed/excluded checks for that domain.
        # NoCoverageDataDomains: no coverage sidecar at all for that
        # domain (predates module v1.24.0, or the sidecar wasn't kept
        # alongside the export) - whether it had untested checks cannot
        # be determined either way. Both empty when every domain has
        # full, confirmed coverage.
        IncompleteCoverageDomains = @($incompleteCoverageDomains.DomainName)
        NoCoverageDataDomains     = @($noCoverageDataDomains.DomainName)
    }

    if ($ToJson) {
        try {
            $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $ToJson -Encoding UTF8
            Write-Verbose "Consolidated forest result written to $ToJson"
        }
        catch {
            Write-Warning "Failed to write -ToJson output to '$ToJson': $_"
        }
    }

    return $result
}

function Export-ADForestConsolidationHTML {
    <#
    .SYNOPSIS
        Renders a Get-ADForestConsolidation result as a standalone HTML report.
    .DESCRIPTION
        Reuses the same visual language (gauge, category bars, collapsible-style
        tables) as Export-ADSecurityReportHTML in Reporting.ps1, rather than
        inventing a new stylesheet. Pure rendering over an already-computed
        consolidation object - performs no file discovery or AD access itself.
    .PARAMETER Consolidation
        The object returned by Get-ADForestConsolidation.
    .PARAMETER OutputPath
        Path to write the HTML report to.
    .EXAMPLE
        Get-ADForestConsolidation -ReportPath .\Reports\ |
            Export-ADForestConsolidationHTML -OutputPath .\forest-report.html
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Consolidation,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }

    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $forestScore = [int]$Consolidation.ForestScore
    $gaugeColor = if ($forestScore -ge 75) { '#e74c3c' }
                  elseif ($forestScore -ge 50) { '#e67e22' }
                  elseif ($forestScore -ge 25) { '#f39c12' }
                  else { '#27ae60' }
    $maturityLevel = [int]$Consolidation.ForestMaturityLevel

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Forest Consolidation Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 20px rgba(0,0,0,0.1); border-radius: 8px; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 15px; margin-bottom: 20px; }
        h2 { color: #34495e; margin-top: 30px; margin-bottom: 15px; padding: 10px; background: #ecf0f1; border-left: 4px solid #3498db; }
        h3 { color: #555; margin-top: 20px; margin-bottom: 10px; }
        .header-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px; }
        .header-info div { padding: 10px; }
        .header-info strong { display: block; color: #7f8c8d; font-size: 0.9em; margin-bottom: 5px; }
        .warning-box { background: #fff3cd; border-left: 4px solid #f39c12; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .warning-box p { color: #856404; margin: 5px 0; }
        .scoring-grid { display: grid; grid-template-columns: minmax(260px, 1fr) minmax(260px, 1fr); gap: 20px; margin: 20px 0; }
        @media (max-width: 700px) { .scoring-grid { grid-template-columns: 1fr; } }
        .score-panel, .maturity-panel { padding: 25px; border-radius: 8px; background: #f8f9fa; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .gauge-wrap { display: flex; align-items: center; justify-content: center; gap: 20px; flex-wrap: wrap; }
        .gauge { --pct: 0; --col: #95a5a6; width: 160px; height: 160px; border-radius: 50%;
                 background: radial-gradient(white 58%, transparent 59%),
                 conic-gradient(var(--col) calc(var(--pct) * 1%), #e6e9ec 0);
                 display: flex; align-items: center; justify-content: center; }
        .gauge-inner { text-align: center; }
        .gauge-inner .num { font-size: 2.6em; font-weight: bold; color: #2c3e50; line-height: 1; }
        .gauge-inner .of { font-size: 0.9em; color: #7f8c8d; }
        .score-meta { color: #555; }
        .maturity-head { font-size: 2.2em; font-weight: bold; color: #2c3e50; }
        .maturity-head small { font-size: 0.45em; color: #7f8c8d; font-weight: normal; }
        .cat-bar-row { display: grid; grid-template-columns: 220px 1fr 50px; align-items: center; gap: 10px; margin: 6px 0; font-size: 0.9em; }
        .cat-bar-track { display: block; background: #e6e9ec; border-radius: 10px; height: 16px; overflow: hidden; }
        .cat-bar-fill { display: block; height: 100%; border-radius: 10px; }
        .privileged-users-table, .mitre-table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.9em; }
        .privileged-users-table th, .mitre-table th { background: #34495e; color: white; padding: 10px 12px; text-align: left; font-weight: 600; }
        .privileged-users-table td, .mitre-table td { padding: 8px 10px; border-bottom: 1px solid #ecf0f1; }
        .privileged-users-table tr:nth-child(even), .mitre-table tr:nth-child(even) { background: #f8f9fa; }
        .severity-badge { padding: 4px 12px; border-radius: 20px; font-weight: bold; font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.5px; }
        .severity-critical { background: #e74c3c; color: white; }
        .severity-high { background: #e67e22; color: white; }
        .severity-medium { background: #f39c12; color: white; }
        .severity-low { background: #95a5a6; color: white; }
        .footer { margin-top: 50px; padding-top: 20px; border-top: 2px solid #ecf0f1; text-align: center; color: #7f8c8d; font-size: 0.9em; }
        @media print { body { background: white; padding: 0; } .container { box-shadow: none; } }
    </style>
</head>
<body>
    <div class="container">
        <h1>&#127796; Forest / Multi-Domain Consolidation Report</h1>

        <div class="warning-box">
            <p><strong>&#9888; CONFIDENTIAL SECURITY REPORT</strong></p>
            <p>Offline consolidation over $($Consolidation.DomainCount) previously-exported ADSecurityAudit domain report(s). No Active Directory queries were performed to produce this report.</p>
        </div>

        <div class="header-info">
            <div><strong>DOMAINS CONSOLIDATED</strong><span style="font-size: 1.2em; color: #2c3e50;">$($Consolidation.DomainCount)</span></div>
            <div><strong>REPORT DATE</strong><span style="font-size: 1.2em; color: #2c3e50;">$reportDate</span></div>
            <div><strong>WEAKEST DOMAIN</strong><span style="font-size: 1.2em; color: #2c3e50;">$(HtmlEncode $Consolidation.WorstDomain)</span></div>
        </div>

        <h2>&#127919; Forest Risk Score &amp; Maturity</h2>
        <div class="scoring-grid">
            <div class="score-panel">
                <h3>Forest-Wide Risk Score</h3>
                <div class="gauge-wrap">
                    <div class="gauge" style="--pct: $forestScore; --col: $gaugeColor;">
                        <div class="gauge-inner">
                            <div class="num">$forestScore</div>
                            <div class="of">/ 100</div>
                        </div>
                    </div>
                    <div class="score-meta">
                        <p>Forest score equals the <strong>worst-scoring domain's</strong> own score - the same worst-category/weakest-link philosophy as the per-domain risk score, applied at forest scope. Not an average.</p>
                    </div>
                </div>
            </div>
            <div class="maturity-panel">
                <h3>Forest ANSSI Maturity Level</h3>
                <div class="maturity-head">$maturityLevel <small>/ 5</small></div>
                <p style="color:#555; margin: 6px 0 4px;">$(HtmlEncode $Consolidation.ForestMaturityLabel)</p>
                <p style="font-size:0.85em; color:#7f8c8d; margin-top:10px;">The forest's maturity is the lowest (worst) maturity level present among the consolidated domains.</p>
            </div>
        </div>

        <h2>&#128202; Domain Comparison (worst first)</h2>
        <div style="overflow-x: auto;">
            <table class="privileged-users-table">
                <thead><tr><th>Domain</th><th>Score</th><th>Maturity</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Findings</th><th>Coverage</th></tr></thead>
                <tbody>
"@

    foreach ($row in $Consolidation.DomainComparison) {
        $coverageCell = if (-not $row.CoverageAvailable) {
            '<span style="color:#a05a00; font-size:0.85em;" title="No test coverage sidecar for this domain (predates module v1.24.0, or the sidecar was not kept alongside its export) - untested checks, if any, cannot be determined.">&#9888; no data</span>'
        }
        elseif ($row.UntestedCount -gt 0) {
            "<span style=`"color:#a05a00; font-size:0.85em;`" title=`"$($row.UntestedCount) check(s) failed or were excluded for this domain - its score may look better than a fully-tested domain purely from checking less, not genuinely better posture.`">&#9888; $($row.UntestedCount) untested</span>"
        }
        else {
            '<span style="color:#3f7d3f; font-size:0.85em;">&#10003; full</span>'
        }
        $html += @"
                    <tr>
                        <td><strong>$(HtmlEncode $row.DomainName)</strong></td>
                        <td>$($row.TotalScore)</td>
                        <td>$($row.MaturityLevel)</td>
                        <td>$($row.Critical)</td>
                        <td>$($row.High)</td>
                        <td>$($row.Medium)</td>
                        <td>$($row.Low)</td>
                        <td>$($row.FindingCount)</td>
                        <td>$coverageCell</td>
                    </tr>
"@
    }

    $html += @"
                </tbody>
            </table>
        </div>

        <h2>&#128293; Per-Category Heatmap (worst domain per category)</h2>
        <div style="margin: 10px 0 20px;">
"@

    foreach ($cat in $Consolidation.CategoryHeatmap) {
        $cScore = [int]$cat.WorstScore
        $cColor = if ($cScore -ge 75) { '#e74c3c' }
                  elseif ($cScore -ge 50) { '#e67e22' }
                  elseif ($cScore -ge 25) { '#f39c12' }
                  else { '#27ae60' }
        $html += @"
            <div class="cat-bar-row">
                <span>$(HtmlEncode $cat.Category) <span style="color:#aaa;">(worst: $(HtmlEncode $cat.WorstDomain))</span></span>
                <span class="cat-bar-track"><span class="cat-bar-fill" style="width: $cScore%; background: $cColor;"></span></span>
                <span style="text-align:right; font-weight:600; color:#555;">$cScore</span>
            </div>
"@
    }
    $html += "        </div>"

    if ($Consolidation.TrustRiskEnrichment -and $Consolidation.TrustRiskEnrichment.Count -gt 0) {
        $html += @"

        <h2>&#128272; Cross-Domain Trust Risk</h2>
        <div style="overflow-x: auto;">
            <table class="mitre-table">
                <thead><tr><th>Source Domain</th><th>Trust Finding</th><th>Severity</th><th>Target Domain</th><th>Target Score</th><th>Target Maturity</th></tr></thead>
                <tbody>
"@
        foreach ($t in $Consolidation.TrustRiskEnrichment) {
            $targetScoreText = if ($null -ne $t.TargetScore) { "$($t.TargetScore)/100" } else { 'not scanned this run' }
            $targetMaturityText = if ($t.TargetMaturity) { HtmlEncode $t.TargetMaturity } else { '-' }
            $sevClass = "severity-$(([string]$t.Severity).ToLower())"
            $html += @"
                    <tr>
                        <td>$(HtmlEncode $t.SourceDomain)</td>
                        <td>$(HtmlEncode $t.Issue)</td>
                        <td><span class="severity-badge $sevClass">$(HtmlEncode $t.Severity)</span></td>
                        <td>$(HtmlEncode $t.TargetDomain)</td>
                        <td>$targetScoreText</td>
                        <td>$targetMaturityText</td>
                    </tr>
"@
        }
        $html += @"
                </tbody>
            </table>
        </div>
"@
    }

    if ($Consolidation.MissingDomains -and $Consolidation.MissingDomains.Count -gt 0) {
        $html += @"

        <h2>&#9888; Domains Not Scanned This Run</h2>
        <div class="warning-box">
            <p>The following domains appeared in a prior consolidated run but have no report supplied to this run. They are flagged here rather than silently dropped from history - re-supply their latest export to refresh them.</p>
            <ul>
"@
        foreach ($m in $Consolidation.MissingDomains) {
            $html += "                <li><strong>$(HtmlEncode $m.DomainName)</strong> - $(HtmlEncode $m.Status) (last seen: $($m.LastSeen))</li>`n"
        }
        $html += @"
            </ul>
        </div>
"@
    }

    $html += @"

        <div class="footer">
            <p><strong>Generated by ADSecurityAudit Module v$($script:ModuleVersion) - Forest Consolidation</strong></p>
            <p>Pure offline aggregation of this module's own prior JSON exports. No Active Directory queries were performed to produce this report.</p>
        </div>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Verbose "Forest consolidation HTML report written to $OutputPath"
}

#endregion
