#Requires -Version 5.1
<#
.SYNOPSIS
    Generates synthetic AD_Security_Audit_*.json findings files (and,
    optionally, the HTML/CSV reports built from them) representing a
    made-up domain at four failure-density tiers: 25%, 50%, 75%, 100%.
.DESCRIPTION
    This tool exists to let you exercise the full reporting pipeline
    (JSON -> HTML -> CSV, scoring, maturity classification, category
    grouping) WITHOUT a real Active Directory environment - useful for
    demoing the tool, sanity-checking report rendering after a change
    like SchemaAudits.ps1's per-entry finding split, or just seeing what
    a domain at each maturity level would actually look like in the
    report.

    It does NOT simulate real AD behavior or generate plausible attack
    paths - every synthetic finding is a clearly-labeled placeholder
    ("[SYNTHETIC TEST DATA]" in its Description/Impact/Remediation text)
    built directly from this project's own $Script:ADFindingMetadataMap
    (Scoring.ps1) - i.e. every Issue this project can actually detect,
    with the correct MITRE/ANSSI/Weight metadata and Category the real
    finding-emission code would set, not an approximation. It is NOT a
    substitute for testing against a real domain, or even a real Pester
    suite - it only proves report RENDERING works across the maturity
    spectrum, not that DETECTION logic is correct.

    The four tiers are built by taking the N worst-severity Issues (by
    the same Critical/High/Medium/Low ordering the real scoring model
    uses), so lower tiers represent a domain that has already fixed its
    less-severe gaps and 100% represents "every single check this
    project has would fire" - a believable burn-down story, not a random
    sample.

    Each synthetic finding uses the REAL Category its Issue actually
    ships under in src/*.ps1 (extracted directly from source, not
    guessed) - this matters for more than realism: Get-ADRiskScore's own
    scoring model computes each category's score independently (with
    diminishing returns) and takes the MAX across categories as the
    TotalScore, so dumping every synthetic finding into one shared
    category would saturate that one category almost immediately and
    produce the SAME TotalScore for every tier regardless of how many
    Issues were selected - exactly the bug an early version of this tool
    shipped with, caught only once actually run end-to-end. Every
    synthetic finding is still unambiguously marked as synthetic via its
    Description/Impact/Remediation text ("[SYNTHETIC TEST DATA]"), so
    nobody mistakes a rendered report built from this tool's output for
    a real audit result, without needing to distort the Category and
    break the score gradient to do it.

.PARAMETER OutputPath
    Folder to write the synthetic fixtures (and, if -GenerateReports is
    set, their HTML/CSV) into. Created if it doesn't exist.
.PARAMETER DomainName
    Cosmetic only - used in the synthetic AffectedObject/Description text
    so the output reads like a real domain name instead of a placeholder.
.PARAMETER GenerateReports
    If set, also calls Export-ADSecurityReportHTMLFromJson and
    Export-ADSecurityReportCSVFromJson against each tier's JSON, so you
    get a full set of ready-to-open reports, not just the raw JSON.
.EXAMPLE
    ./tools/New-ADSecurityAuditSyntheticFixtures.ps1 -OutputPath ./synthetic-fixtures -GenerateReports

    Generates AD_Security_Audit_100pct_<timestamp>.json (and the 75/50/25
    equivalents), their AD_Security_Score_*.json sidecars, and - because
    -GenerateReports was passed - the matching HTML and CSV reports, all
    under ./synthetic-fixtures.
.NOTES
    Run from the repo root:
        pwsh ./tools/New-ADSecurityAuditSyntheticFixtures.ps1 -OutputPath ./synthetic-fixtures -GenerateReports

    Real, checked-in sample output from this tool (all four tiers -
    JSON findings, score sidecars, rebuilt HTML/CSV) lives in
    tools/synthetic-fixtures-samples/, along with a checklist for
    validating a NEW check before it ships (confirm its Scoring.ps1
    entry, confirm it renders in the correct Category/tier, etc.) - see
    that folder's own README.md.

    Verified end-to-end (including the fix for a real bug this tool's
    first run caught - see CHANGELOG.md v1.30.3) using a real PowerShell
    7.6.6 runtime. Full Pester coverage of this script itself is still
    open - only the checks it exercises have Pester coverage, not this
    generator's own selection/scoring logic.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'synthetic-fixtures'),

    [Parameter()]
    [string]$DomainName = 'fabrikam.local',

    [Parameter()]
    [switch]$GenerateReports
)

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'src/Common.ps1')
. (Join-Path $root 'src/Scoring.ps1')
. (Join-Path $root 'src/FindingNarrativeLibrary.ps1')
if ($GenerateReports) {
    # Export-ADSecurityReportHTMLFromJson/CSVFromJson (Reporting.ps1) both
    # call Resolve-ADRetestReportFile, which lives in RetestComparison.ps1
    # - a real cross-file dependency this tool must dot-source explicitly
    # (a plain dot-source of individual files, unlike Import-Module
    # against the real module manifest, does not resolve this
    # automatically).
    . (Join-Path $root 'src/RetestComparison.ps1')
    . (Join-Path $root 'src/Reporting.ps1')
}

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# --- Severity classification, reusing this project's own strict
#     vuln<N>_ -> Weight -> Severity correlation (verified elsewhere in
#     this codebase: vuln1=40/Critical, vuln2=20/High, vuln3=10/Medium,
#     vuln4-5=4-1/Low) rather than inventing a separate mapping. ---
function Get-ADSecurityAuditSyntheticSeverity {
    param([string]$Issue)
    $meta = $Script:ADFindingMetadataMap[$Issue]
    $anssi = if ($meta) { $meta.Anssi } else { '' }
    switch -regex ($anssi) {
        '^vuln1_' { return [PSCustomObject]@{ Severity = 'Critical'; SeverityLevel = 4 } }
        '^vuln2_' { return [PSCustomObject]@{ Severity = 'High';     SeverityLevel = 3 } }
        '^vuln3_' { return [PSCustomObject]@{ Severity = 'Medium';   SeverityLevel = 2 } }
        default   { return [PSCustomObject]@{ Severity = 'Low';      SeverityLevel = 1 } }
    }
}

$allIssues = @($Script:ADFindingMetadataMap.Keys | Sort-Object)
if ($allIssues.Count -eq 0) {
    throw "`$Script:ADFindingMetadataMap is empty - is src/Scoring.ps1 up to date/dot-sourced correctly?"
}

# --- Real Category per Issue, extracted directly from source (not
#     guessed) ---
# CORRECTED after a real bug found on first run: this tool originally put
# every synthetic finding into one shared "Synthetic Fixture" category.
# Get-ADRiskScore's own scoring model (Scoring.ps1) uses per-category
# diminishing returns with TotalScore = MAX(category scores) - dumping
# every finding into a single category saturates that one category's
# score almost immediately, so every tier (even 25%) came back with the
# same TotalScore=100, defeating the entire point of a four-tier maturity
# gradient. Fixed by extracting each Issue's REAL Category directly from
# its own $finding.Category assignment in src/*.ps1 (a "nearest preceding
# Category match" scan - not a guess/keyword heuristic), so synthetic
# findings spread across this project's actual ~25 categories the same
# way a real audit's findings would.
function Get-ADSecurityAuditRealIssueCategoryMap {
    param([string]$SrcRoot)
    $map = @{}
    Get-ChildItem -Path $SrcRoot -Filter '*.ps1' | ForEach-Object {
        $content = Get-Content -Path $_.FullName -Raw
        $catMatches = [regex]::Matches($content, '\$finding\.Category\s*=\s*["'']([^"'']+)["'']')
        $issueMatches = [regex]::Matches($content, '\$finding\.Issue\s*=\s*["'']([^"'']+)["'']')
        foreach ($im in $issueMatches) {
            $nearestCat = $null
            foreach ($cm in $catMatches) {
                if ($cm.Index -lt $im.Index) { $nearestCat = $cm.Groups[1].Value }
            }
            if ($nearestCat -and -not $map.ContainsKey($im.Groups[1].Value)) {
                $map[$im.Groups[1].Value] = $nearestCat
            }
        }
    }
    return $map
}
$issueCategoryMap = Get-ADSecurityAuditRealIssueCategoryMap -SrcRoot (Join-Path $root 'src')
Write-Host "Resolved real Category for $($issueCategoryMap.Count) of $($allIssues.Count) known Issues (source-code scan)." -ForegroundColor Cyan

$ranked = $allIssues | ForEach-Object {
    $sev = Get-ADSecurityAuditSyntheticSeverity -Issue $_
    [PSCustomObject]@{ Issue = $_; SeverityLevel = $sev.SeverityLevel; Severity = $sev.Severity }
} | Sort-Object -Property SeverityLevel, Issue -Descending

$tiers = [ordered]@{
    '100pct' = 1.00
    '75pct'  = 0.75
    '50pct'  = 0.50
    '25pct'  = 0.25
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

foreach ($tierName in $tiers.Keys) {
    $fraction = $tiers[$tierName]
    $count = [math]::Max(1, [math]::Ceiling($ranked.Count * $fraction))
    $selected = $ranked | Select-Object -First $count

    Write-Host "Building tier '$tierName': $count of $($ranked.Count) known Issues ($([math]::Round($fraction * 100))%)..." -ForegroundColor Cyan

    $objectCounter = 0
    $findings = foreach ($item in $selected) {
        $objectCounter++
        $meta = $Script:ADFindingMetadataMap[$item.Issue]

        $finding = [ADSecurityFinding]::new()
        $finding.Category       = if ($issueCategoryMap.ContainsKey($item.Issue)) { $issueCategoryMap[$item.Issue] } else { 'Uncategorized (Synthetic)' }
        $finding.Issue          = $item.Issue
        $finding.Severity       = $item.Severity
        $finding.SeverityLevel  = $item.SeverityLevel
        $finding.AffectedObject = "synthetic-object-$objectCounter.$DomainName"
        $finding.Description    = "[SYNTHETIC TEST DATA] Placeholder finding for '$($item.Issue)', generated to exercise report rendering - not a real detection result against '$DomainName' or any other domain."
        $finding.Impact         = "[SYNTHETIC TEST DATA] Placeholder impact text for '$($item.Issue)'. See src/Scoring.ps1 and the corresponding src/*.ps1 check for this Issue's real Impact wording."
        $finding.Remediation    = "[SYNTHETIC TEST DATA] Placeholder remediation text for '$($item.Issue)'."
        $finding.DetectedDate   = Get-Date
        $finding.MitreTechnique = if ($meta) { $meta.Mitre } else { '' }
        $finding.AnssiControl   = if ($meta) { $meta.Anssi } else { '' }
        $finding.Weight         = if ($meta) { $meta.Weight } else { 0 }
        $finding.Details        = @{ Synthetic = $true; Tier = $tierName }
        $finding
    }

    $jsonPath = Join-Path $OutputPath "AD_Security_Audit_${tierName}_$timestamp.json"
    if ($findings.Count -eq 0) {
        '[]' | Out-File -FilePath $jsonPath -Encoding UTF8
    }
    else {
        $findings | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    }
    Write-Host "  Wrote $jsonPath" -ForegroundColor Green

    $flatFindings = ConvertTo-ADFlatFindingsArray -Findings $findings
    $riskScore = Get-ADRiskScore -Findings $flatFindings
    $scorePath = Join-Path $OutputPath "AD_Security_Score_${tierName}_$timestamp.json"
    $scoreSidecar = [PSCustomObject]@{
        GeneratedDate  = (Get-Date).ToString('o')
        Domain         = $DomainName
        ModuleVersion  = (Import-PowerShellDataFile (Join-Path $root 'ADSecurityAudit.psd1')).ModuleVersion
        TotalScore     = $riskScore.TotalScore
        MaturityLevel  = $riskScore.MaturityLevel
        MaturityLabel  = $riskScore.MaturityLabel
        CategoryScores = $riskScore.CategoryScores
    }
    $scoreSidecar | ConvertTo-Json -Depth 6 | Out-File -FilePath $scorePath -Encoding UTF8
    Write-Host "  Wrote $scorePath (TotalScore=$($riskScore.TotalScore), Maturity=$($riskScore.MaturityLabel))" -ForegroundColor Green

    if ($GenerateReports) {
        $htmlPath = Join-Path $OutputPath "AD_Security_Audit_${tierName}_$timestamp.html"
        Export-ADSecurityReportHTMLFromJson -FindingsPath $jsonPath -OutputPath $htmlPath
        Write-Host "  Wrote $htmlPath" -ForegroundColor Green

        Export-ADSecurityReportCSVFromJson -FindingsPath $jsonPath -OutputPath $OutputPath
        Write-Host "  Wrote CSV report(s) alongside $jsonPath" -ForegroundColor Green
    }
}

Write-Host "`nDone. Four tiers written to '$OutputPath':" -ForegroundColor Cyan
Write-Host "  100pct - every known Issue this project can detect fires once"
Write-Host "  75pct  - the 75% worst-severity Issues fire"
Write-Host "  50pct  - the 50% worst-severity Issues fire"
Write-Host "  25pct  - the 25% worst-severity Issues fire (the domain's worst problems only)"
if (-not $GenerateReports) {
    Write-Host "`nRe-run with -GenerateReports to also produce the HTML/CSV reports for each tier." -ForegroundColor Yellow
}
