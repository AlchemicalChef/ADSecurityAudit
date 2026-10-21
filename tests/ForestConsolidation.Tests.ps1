#Requires -Modules Pester
<#
    Unit tests for Step 16 - Get-ADForestConsolidation / Export-ADForestConsolidationHTML.

    These tests do NOT touch Active Directory. Like Scoring.Tests.ps1, they only
    exercise this project's own scoring/serialization contract: two synthetic
    "domain" exports (findings JSON + score sidecar JSON, in the exact shape
    Start-ADSecurityAudit already writes) are written to TestDrive and fed to
    Get-ADForestConsolidation entirely offline - matching this feature's own
    "no lab domain needed" test/validation notes.

    Run from the repo root:  Invoke-Pester ./tests/ForestConsolidation.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/ForestConsolidation.ps1')

    function New-TestFinding {
        param([string]$Issue, [string]$Category, [string]$Severity, [int]$SeverityLevel, [string]$AffectedObject = '', [hashtable]$Details = @{})
        $f = [ADSecurityFinding]::new()
        $f.Issue = $Issue
        $f.Category = $Category
        $f.Severity = $Severity
        $f.SeverityLevel = $SeverityLevel
        $f.AffectedObject = $AffectedObject
        $f.Details = $Details
        return $f
    }

    function New-DomainFixture {
        param(
            [string]$FolderName,
            [array]$Findings,
            [string]$Timestamp = '2026-07-01_00-00-00',
            [array]$TestCoverage
        )
        foreach ($finding in $Findings) { [void](Set-ADFindingMetadata -Finding $finding) }
        $riskScore = Get-ADRiskScore -Findings $Findings

        $domainFolder = Join-Path $TestDrive $FolderName
        New-Item -ItemType Directory -Path $domainFolder -Force | Out-Null

        $findingsPath = Join-Path $domainFolder "AD_Security_Audit_$Timestamp.json"
        $scorePath    = Join-Path $domainFolder "AD_Security_Score_$Timestamp.json"

        # See ConvertTo-ADFlatFindingsArray's own docs / Main.ps1's export
        # fix - a plain "@() | ConvertTo-Json" pipes nothing through and
        # writes an empty file rather than valid "[]" JSON.
        if (@($Findings).Count -eq 0) {
            '[]' | Out-File -FilePath $findingsPath -Encoding UTF8
        }
        else {
            $Findings | ConvertTo-Json -Depth 10 | Out-File -FilePath $findingsPath -Encoding UTF8
        }
        $riskScore  | ConvertTo-Json -Depth 6  | Out-File -FilePath $scorePath -Encoding UTF8

        if ($PSBoundParameters.ContainsKey('TestCoverage')) {
            $coveragePath = Join-Path $domainFolder "AD_Security_TestCoverage_$Timestamp.json"
            $TestCoverage | ConvertTo-Json -Depth 4 | Out-File -FilePath $coveragePath -Encoding UTF8
        }

        return $riskScore
    }
}

Describe 'Get-ADForestConsolidation (two-domain fixture, one clearly worse)' {
    BeforeAll {
        # DomainA: two Criticals -> clearly the worse domain.
        $findingsA = @(
            (New-TestFinding 'KRBTGT Password Age Exceeds Recommended Threshold' 'Kerberos Security' 'Critical' 4)
            (New-TestFinding 'Unauthorized DCSync Permissions' 'Replication Security' 'Critical' 4)
            (New-TestFinding 'Bidirectional Domain Trust' 'Domain Trusts' 'Medium' 2 -AffectedObject 'domainb.contoso.com' -Details @{ Target = 'domainb.contoso.com'; Direction = 'Bidirectional' })
            (New-TestFinding 'Forest Trust Without Selective Authentication' 'Domain Trusts' 'High' 3 -AffectedObject 'unknownexternal.example.com' -Details @{ Target = 'unknownexternal.example.com' })
        )
        $script:ScoreA = New-DomainFixture -FolderName 'DomainA' -Findings $findingsA

        # DomainB: only a single Low -> clearly the better domain.
        $findingsB = @(
            (New-TestFinding 'Inactive Enabled Account' 'User Account' 'Low' 1)
        )
        $script:ScoreB = New-DomainFixture -FolderName 'DomainB' -Findings $findingsB -Timestamp '2026-07-01_00-00-00'

        $script:Consolidation = Get-ADForestConsolidation -ReportPath $TestDrive
    }

    It 'discovers both domain report pairs, named from their subfolders' {
        $script:Consolidation.DomainCount | Should -Be 2
        $script:Consolidation.Domains.DomainName | Should -Contain 'DomainA'
        $script:Consolidation.Domains.DomainName | Should -Contain 'DomainB'
    }

    It 'sets the forest score to the worse domain''s score, not an average' {
        $script:Consolidation.ForestScore | Should -Be $script:ScoreA.TotalScore
        $script:Consolidation.ForestScore | Should -Not -Be ([math]::Round((($script:ScoreA.TotalScore + $script:ScoreB.TotalScore) / 2)))
        $script:Consolidation.WorstDomain | Should -Be 'DomainA'
    }

    It 'sets forest maturity to the lowest (worst) maturity level present' {
        $script:Consolidation.ForestMaturityLevel | Should -Be ([math]::Min($script:ScoreA.MaturityLevel, $script:ScoreB.MaturityLevel))
    }

    It 'builds a worst-first domain comparison table' {
        $script:Consolidation.DomainComparison[0].DomainName | Should -Be 'DomainA'
    }

    It 'builds a per-category heatmap using the worst domain per category, not an average' {
        $kerberosRow = $script:Consolidation.CategoryHeatmap | Where-Object Category -eq 'Kerberos Security'
        $kerberosRow.WorstDomain | Should -Be 'DomainA'
    }

    It 'annotates a trust finding whose target domain report is present in the input set' {
        $enriched = $script:Consolidation.TrustRiskEnrichment | Where-Object { $_.TargetDomain -eq 'DomainB' }
        $enriched | Should -Not -BeNullOrEmpty
        $enriched.Annotated | Should -BeTrue
        $enriched.TargetScore | Should -Be $script:ScoreB.TotalScore
    }

    It 'leaves a trust finding unannotated (not an error) when its target domain is absent from the input set' {
        $unmatched = $script:Consolidation.TrustRiskEnrichment | Where-Object { $_.TargetDomain -eq 'unknownexternal.example.com' }
        $unmatched | Should -Not -BeNullOrEmpty
        $unmatched.Annotated | Should -BeFalse
        $unmatched.TargetScore | Should -BeNullOrEmpty
    }

    It 'reports no missing domains when no prior consolidation is supplied' {
        $script:Consolidation.MissingDomains.Count | Should -Be 0
    }
}

Describe 'Get-ADForestConsolidation (missing-domain detection across runs)' {
    BeforeAll {
        $findingsC = @( (New-TestFinding 'Inactive Enabled Account' 'User Account' 'Low' 1) )
        New-DomainFixture -FolderName 'DomainC' -Findings $findingsC -Timestamp '2026-06-01_00-00-00' | Out-Null

        # Prior run saw DomainA, DomainB (from the other Describe's TestDrive... use a
        # fresh, self-contained prior-consolidation JSON instead of relying on order).
        $priorPath = Join-Path $TestDrive 'AD_Forest_Consolidation_prior.json'
        [PSCustomObject]@{
            GeneratedDate = (Get-Date).AddDays(-7)
            Domains       = @(
                [PSCustomObject]@{ DomainName = 'DomainC' }
                [PSCustomObject]@{ DomainName = 'DomainD-not-scanned-this-run' }
            )
        } | ConvertTo-Json -Depth 5 | Out-File -FilePath $priorPath -Encoding UTF8

        $script:Result = Get-ADForestConsolidation -ReportPath (Join-Path $TestDrive 'DomainC') -DomainName 'DomainC' -PriorConsolidationPath $priorPath
    }

    It 'flags a domain present in the prior run but absent from this one as not scanned this run' {
        $script:Result.MissingDomains.DomainName | Should -Contain 'DomainD-not-scanned-this-run'
        ($script:Result.MissingDomains | Where-Object DomainName -eq 'DomainD-not-scanned-this-run').Status | Should -Be 'not scanned this run'
    }

    It 'does not flag a domain that is present in both the prior run and this one' {
        $script:Result.MissingDomains.DomainName | Should -Not -Contain 'DomainC'
    }
}

Describe 'Get-ADForestConsolidation (input validation)' {
    It 'throws a clear error when no matching exports are found' {
        $emptyDir = Join-Path $TestDrive 'Empty'
        New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
        { Get-ADForestConsolidation -ReportPath $emptyDir } | Should -Throw
    }
}

Describe 'Get-ADForestConsolidation - test coverage awareness' {
    <#
        Regression coverage for a reported gap: a domain with several
        excluded/failed checks looks "cleaner" (lower score) than a
        fully-tested domain purely from checking less, with nothing in
        the forest-wide comparison distinguishing the two.
    #>
    BeforeAll {
        # DomainX: fully covered, genuinely worse (score reflects a real finding).
        New-DomainFixture -FolderName 'CoverageDomainX' -Findings @(
            (New-TestFinding 'Inactive Enabled Account' 'User Account' 'Low' 1)
        ) -Timestamp '2026-08-01_00-00-00' -TestCoverage @(
            [PSCustomObject]@{ TestName = 'UserAccounts'; Status = 'Completed'; FindingCount = 1; ErrorMessage = $null }
            [PSCustomObject]@{ TestName = 'RodcSecurity'; Status = 'Completed'; FindingCount = 0; ErrorMessage = $null }
        )
        # DomainY: looks BETTER (zero findings) but RodcSecurity was excluded - misleading.
        New-DomainFixture -FolderName 'CoverageDomainY' -Findings @() -Timestamp '2026-08-01_00-00-00' -TestCoverage @(
            [PSCustomObject]@{ TestName = 'UserAccounts'; Status = 'Completed'; FindingCount = 0; ErrorMessage = $null }
            [PSCustomObject]@{ TestName = 'RodcSecurity'; Status = 'Excluded'; FindingCount = 0; ErrorMessage = $null }
        )
        # DomainZ: no coverage sidecar at all.
        New-DomainFixture -FolderName 'CoverageDomainZ' -Findings @() -Timestamp '2026-08-01_00-00-00'

        $script:Consolidation = Get-ADForestConsolidation -ReportPath $TestDrive
    }

    It 'flags the domain with an excluded check as having incomplete coverage' {
        $script:Consolidation.IncompleteCoverageDomains | Should -Contain 'CoverageDomainY'
        $script:Consolidation.IncompleteCoverageDomains | Should -Not -Contain 'CoverageDomainX'
    }

    It 'flags the domain with no coverage sidecar distinctly from the incomplete one' {
        $script:Consolidation.NoCoverageDataDomains | Should -Contain 'CoverageDomainZ'
        $script:Consolidation.NoCoverageDataDomains | Should -Not -Contain 'CoverageDomainY'
    }

    It 'does not flag the fully-covered domain either way' {
        $script:Consolidation.IncompleteCoverageDomains | Should -Not -Contain 'CoverageDomainX'
        $script:Consolidation.NoCoverageDataDomains | Should -Not -Contain 'CoverageDomainX'
    }

    It 'DomainComparison rows carry CoverageAvailable/UntestedCount matching the domain-level flags' {
        $rowY = $script:Consolidation.DomainComparison | Where-Object DomainName -eq 'CoverageDomainY'
        $rowY.CoverageAvailable | Should -BeTrue
        $rowY.UntestedCount | Should -Be 1

        $rowZ = $script:Consolidation.DomainComparison | Where-Object DomainName -eq 'CoverageDomainZ'
        $rowZ.CoverageAvailable | Should -BeFalse
    }

    It 'Export-ADForestConsolidationHTML renders the coverage column without throwing' {
        $outPath = Join-Path $TestDrive 'forest-coverage.html'
        { Export-ADForestConsolidationHTML -Consolidation $script:Consolidation -OutputPath $outPath } | Should -Not -Throw
        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'Coverage'
        $content | Should -Match 'untested'
        $content | Should -Match 'no data'
    }
}
