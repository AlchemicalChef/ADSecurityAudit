#Requires -Modules Pester
<#
    Unit tests for Get-ADRetestComparison / Export-ADRetestComparisonHTML.

    These tests do NOT touch Active Directory. Like ForestConsolidation.Tests.ps1,
    they only exercise this project's own scoring/serialization contract: two
    synthetic "run" exports (findings JSON + score sidecar JSON, in the exact
    shape Start-ADSecurityAudit already writes) are written to TestDrive and
    fed to Get-ADRetestComparison entirely offline.

    Run from the repo root:  Invoke-Pester ./tests/RetestComparison.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/RetestComparison.ps1')

    function New-TestFinding {
        param(
            [string]$Issue,
            [string]$Category,
            [string]$Severity,
            [int]$SeverityLevel,
            [string]$AffectedObject = '',
            [string]$TestName = ''
        )
        $f = [ADSecurityFinding]::new()
        $f.Issue = $Issue
        $f.Category = $Category
        $f.Severity = $Severity
        $f.SeverityLevel = $SeverityLevel
        $f.AffectedObject = $AffectedObject
        $f.TestName = $TestName
        return $f
    }

    function New-RunFixture {
        param(
            [string]$FolderName,
            [array]$Findings,
            [string]$Timestamp,
            [switch]$NoScoreSidecar,
            [array]$TestCoverage
        )
        foreach ($finding in $Findings) { [void](Set-ADFindingMetadata -Finding $finding) }
        $folder = Join-Path $TestDrive $FolderName
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        $findingsPath = Join-Path $folder "AD_Security_Audit_$Timestamp.json"
        # A plain "$Findings | ConvertTo-Json" pipes NOTHING through when
        # $Findings is an empty array (PowerShell pipeline semantics -
        # see ConvertTo-ADFlatFindingsArray's own docs for the general
        # form of this), producing an empty FILE rather than valid "[]"
        # JSON - not what a real current-version Start-ADSecurityAudit
        # run now writes for a zero-finding run (see Main.ps1's own fix
        # for this exact issue). Special-case it here so this fixture
        # matches real output instead of accidentally exercising a
        # different, already-fixed bug.
        if (@($Findings).Count -eq 0) {
            '[]' | Out-File -FilePath $findingsPath -Encoding UTF8
        }
        else {
            $Findings | ConvertTo-Json -Depth 6 | Out-File -FilePath $findingsPath -Encoding UTF8
        }

        if (-not $NoScoreSidecar) {
            $riskScore = Get-ADRiskScore -Findings $Findings
            $scorePath = Join-Path $folder "AD_Security_Score_$Timestamp.json"
            $riskScore | ConvertTo-Json -Depth 6 | Out-File -FilePath $scorePath -Encoding UTF8
        }
        if ($PSBoundParameters.ContainsKey('TestCoverage')) {
            $coveragePath = Join-Path $folder "AD_Security_TestCoverage_$Timestamp.json"
            $TestCoverage | ConvertTo-Json -Depth 4 | Out-File -FilePath $coveragePath -Encoding UTF8
        }
        return $folder
    }

    # --- Baseline: 3 stale accounts + 1 High privileged-group finding ---
    $script:BaselineFindings = @(
        New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'user1'
        New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'user2'
        New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'user3'
        New-TestFinding -Issue 'Excessive Privileged Group Membership' -Category 'Privileged Groups' -Severity 'High' -SeverityLevel 3 -AffectedObject 'Domain Admins'
    )

    # --- Retest: 2 of the 3 stale accounts resolved, the privileged-group
    # finding's severity changed, and one brand-new finding. ---
    $script:RetestFindings = @(
        New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'user3'
        New-TestFinding -Issue 'Excessive Privileged Group Membership' -Category 'Privileged Groups' -Severity 'Critical' -SeverityLevel 4 -AffectedObject 'Domain Admins'
        New-TestFinding -Issue 'Weak Minimum Password Length' -Category 'Domain Security' -Severity 'Medium' -SeverityLevel 2 -AffectedObject 'contoso.com'
    )
}

Describe 'Get-ADRetestComparison' {
    BeforeAll {
        $script:BaselineFolder = New-RunFixture -FolderName 'baseline' -Findings $script:BaselineFindings -Timestamp '2026-01-01_00-00-00'
        $script:RetestFolder   = New-RunFixture -FolderName 'retest'   -Findings $script:RetestFindings   -Timestamp '2026-02-01_00-00-00'
        $script:Comparison = Get-ADRetestComparison -BaselinePath $script:BaselineFolder -RetestPath $script:RetestFolder
    }

    It 'classifies a finding present only in the retest as New' {
        $script:Comparison.NewFindings.Count | Should -Be 1
        $script:Comparison.NewFindings[0].Issue | Should -Be 'Weak Minimum Password Length'
    }

    It 'classifies a finding present only in the baseline as Resolved' {
        $script:Comparison.ResolvedFindings.Count | Should -Be 2
        ($script:Comparison.ResolvedFindings.AffectedObject | Sort-Object) | Should -Be @('user1', 'user2')
    }

    It 'classifies an unchanged matched finding as StillOpen' {
        $script:Comparison.StillOpenFindings.Count | Should -Be 1
        $script:Comparison.StillOpenFindings[0].AffectedObject | Should -Be 'user3'
    }

    It 'classifies a matched finding whose severity differs as Changed, not StillOpen' {
        $script:Comparison.ChangedFindings.Count | Should -Be 1
        $script:Comparison.ChangedFindings[0].BaselineFinding.Severity | Should -Be 'High'
        $script:Comparison.ChangedFindings[0].RetestFinding.Severity | Should -Be 'Critical'
    }

    It 'matches findings on Category+Issue+AffectedObject, not Category+Issue alone (partial remediation is visible)' {
        # 3 stale accounts down to 1: 2 Resolved + 1 StillOpen, not one coarse bucket.
        $script:Comparison.ResolvedFindings.Count | Should -Be 2
        $script:Comparison.StillOpenFindings.Count | Should -Be 1
    }

    It 'surfaces each run''s own recorded ModuleVersion/GeneratedDate in BaselineMeta/RetestMeta for context' {
        $script:Comparison.BaselineMeta.ScorePath | Should -Not -BeNullOrEmpty
        $script:Comparison.RetestMeta.ScorePath | Should -Not -BeNullOrEmpty
    }

    It 'stores GeneratedDate as a clean, parseable date string - not the raw ConvertTo-Json expansion of a [datetime] object (regression)' {
        # Regression coverage for a real bug: Get-ADRiskScore used to store
        # GeneratedDate as a raw [datetime]. ConvertTo-Json expands a raw
        # [datetime] using its own DisplayHint/DateTime/value note
        # properties instead of a plain string, so ConvertFrom-Json handed
        # back "@{value=...; DisplayHint=2; DateTime=...}" wherever this was
        # read from a score sidecar - visible directly in the retest
        # report's header as unreadable text instead of a date.
        $script:Comparison.BaselineMeta.GeneratedDate | Should -Not -BeNullOrEmpty
        $script:Comparison.BaselineMeta.GeneratedDate | Should -Not -Match 'DisplayHint'
        { [datetime]$script:Comparison.BaselineMeta.GeneratedDate } | Should -Not -Throw

        $script:Comparison.RetestMeta.GeneratedDate | Should -Not -BeNullOrEmpty
        $script:Comparison.RetestMeta.GeneratedDate | Should -Not -Match 'DisplayHint'
        { [datetime]$script:Comparison.RetestMeta.GeneratedDate } | Should -Not -Throw
    }

    It 'exposes BaselineScore/RetestScore FindingCount for the report header' {
        $script:Comparison.BaselineScore.FindingCount | Should -Be $script:BaselineFindings.Count
        $script:Comparison.RetestScore.FindingCount | Should -Be $script:RetestFindings.Count
    }

    It 'recomputes both runs'' scores via the current Get-ADRiskScore rather than trusting stored sidecar values' {
        # Even though weight is issue-keyed (not severity-keyed) in the mapping
        # table, the recomputed score must come from Get-ADRiskScore's own
        # diminishing-returns model, not a passthrough of the sidecar file.
        $expectedRetest = Get-ADRiskScore -Findings $script:RetestFindings
        $script:Comparison.RetestScore.TotalScore | Should -Be $expectedRetest.TotalScore
    }

    It 'produces arithmetically correct ScoreDelta/MaturityDelta against Get-ADRiskScore run independently on each side' {
        $expectedBaseline = Get-ADRiskScore -Findings $script:BaselineFindings
        $expectedRetest   = Get-ADRiskScore -Findings $script:RetestFindings
        $script:Comparison.ScoreDelta    | Should -Be ($expectedRetest.TotalScore - $expectedBaseline.TotalScore)
        $script:Comparison.MaturityDelta | Should -Be ($expectedRetest.MaturityLevel - $expectedBaseline.MaturityLevel)
    }

    It 'produces correct per-category deltas including a category only present in one run' {
        $domainSecDelta = $script:Comparison.CategoryDeltas | Where-Object { $_.Category -eq 'Domain Security' }
        $domainSecDelta.BaselineScore | Should -Be 0
        $domainSecDelta.RetestScore | Should -BeGreaterThan 0
    }
}

Describe 'Get-ADRetestComparison - identity case' {
    It 'feeding the same run as both -BaselinePath and -RetestPath yields all-StillOpen, zero New/Resolved, zero deltas' {
        $folder = New-RunFixture -FolderName 'identity' -Findings $script:BaselineFindings -Timestamp '2026-03-01_00-00-00'
        $cmp = Get-ADRetestComparison -BaselinePath $folder -RetestPath $folder

        $cmp.NewFindings.Count | Should -Be 0
        $cmp.ResolvedFindings.Count | Should -Be 0
        $cmp.ChangedFindings.Count | Should -Be 0
        $cmp.StillOpenFindings.Count | Should -Be $script:BaselineFindings.Count
        $cmp.ScoreDelta | Should -Be 0
        $cmp.MaturityDelta | Should -Be 0
    }
}

Describe 'Get-ADRetestComparison - input resolution and error handling' {
    It 'accepts an explicit AD_Security_Audit_*.json file path, not just a folder' {
        $folder = New-RunFixture -FolderName 'explicit-file' -Findings $script:BaselineFindings -Timestamp '2026-04-01_00-00-00'
        $explicitFile = Join-Path $folder 'AD_Security_Audit_2026-04-01_00-00-00.json'
        { Get-ADRetestComparison -BaselinePath $explicitFile -RetestPath $explicitFile } | Should -Not -Throw
    }

    It 'throws a clear error when a path does not exist' {
        { Get-ADRetestComparison -BaselinePath (Join-Path $TestDrive 'does-not-exist') -RetestPath (Join-Path $TestDrive 'does-not-exist') } | Should -Throw
    }

    It 'still produces a comparison when a score sidecar is missing (sidecar is optional/informational only)' {
        $folderNoSidecar = New-RunFixture -FolderName 'no-sidecar' -Findings $script:BaselineFindings -Timestamp '2026-05-01_00-00-00' -NoScoreSidecar
        $cmp = Get-ADRetestComparison -BaselinePath $folderNoSidecar -RetestPath $folderNoSidecar
        $cmp.BaselineMeta.ScorePath | Should -BeNullOrEmpty
        $cmp.BaselineMeta.ModuleVersion | Should -BeNullOrEmpty
        $cmp.StillOpenFindings.Count | Should -Be $script:BaselineFindings.Count
    }
}

Describe 'Get-ADRetestComparison - jagged/nested findings export (regression)' {
    <#
        Regression coverage for a real crash reported from production data:
        a findings export whose top-level array contained an element that
        was itself a sub-array of several findings (rather than one)
        crashed deep inside Get-ADRiskScore with a confusing "cannot
        convert System.Object[] to Int32" error. Get-ADRetestComparison now
        flattens both exports defensively (ConvertTo-ADFlatFindingsArray in
        Common.ps1) immediately after parsing them.
    #>
    BeforeAll {
        function New-TaggedFinding {
            param([string]$Category, [string]$Issue, [string]$Severity, [int]$SeverityLevel, [string]$AffectedObject, [int]$Weight, [string]$Anssi)
            $f = [ADSecurityFinding]::new()
            $f.Category = $Category; $f.Issue = $Issue; $f.Severity = $Severity; $f.SeverityLevel = $SeverityLevel
            $f.AffectedObject = $AffectedObject
            $f.Weight = $Weight
            $f.AnssiControl = $Anssi
            return $f
        }
    }

    It 'reads a jagged findings export without throwing, treating the nested sub-array as individual findings' {
        $f1 = New-TaggedFinding -Category 'User Account' -Issue 'I1' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'o1' -Weight 4 -Anssi 'vuln4_test'
        $f2 = New-TaggedFinding -Category 'User Account' -Issue 'I2' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'o2' -Weight 4 -Anssi 'vuln4_test'
        $f3 = New-TaggedFinding -Category 'Privileged Groups' -Issue 'I3' -Severity 'High' -SeverityLevel 3 -AffectedObject 'o3' -Weight 20 -Anssi 'vuln2_test'

        # A top-level array where one element is itself a sub-array of two
        # findings - exactly the shape that crashed in production.
        $jagged = @( @($f1, $f2), $f3 )

        $folder = Join-Path $TestDrive 'jagged'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        $path = Join-Path $folder 'AD_Security_Audit_jagged.json'
        $jagged | ConvertTo-Json -Depth 10 | Out-File -FilePath $path -Encoding UTF8

        { Get-ADRetestComparison -BaselinePath $path -RetestPath $path } | Should -Not -Throw

        $cmp = Get-ADRetestComparison -BaselinePath $path -RetestPath $path
        $cmp.StillOpenFindings.Count | Should -Be 3
        $cmp.ScoreDelta | Should -Be 0
    }
}

Describe 'Get-ADRetestComparison - test coverage awareness (UnconfirmedFindings)' {
    <#
        Regression coverage for a reported gap: a finding that disappeared
        between baseline and retest was ALWAYS classified as Resolved,
        with no consideration of whether the check that would have
        produced it actually ran in the retest. A check excluded via
        -ExcludeTests or one that failed (an exception) during the retest
        makes every finding it would have reported disappear too -
        identically to genuine remediation as far as a key-based diff can
        tell, producing a false "Resolved" claim.
    #>
    BeforeAll {
        $script:RodcFinding = New-TestFinding -Issue 'RODC Password Replication Policy Misconfigured' -Category 'RODC Security' -Severity 'High' -SeverityLevel 3 -AffectedObject 'RODC01' -TestName 'RodcSecurity'
        $script:UserFinding = New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'user1' -TestName 'UserAccounts'
    }

    It 'reclassifies a disappeared finding as Unconfirmed (not Resolved) when its check was Excluded in the retest' {
        $baselineFolder = New-RunFixture -FolderName 'coverage-baseline-excluded' -Findings @($script:RodcFinding, $script:UserFinding) -Timestamp '2026-07-01_00-00-00'
        $retestFolder = New-RunFixture -FolderName 'coverage-retest-excluded' -Findings @() -Timestamp '2026-07-02_00-00-00' -TestCoverage @(
            [PSCustomObject]@{ TestName = 'UserAccounts'; Status = 'Completed'; FindingCount = 0; ErrorMessage = $null }
            [PSCustomObject]@{ TestName = 'RodcSecurity'; Status = 'Excluded'; FindingCount = 0; ErrorMessage = $null }
        )

        $cmp = Get-ADRetestComparison -BaselinePath $baselineFolder -RetestPath $retestFolder

        @($cmp.ResolvedFindings).Count | Should -Be 1
        ($cmp.ResolvedFindings | Where-Object Issue -eq 'Inactive Enabled Account') | Should -Not -BeNullOrEmpty
        @($cmp.UnconfirmedFindings).Count | Should -Be 1
        $cmp.UnconfirmedFindings[0].Finding.Issue | Should -Be 'RODC Password Replication Policy Misconfigured'
        $cmp.UnconfirmedFindings[0].Reason | Should -Match 'excluded'
        @($cmp.CoverageCaveats).Count | Should -BeGreaterThan 0
    }

    It 'reclassifies a disappeared finding as Unconfirmed (not Resolved) when its check Failed in the retest' {
        $baselineFolder = New-RunFixture -FolderName 'coverage-baseline-failed' -Findings @($script:RodcFinding) -Timestamp '2026-07-03_00-00-00'
        $retestFolder = New-RunFixture -FolderName 'coverage-retest-failed' -Findings @() -Timestamp '2026-07-04_00-00-00' -TestCoverage @(
            [PSCustomObject]@{ TestName = 'RodcSecurity'; Status = 'Failed'; FindingCount = 0; ErrorMessage = 'Access is denied' }
        )

        $cmp = Get-ADRetestComparison -BaselinePath $baselineFolder -RetestPath $retestFolder

        @($cmp.ResolvedFindings).Count | Should -Be 0
        @($cmp.UnconfirmedFindings).Count | Should -Be 1
        $cmp.UnconfirmedFindings[0].Reason | Should -Match 'Access is denied'
    }

    It 'keeps a disappeared finding as genuinely Resolved when its check ran Completed in the retest' {
        $baselineFolder = New-RunFixture -FolderName 'coverage-baseline-clean' -Findings @($script:RodcFinding) -Timestamp '2026-07-05_00-00-00'
        $retestFolder = New-RunFixture -FolderName 'coverage-retest-clean' -Findings @() -Timestamp '2026-07-06_00-00-00' -TestCoverage @(
            [PSCustomObject]@{ TestName = 'RodcSecurity'; Status = 'Completed'; FindingCount = 0; ErrorMessage = $null }
        )

        $cmp = Get-ADRetestComparison -BaselinePath $baselineFolder -RetestPath $retestFolder

        @($cmp.ResolvedFindings).Count | Should -Be 1
        @($cmp.UnconfirmedFindings).Count | Should -Be 0
    }

    It 'does not reclassify (benefit of the doubt) when neither run has any coverage data at all - old exports predating tracking' {
        $baselineFolder = New-RunFixture -FolderName 'coverage-baseline-none' -Findings @($script:RodcFinding) -Timestamp '2026-07-07_00-00-00'
        $retestFolder = New-RunFixture -FolderName 'coverage-retest-none' -Findings @() -Timestamp '2026-07-08_00-00-00'

        $cmp = Get-ADRetestComparison -BaselinePath $baselineFolder -RetestPath $retestFolder

        @($cmp.ResolvedFindings).Count | Should -Be 1
        @($cmp.UnconfirmedFindings).Count | Should -Be 0
        @($cmp.CoverageCaveats).Count | Should -BeGreaterThan 0 -Because 'a caveat should still note coverage data was unavailable, even though nothing could be reclassified'
    }

    It 'Export-ADRetestComparisonHTML renders the Unconfirmed section and coverage caveats without throwing' {
        $baselineFolder = New-RunFixture -FolderName 'coverage-html-baseline' -Findings @($script:RodcFinding, $script:UserFinding) -Timestamp '2026-07-09_00-00-00'
        $retestFolder = New-RunFixture -FolderName 'coverage-html-retest' -Findings @() -Timestamp '2026-07-10_00-00-00' -TestCoverage @(
            [PSCustomObject]@{ TestName = 'UserAccounts'; Status = 'Completed'; FindingCount = 0; ErrorMessage = $null }
            [PSCustomObject]@{ TestName = 'RodcSecurity'; Status = 'Excluded'; FindingCount = 0; ErrorMessage = $null }
        )
        $cmp = Get-ADRetestComparison -BaselinePath $baselineFolder -RetestPath $retestFolder
        $outPath = Join-Path $TestDrive 'coverage-comparison.html'

        { Export-ADRetestComparisonHTML -Comparison $cmp -OutputPath $outPath } | Should -Not -Throw
        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'Unconfirmed'
        $content | Should -Match 'COVERAGE CAVEATS'
        $content | Should -Match 'RODC Password Replication Policy Misconfigured'
    }
}

Describe 'Get-ADRetestComparison -ToJson' {
    It 'persists a parseable AD_Retest_Comparison_<timestamp>.json' {
        $folder = New-RunFixture -FolderName 'tojson' -Findings $script:BaselineFindings -Timestamp '2026-06-01_00-00-00'
        $outPath = Join-Path $TestDrive 'AD_Retest_Comparison_2026-06-01_00-00-00.json'
        Get-ADRetestComparison -BaselinePath $folder -RetestPath $folder -ToJson $outPath | Out-Null

        Test-Path $outPath | Should -BeTrue
        $parsed = Get-Content -Path $outPath -Raw | ConvertFrom-Json
        $parsed.StillOpenFindings.Count | Should -Be $script:BaselineFindings.Count
    }
}

Describe 'Export-ADRetestComparisonHTML' {
    BeforeAll {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/Reporting.ps1')
        $folderB = New-RunFixture -FolderName 'html-baseline' -Findings $script:BaselineFindings -Timestamp '2026-07-01_00-00-00'
        $folderR = New-RunFixture -FolderName 'html-retest'   -Findings $script:RetestFindings   -Timestamp '2026-07-15_00-00-00'
        $script:HtmlComparison = Get-ADRetestComparison -BaselinePath $folderB -RetestPath $folderR
    }

    It 'produces a single self-contained HTML file with the Current State / Delta View toggle' {
        $outPath = Join-Path $TestDrive 'retest-report.html'
        Export-ADRetestComparisonHTML -Comparison $script:HtmlComparison -OutputPath $outPath

        Test-Path $outPath | Should -BeTrue
        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'Current State'
        $content | Should -Match 'Delta View'
    }

    It 'does not regress the v1.20.3 [hidden]-specificity bug: .view-panel[hidden] is declared as an explicit override' {
        $outPath = Join-Path $TestDrive 'retest-report-hidden-check.html'
        Export-ADRetestComparisonHTML -Comparison $script:HtmlComparison -OutputPath $outPath
        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match '\.view-panel\[hidden\]\s*\{\s*display:\s*none;\s*\}'
    }

    It 'accepts the comparison object via the pipeline' {
        $outPath = Join-Path $TestDrive 'retest-report-pipeline.html'
        $script:HtmlComparison | Export-ADRetestComparisonHTML -OutputPath $outPath
        Test-Path $outPath | Should -BeTrue
    }

    It 'never renders the raw ConvertTo-Json expansion of a [datetime] object in the header (regression)' {
        $outPath = Join-Path $TestDrive 'retest-report-date-regression.html'
        Export-ADRetestComparisonHTML -Comparison $script:HtmlComparison -OutputPath $outPath
        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'BASELINE GENERATED'
        $content | Should -Not -Match 'DisplayHint'
    }

    It 'includes BASELINE FINDINGS / RETEST FINDINGS counts in the header' {
        $outPath = Join-Path $TestDrive 'retest-report-findings-count.html'
        Export-ADRetestComparisonHTML -Comparison $script:HtmlComparison -OutputPath $outPath
        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'BASELINE FINDINGS'
        $content | Should -Match 'RETEST FINDINGS'
    }

    It 'renders correctly from a JSON round-trip via -ToJson, including a pre-fix corrupted GeneratedDate sidecar (regression)' {
        # Exercises the exact "recreate the HTML report from an existing
        # JSON file" workflow documented in the README: -ToJson now, then
        # ConvertFrom-Json + Export-ADRetestComparisonHTML later, possibly
        # in a different session.
        $jsonPath = Join-Path $TestDrive 'AD_Retest_Comparison_roundtrip.json'
        Get-ADRetestComparison -BaselinePath $folderB -RetestPath $folderR -ToJson $jsonPath | Out-Null

        $reloaded = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
        $outPath = Join-Path $TestDrive 'retest-report-roundtrip.html'
        { Export-ADRetestComparisonHTML -Comparison $reloaded -OutputPath $outPath } | Should -Not -Throw

        Test-Path $outPath | Should -BeTrue
        $content = Get-Content -Path $outPath -Raw
        $content | Should -Not -Match 'DisplayHint'
    }
}

Describe 'ConvertTo-ADFriendlyDateText' {
    BeforeAll {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/Common.ps1')
    }

    It 'returns $null for a null/empty value' {
        ConvertTo-ADFriendlyDateText -Value $null | Should -BeNullOrEmpty
    }

    It 'formats a real [datetime] object' {
        $result = ConvertTo-ADFriendlyDateText -Value ([datetime]'2026-08-20 00:47:43')
        $result | Should -Be '2026-08-20 00:47:43'
    }

    It 'passes through a plain ISO-8601 string unchanged in content (current, fixed sidecar format)' {
        $result = ConvertTo-ADFriendlyDateText -Value '2026-08-20T00:47:43.0000000+00:00'
        { [datetime]$result } | Should -Not -Throw
        $result | Should -Not -Match 'DisplayHint'
    }

    It 'recovers a clean date from the corrupted legacy shape (ConvertTo-Json''s expansion of a raw [datetime])' {
        # This is exactly the object shape ConvertFrom-Json hands back for a
        # pre-fix score sidecar whose GeneratedDate was stored as a raw
        # [datetime] rather than a string.
        $corrupted = [PSCustomObject]@{
            value       = '08/20/2026 00:47:43'
            DisplayHint = 2
            DateTime    = 'Thursday, 20 August 2026 12:47:43 AM'
        }
        $result = ConvertTo-ADFriendlyDateText -Value $corrupted
        $result | Should -Not -Match 'DisplayHint'
        { [datetime]$result } | Should -Not -Throw
    }
}
