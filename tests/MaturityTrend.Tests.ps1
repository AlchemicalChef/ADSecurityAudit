#Requires -Modules Pester
<#
    Unit tests for Get-ADMaturityTrend / Export-ADMaturityTrendHTML.

    These tests do NOT touch Active Directory. Like ForestConsolidation.Tests.ps1
    and RetestComparison.Tests.ps1, they only exercise this project's own
    scoring/serialization contract: synthetic AD_Security_Score_*.json
    sidecars (in the exact shape Start-ADSecurityAudit already writes) are
    written to TestDrive and fed to Get-ADMaturityTrend entirely offline.

    Run from the repo root:  Invoke-Pester ./tests/MaturityTrend.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/MaturityTrend.ps1')

    function New-TestFinding {
        param(
            [string]$Issue,
            [string]$Category,
            [string]$Severity,
            [int]$SeverityLevel,
            [string]$AffectedObject = ''
        )
        $f = [ADSecurityFinding]::new()
        $f.Issue = $Issue
        $f.Category = $Category
        $f.Severity = $Severity
        $f.SeverityLevel = $SeverityLevel
        $f.AffectedObject = $AffectedObject
        return $f
    }

    function New-ScoreSidecarFixture {
        param(
            [string]$Folder,
            [array]$Findings,
            [string]$Timestamp,
            [string]$ModuleVersion = '1.21.0',
            [datetime]$GeneratedDate,
            [array]$TestCoverage
        )
        foreach ($finding in $Findings) { [void](Set-ADFindingMetadata -Finding $finding) }
        $script:ModuleVersion = $ModuleVersion
        $riskScore = Get-ADRiskScore -Findings $Findings
        $riskScore.GeneratedDate = $GeneratedDate
        $path = Join-Path $Folder "AD_Security_Score_$Timestamp.json"
        $riskScore | ConvertTo-Json -Depth 6 | Out-File -FilePath $path -Encoding UTF8
        if ($PSBoundParameters.ContainsKey('TestCoverage')) {
            $coveragePath = Join-Path $Folder "AD_Security_TestCoverage_$Timestamp.json"
            $TestCoverage | ConvertTo-Json -Depth 4 | Out-File -FilePath $coveragePath -Encoding UTF8
        }
        return $path
    }
}

Describe 'Get-ADMaturityTrend - chronological ordering and trend direction' {
    BeforeAll {
        $script:Folder = Join-Path $TestDrive 'domain'
        New-Item -ItemType Directory -Path $script:Folder -Force | Out-Null

        # 4 runs, improving over time (fewer findings each time), one
        # module-version bump partway through. Deliberately written with
        # filenames that do NOT sort chronologically, to prove ordering
        # comes from each sidecar's own GeneratedDate field.
        New-ScoreSidecarFixture -Folder $script:Folder -Timestamp 'z-run-oldest' -ModuleVersion '1.19.0' -GeneratedDate ([datetime]'2026-01-01') -Findings @(
            New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'u1'
            New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'u2'
            New-TestFinding -Issue 'Excessive Privileged Group Membership' -Category 'Privileged Groups' -Severity 'High' -SeverityLevel 3 -AffectedObject 'Domain Admins'
        )
        New-ScoreSidecarFixture -Folder $script:Folder -Timestamp 'a-run-middle' -ModuleVersion '1.19.0' -GeneratedDate ([datetime]'2026-04-01') -Findings @(
            New-TestFinding -Issue 'Excessive Privileged Group Membership' -Category 'Privileged Groups' -Severity 'High' -SeverityLevel 3 -AffectedObject 'Domain Admins'
        )
        New-ScoreSidecarFixture -Folder $script:Folder -Timestamp 'm-run-newest' -ModuleVersion '1.21.0' -GeneratedDate ([datetime]'2026-07-01') -Findings @()

        $script:Trend = Get-ADMaturityTrend -ReportPath $script:Folder
    }

    It 'orders runs chronologically by each sidecar''s own GeneratedDate, not by filename' {
        $dates = $script:Trend.Series.GeneratedDate
        $dates[0] | Should -Be ([datetime]'2026-01-01')
        $dates[1] | Should -Be ([datetime]'2026-04-01')
        $dates[2] | Should -Be ([datetime]'2026-07-01')
    }

    It 'surfaces each run''s own ModuleVersion so a score jump can be attributed to a tool change' {
        $script:Trend.Series[0].ModuleVersion | Should -Be '1.19.0'
        $script:Trend.Series[2].ModuleVersion | Should -Be '1.21.0'
    }

    It 'classifies an overall falling score (0-100, higher=worse) as Improving' {
        $script:Trend.OverallDirection | Should -Be 'Improving'
    }

    It 'produces a per-category trend for every category seen across the runs, defaulting absent runs to 0' {
        $userAccountTrend = $script:Trend.CategoryTrends | Where-Object { $_.Category -eq 'User Account' }
        $userAccountTrend | Should -Not -BeNullOrEmpty
        $userAccountTrend.Series[-1].Score | Should -Be 0
        $userAccountTrend.Direction | Should -Be 'Improving'
    }

    It 'RunCount and DateRange reflect the discovered sidecars' {
        $script:Trend.RunCount | Should -Be 3
        $script:Trend.DateRange.Earliest | Should -Be ([datetime]'2026-01-01')
        $script:Trend.DateRange.Latest | Should -Be ([datetime]'2026-07-01')
    }
}

Describe 'Get-ADMaturityTrend - direction classification is simple first-vs-last arithmetic' {
    It 'classifies a small within-tolerance change as Flat, not Improving/Regressing' {
        Get-ADMaturityTrendDirection -Values @(20, 22) | Should -Be 'Flat'
    }

    It 'classifies a rising score (worse) beyond tolerance as Regressing' {
        Get-ADMaturityTrendDirection -Values @(10, 30) | Should -Be 'Regressing'
    }

    It 'classifies a falling score (better) beyond tolerance as Improving' {
        Get-ADMaturityTrendDirection -Values @(40, 10) | Should -Be 'Improving'
    }

    It 'only looks at the first and last point, ignoring a worse midpoint' {
        Get-ADMaturityTrendDirection -Values @(20, 90, 18) | Should -Be 'Flat'
    }
}

Describe 'Get-ADMaturityTrend - 1-run and 2-run inputs handled gracefully' {
    It 'handles a single sidecar with a clear message, not an error' {
        $folder = Join-Path $TestDrive 'one-run'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        New-ScoreSidecarFixture -Folder $folder -Timestamp 'only' -GeneratedDate ([datetime]'2026-01-01') -Findings @(
            New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'u1'
        )

        { Get-ADMaturityTrend -ReportPath $folder -WarningAction SilentlyContinue } | Should -Not -Throw
        $trend = Get-ADMaturityTrend -ReportPath $folder -WarningAction SilentlyContinue
        $trend.RunCount | Should -Be 1
        $trend.OverallDirection | Should -Be 'InsufficientData'
        $trend.Message | Should -Not -BeNullOrEmpty
    }

    It 'treats a 2-run input as a plain pairwise delta' {
        $folder = Join-Path $TestDrive 'two-run'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        New-ScoreSidecarFixture -Folder $folder -Timestamp 'first' -GeneratedDate ([datetime]'2026-01-01') -Findings @(
            New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'u1'
            New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'u2'
            New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'u3'
        )
        New-ScoreSidecarFixture -Folder $folder -Timestamp 'second' -GeneratedDate ([datetime]'2026-02-01') -Findings @()

        $trend = Get-ADMaturityTrend -ReportPath $folder
        $trend.RunCount | Should -Be 2
        $trend.Message | Should -BeNullOrEmpty
        $trend.OverallDirection | Should -Be 'Improving'
    }
}

Describe 'Get-ADMaturityTrend - error handling' {
    It 'throws a clear error when no score sidecars exist under -ReportPath' {
        $emptyFolder = Join-Path $TestDrive 'empty'
        New-Item -ItemType Directory -Path $emptyFolder -Force | Out-Null
        { Get-ADMaturityTrend -ReportPath $emptyFolder } | Should -Throw
    }

    It 'throws a clear error when -ReportPath does not exist' {
        { Get-ADMaturityTrend -ReportPath (Join-Path $TestDrive 'does-not-exist') } | Should -Throw
    }
}

Describe 'Get-ADMaturityTrend -ToJson' {
    It 'persists a parseable AD_Maturity_Trend_<timestamp>.json' {
        $folder = Join-Path $TestDrive 'tojson'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        New-ScoreSidecarFixture -Folder $folder -Timestamp 'a' -GeneratedDate ([datetime]'2026-01-01') -Findings @()
        New-ScoreSidecarFixture -Folder $folder -Timestamp 'b' -GeneratedDate ([datetime]'2026-02-01') -Findings @()

        $outPath = Join-Path $TestDrive 'AD_Maturity_Trend_test.json'
        Get-ADMaturityTrend -ReportPath $folder -ToJson $outPath | Out-Null

        Test-Path $outPath | Should -BeTrue
        $parsed = Get-Content -Path $outPath -Raw | ConvertFrom-Json
        $parsed.RunCount | Should -Be 2
    }
}

Describe 'Export-ADMaturityTrendHTML' {
    BeforeAll {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/Reporting.ps1')
        $folder = Join-Path $TestDrive 'html'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        New-ScoreSidecarFixture -Folder $folder -Timestamp 'a' -GeneratedDate ([datetime]'2026-01-01') -Findings @(
            New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'u1'
        )
        New-ScoreSidecarFixture -Folder $folder -Timestamp 'b' -GeneratedDate ([datetime]'2026-02-01') -Findings @()
        $script:HtmlTrend = Get-ADMaturityTrend -ReportPath $folder
    }

    It 'produces a single self-contained HTML file with the per-run ModuleVersion table' {
        $outPath = Join-Path $TestDrive 'trend-report.html'
        Export-ADMaturityTrendHTML -Trend $script:HtmlTrend -OutputPath $outPath
        Test-Path $outPath | Should -BeTrue
        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'Module Version'
        $content | Should -Match 'Per-Category Trend'
    }

    It 'accepts the trend object via the pipeline' {
        $outPath = Join-Path $TestDrive 'trend-report-pipeline.html'
        $script:HtmlTrend | Export-ADMaturityTrendHTML -OutputPath $outPath
        Test-Path $outPath | Should -BeTrue
    }
}

Describe 'Get-ADMaturityTrend - estimated-date fallback for pre-v1.21.0 sidecars' {
    It 'includes a sidecar with no GeneratedDate field, estimating its date from the file''s last-write time instead of dropping it' {
        $folder = Join-Path $TestDrive 'legacy-sidecar'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null

        # Simulate a PRE-v1.21.0 sidecar: exactly what Get-ADRiskScore
        # returned before GeneratedDate/ModuleVersion were added.
        $legacySidecar = [PSCustomObject]@{
            TotalScore     = 20
            MaturityLevel  = 2
            MaturityLabel  = 'Level 2 - Partial hygiene'
            CategoryScores = @([PSCustomObject]@{ Category = 'User Account'; Score = 20; Findings = 1; RawPoints = 4 })
            MitreSummary   = @()
            FindingCount   = 1
            WeightedPoints = 4
            SeverityCounts = [PSCustomObject]@{ Critical = 0; High = 0; Medium = 0; Low = 1; Info = 0 }
        }
        $legacyPath = Join-Path $folder 'AD_Security_Score_legacy.json'
        $legacySidecar | ConvertTo-Json -Depth 6 | Out-File -FilePath $legacyPath -Encoding UTF8

        New-ScoreSidecarFixture -Folder $folder -Timestamp 'current' -GeneratedDate ([datetime]'2026-06-01') -Findings @()

        $trend = Get-ADMaturityTrend -ReportPath $folder -WarningAction SilentlyContinue

        # Both runs present - the legacy one is NOT dropped.
        $trend.RunCount | Should -Be 2
        $trend.EstimatedDateCount | Should -Be 1

        $legacyEntry = $trend.Series | Where-Object { $_.DateEstimated }
        $legacyEntry | Should -Not -BeNullOrEmpty
        $legacyEntry.GeneratedDate | Should -Be (Get-Item $legacyPath).LastWriteTime
        $legacyEntry.TotalScore | Should -Be 20

        $trend.Message | Should -Match 'ESTIMATED'
        $trend.Message | Should -Match '1 of 2'
    }

    It 'does not flag a run whose sidecar has a valid GeneratedDate' {
        $folder = Join-Path $TestDrive 'no-estimation-needed'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        New-ScoreSidecarFixture -Folder $folder -Timestamp 'a' -GeneratedDate ([datetime]'2026-01-01') -Findings @()
        New-ScoreSidecarFixture -Folder $folder -Timestamp 'b' -GeneratedDate ([datetime]'2026-02-01') -Findings @()

        $trend = Get-ADMaturityTrend -ReportPath $folder
        $trend.EstimatedDateCount | Should -Be 0
        ($trend.Series | Where-Object { $_.DateEstimated }).Count | Should -Be 0
        $trend.Message | Should -BeNullOrEmpty
    }
}

Describe 'Get-ADMaturityTrend - test coverage awareness' {
    <#
        Regression coverage for a reported gap: a run with several
        excluded/failed checks scores BETTER than a fully-tested run
        purely from checking less, with nothing distinguishing "genuine
        improvement" from "checked less this time" in the trend.
    #>
    It 'flags a run with untested (failed/excluded) checks and surfaces it in the Message' {
        $folder = Join-Path $TestDrive 'incomplete-coverage'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null

        New-ScoreSidecarFixture -Folder $folder -Timestamp 'full' -GeneratedDate ([datetime]'2026-01-01') -Findings @() -TestCoverage @(
            [PSCustomObject]@{ TestName = 'UserAccounts'; Status = 'Completed'; FindingCount = 0; ErrorMessage = $null }
        )
        New-ScoreSidecarFixture -Folder $folder -Timestamp 'partial' -GeneratedDate ([datetime]'2026-02-01') -Findings @() -TestCoverage @(
            [PSCustomObject]@{ TestName = 'UserAccounts'; Status = 'Completed'; FindingCount = 0; ErrorMessage = $null }
            [PSCustomObject]@{ TestName = 'RodcSecurity'; Status = 'Excluded'; FindingCount = 0; ErrorMessage = $null }
        )

        $trend = Get-ADMaturityTrend -ReportPath $folder -WarningAction SilentlyContinue

        $trend.IncompleteCoverageCount | Should -Be 1
        $trend.NoCoverageDataCount | Should -Be 0
        $fullRun = $trend.Series | Where-Object { $_.GeneratedDate -match '2026-01-01' }
        $fullRun.CoverageAvailable | Should -BeTrue
        $fullRun.UntestedCount | Should -Be 0
        $partialRun = $trend.Series | Where-Object { $_.GeneratedDate -match '2026-02-01' }
        $partialRun.CoverageAvailable | Should -BeTrue
        $partialRun.UntestedCount | Should -Be 1
        $trend.Message | Should -Match 'untested'
    }

    It 'flags a run with no coverage sidecar at all, distinctly from an incomplete-but-present one' {
        $folder = Join-Path $TestDrive 'no-coverage-data'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null

        New-ScoreSidecarFixture -Folder $folder -Timestamp 'nodatarun' -GeneratedDate ([datetime]'2026-03-01') -Findings @()
        New-ScoreSidecarFixture -Folder $folder -Timestamp 'seconddate' -GeneratedDate ([datetime]'2026-04-01') -Findings @() -TestCoverage @(
            [PSCustomObject]@{ TestName = 'UserAccounts'; Status = 'Completed'; FindingCount = 0; ErrorMessage = $null }
        )

        $trend = Get-ADMaturityTrend -ReportPath $folder -WarningAction SilentlyContinue

        $trend.NoCoverageDataCount | Should -Be 1
        $trend.IncompleteCoverageCount | Should -Be 0
        $noDataRun = $trend.Series | Where-Object { $_.GeneratedDate -match '2026-03-01' }
        $noDataRun.CoverageAvailable | Should -BeFalse
        $trend.Message | Should -Match 'no test coverage data'
    }

    It 'does not flag anything when every run has full coverage' {
        $folder = Join-Path $TestDrive 'all-full-coverage'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null

        New-ScoreSidecarFixture -Folder $folder -Timestamp 'a' -GeneratedDate ([datetime]'2026-01-01') -Findings @() -TestCoverage @(
            [PSCustomObject]@{ TestName = 'UserAccounts'; Status = 'Completed'; FindingCount = 0; ErrorMessage = $null }
        )
        New-ScoreSidecarFixture -Folder $folder -Timestamp 'b' -GeneratedDate ([datetime]'2026-02-01') -Findings @() -TestCoverage @(
            [PSCustomObject]@{ TestName = 'UserAccounts'; Status = 'Completed'; FindingCount = 0; ErrorMessage = $null }
        )

        $trend = Get-ADMaturityTrend -ReportPath $folder
        $trend.IncompleteCoverageCount | Should -Be 0
        $trend.NoCoverageDataCount | Should -Be 0
        $trend.Message | Should -BeNullOrEmpty
    }

    It 'Export-ADMaturityTrendHTML renders the coverage column without throwing' {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/Reporting.ps1')
        $folder = Join-Path $TestDrive 'html-coverage'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null

        New-ScoreSidecarFixture -Folder $folder -Timestamp 'a' -GeneratedDate ([datetime]'2026-01-01') -Findings @() -TestCoverage @(
            [PSCustomObject]@{ TestName = 'UserAccounts'; Status = 'Completed'; FindingCount = 0; ErrorMessage = $null }
            [PSCustomObject]@{ TestName = 'RodcSecurity'; Status = 'Excluded'; FindingCount = 0; ErrorMessage = $null }
        )
        New-ScoreSidecarFixture -Folder $folder -Timestamp 'b' -GeneratedDate ([datetime]'2026-02-01') -Findings @()

        $trend = Get-ADMaturityTrend -ReportPath $folder -WarningAction SilentlyContinue
        $outPath = Join-Path $TestDrive 'trend-coverage.html'

        { Export-ADMaturityTrendHTML -Trend $trend -OutputPath $outPath } | Should -Not -Throw
        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'Coverage'
        $content | Should -Match 'untested'
        $content | Should -Match 'no data'
    }
}

Describe 'Export-ADMaturityTrendHTML - estimated-date flag' {
    It 'visually flags a row whose date was estimated' {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/Reporting.ps1')
        $folder = Join-Path $TestDrive 'html-estimated'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null

        $legacySidecar = [PSCustomObject]@{
            TotalScore     = 10
            MaturityLevel  = 3
            MaturityLabel  = 'Level 3 - Standard hardening'
            CategoryScores = @()
            MitreSummary   = @()
            FindingCount   = 0
            WeightedPoints = 0
            SeverityCounts = [PSCustomObject]@{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
        }
        $legacySidecar | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $folder 'AD_Security_Score_legacy.json') -Encoding UTF8
        New-ScoreSidecarFixture -Folder $folder -Timestamp 'current' -GeneratedDate ([datetime]'2026-06-01') -Findings @()

        $trend = Get-ADMaturityTrend -ReportPath $folder -WarningAction SilentlyContinue
        $outPath = Join-Path $TestDrive 'trend-estimated.html'
        Export-ADMaturityTrendHTML -Trend $trend -OutputPath $outPath

        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'estimated-flag'
        $content | Should -Match 'estimated'
    }
}

Describe 'Get-ADSvgTrendLine' {
    It 'renders a flat 2-point line for a single value without dividing by zero' {
        { Get-ADSvgTrendLine -Values @(42) } | Should -Not -Throw
    }

    It 'renders an empty-but-valid SVG for zero values' {
        $svg = Get-ADSvgTrendLine -Values @()
        $svg | Should -Match '<svg'
    }
}
