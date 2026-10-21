#Requires -Modules Pester
<#
    Unit tests for Export-ADSecurityReportCSVFromJson and
    ConvertTo-ADFindingsCsvRows (src/Reporting.ps1 / src/Common.ps1).

    Reported gap: Export-ADSecurityReportHTMLFromJson existed to rebuild
    the HTML report from an old JSON export, but there was no equivalent
    for the CSV. These tests cover the new CSV rebuild path, and the
    shared row-construction helper it uses (also used by Main.ps1's live
    export) so the two column lists cannot independently drift apart the
    way the CSV previously drifted from the JSON export it mirrors.

    These tests do NOT touch Active Directory.

    Run from the repo root:  Invoke-Pester ./tests/ReportingCSVFromJson.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/FindingNarrativeLibrary.ps1')
    . (Join-Path $root 'src/RetestComparison.ps1')
    . (Join-Path $root 'src/Reporting.ps1')

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

    $script:Findings = @(
        New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'user1'
        New-TestFinding -Issue 'Kerberoastable Account' -Category 'Kerberos Security' -Severity 'High' -SeverityLevel 3 -AffectedObject 'svc1'
    )

    function New-FindingsFixture {
        param(
            [string]$FolderName,
            [array]$Findings,
            [string]$Timestamp,
            [array]$TestCoverage
        )
        $folder = Join-Path $TestDrive $FolderName
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        $findingsPath = Join-Path $folder "AD_Security_Audit_$Timestamp.json"
        $Findings | ConvertTo-Json -Depth 6 | Out-File -FilePath $findingsPath -Encoding UTF8
        if ($PSBoundParameters.ContainsKey('TestCoverage')) {
            $coveragePath = Join-Path $folder "AD_Security_TestCoverage_$Timestamp.json"
            $TestCoverage | ConvertTo-Json -Depth 4 | Out-File -FilePath $coveragePath -Encoding UTF8
        }
        return $folder
    }
}

Describe 'ConvertTo-ADFindingsCsvRows' {
    It 'produces one row per finding with the expected columns' {
        $rows = @(ConvertTo-ADFindingsCsvRows -Findings $script:Findings)
        $rows.Count | Should -Be 2
        $rows[0].PSObject.Properties.Name | Should -Contain 'Category'
        $rows[0].PSObject.Properties.Name | Should -Contain 'EstimatedEffort'
        $rows[0].PSObject.Properties.Name | Should -Contain 'OperationalNotes'
        $rows[0].PSObject.Properties.Name | Should -Contain 'Details'
    }

    It 'sanitizes a formula-injection-looking value' {
        $evil = [ADSecurityFinding]::new()
        $evil.Issue = '=cmd|/c calc'
        $evil.Category = 'Test'
        $evil.Severity = 'Low'
        $rows = @(ConvertTo-ADFindingsCsvRows -Findings @($evil))
        $rows[0].Issue | Should -Match "^'="
    }

    It 'returns an empty collection (no throw) for zero findings' {
        { ConvertTo-ADFindingsCsvRows -Findings @() } | Should -Not -Throw
        @(ConvertTo-ADFindingsCsvRows -Findings @()).Count | Should -Be 0
    }

    It 'works identically whether findings are live [ADSecurityFinding] objects or JSON-deserialized PSCustomObjects' {
        $liveRows = @(ConvertTo-ADFindingsCsvRows -Findings $script:Findings)
        $jsonFindings = ($script:Findings | ConvertTo-Json -Depth 6) | ConvertFrom-Json
        $jsonRows = @(ConvertTo-ADFindingsCsvRows -Findings @($jsonFindings))

        $liveRows.Count | Should -Be $jsonRows.Count
        $liveRows[0].Issue | Should -Be $jsonRows[0].Issue
        $liveRows[1].Category | Should -Be $jsonRows[1].Category
    }
}

Describe 'Export-ADSecurityReportCSVFromJson' {
    It 'accepts an explicit AD_Security_Audit_*.json file path and writes a CSV' {
        $folder = New-FindingsFixture -FolderName 'explicit-file' -Findings $script:Findings -Timestamp '2026-08-01_00-00-00'
        $explicitFile = Join-Path $folder 'AD_Security_Audit_2026-08-01_00-00-00.json'
        $outPath = Join-Path $TestDrive 'recreated-explicit.csv'

        { Export-ADSecurityReportCSVFromJson -FindingsPath $explicitFile -OutputPath $outPath } | Should -Not -Throw
        Test-Path $outPath | Should -BeTrue

        $rows = Import-Csv -Path $outPath
        $rows.Count | Should -Be 2
        $rows[0].Category | Should -Not -BeNullOrEmpty
    }

    It 'accepts a folder and picks the newest AD_Security_Audit_*.json in it' {
        $folder = New-FindingsFixture -FolderName 'folder-form' -Findings $script:Findings -Timestamp '2026-08-02_00-00-00'
        $outPath = Join-Path $TestDrive 'recreated-folder.csv'

        { Export-ADSecurityReportCSVFromJson -FindingsPath $folder -OutputPath $outPath } | Should -Not -Throw
        Test-Path $outPath | Should -BeTrue
    }

    It 'accepts an existing folder for -OutputPath and auto-names the file inside it' {
        $folder = New-FindingsFixture -FolderName 'output-folder-existing' -Findings $script:Findings -Timestamp '2026-08-17_00-00-00'

        { Export-ADSecurityReportCSVFromJson -FindingsPath $folder -OutputPath $folder } | Should -Not -Throw
        $expected = Join-Path $folder 'AD_Security_Audit_2026-08-17_00-00-00-recreated.csv'
        Test-Path $expected | Should -BeTrue
    }

    It 'creates a not-yet-existing folder for -OutputPath and auto-names the file inside it' {
        $folder = New-FindingsFixture -FolderName 'output-folder-new-source' -Findings $script:Findings -Timestamp '2026-08-18_00-00-00'
        $newFolder = Join-Path $TestDrive 'brand-new-csv-output-folder'
        Test-Path $newFolder | Should -BeFalse

        { Export-ADSecurityReportCSVFromJson -FindingsPath $folder -OutputPath $newFolder } | Should -Not -Throw
        Test-Path $newFolder | Should -BeTrue
        $expected = Join-Path $newFolder 'AD_Security_Audit_2026-08-18_00-00-00-recreated.csv'
        Test-Path $expected | Should -BeTrue
    }

    It 'does not overwrite an original same-timestamp CSV when -OutputPath is that same folder' {
        $folder = New-FindingsFixture -FolderName 'output-folder-no-overwrite' -Findings $script:Findings -Timestamp '2026-08-19_00-00-00'
        $originalCsvPath = Join-Path $folder 'AD_Security_Audit_2026-08-19_00-00-00.csv'
        'ORIGINAL - DO NOT OVERWRITE' | Out-File -FilePath $originalCsvPath -Encoding UTF8

        Export-ADSecurityReportCSVFromJson -FindingsPath $folder -OutputPath $folder

        (Get-Content -Path $originalCsvPath -Raw) | Should -Match 'DO NOT OVERWRITE'
    }

    It 'derives the coverage CSV name correctly when -OutputPath was a folder' {
        $coverage = @([PSCustomObject]@{ TestName = 'UserAccounts'; Status = 'Completed'; FindingCount = 2; ErrorMessage = $null })
        $folder = New-FindingsFixture -FolderName 'output-folder-coverage' -Findings $script:Findings -Timestamp '2026-08-20_00-00-00' -TestCoverage $coverage

        Export-ADSecurityReportCSVFromJson -FindingsPath $folder -OutputPath $folder

        $expectedCoverage = Join-Path $folder 'AD_Security_Audit_2026-08-20_00-00-00-recreated-coverage.csv'
        Test-Path $expectedCoverage | Should -BeTrue
    }

    It 'throws a clear error when the path does not exist' {
        { Export-ADSecurityReportCSVFromJson -FindingsPath (Join-Path $TestDrive 'does-not-exist') -OutputPath (Join-Path $TestDrive 'irrelevant.csv') } | Should -Throw
    }

    It 'backfills supporting-information fields from current guidance, same as the HTML rebuild path' {
        $ouFinding = [ADSecurityFinding]::new()
        $ouFinding.Category = 'Permissions'
        $ouFinding.Issue = 'Dangerous Rights on Critical OU'
        $ouFinding.Severity = 'Critical'
        $ouFinding.SeverityLevel = 4
        $ouFinding.AffectedObject = 'evilsvc'
        # Deliberately leave EstimatedEffort/KnownRisks/BackupRollback/
        # OperationalNotes blank, as an old export would have them.

        $folder = New-FindingsFixture -FolderName 'backfill' -Findings @($ouFinding) -Timestamp '2026-08-03_00-00-00'
        $outPath = Join-Path $TestDrive 'recreated-backfill.csv'
        Export-ADSecurityReportCSVFromJson -FindingsPath $folder -OutputPath $outPath

        $rows = Import-Csv -Path $outPath
        $rows[0].EstimatedEffort | Should -Not -BeNullOrEmpty
        $rows[0].KnownRisks | Should -Not -BeNullOrEmpty
    }

    Context 'Test Coverage CSV sidecar' {
        It 'writes a "-coverage" CSV alongside the findings CSV when a coverage sidecar exists' {
            $coverage = @(
                [PSCustomObject]@{ TestName = 'UserAccounts'; Status = 'Completed'; FindingCount = 2; ErrorMessage = $null }
                [PSCustomObject]@{ TestName = 'CertificateServices'; Status = 'Failed'; FindingCount = 0; ErrorMessage = 'Access is denied' }
                [PSCustomObject]@{ TestName = 'RodcSecurity'; Status = 'Excluded'; FindingCount = 0; ErrorMessage = $null }
            )
            $folder = New-FindingsFixture -FolderName 'with-coverage' -Findings $script:Findings -Timestamp '2026-08-04_00-00-00' -TestCoverage $coverage
            $outPath = Join-Path $TestDrive 'recreated-with-coverage.csv'
            Export-ADSecurityReportCSVFromJson -FindingsPath $folder -OutputPath $outPath

            $coveragePath = Join-Path $TestDrive 'recreated-with-coverage-coverage.csv'
            Test-Path $coveragePath | Should -BeTrue

            $covRows = Import-Csv -Path $coveragePath
            $covRows.Count | Should -Be 3
            ($covRows | Where-Object TestName -eq 'CertificateServices').Status | Should -Be 'Failed'
            ($covRows | Where-Object TestName -eq 'CertificateServices').ErrorMessage | Should -Be 'Access is denied'
            ($covRows | Where-Object TestName -eq 'RodcSecurity').Status | Should -Be 'Excluded'
        }

        It 'writes a coverage CSV with a single explanatory "NotAvailable" row (not a missing file) when no coverage sidecar exists' {
            $folder = New-FindingsFixture -FolderName 'no-coverage' -Findings $script:Findings -Timestamp '2026-08-05_00-00-00'
            $outPath = Join-Path $TestDrive 'recreated-no-coverage.csv'

            { Export-ADSecurityReportCSVFromJson -FindingsPath $folder -OutputPath $outPath } | Should -Not -Throw
            Test-Path $outPath | Should -BeTrue

            $coveragePath = Join-Path $TestDrive 'recreated-no-coverage-coverage.csv'
            Test-Path $coveragePath | Should -BeTrue -Because 'the limitation should be visible in the output artifact itself, not just a missing file'

            $covRows = Import-Csv -Path $coveragePath
            $covRows.Count | Should -Be 1
            $covRows[0].Status | Should -Be 'NotAvailable'
            $covRows[0].ErrorMessage | Should -Match '1\.24\.0'
        }

        It 'repairs a malformed "columnar" coverage sidecar (System.Object[] regression) instead of writing garbage rows' {
            <#
                Regression coverage for a reported bug: a real coverage
                sidecar came back from Get-ADTestCoverageSidecar as ONE
                entry whose TestName/Status/FindingCount/ErrorMessage were
                each arrays (not the intended one-entry-per-check shape).
                Export-Csv then called .ToString() on each still-array
                property, writing the literal string "System.Object[]"
                into every column. See ConvertTo-ADNormalizedTestCoverage's
                own docs (Common.ps1) for the confirmed rendering mechanism
                and why the columnar shape itself wasn't reproducible from
                a normal write/read round-trip.
            #>
            $folder = New-FindingsFixture -FolderName 'columnar-coverage' -Findings $script:Findings -Timestamp '2026-08-22_00-00-00'
            $columnarCoveragePath = Join-Path $folder 'AD_Security_TestCoverage_2026-08-22_00-00-00.json'
            @{
                TestName     = @('ADCSChaseFallback', 'ADCSExtended', 'AdminSDHolder')
                Status       = @('Completed', 'Completed', 'Failed')
                FindingCount = @(1, 14, 0)
                ErrorMessage = @($null, $null, 'Access is denied')
            } | ConvertTo-Json -Depth 4 | Out-File -FilePath $columnarCoveragePath -Encoding UTF8

            $outPath = Join-Path $TestDrive 'recreated-columnar.csv'
            Export-ADSecurityReportCSVFromJson -FindingsPath $folder -OutputPath $outPath -WarningAction SilentlyContinue

            $coveragePath = Join-Path $TestDrive 'recreated-columnar-coverage.csv'
            $covRows = Import-Csv -Path $coveragePath
            $covRows.Count | Should -Be 3
            $covRows | Where-Object { $_.TestName -eq 'System.Object[]' } | Should -BeNullOrEmpty
            ($covRows | Where-Object TestName -eq 'AdminSDHolder').Status | Should -Be 'Failed'
            ($covRows | Where-Object TestName -eq 'AdminSDHolder').ErrorMessage | Should -Be 'Access is denied'
        }
    }
}

Describe 'ConvertTo-ADNormalizedTestCoverage' {
    It 'un-transposes a columnar shape into one entry per check' {
        $columnar = @([PSCustomObject]@{
            TestName     = @('A', 'B', 'C')
            Status       = @('Completed', 'Completed', 'Failed')
            FindingCount = @(1, 0, 0)
            ErrorMessage = @($null, $null, 'boom')
        })
        $fixed = @(ConvertTo-ADNormalizedTestCoverage -Coverage $columnar -WarningAction SilentlyContinue)
        $fixed.Count | Should -Be 3
        $fixed[0].TestName | Should -Be 'A'
        $fixed[2].Status | Should -Be 'Failed'
        $fixed[2].ErrorMessage | Should -Be 'boom'
    }

    It 'leaves an already-correctly-shaped array unchanged' {
        $normal = @(
            [PSCustomObject]@{ TestName = 'A'; Status = 'Completed'; FindingCount = 1; ErrorMessage = $null }
            [PSCustomObject]@{ TestName = 'B'; Status = 'Failed'; FindingCount = 0; ErrorMessage = 'err' }
        )
        $result = @(ConvertTo-ADNormalizedTestCoverage -Coverage $normal)
        $result.Count | Should -Be 2
        $result[0].TestName | Should -Be 'A'
        $result[1].TestName | Should -Be 'B'
    }

    It 'returns an empty array (no throw) for empty input' {
        { ConvertTo-ADNormalizedTestCoverage -Coverage @() } | Should -Not -Throw
        @(ConvertTo-ADNormalizedTestCoverage -Coverage @()).Count | Should -Be 0
    }

    It 'detects a malformation on a property OTHER than TestName (broadened detection)' {
        $columnar = @([PSCustomObject]@{
            TestName     = 'ThisStaysScalarSomehow'
            Status       = @('Completed', 'Failed')
            FindingCount = @(1, 0)
            ErrorMessage = @($null, 'boom')
        })
        $fixed = @(ConvertTo-ADNormalizedTestCoverage -Coverage $columnar -WarningAction SilentlyContinue)
        $fixed.Count | Should -Be 2
        $fixed[1].Status | Should -Be 'Failed'
    }
}
