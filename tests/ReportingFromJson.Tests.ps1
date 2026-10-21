#Requires -Modules Pester
<#
    Unit tests for Export-ADSecurityReportHTMLFromJson (src/Reporting.ps1).

    These tests do NOT touch Active Directory. Like RetestComparison.Tests.ps1,
    they write a synthetic AD_Security_Audit_<timestamp>.json (the exact shape
    Start-ADSecurityAudit already writes) to TestDrive and feed it to
    Export-ADSecurityReportHTMLFromJson entirely offline.

    Run from the repo root:  Invoke-Pester ./tests/ReportingFromJson.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
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

    $script:ControlPathFinding = New-TestFinding -Issue 'Control Path to Domain Admins' -Category 'Attack Paths' -Severity 'High' -SeverityLevel 3 -AffectedObject 'user1'
    $script:ControlPathFinding.Details = @{
        HopChain  = 'user1 -> GroupA -> Domain Admins'
        Source    = 'user1'
        Target    = 'Domain Admins'
        HopCount  = 2
    }

    $script:Findings = @(
        New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'user1'
        New-TestFinding -Issue 'Kerberoastable Account' -Category 'Kerberos Security' -Severity 'High' -SeverityLevel 3 -AffectedObject 'svc1'
        New-TestFinding -Issue 'AdminSDHolder ACL Modified' -Category 'AdminSDHolder' -Severity 'Critical' -SeverityLevel 4 -AffectedObject 'AdminSDHolder'
        $script:ControlPathFinding
    )
    foreach ($finding in $script:Findings) { [void](Set-ADFindingMetadata -Finding $finding) }

    function New-FindingsFixture {
        param(
            [string]$FolderName,
            [array]$Findings,
            [string]$Timestamp,
            [switch]$WithScoreSidecar,
            [array]$TestCoverage
        )
        $folder = Join-Path $TestDrive $FolderName
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        $findingsPath = Join-Path $folder "AD_Security_Audit_$Timestamp.json"
        $Findings | ConvertTo-Json -Depth 6 | Out-File -FilePath $findingsPath -Encoding UTF8

        if ($WithScoreSidecar) {
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
}

Describe 'Export-ADSecurityReportHTMLFromJson' {
    It 'accepts an explicit AD_Security_Audit_*.json file path' {
        $folder = New-FindingsFixture -FolderName 'explicit-file' -Findings $script:Findings -Timestamp '2026-08-01_00-00-00'
        $explicitFile = Join-Path $folder 'AD_Security_Audit_2026-08-01_00-00-00.json'
        $outPath = Join-Path $TestDrive 'recreated-explicit.html'

        { Export-ADSecurityReportHTMLFromJson -FindingsPath $explicitFile -OutputPath $outPath } | Should -Not -Throw
        Test-Path $outPath | Should -BeTrue
    }

    It 'accepts a folder path and resolves the newest AD_Security_Audit_*.json in it' {
        $folder = New-FindingsFixture -FolderName 'folder-form' -Findings $script:Findings -Timestamp '2026-08-02_00-00-00'
        $outPath = Join-Path $TestDrive 'recreated-folder.html'

        { Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath } | Should -Not -Throw
        Test-Path $outPath | Should -BeTrue
    }

    It 'accepts an existing folder for -OutputPath and auto-names the file inside it' {
        $folder = New-FindingsFixture -FolderName 'output-folder-existing' -Findings $script:Findings -Timestamp '2026-08-13_00-00-00'

        { Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $folder } | Should -Not -Throw
        $expected = Join-Path $folder 'AD_Security_Audit_2026-08-13_00-00-00-recreated.html'
        Test-Path $expected | Should -BeTrue
    }

    It 'creates a not-yet-existing folder for -OutputPath and auto-names the file inside it' {
        $folder = New-FindingsFixture -FolderName 'output-folder-new-source' -Findings $script:Findings -Timestamp '2026-08-14_00-00-00'
        $newFolder = Join-Path $TestDrive 'brand-new-output-folder'
        Test-Path $newFolder | Should -BeFalse

        { Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $newFolder } | Should -Not -Throw
        Test-Path $newFolder | Should -BeTrue
        $expected = Join-Path $newFolder 'AD_Security_Audit_2026-08-14_00-00-00-recreated.html'
        Test-Path $expected | Should -BeTrue
    }

    It 'does not overwrite an original same-timestamp HTML report when -OutputPath is that same folder' {
        $folder = New-FindingsFixture -FolderName 'output-folder-no-overwrite' -Findings $script:Findings -Timestamp '2026-08-15_00-00-00'
        $originalHtmlPath = Join-Path $folder 'AD_Security_Audit_2026-08-15_00-00-00.html'
        'ORIGINAL - DO NOT OVERWRITE' | Out-File -FilePath $originalHtmlPath -Encoding UTF8

        Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $folder

        (Get-Content -Path $originalHtmlPath -Raw) | Should -Match 'DO NOT OVERWRITE'
    }

    It 'still treats a path with a .html extension as an exact file, even if it does not exist yet' {
        $folder = New-FindingsFixture -FolderName 'output-exact-path-form' -Findings $script:Findings -Timestamp '2026-08-16_00-00-00'
        $exactPath = Join-Path $TestDrive 'exact-path-does-not-exist-yet.html'
        Test-Path $exactPath | Should -BeFalse

        Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $exactPath

        Test-Path $exactPath | Should -BeTrue
        # Confirm it did NOT also create an auto-named file - the exact path was honored as given.
        Test-Path (Join-Path $TestDrive 'AD_Security_Audit_2026-08-16_00-00-00-recreated.html') | Should -BeFalse
    }

    It 'produces a report whose Executive Summary counts match the findings by severity' {
        $folder = New-FindingsFixture -FolderName 'summary-counts' -Findings $script:Findings -Timestamp '2026-08-03_00-00-00'
        $outPath = Join-Path $TestDrive 'recreated-summary.html'
        Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath

        $content = Get-Content -Path $outPath -Raw
        # One Critical, one High, zero Medium, one Low in the fixture above.
        $content | Should -Match 'AdminSDHolder ACL Modified'
        $content | Should -Match 'Kerberoastable Account'
        $content | Should -Match 'Inactive Enabled Account'
    }

    It 'shows a placeholder Domain rather than a blank/incorrect value when -Domain is omitted' {
        $folder = New-FindingsFixture -FolderName 'no-domain' -Findings $script:Findings -Timestamp '2026-08-04_00-00-00'
        $outPath = Join-Path $TestDrive 'recreated-no-domain.html'
        Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath

        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'recreated from JSON export'
    }

    It 'reflects an explicitly-passed -Domain instead of the placeholder' {
        $folder = New-FindingsFixture -FolderName 'with-domain' -Findings $script:Findings -Timestamp '2026-08-05_00-00-00'
        $outPath = Join-Path $TestDrive 'recreated-with-domain.html'
        Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath -Domain 'contoso.com'

        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'contoso\.com'
        $content | Should -Not -Match 'recreated from JSON export'
    }

    It 'recomputes the risk score via Get-ADRiskScore rather than trusting a stray score sidecar' {
        # Even when a sidecar happens to exist alongside the findings export,
        # the recreated report's score must come from Get-ADRiskScore run
        # fresh against the findings - never a passthrough of the sidecar.
        $folder = New-FindingsFixture -FolderName 'with-sidecar' -Findings $script:Findings -Timestamp '2026-08-06_00-00-00' -WithScoreSidecar
        $expected = Get-ADRiskScore -Findings $script:Findings
        $outPath = Join-Path $TestDrive 'recreated-with-sidecar.html'
        Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath

        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match [regex]::Escape("$($expected.TotalScore)")
    }

    It 'throws a clear error when the path does not exist' {
        { Export-ADSecurityReportHTMLFromJson -FindingsPath (Join-Path $TestDrive 'does-not-exist') -OutputPath (Join-Path $TestDrive 'irrelevant.html') } | Should -Throw
    }

    Context 'Control-path (Attack Paths) findings - Details survives the JSON round-trip' {
        <#
            Regression coverage for a reported bug: Details is declared
            [hashtable] on a live ADSecurityFinding, but
            Export-ADSecurityReportHTMLFromJson reads findings back via a
            plain ConvertFrom-Json (no -AsHashtable), which deserializes
            every JSON object - including a finding's Details - into a
            PSCustomObject instead. The control-path rendering code in
            Export-ADSecurityReportHTML called $finding.Details.ContainsKey(...)
            unconditionally, which only exists on Hashtable/IDictionary,
            so recreating a report from JSON for ANY run that had a
            control-path finding threw "Method invocation failed because
            [...PSCustomObject] does not contain a method named
            'ContainsKey'" on every single one. Fixed via
            Test-ADFindingDetailsKey (Common.ps1), which works for either
            shape.
        #>
        It 'recreates a report containing a control-path finding without throwing' {
            $folder = New-FindingsFixture -FolderName 'control-path' -Findings $script:Findings -Timestamp '2026-08-07_00-00-00'
            $outPath = Join-Path $TestDrive 'recreated-control-path.html'

            { Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath } | Should -Not -Throw
            Test-Path $outPath | Should -BeTrue
        }

        It 'renders the HopChain from a JSON-deserialized (PSCustomObject) Details' {
            $folder = New-FindingsFixture -FolderName 'control-path-hopchain' -Findings $script:Findings -Timestamp '2026-08-08_00-00-00'
            $outPath = Join-Path $TestDrive 'recreated-control-path-hopchain.html'
            Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath

            $content = Get-Content -Path $outPath -Raw
            $content | Should -Match 'Control Path to Domain Admins'
            $content | Should -Match 'user1 -&gt; GroupA -&gt; Domain Admins'
        }

        It 'still works when Details is a genuine Hashtable (not JSON-sourced), unaffected by the fix' {
            $liveFindings = @($script:ControlPathFinding)
            $outPath = Join-Path $TestDrive 'live-control-path.html'
            $summary = @{ Critical = 0; High = 1; Medium = 0; Low = 0 }
            $riskScore = Get-ADRiskScore -Findings $liveFindings
            { Export-ADSecurityReportHTML -Findings $liveFindings -OutputPath $outPath -Domain 'contoso.com' -Summary $summary `
                -Duration ([timespan]::Zero) -RiskScore $riskScore `
                -PrivilegedUsers $null } | Should -Not -Throw

            $content = Get-Content -Path $outPath -Raw
            $content | Should -Match 'user1 -&gt; GroupA -&gt; Domain Admins'
        }
    }
}

Describe 'Export-ADSecurityReportHTMLFromJson - Test Coverage sidecar' {
    <#
        Regression coverage for the reported gap: neither the HTML nor CSV
        report indicated which checks did NOT run (excluded/failed) or
        which ran and found nothing. Main.ps1 now writes a sibling
        AD_Security_TestCoverage_<timestamp>.json; this recovers it via
        Get-ADTestCoverageSidecar (Common.ps1) when recreating the report.
    #>
    It 'summarizes passed-clean vs found-issues vs untested (failed+excluded) as distinct counts, not lumped into one "completed" figure' {
        $coverage = @(
            [PSCustomObject]@{ TestName = 'FoundSomething'; Status = 'Completed'; FindingCount = 2; ErrorMessage = $null }
            [PSCustomObject]@{ TestName = 'RanClean1'; Status = 'Completed'; FindingCount = 0; ErrorMessage = $null }
            [PSCustomObject]@{ TestName = 'RanClean2'; Status = 'Completed'; FindingCount = 0; ErrorMessage = $null }
            [PSCustomObject]@{ TestName = 'ErroredOut'; Status = 'Failed'; FindingCount = 0; ErrorMessage = 'boom' }
            [PSCustomObject]@{ TestName = 'SkippedCheck'; Status = 'Excluded'; FindingCount = 0; ErrorMessage = $null }
        )
        $folder = New-FindingsFixture -FolderName 'summary-counts' -Findings $script:Findings -Timestamp '2026-08-13_00-00-00' -TestCoverage $coverage
        $outPath = Join-Path $TestDrive 'recreated-summary-counts.html'
        Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath

        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match '2 passed clean'
        $content | Should -Match '1 found issue'
        $content | Should -Match '2 untested'
        $content | Should -Match '1 failed'
        $content | Should -Match '1 excluded'
    }

    It 'renders a Test Coverage section when a coverage sidecar exists next to the findings JSON' {
        $coverage = @(
            [PSCustomObject]@{ TestName = 'UserAccounts'; Status = 'Completed'; FindingCount = 1; ErrorMessage = $null }
            [PSCustomObject]@{ TestName = 'CertificateServices'; Status = 'Failed'; FindingCount = 0; ErrorMessage = 'Access is denied' }
            [PSCustomObject]@{ TestName = 'RodcSecurity'; Status = 'Excluded'; FindingCount = 0; ErrorMessage = $null }
        )
        $folder = New-FindingsFixture -FolderName 'with-coverage' -Findings $script:Findings -Timestamp '2026-08-10_00-00-00' -TestCoverage $coverage
        $outPath = Join-Path $TestDrive 'recreated-with-coverage.html'
        Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath

        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'TEST COVERAGE'
        $content | Should -Match 'CertificateServices'
        $content | Should -Match 'Access is denied'
        $content | Should -Match 'EXCLUDED'
    }

    It 'renders the Test Coverage section as a collapsed-by-default <details> element, not an always-expanded box' {
        $coverage = @([PSCustomObject]@{ TestName = 'UserAccounts'; Status = 'Completed'; FindingCount = 1; ErrorMessage = $null })
        $folder = New-FindingsFixture -FolderName 'collapsible-coverage' -Findings $script:Findings -Timestamp '2026-08-21_00-00-00' -TestCoverage $coverage
        $outPath = Join-Path $TestDrive 'recreated-collapsible-coverage.html'
        Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath

        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match '<details class="warning-box"[^>]*id="test-coverage"'
        # No "open" attribute on that specific <details> tag - collapsed by default.
        $content | Should -Not -Match '<details[^>]*id="test-coverage"[^>]*\sopen'
        $content | Should -Match '<summary[^>]*>.*TEST COVERAGE'
    }

    It 'renders a COMPLETED (not CLEAN) badge for a check with findings, and a CLEAN badge for a check with none - regression test for a switch $_ rebind bug that previously always showed CLEAN' {
        $coverage = @(
            [PSCustomObject]@{ TestName = 'HasFindings'; Status = 'Completed'; FindingCount = 3; ErrorMessage = $null }
            [PSCustomObject]@{ TestName = 'NoFindings'; Status = 'Completed'; FindingCount = 0; ErrorMessage = $null }
        )
        $folder = New-FindingsFixture -FolderName 'badge-regression' -Findings $script:Findings -Timestamp '2026-08-11_00-00-00' -TestCoverage $coverage
        $outPath = Join-Path $TestDrive 'recreated-badge-regression.html'
        Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath

        $content = Get-Content -Path $outPath -Raw
        # The HasFindings row must show COMPLETED (not CLEAN) despite both
        # sharing the 'Completed' Status - only FindingCount distinguishes
        # them, and reading FindingCount off the wrong object (the switch
        # subject string, pre-fix) silently always took the "0" branch.
        ($content -match '(?s)HasFindings.{0,200}?COMPLETED') | Should -BeTrue
        ($content -match '(?s)NoFindings.{0,200}?CLEAN') | Should -BeTrue
    }

    It 'omits the real Test Coverage section (no throw) when no coverage sidecar exists, but adds a clear "not available" note citing the version boundary' {
        $folder = New-FindingsFixture -FolderName 'no-coverage' -Findings $script:Findings -Timestamp '2026-08-12_00-00-00'
        $outPath = Join-Path $TestDrive 'recreated-no-coverage.html'
        { Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath } | Should -Not -Throw

        $content = Get-Content -Path $outPath -Raw
        $content | Should -Not -Match 'check\(s\) tracked for this run' -Because 'the real Test Coverage section (with counts) should not render when there is no data'
        $content | Should -Match 'Test Coverage Not Available'
        $content | Should -Match '1\.24\.0' -Because 'the note should name the version test coverage tracking was introduced in, so a reader can tell whether their export predates it'
    }

    It 'does NOT add the "not available" note when a real coverage sidecar exists' {
        $coverage = @([PSCustomObject]@{ TestName = 'UserAccounts'; Status = 'Completed'; FindingCount = 1; ErrorMessage = $null })
        $folder = New-FindingsFixture -FolderName 'has-coverage-no-false-note' -Findings $script:Findings -Timestamp '2026-08-14_00-00-00' -TestCoverage $coverage
        $outPath = Join-Path $TestDrive 'recreated-has-coverage-no-false-note.html'
        Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath

        $content = Get-Content -Path $outPath -Raw
        $content | Should -Not -Match 'Test Coverage Not Available'
        $content | Should -Match 'check\(s\) tracked for this run'
    }
}

Describe 'Export-ADSecurityReportHTML - unexpected Severity values are never silently dropped' {
    <#
        Regression coverage from a full-codebase audit: every current check
        only ever assigns Severity = Critical/High/Medium/Low, but the
        HTML report's severity-bucketing only ever created sections for
        those four values. A finding with any OTHER Severity (a future
        check, a typo, or an externally-supplied finding) would still be
        scored (Scoring.ps1 has its own "Info" catch-all bucket) and still
        appear in JSON/CSV (neither filters by severity), but would never
        have rendered ANYWHERE in the HTML report - completely invisible,
        with no warning. Fixed with a catch-all "Other / Unclassified
        Severity" section plus a Write-Warning naming the affected Issue(s).
    #>
    It 'renders a finding with an unexpected Severity value in a dedicated "Other" section instead of dropping it' {
        $normalFinding = New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'user1'
        $weirdFinding = New-TestFinding -Issue 'Something With Unexpected Severity' -Category 'Custom Check' -Severity 'Informational' -SeverityLevel 1 -AffectedObject 'obj1'
        $findings = @($normalFinding, $weirdFinding)

        $outPath = Join-Path $TestDrive 'other-severity.html'
        $riskScore = Get-ADRiskScore -Findings $findings
        Export-ADSecurityReportHTML -Findings $findings -OutputPath $outPath -Domain 'contoso.com' `
            -Summary @{ Critical = 0; High = 0; Medium = 0; Low = 1 } -Duration ([timespan]::Zero) `
            -RiskScore $riskScore -WarningAction SilentlyContinue

        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'Something With Unexpected Severity'
        $content | Should -Match 'Other / Unclassified Severity Findings'
        $content | Should -Match 'Inactive Enabled Account'
        $content | Should -Match 'other-findings'
    }

    It 'warns naming the affected Issue(s) when this happens' {
        $weirdFinding = New-TestFinding -Issue 'Weird' -Category 'X' -Severity 'Bogus' -SeverityLevel 1 -AffectedObject 'o'
        $outPath = Join-Path $TestDrive 'other-severity-warn.html'
        $riskScore = Get-ADRiskScore -Findings @($weirdFinding)

        $warnings = @()
        Export-ADSecurityReportHTML -Findings @($weirdFinding) -OutputPath $outPath -Domain 'x' `
            -Summary @{ Critical = 0; High = 0; Medium = 0; Low = 0 } -Duration ([timespan]::Zero) `
            -RiskScore $riskScore -WarningVariable warnings -WarningAction SilentlyContinue

        $warnings.Count | Should -BeGreaterThan 0
        ($warnings -join ' ') | Should -Match 'Weird'
    }

    It 'does not create an Other section (or nav link) when every finding has a canonical severity' {
        $normalFinding = New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'user1'
        $outPath = Join-Path $TestDrive 'no-other-section.html'
        $riskScore = Get-ADRiskScore -Findings @($normalFinding)
        Export-ADSecurityReportHTML -Findings @($normalFinding) -OutputPath $outPath -Domain 'contoso.com' `
            -Summary @{ Critical = 0; High = 0; Medium = 0; Low = 1 } -Duration ([timespan]::Zero) `
            -RiskScore $riskScore

        $content = Get-Content -Path $outPath -Raw
        $content | Should -Not -Match 'Other / Unclassified Severity Findings'
    }
}

Describe 'Test-ADFindingDetailsKey' {
    It 'finds a key on a real Hashtable' {
        Test-ADFindingDetailsKey -Details @{ Foo = 'bar' } -Key 'Foo' | Should -BeTrue
    }
    It 'returns $false for a missing key on a Hashtable' {
        Test-ADFindingDetailsKey -Details @{ Foo = 'bar' } -Key 'Missing' | Should -BeFalse
    }
    It 'finds a key on a JSON-deserialized PSCustomObject' {
        $obj = (@{ Foo = 'bar' } | ConvertTo-Json | ConvertFrom-Json)
        Test-ADFindingDetailsKey -Details $obj -Key 'Foo' | Should -BeTrue
    }
    It 'returns $false for a missing key on a PSCustomObject' {
        $obj = (@{ Foo = 'bar' } | ConvertTo-Json | ConvertFrom-Json)
        Test-ADFindingDetailsKey -Details $obj -Key 'Missing' | Should -BeFalse
    }
    It 'returns $false (not a throw) for $null Details' {
        { Test-ADFindingDetailsKey -Details $null -Key 'Foo' } | Should -Not -Throw
        Test-ADFindingDetailsKey -Details $null -Key 'Foo' | Should -BeFalse
    }
}
