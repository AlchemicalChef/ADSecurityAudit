#Requires -Modules Pester
<#
    Unit tests for Set-ADRemediationState / Get-ADRemediationState and their
    integration into Get-ADRetestComparison via -RemediationStatePath.

    These tests do NOT touch Active Directory.

    Run from the repo root:  Invoke-Pester ./tests/RemediationState.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/RetestComparison.ps1')
    . (Join-Path $root 'src/RemediationState.ps1')

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
}

Describe 'Get-ADRemediationState' {
    It 'returns an empty/default structure when the state file does not exist yet (no pre-creation required)' {
        $missingPath = Join-Path $TestDrive 'does-not-exist.json'
        $state = Get-ADRemediationState -StatePath $missingPath
        $state.DomainName | Should -BeNullOrEmpty
        $state.Entries.Count | Should -Be 0
    }

    It 'throws a clear error for a malformed (unparsable) state file' {
        $badPath = Join-Path $TestDrive 'bad.json'
        'not valid json {' | Out-File -FilePath $badPath -Encoding UTF8
        { Get-ADRemediationState -StatePath $badPath } | Should -Throw
    }
}

Describe 'Set-ADRemediationState' {
    It 'creates a new state file and entry on first use' {
        $path = Join-Path $TestDrive 'new-state.json'
        $key = Get-ADFindingMatchKey -Category 'Certificate Services' -Issue 'ESC3' -AffectedObject 'CN=LegacyEnroll'
        Set-ADRemediationState -Key $key -Status AcceptedRisk -Owner 'jane.doe@contoso.com' -Note 'JIRA-1234' -StatePath $path -DomainName 'contoso.com' | Out-Null

        Test-Path $path | Should -BeTrue
        $state = Get-ADRemediationState -StatePath $path
        $state.DomainName | Should -Be 'contoso.com'
        $state.Entries.Count | Should -Be 1
        $state.Entries[0].Key | Should -Be $key
        $state.Entries[0].Status | Should -Be 'AcceptedRisk'
        $state.Entries[0].Owner | Should -Be 'jane.doe@contoso.com'
    }

    It 'upserts by Key - calling it twice for the same key updates the entry rather than duplicating it, and the second call''s value wins' {
        $path = Join-Path $TestDrive 'upsert-state.json'
        $key = Get-ADFindingMatchKey -Category 'DNS Security' -Issue 'Stale Delegation' -AffectedObject 'child.contoso.com'

        Set-ADRemediationState -Key $key -Status InProgress -Owner 'alice' -StatePath $path | Out-Null
        Set-ADRemediationState -Key $key -Status Remediated -Owner 'bob' -Note 'fixed in change CR-42' -StatePath $path | Out-Null

        $state = Get-ADRemediationState -StatePath $path
        $state.Entries.Count | Should -Be 1
        $state.Entries[0].Status | Should -Be 'Remediated'
        $state.Entries[0].Owner | Should -Be 'bob'
        $state.Entries[0].Note | Should -Be 'fixed in change CR-42'
    }

    It 'preserves an existing entry for a different key when upserting one key' {
        $path = Join-Path $TestDrive 'multi-key-state.json'
        $keyA = Get-ADFindingMatchKey -Category 'User Account' -Issue 'Inactive Enabled Account' -AffectedObject 'u1'
        $keyB = Get-ADFindingMatchKey -Category 'User Account' -Issue 'Inactive Enabled Account' -AffectedObject 'u2'

        Set-ADRemediationState -Key $keyA -Status AcceptedRisk -StatePath $path | Out-Null
        Set-ADRemediationState -Key $keyB -Status InProgress -StatePath $path | Out-Null

        $state = Get-ADRemediationState -StatePath $path
        $state.Entries.Count | Should -Be 2
        ($state.Entries | Where-Object { $_.Key -eq $keyA }).Status | Should -Be 'AcceptedRisk'
        ($state.Entries | Where-Object { $_.Key -eq $keyB }).Status | Should -Be 'InProgress'
    }

    It 'rejects a Status value outside Open/AcceptedRisk/InProgress/Remediated' {
        $path = Join-Path $TestDrive 'invalid-status.json'
        { Set-ADRemediationState -Key 'x|y|z' -Status 'Ignored' -StatePath $path } | Should -Throw
    }

    It 'creates the parent directory for -StatePath if it does not exist' {
        $path = Join-Path $TestDrive 'nested/dir/state.json'
        { Set-ADRemediationState -Key 'x|y|z' -Status Open -StatePath $path } | Should -Not -Throw
        Test-Path $path | Should -BeTrue
    }
}

Describe 'Get-ADRetestComparison -RemediationStatePath integration' {
    BeforeAll {
        $script:BaselineFolder = Join-Path $TestDrive 'rem-baseline'
        $script:RetestFolder   = Join-Path $TestDrive 'rem-retest'
        New-Item -ItemType Directory -Path $script:BaselineFolder -Force | Out-Null
        New-Item -ItemType Directory -Path $script:RetestFolder -Force | Out-Null

        $findings = @(
            New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'u1'
            New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'u2'
        )
        foreach ($f in $findings) { [void](Set-ADFindingMetadata -Finding $f) }
        $findings | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $script:BaselineFolder 'AD_Security_Audit_2026-01-01_00-00-00.json') -Encoding UTF8
        $findings | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $script:RetestFolder 'AD_Security_Audit_2026-02-01_00-00-00.json') -Encoding UTF8

        $script:StatePath = Join-Path $TestDrive 'rem-integration-state.json'
        $script:TrackedKey = Get-ADFindingMatchKey -Category 'User Account' -Issue 'Inactive Enabled Account' -AffectedObject 'u1'
        Set-ADRemediationState -Key $script:TrackedKey -Status AcceptedRisk -Owner 'jane.doe@contoso.com' -Note 'JIRA-1234' -StatePath $script:StatePath | Out-Null
    }

    It 'behaves identically (no RemediationState property) when -RemediationStatePath is omitted - no regression' {
        $cmp = Get-ADRetestComparison -BaselinePath $script:BaselineFolder -RetestPath $script:RetestFolder
        foreach ($f in $cmp.StillOpenFindings) {
            $f.PSObject.Properties.Name -contains 'RemediationState' | Should -BeFalse
        }
    }

    It 'annotates the tracked Still-Open finding with its full RemediationState, and defaults the untracked one to Open/nulls' {
        $cmp = Get-ADRetestComparison -BaselinePath $script:BaselineFolder -RetestPath $script:RetestFolder -RemediationStatePath $script:StatePath

        $tracked = $cmp.StillOpenFindings | Where-Object { $_.AffectedObject -eq 'u1' }
        $untracked = $cmp.StillOpenFindings | Where-Object { $_.AffectedObject -eq 'u2' }

        $tracked.RemediationState.Status | Should -Be 'AcceptedRisk'
        $tracked.RemediationState.Owner  | Should -Be 'jane.doe@contoso.com'
        $tracked.RemediationState.Note   | Should -Be 'JIRA-1234'

        $untracked.RemediationState.Status | Should -Be 'Open'
        $untracked.RemediationState.Owner  | Should -BeNullOrEmpty
        $untracked.RemediationState.Note   | Should -BeNullOrEmpty
    }

    It 'does not change the New/Resolved/StillOpen/Changed classification itself' {
        $cmpWithout = Get-ADRetestComparison -BaselinePath $script:BaselineFolder -RetestPath $script:RetestFolder
        $cmpWith    = Get-ADRetestComparison -BaselinePath $script:BaselineFolder -RetestPath $script:RetestFolder -RemediationStatePath $script:StatePath

        $cmpWith.NewFindings.Count | Should -Be $cmpWithout.NewFindings.Count
        $cmpWith.ResolvedFindings.Count | Should -Be $cmpWithout.ResolvedFindings.Count
        $cmpWith.StillOpenFindings.Count | Should -Be $cmpWithout.StillOpenFindings.Count
        $cmpWith.ChangedFindings.Count | Should -Be $cmpWithout.ChangedFindings.Count
    }

    It "confirms Get-ADRiskScore's computed score is unaffected by remediation state" {
        $cmpWithout = Get-ADRetestComparison -BaselinePath $script:BaselineFolder -RetestPath $script:RetestFolder
        $cmpWith    = Get-ADRetestComparison -BaselinePath $script:BaselineFolder -RetestPath $script:RetestFolder -RemediationStatePath $script:StatePath
        $cmpWith.RetestScore.TotalScore | Should -Be $cmpWithout.RetestScore.TotalScore
        $cmpWith.ScoreDelta | Should -Be $cmpWithout.ScoreDelta
    }
}

Describe 'Export-ADRetestComparisonHTML - remediation-state badges' {
    BeforeAll {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/Reporting.ps1')

        $folder = Join-Path $TestDrive 'rem-html'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        $findings = @(
            New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'u1'
        )
        foreach ($f in $findings) { [void](Set-ADFindingMetadata -Finding $f) }
        $findings | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $folder 'AD_Security_Audit_2026-01-01_00-00-00.json') -Encoding UTF8

        $statePath = Join-Path $TestDrive 'rem-html-state.json'
        $key = Get-ADFindingMatchKey -Category 'User Account' -Issue 'Inactive Enabled Account' -AffectedObject 'u1'
        Set-ADRemediationState -Key $key -Status AcceptedRisk -Owner 'jane.doe@contoso.com' -StatePath $statePath | Out-Null

        $script:Cmp = Get-ADRetestComparison -BaselinePath $folder -RetestPath $folder -RemediationStatePath $statePath
    }

    It 'badges a tracked AcceptedRisk finding distinctly from the default Open styling' {
        $outPath = Join-Path $TestDrive 'rem-report.html'
        Export-ADRetestComparisonHTML -Comparison $script:Cmp -OutputPath $outPath
        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'remediation-acceptedrisk'
        $content | Should -Match 'jane\.doe@contoso\.com'
    }
}
