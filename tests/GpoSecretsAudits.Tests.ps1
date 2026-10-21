#Requires -Modules Pester
<#
    Unit tests for Test-ADGpoDeployedSecrets (GPP cpassword, script
    credentials, insecure GPO settings, and the GPO Grants Sensitive Logon
    Right to Broad Principal / A-AnonymousAuthorizedGPO-comparable check).

    Test-ADGpoDeployedSecrets is entirely live-only (its whole purpose is
    reading SYSVOL file content). These tests shadow Import-Module,
    Get-GPO, and Get-ADGpoSecretsSysvolPolicyRoot with local functions so no
    real AD module, GroupPolicy module, or SYSVOL share is required - the
    "SYSVOL policy root" is a real temp directory on disk, and real files
    are written under it, since the function under test does genuine
    Test-Path/Get-Content/Get-ChildItem reads.

    Run from the repo root:  Invoke-Pester ./tests/GpoSecretsAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/GpoSecretsAudits.ps1')

    function New-GpoSecretsTestRoot {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("GpoSecretsAuditsTests_" + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
        return $tempRoot
    }

    function New-GpoTmplFixture {
        param(
            [string]$PolicyRoot,
            [string]$GpoId,
            [string]$PrivilegeRightsBody
        )

        $gpoFolder = Join-Path $PolicyRoot "{$GpoId}"
        $secEditFolder = Join-Path $gpoFolder 'Machine\Microsoft\Windows NT\SecEdit'
        New-Item -ItemType Directory -Path $secEditFolder -Force | Out-Null

        $content = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$PrivilegeRightsBody
"@
        Set-Content -LiteralPath (Join-Path $secEditFolder 'GptTmpl.inf') -Value $content -NoNewline
        return $gpoFolder
    }
}

Describe 'Test-ADGpoDeployedSecrets / GPO Grants Sensitive Logon Right to Broad Principal' {
    BeforeEach {
        $script:policyRoot = New-GpoSecretsTestRoot
        function Import-Module { param($Name, [switch]$ErrorAction) }
        function Get-ADGpoSecretsSysvolPolicyRoot { $script:policyRoot }
    }

    AfterEach {
        if ($script:policyRoot -and (Test-Path -LiteralPath $script:policyRoot)) {
            Remove-Item -LiteralPath $script:policyRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'fires for SeNetworkLogonRight granted to Everyone alongside a specific group (fixture 1)' {
        $gpoId = 'AAAAAAAA-0000-0000-0000-000000000001'
        function Get-GPO { param([switch]$All) @([PSCustomObject]@{ Id = 'AAAAAAAA-0000-0000-0000-000000000001'; DisplayName = 'Fixture1-Everyone' }) }
        New-GpoTmplFixture -PolicyRoot $script:policyRoot -GpoId $gpoId `
            -PrivilegeRightsBody 'SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544'

        $findings = Test-ADGpoDeployedSecrets
        $finding = $findings | Where-Object { $_.Issue -eq 'GPO Grants Sensitive Logon Right to Broad Principal' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'Critical'
        $finding.SeverityLevel | Should -Be 4
        $finding.Details.BroadGrants[0].Right | Should -Be 'SeNetworkLogonRight'
        $finding.Details.BroadGrants[0].BroadPrincipals | Should -Contain 'Everyone'
    }

    It 'does not fire when only a specific (non-broad) principal is granted (fixture 2)' {
        $gpoId = 'AAAAAAAA-0000-0000-0000-000000000002'
        function Get-GPO { param([switch]$All) @([PSCustomObject]@{ Id = 'AAAAAAAA-0000-0000-0000-000000000002'; DisplayName = 'Fixture2-RDPUsersOnly' }) }
        New-GpoTmplFixture -PolicyRoot $script:policyRoot -GpoId $gpoId `
            -PrivilegeRightsBody 'SeRemoteInteractiveLogonRight = *S-1-5-32-555'

        $findings = Test-ADGpoDeployedSecrets
        ($findings | Where-Object { $_.Issue -eq 'GPO Grants Sensitive Logon Right to Broad Principal' }) | Should -BeNullOrEmpty
    }

    It 'fires for SeNetworkLogonRight granted to ANONYMOUS LOGON alone (fixture 3)' {
        $gpoId = 'AAAAAAAA-0000-0000-0000-000000000003'
        function Get-GPO { param([switch]$All) @([PSCustomObject]@{ Id = 'AAAAAAAA-0000-0000-0000-000000000003'; DisplayName = 'Fixture3-AnonymousLogon' }) }
        New-GpoTmplFixture -PolicyRoot $script:policyRoot -GpoId $gpoId `
            -PrivilegeRightsBody 'SeNetworkLogonRight = *S-1-5-7'

        $findings = Test-ADGpoDeployedSecrets
        $finding = $findings | Where-Object { $_.Issue -eq 'GPO Grants Sensitive Logon Right to Broad Principal' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Details.BroadGrants[0].BroadPrincipals | Should -Contain 'ANONYMOUS LOGON'
    }

    It 'does not disturb the existing Insecure Setting Deployed via GPO check sharing the same GptTmpl.inf read' {
        $gpoId = 'AAAAAAAA-0000-0000-0000-000000000004'
        function Get-GPO { param([switch]$All) @([PSCustomObject]@{ Id = 'AAAAAAAA-0000-0000-0000-000000000004'; DisplayName = 'Fixture4-Combined' }) }
        New-GpoTmplFixture -PolicyRoot $script:policyRoot -GpoId $gpoId -PrivilegeRightsBody @'
SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544
'@
        # Append an insecure-firewall setting outside [Privilege Rights] to
        # exercise both checks against the same file in one pass.
        $gptTmplPath = Join-Path $script:policyRoot "{$gpoId}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        Add-Content -LiteralPath $gptTmplPath -Value "`n[System Access]`nEnableFirewall=0"

        $findings = Test-ADGpoDeployedSecrets
        ($findings | Where-Object { $_.Issue -eq 'GPO Grants Sensitive Logon Right to Broad Principal' }) | Should -Not -BeNullOrEmpty
        ($findings | Where-Object { $_.Issue -eq 'Insecure Setting Deployed via GPO' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-ADGpoDeployedSecrets / GPO Deploys Restricted Groups Membership' {
    BeforeEach {
        $script:policyRoot = New-GpoSecretsTestRoot
        function Import-Module { param($Name, [switch]$ErrorAction) }
        function Get-ADGpoSecretsSysvolPolicyRoot { $script:policyRoot }
    }

    AfterEach {
        if ($script:policyRoot -and (Test-Path -LiteralPath $script:policyRoot)) {
            Remove-Item -LiteralPath $script:policyRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'flags a GPO that pushes Administrators membership as Critical' {
        $gpoId = 'BBBBBBBB-0000-0000-0000-000000000001'
        function Get-GPO { param([switch]$All) @([PSCustomObject]@{ Id = $gpoId; DisplayName = 'RestrictedGroups-Admins' }) }
        New-GpoTmplFixture -PolicyRoot $script:policyRoot -GpoId $gpoId -PrivilegeRightsBody 'SeNetworkLogonRight ='
        $gptTmplPath = Join-Path $script:policyRoot "{$gpoId}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        Add-Content -LiteralPath $gptTmplPath -Value "`n[Group Membership]`n*S-1-5-32-544__Memberof =`n*S-1-5-32-544__Members = CONTOSO\jdoe,CONTOSO\Helpdesk"

        $findings = Test-ADGpoDeployedSecrets
        $finding = $findings | Where-Object { $_.Issue -eq 'GPO Deploys Restricted Groups Membership' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'Critical'
        $finding.Details.RestrictedGroups[0].GroupName | Should -Be 'Administrators'
        $finding.Details.RestrictedGroups[0].Members | Should -Contain 'CONTOSO\jdoe'
        $finding.Details.RestrictedGroups[0].Members | Should -Contain 'CONTOSO\Helpdesk'
    }

    It 'flags a GPO that pushes Remote Desktop Users membership as High (not Critical)' {
        $gpoId = 'BBBBBBBB-0000-0000-0000-000000000002'
        function Get-GPO { param([switch]$All) @([PSCustomObject]@{ Id = $gpoId; DisplayName = 'RestrictedGroups-RDP' }) }
        New-GpoTmplFixture -PolicyRoot $script:policyRoot -GpoId $gpoId -PrivilegeRightsBody 'SeNetworkLogonRight ='
        $gptTmplPath = Join-Path $script:policyRoot "{$gpoId}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        Add-Content -LiteralPath $gptTmplPath -Value "`n[Group Membership]`n*S-1-5-32-555__Members = CONTOSO\HelpdeskStaff"

        $findings = Test-ADGpoDeployedSecrets
        $finding = $findings | Where-Object { $_.Issue -eq 'GPO Deploys Restricted Groups Membership' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'High'
        $finding.Details.RestrictedGroups[0].GroupName | Should -Be 'Remote Desktop Users'
    }

    It 'resolves a *SID member entry to a display name when translatable, and falls back to the raw SID otherwise' {
        $gpoId = 'BBBBBBBB-0000-0000-0000-000000000003'
        function Get-GPO { param([switch]$All) @([PSCustomObject]@{ Id = $gpoId; DisplayName = 'RestrictedGroups-SidMember' }) }
        New-GpoTmplFixture -PolicyRoot $script:policyRoot -GpoId $gpoId -PrivilegeRightsBody 'SeNetworkLogonRight ='
        $gptTmplPath = Join-Path $script:policyRoot "{$gpoId}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        # An unresolvable made-up SID - Translate() will fail in this
        # environment, so the raw SID string is the expected, correct
        # fallback (not a test artifact to work around).
        Add-Content -LiteralPath $gptTmplPath -Value "`n[Group Membership]`n*S-1-5-32-544__Members = *S-1-5-21-9999-8888-7777-1234"

        $findings = Test-ADGpoDeployedSecrets
        $finding = $findings | Where-Object { $_.Issue -eq 'GPO Deploys Restricted Groups Membership' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Details.RestrictedGroups[0].Members | Should -Contain 'S-1-5-21-9999-8888-7777-1234'
    }

    It 'does not flag a GPO with no [Group Membership] section at all' {
        $gpoId = 'BBBBBBBB-0000-0000-0000-000000000004'
        function Get-GPO { param([switch]$All) @([PSCustomObject]@{ Id = $gpoId; DisplayName = 'NoRestrictedGroups' }) }
        New-GpoTmplFixture -PolicyRoot $script:policyRoot -GpoId $gpoId -PrivilegeRightsBody 'SeNetworkLogonRight ='

        $findings = Test-ADGpoDeployedSecrets
        ($findings | Where-Object { $_.Issue -eq 'GPO Deploys Restricted Groups Membership' }) | Should -BeNullOrEmpty
    }

    It 'does not flag a [Group Membership] section whose Members value is empty' {
        $gpoId = 'BBBBBBBB-0000-0000-0000-000000000005'
        function Get-GPO { param([switch]$All) @([PSCustomObject]@{ Id = $gpoId; DisplayName = 'EmptyRestrictedGroups' }) }
        New-GpoTmplFixture -PolicyRoot $script:policyRoot -GpoId $gpoId -PrivilegeRightsBody 'SeNetworkLogonRight ='
        $gptTmplPath = Join-Path $script:policyRoot "{$gpoId}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        Add-Content -LiteralPath $gptTmplPath -Value "`n[Group Membership]`n*S-1-5-32-544__Members ="

        $findings = Test-ADGpoDeployedSecrets
        ($findings | Where-Object { $_.Issue -eq 'GPO Deploys Restricted Groups Membership' }) | Should -BeNullOrEmpty
    }
}
