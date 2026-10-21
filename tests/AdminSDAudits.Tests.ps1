#Requires -Modules Pester
<#
    Unit tests for Test-AdminSDHolder (src/AdminSDAudits.ps1).

    This module previously had NO Pester coverage at all - a real gap
    found while reviewing v1.30.0's new 'AdminSDHolder Inheritance
    Re-Enabled' check (files/15-schema-persistence-tampering.md), which
    was added to this file but shipped with no regression test protecting
    it or the pre-existing checks in the same function.

    This file intentionally focuses on the new inheritance check only -
    it does not attempt full coverage of Test-AdminSDHolder's existing
    ACE/adminCount checks, which would need their own, separate pass.

    Shadows Get-ADDomain, Get-ADObject, and Get-ADUser with local
    functions - no real Active Directory or connectivity is required.

    Run from the repo root:  Invoke-Pester ./tests/AdminSDAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/AdminSDAudits.ps1')

    function Get-ADDomain {
        param($Server)
        [PSCustomObject]@{
            DistinguishedName = 'DC=contoso,DC=com'
            NetBIOSName       = 'CONTOSO'
        }
    }

    # No adminCount=1 stragglers by default - keeps these tests focused on
    # the inheritance check alone, per the file header above.
    function Get-ADUser {
        param($Filter, $Properties, $Server)
        @()
    }

    function New-ADSecurityAuditTestAce {
        param($Identity, $Rights = 'GenericAll')
        [PSCustomObject]@{
            IdentityReference     = [PSCustomObject]@{ Value = $Identity }
            ActiveDirectoryRights = $Rights
            AccessControlType     = 'Allow'
            IsInherited           = $false
        }
    }
}

Describe 'Test-AdminSDHolder / AdminSDHolder Inheritance Re-Enabled' {
    It 'flags AdminSDHolder when ACL inheritance is enabled (AreAccessRulesProtected = $false)' {
        function Get-ADObject {
            param($Identity, $Properties, $Server)
            [PSCustomObject]@{
                DistinguishedName = $Identity
                nTSecurityDescriptor = [PSCustomObject]@{
                    AreAccessRulesProtected = $false
                    Access = @(
                        New-ADSecurityAuditTestAce -Identity 'NT AUTHORITY\SYSTEM'
                        New-ADSecurityAuditTestAce -Identity 'CONTOSO\Domain Admins'
                    )
                }
            }
        }

        $findings = Test-AdminSDHolder
        $finding = $findings | Where-Object { $_.Issue -eq 'AdminSDHolder Inheritance Re-Enabled' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'Critical'
        $finding.Details.AreAccessRulesProtected | Should -Be $false
    }

    It 'does NOT flag AdminSDHolder when ACL inheritance is disabled (the normal, protected state)' {
        function Get-ADObject {
            param($Identity, $Properties, $Server)
            [PSCustomObject]@{
                DistinguishedName = $Identity
                nTSecurityDescriptor = [PSCustomObject]@{
                    AreAccessRulesProtected = $true
                    Access = @(
                        New-ADSecurityAuditTestAce -Identity 'NT AUTHORITY\SYSTEM'
                        New-ADSecurityAuditTestAce -Identity 'CONTOSO\Domain Admins'
                    )
                }
            }
        }

        $findings = Test-AdminSDHolder
        ($findings | Where-Object { $_.Issue -eq 'AdminSDHolder Inheritance Re-Enabled' }) | Should -BeNullOrEmpty
    }

    It 'does not error when nTSecurityDescriptor itself is unavailable' {
        function Get-ADObject {
            param($Identity, $Properties, $Server)
            [PSCustomObject]@{
                DistinguishedName    = $Identity
                nTSecurityDescriptor = $null
            }
        }

        { Test-AdminSDHolder } | Should -Not -Throw
        $findings = Test-AdminSDHolder
        ($findings | Where-Object { $_.Issue -eq 'AdminSDHolder Inheritance Re-Enabled' }) | Should -BeNullOrEmpty
    }
}
