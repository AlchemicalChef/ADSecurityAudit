#Requires -Modules Pester
<#
    Unit tests for Test-ADReplicationSecurity (src/ReplicationAudits.ps1).

    This module previously had NO Pester coverage at all - a real gap
    found while reviewing v1.30.0's new 'SPN-Holding Account Also Has
    DCSync Rights' cross-check (files/23-dcsync-spn-crosscheck.md), which
    was added to this file but shipped with no regression test protecting
    it or the pre-existing DCSync-rights check in the same function.

    This file intentionally focuses on the new cross-check only - it does
    not attempt full coverage of Test-ADReplicationSecurity's existing
    checks, which would need their own, separate pass.

    IMPORTANT: identity references in these fixtures use SID strings
    (S-1-5-...), not "DOMAIN\name" strings. The function under test
    resolves non-SID identities via a real
    [System.Security.Principal.NTAccount]::Translate() .NET call, which
    requires a real Windows account/domain to resolve and will fail in
    this (or any non-domain-joined) test environment - using a SID string
    directly bypasses that call entirely (see the identityReference
    -match '^S-1-' branch in the source), keeping these tests fully
    offline and deterministic.

    Shadows Get-ADDomain, Get-ADObject, Get-ADUser, Get-ADGroup, and
    Get-ADGroupMember with local functions - no real Active Directory,
    domain membership, or connectivity is required.

    Run from the repo root:  Invoke-Pester ./tests/ReplicationAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/ReplicationAudits.ps1')

    $script:TestSpnUserSid = 'S-1-5-21-1111111111-2222222222-3333333333-1105'

    function Get-ADDomain {
        param($Server)
        [PSCustomObject]@{
            DistinguishedName = 'DC=contoso,DC=com'
            NetBIOSName       = 'CONTOSO'
        }
    }

    # No group-membership-based DCSync grants for these tests - keeps
    # focus on the direct-ACE cross-check, per the file header above.
    function Get-ADGroup {
        param($Filter, $Server)
        $null
    }
    function Get-ADGroupMember {
        param($Identity, $Server)
        @()
    }

    function New-ADSecurityAuditDCSyncAce {
        param($IdentitySid, $ObjectTypeGuid = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2')
        [PSCustomObject]@{
            IdentityReference     = [PSCustomObject]@{ Value = $IdentitySid }
            ActiveDirectoryRights = 'ExtendedRight'
            ObjectType            = [guid]$ObjectTypeGuid
            IsInherited           = $false
        }
    }
}

Describe 'Test-ADReplicationSecurity / SPN-Holding Account Also Has DCSync Rights' {
    It 'flags an account that both holds an SPN and has DCSync-capable rights' {
        function Get-ADObject {
            param($Identity, $Filter, $Properties, $Server, $ErrorAction)
            if ($Identity -eq 'DC=contoso,DC=com') {
                return [PSCustomObject]@{
                    nTSecurityDescriptor = [PSCustomObject]@{
                        Access = @( New-ADSecurityAuditDCSyncAce -IdentitySid $script:TestSpnUserSid )
                    }
                }
            }
            if ($Filter -like "*objectSid*$($script:TestSpnUserSid)*") {
                return [PSCustomObject]@{
                    DistinguishedName = 'CN=svc-backup,OU=Service Accounts,DC=contoso,DC=com'
                    objectClass       = 'user'
                }
            }
            throw "unexpected Get-ADObject call: Identity=$Identity Filter=$Filter"
        }
        function Get-ADUser {
            param($Identity, $Properties, $Server, $ErrorAction)
            [PSCustomObject]@{
                DistinguishedName     = $Identity
                ServicePrincipalName  = @('MSSQLSvc/sql01.contoso.com:1433')
            }
        }

        $findings = Test-ADReplicationSecurity
        $finding = $findings | Where-Object { $_.Issue -eq 'SPN-Holding Account Also Has DCSync Rights' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'Critical'
        $finding.Details.ServicePrincipalNames | Should -Match 'MSSQLSvc'
        # The standalone DCSync finding should still fire independently -
        # this cross-check is additive, not a replacement.
        ($findings | Where-Object { $_.Issue -eq 'Unauthorized DCSync Permissions' }) | Should -Not -BeNullOrEmpty
    }

    It 'does NOT flag an account with DCSync rights but no SPN' {
        function Get-ADObject {
            param($Identity, $Filter, $Properties, $Server, $ErrorAction)
            if ($Identity -eq 'DC=contoso,DC=com') {
                return [PSCustomObject]@{
                    nTSecurityDescriptor = [PSCustomObject]@{
                        Access = @( New-ADSecurityAuditDCSyncAce -IdentitySid $script:TestSpnUserSid )
                    }
                }
            }
            if ($Filter -like "*objectSid*$($script:TestSpnUserSid)*") {
                return [PSCustomObject]@{
                    DistinguishedName = 'CN=svc-backup,OU=Service Accounts,DC=contoso,DC=com'
                    objectClass       = 'user'
                }
            }
            throw "unexpected Get-ADObject call: Identity=$Identity Filter=$Filter"
        }
        function Get-ADUser {
            param($Identity, $Properties, $Server, $ErrorAction)
            [PSCustomObject]@{
                DistinguishedName    = $Identity
                ServicePrincipalName = @()
            }
        }

        $findings = Test-ADReplicationSecurity
        ($findings | Where-Object { $_.Issue -eq 'SPN-Holding Account Also Has DCSync Rights' }) | Should -BeNullOrEmpty
        # Standalone DCSync finding still fires - only the cross-check is absent.
        ($findings | Where-Object { $_.Issue -eq 'Unauthorized DCSync Permissions' }) | Should -Not -BeNullOrEmpty
    }

    It 'does NOT flag when the DCSync-capable identity resolves to a group, not a user (documented limitation)' {
        function Get-ADObject {
            param($Identity, $Filter, $Properties, $Server, $ErrorAction)
            if ($Identity -eq 'DC=contoso,DC=com') {
                return [PSCustomObject]@{
                    nTSecurityDescriptor = [PSCustomObject]@{
                        Access = @( New-ADSecurityAuditDCSyncAce -IdentitySid $script:TestSpnUserSid )
                    }
                }
            }
            if ($Filter -like "*objectSid*$($script:TestSpnUserSid)*") {
                return [PSCustomObject]@{
                    DistinguishedName = 'CN=Backup Operators Proxy,OU=Groups,DC=contoso,DC=com'
                    objectClass       = 'group'
                }
            }
            throw "unexpected Get-ADObject call: Identity=$Identity Filter=$Filter"
        }
        function Get-ADUser {
            param($Identity, $Properties, $Server, $ErrorAction)
            throw "Get-ADUser should not be called for a group identity"
        }

        { Test-ADReplicationSecurity } | Should -Not -Throw
        $findings = Test-ADReplicationSecurity
        ($findings | Where-Object { $_.Issue -eq 'SPN-Holding Account Also Has DCSync Rights' }) | Should -BeNullOrEmpty
    }
}
