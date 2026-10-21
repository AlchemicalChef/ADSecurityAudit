#Requires -Modules Pester
<#
    Unit tests for the two new findings added to Test-ADDangerousPermissions
    in src/PermissionsAudits.ps1:
      - "Non-Standard Permissions on Schema Naming Context"
      - "Non-Standard Permissions on Configuration Naming Context"

    These tests shadow every live
    AD cmdlet the function touches: Get-ADDomain, Get-ADObject, Get-ADGroup,
    and Get-ADRootDSEValue (via Get-ADRootDSE). No real Active Directory
    access is used.

    Run from the repo root:  Invoke-Pester ./tests/PermissionsAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/PermissionsAudits.ps1')
}

function New-FlatAce {
    param(
        [string]$IdentityReference,
        [string]$ActiveDirectoryRights,
        [string]$AccessControlType = 'Allow',
        [bool]$IsInherited = $false,
        [string]$ObjectType = '00000000-0000-0000-0000-000000000000'
    )
    [PSCustomObject]@{
        IdentityReference     = $IdentityReference
        ActiveDirectoryRights = $ActiveDirectoryRights
        AccessControlType     = $AccessControlType
        IsInherited           = $IsInherited
        ObjectType            = $ObjectType
    }
}

Describe 'Test-ADDangerousPermissions (Schema/Configuration NC ACLs)' {
    BeforeEach {
        function Get-ADDomain {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com'; DNSRoot = 'contoso.com' }
        }
        function Get-ADGroup {
            param($Filter, [switch]$ErrorAction, $Server)
            throw "Enterprise Key Admins group not found in the target domain"
        }
        function Get-ADRootDSE {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{
                schemaNamingContext        = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
                configurationNamingContext = 'CN=Configuration,DC=contoso,DC=com'
            }
        }
        # Domain root and critical-OU reads all return an empty ACL by
        # default; the NC-specific test data is layered on top per-test.
        function Get-ADObject {
            param($Identity, $Properties, $Server, [switch]$ErrorAction)
            switch ($Identity) {
                'CN=Schema,CN=Configuration,DC=contoso,DC=com' {
                    [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @() } }
                }
                'CN=Configuration,DC=contoso,DC=com' {
                    [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @() } }
                }
                default {
                    [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @() } }
                }
            }
        }
    }

    It 'produces no NC findings when both head objects have only expected trustees' {
        $findings = Test-ADDangerousPermissions
        ($findings | Where-Object { $_.Issue -match 'Naming Context' }) | Should -BeNullOrEmpty
    }

    It 'fires live for a non-standard ACE on the Schema NC head object' {
        function Get-ADObject {
            param($Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($Identity -eq 'CN=Schema,CN=Configuration,DC=contoso,DC=com') {
                [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @(New-FlatAce -IdentityReference 'CONTOSO\svc-backup' -ActiveDirectoryRights 'GenericAll') } }
            }
            else {
                [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @() } }
            }
        }

        $findings = Test-ADDangerousPermissions
        $finding = $findings | Where-Object { $_.Issue -eq 'Non-Standard Permissions on Schema Naming Context' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.AffectedObject | Should -Match 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
    }

    It 'fires live for a non-standard ACE on the Configuration NC head object' {
        function Get-ADObject {
            param($Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($Identity -eq 'CN=Configuration,DC=contoso,DC=com') {
                [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @(New-FlatAce -IdentityReference 'CONTOSO\helpdesk-admins' -ActiveDirectoryRights 'WriteDacl') } }
            }
            else {
                [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @() } }
            }
        }

        $findings = Test-ADDangerousPermissions
        $finding = $findings | Where-Object { $_.Issue -eq 'Non-Standard Permissions on Configuration Naming Context' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.AffectedObject | Should -Match 'CN=Configuration,DC=contoso,DC=com'
    }

    It 'does not throw and produces no NC findings when schema/configuration naming context cannot be resolved' {
        function Get-ADRootDSE {
            param([switch]$ErrorAction, $Server)
            throw "RootDSE unavailable"
        }

        { Test-ADDangerousPermissions } | Should -Not -Throw
        $findings = Test-ADDangerousPermissions
        ($findings | Where-Object { $_.Issue -match 'Naming Context' }) | Should -BeNullOrEmpty
    }
}
