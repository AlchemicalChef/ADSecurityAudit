#Requires -Modules Pester
<#
    Unit tests for two additions to Test-ADUserSecurity (UserAudits.ps1):

      1. 'Privileged Account Not Configured as Sensitive and Cannot Be
         Delegated' - flags a highly-privileged account (Domain Admins/
         Enterprise Admins/Schema Admins) whose userAccountControl does
         not have the NOT_DELEGATED bit (0x100000) set.
      2. 'Built-in Administrator Account Enabled and Not Recently
         Rotated' - flags the well-known RID-500 account, identified by
         SID rather than name, when it is enabled and its password is
         stale (or was never set).

    Live-mode tests shadow Get-ADUser (both the main sweep's -Filter call
    and the RID-500 lookup's -Identity call), Get-ADGroup (Protected
    Users), and Get-ADDomain (for the RID-500 SID). No real Active
    Directory access is used.

    Run from the repo root:  Invoke-Pester ./tests/UserAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/UserAudits.ps1')

    function New-TestUser {
        param(
            [string]$SamAccountName,
            [string]$DistinguishedName,
            [string[]]$MemberOf = @(),
            [int]$UserAccountControl = 512,
            [datetime]$PasswordLastSet = (Get-Date).AddDays(-30),
            [bool]$Enabled = $true
        )
        [PSCustomObject]@{
            SamAccountName                     = $SamAccountName
            DistinguishedName                  = $DistinguishedName
            MemberOf                           = $MemberOf
            userAccountControl                 = $UserAccountControl
            DoesNotRequirePreAuth              = $false
            UseDESKeyOnly                      = $false
            AllowReversiblePasswordEncryption   = $false
            PasswordNeverExpires               = $false
            TrustedForDelegation               = $false
            LastLogonDate                      = (Get-Date).AddDays(-1)
            PasswordLastSet                    = $PasswordLastSet
            ServicePrincipalNames              = @()
            Enabled                            = $Enabled
            UserPrincipalName                  = "$SamAccountName@contoso.com"
            adminCount                         = $null
            SID                                = [PSCustomObject]@{ Value = "S-1-5-21-1111-2222-3333-$($SamAccountName.Length)00" }
            Description                        = $null
            'msDS-SupportedEncryptionTypes'    = $null
        }
    }

    # Default: no Protected Users group found (harmless for the
    # NOT_DELEGATED tests, which don't depend on it), and no built-in
    # Administrator match (the -Identity lookup returns $null) unless a
    # test overrides it.
    function Get-ADGroup { param($Filter, $Server, [switch]$ErrorAction) $null }
    function Get-ADDomain {
        param([switch]$ErrorAction, $Server)
        [PSCustomObject]@{ DomainSID = [PSCustomObject]@{ Value = 'S-1-5-21-1111-2222-3333' } }
    }
}

Describe 'Test-ADUserSecurity - Privileged Account Not Configured as Sensitive and Cannot Be Delegated' {
    BeforeEach {
        function Get-ADUser {
            param($Filter, $Identity, $Properties, $Server, $SearchBase, $ResultPageSize, [switch]$ErrorAction)
            if ($Identity) { return $null }  # no built-in Administrator match by default
            return @()
        }
    }

    It 'flags a Domain Admins member whose userAccountControl lacks the NOT_DELEGATED bit' {
        function Get-ADUser {
            param($Filter, $Identity, $Properties, $Server, $SearchBase, $ResultPageSize, [switch]$ErrorAction)
            if ($Identity) { return $null }
            return @(New-TestUser -SamAccountName 'jdoe' -DistinguishedName 'CN=jdoe,CN=Users,DC=contoso,DC=com' -MemberOf @('CN=Domain Admins,CN=Users,DC=contoso,DC=com') -UserAccountControl 512)
        }

        $findings = Test-ADUserSecurity
        $hit = $findings | Where-Object { $_.Issue -eq 'Privileged Account Not Configured as Sensitive and Cannot Be Delegated' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.AffectedObject | Should -Be 'jdoe'
        $hit.Severity | Should -Be 'High'
    }

    It 'does not flag a Domain Admins member that already has the NOT_DELEGATED bit set' {
        function Get-ADUser {
            param($Filter, $Identity, $Properties, $Server, $SearchBase, $ResultPageSize, [switch]$ErrorAction)
            if ($Identity) { return $null }
            # 512 (NORMAL_ACCOUNT) + 0x100000 (NOT_DELEGATED) = 1048832
            return @(New-TestUser -SamAccountName 'asmith' -DistinguishedName 'CN=asmith,CN=Users,DC=contoso,DC=com' -MemberOf @('CN=Domain Admins,CN=Users,DC=contoso,DC=com') -UserAccountControl 1048832)
        }

        $findings = Test-ADUserSecurity
        ($findings | Where-Object { $_.Issue -eq 'Privileged Account Not Configured as Sensitive and Cannot Be Delegated' }) | Should -BeNullOrEmpty
    }

    It 'does not flag a non-privileged account regardless of the NOT_DELEGATED bit' {
        function Get-ADUser {
            param($Filter, $Identity, $Properties, $Server, $SearchBase, $ResultPageSize, [switch]$ErrorAction)
            if ($Identity) { return $null }
            return @(New-TestUser -SamAccountName 'helpdeskuser' -DistinguishedName 'CN=helpdeskuser,CN=Users,DC=contoso,DC=com' -MemberOf @('CN=Helpdesk Staff,CN=Users,DC=contoso,DC=com') -UserAccountControl 512)
        }

        $findings = Test-ADUserSecurity
        ($findings | Where-Object { $_.Issue -eq 'Privileged Account Not Configured as Sensitive and Cannot Be Delegated' }) | Should -BeNullOrEmpty
    }
}

Describe 'Test-ADUserSecurity - Built-in Administrator Account (RID 500)' {
    BeforeEach {
        function Get-ADUser {
            param($Filter, $Identity, $Properties, $Server, $SearchBase, $ResultPageSize, [switch]$ErrorAction)
            if ($Identity) { return $null }
            return @()
        }
    }

    It 'flags the built-in Administrator account when enabled with a stale password' {
        function Get-ADUser {
            param($Filter, $Identity, $Properties, $Server, $SearchBase, $ResultPageSize, [switch]$ErrorAction)
            if ($Identity -eq 'S-1-5-21-1111-2222-3333-500') {
                return [PSCustomObject]@{
                    SamAccountName    = 'Administrator'
                    DistinguishedName = 'CN=Administrator,CN=Users,DC=contoso,DC=com'
                    Enabled           = $true
                    PasswordLastSet   = (Get-Date).AddDays(-400)
                }
            }
            return @()
        }

        $findings = Test-ADUserSecurity
        $hit = $findings | Where-Object { $_.Issue -eq 'Built-in Administrator Account Enabled and Not Recently Rotated' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Severity | Should -Be 'High'
        $hit.Details.SID | Should -Be 'S-1-5-21-1111-2222-3333-500'
    }

    It 'does not flag the built-in Administrator account when it is disabled' {
        function Get-ADUser {
            param($Filter, $Identity, $Properties, $Server, $SearchBase, $ResultPageSize, [switch]$ErrorAction)
            if ($Identity -eq 'S-1-5-21-1111-2222-3333-500') {
                return [PSCustomObject]@{
                    SamAccountName    = 'Administrator'
                    DistinguishedName = 'CN=Administrator,CN=Users,DC=contoso,DC=com'
                    Enabled           = $false
                    PasswordLastSet   = (Get-Date).AddDays(-400)
                }
            }
            return @()
        }

        $findings = Test-ADUserSecurity
        ($findings | Where-Object { $_.Issue -eq 'Built-in Administrator Account Enabled and Not Recently Rotated' }) | Should -BeNullOrEmpty
    }

    It 'does not flag the built-in Administrator account when enabled with a recently-rotated password' {
        function Get-ADUser {
            param($Filter, $Identity, $Properties, $Server, $SearchBase, $ResultPageSize, [switch]$ErrorAction)
            if ($Identity -eq 'S-1-5-21-1111-2222-3333-500') {
                return [PSCustomObject]@{
                    SamAccountName    = 'Administrator'
                    DistinguishedName = 'CN=Administrator,CN=Users,DC=contoso,DC=com'
                    Enabled           = $true
                    PasswordLastSet   = (Get-Date).AddDays(-10)
                }
            }
            return @()
        }

        $findings = Test-ADUserSecurity
        ($findings | Where-Object { $_.Issue -eq 'Built-in Administrator Account Enabled and Not Recently Rotated' }) | Should -BeNullOrEmpty
    }

    It 'flags the built-in Administrator account (renamed) whose password was apparently never set' {
        function Get-ADUser {
            param($Filter, $Identity, $Properties, $Server, $SearchBase, $ResultPageSize, [switch]$ErrorAction)
            if ($Identity -eq 'S-1-5-21-1111-2222-3333-500') {
                return [PSCustomObject]@{
                    SamAccountName    = 'svc-legacy-admin'
                    DistinguishedName = 'CN=svc-legacy-admin,CN=Users,DC=contoso,DC=com'
                    Enabled           = $true
                    PasswordLastSet   = $null
                }
            }
            return @()
        }

        $findings = Test-ADUserSecurity
        $hit = $findings | Where-Object { $_.Issue -eq 'Built-in Administrator Account Enabled and Not Recently Rotated' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.AffectedObject | Should -Be 'svc-legacy-admin'
        $hit.Details.PasswordAgeDays | Should -Be 'Unknown'
    }

    It 'does not throw when the built-in Administrator lookup fails' {
        function Get-ADUser {
            param($Filter, $Identity, $Properties, $Server, $SearchBase, $ResultPageSize, [switch]$ErrorAction)
            if ($Identity) { throw 'ADIdentityNotFoundException' }
            return @()
        }

        { Test-ADUserSecurity } | Should -Not -Throw
    }
}
