#Requires -Modules Pester
<#
    Unit tests for the two new forest-level findings added to
    Test-ADDomainSecurity in src/DomainSecurityAudits.ps1:
      - "Outdated Forest Functional Level"
      - "Short Tombstone Lifetime"

    These tests shadow every live AD cmdlet the function touches:
    Get-ADDomain, Get-ADDefaultDomainPasswordPolicy, Get-ADForest,
    Get-ADRootDSE, Get-ADObject, Get-ADOptionalFeature, Get-ADComputer. No
    real Active Directory access is used.

    Run from the repo root:  Invoke-Pester ./tests/DomainSecurityAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/DomainSecurityAudits.ps1')
}

Describe 'Test-ADDomainSecurity (Outdated Forest Functional Level / Short Tombstone Lifetime)' {
    BeforeEach {
        function Get-ADDomain {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com'; DNSRoot = 'contoso.com'; DomainMode = 'Windows2016Domain'; NetBIOSName = 'CONTOSO'; DomainSID = 'S-1-5-21-1-2-3'; Forest = 'contoso.com' }
        }
        function Get-ADDefaultDomainPasswordPolicy {
            param($Server)
            [PSCustomObject]@{ MinPasswordLength = 14; ComplexityEnabled = $true; ReversibleEncryptionEnabled = $false; LockoutThreshold = 5 }
        }
        function Get-ADForest {
            param($Server)
            [PSCustomObject]@{ ForestMode = 'Windows2016Forest' }
        }
        function Get-ADRootDSE {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{ configurationNamingContext = 'CN=Configuration,DC=contoso,DC=com' }
        }
        function Get-ADObject {
            param($Identity, $Properties, $Server, [switch]$ErrorAction)
            [PSCustomObject]@{ tombstoneLifetime = 180 }
        }
        function Get-ADOptionalFeature {
            param($Filter, $Server)
            [PSCustomObject]@{ EnabledScopes = @('CN=Configuration,DC=contoso,DC=com') }
        }
        function Get-ADComputer {
            param($Filter, $Properties, $LDAPFilter, $Server)
            @()
        }
    }

    It 'fires Outdated Forest Functional Level live when the forest mode is deprecated' {
        function Get-ADForest { param($Server) [PSCustomObject]@{ ForestMode = 'Windows2012R2Forest' } }

        $findings = Test-ADDomainSecurity
        $finding = $findings | Where-Object { $_.Issue -eq 'Outdated Forest Functional Level' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Details.CurrentLevel | Should -Be 'Windows2012R2Forest'
    }

    It 'fires Short Tombstone Lifetime live when the Directory Service object has no explicit value (60-day default)' {
        function Get-ADObject {
            param($Identity, $Properties, $Server, [switch]$ErrorAction)
            [PSCustomObject]@{ tombstoneLifetime = $null }
        }

        $findings = Test-ADDomainSecurity
        $finding = $findings | Where-Object { $_.Issue -eq 'Short Tombstone Lifetime' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Details.CurrentValueDays | Should -Be 60
    }

    It 'does not throw and produces no tombstone finding if the Directory Service object read fails' {
        function Get-ADObject {
            param($Identity, $Properties, $Server, [switch]$ErrorAction)
            throw "access denied"
        }

        { Test-ADDomainSecurity } | Should -Not -Throw
        $findings = Test-ADDomainSecurity
        ($findings | Where-Object { $_.Issue -eq 'Short Tombstone Lifetime' }) | Should -BeNullOrEmpty
    }
}

Describe 'Test-ADDomainSecurity (Account Lockout Policy)' {
    BeforeEach {
        function Get-ADDomain {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com'; DNSRoot = 'contoso.com'; DomainMode = 'Windows2016Domain'; NetBIOSName = 'CONTOSO'; DomainSID = 'S-1-5-21-1-2-3'; Forest = 'contoso.com' }
        }
        function Get-ADForest {
            param($Server)
            [PSCustomObject]@{ ForestMode = 'Windows2016Forest' }
        }
        function Get-ADRootDSE {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{ configurationNamingContext = 'CN=Configuration,DC=contoso,DC=com' }
        }
        function Get-ADObject {
            param($Identity, $Properties, $Server, [switch]$ErrorAction)
            [PSCustomObject]@{ tombstoneLifetime = 180 }
        }
        function Get-ADOptionalFeature {
            param($Filter, $Server)
            [PSCustomObject]@{ EnabledScopes = @('CN=Configuration,DC=contoso,DC=com') }
        }
        function Get-ADComputer {
            param($Filter, $Properties, $LDAPFilter, $Server)
            @()
        }
    }

    It 'flags Account Lockout Disabled (Critical) when LockoutThreshold is 0' {
        function Get-ADDefaultDomainPasswordPolicy {
            param($Server)
            [PSCustomObject]@{ MinPasswordLength = 14; ComplexityEnabled = $true; ReversibleEncryptionEnabled = $false; LockoutThreshold = 0 }
        }

        $findings = Test-ADDomainSecurity
        $finding = $findings | Where-Object { $_.Issue -eq 'Account Lockout Disabled' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'Critical'
        $finding.Details.LockoutThreshold | Should -Be 0
        # Mutually exclusive with the "above maximum" finding.
        ($findings | Where-Object { $_.Issue -eq 'Account Lockout Threshold Above Recommended Maximum' }) | Should -BeNullOrEmpty
    }

    It 'flags Account Lockout Threshold Above Recommended Maximum (Medium) when the threshold exceeds 5' {
        function Get-ADDefaultDomainPasswordPolicy {
            param($Server)
            [PSCustomObject]@{ MinPasswordLength = 14; ComplexityEnabled = $true; ReversibleEncryptionEnabled = $false; LockoutThreshold = 10 }
        }

        $findings = Test-ADDomainSecurity
        $finding = $findings | Where-Object { $_.Issue -eq 'Account Lockout Threshold Above Recommended Maximum' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'Medium'
        $finding.Details.LockoutThreshold | Should -Be 10
        ($findings | Where-Object { $_.Issue -eq 'Account Lockout Disabled' }) | Should -BeNullOrEmpty
    }

    It 'does not flag either lockout finding when the threshold is within the recommended range (1-5)' {
        function Get-ADDefaultDomainPasswordPolicy {
            param($Server)
            [PSCustomObject]@{ MinPasswordLength = 14; ComplexityEnabled = $true; ReversibleEncryptionEnabled = $false; LockoutThreshold = 5 }
        }

        $findings = Test-ADDomainSecurity
        ($findings | Where-Object { $_.Issue -eq 'Account Lockout Disabled' }) | Should -BeNullOrEmpty
        ($findings | Where-Object { $_.Issue -eq 'Account Lockout Threshold Above Recommended Maximum' }) | Should -BeNullOrEmpty
    }
}
