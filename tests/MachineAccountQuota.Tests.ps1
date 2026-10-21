#Requires -Modules Pester
<#
    Unit tests for Test-ADMachineAccountQuota (feature 03).

    These tests shadow Get-ADDomain / Get-ADObject with local functions so
    no real AD module or connectivity is required.

    Run from the repo root:  Invoke-Pester ./tests/MachineAccountQuota.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/MachineAccountQuotaAudits.ps1')

    # Test-ADMachineAccountQuota now defaults -Server to $env:USERDNSDOMAIN
    # when -Server isn't passed (see Resolve-ADSecurityAuditTargetServer).
    # Save/clear it here so every test below is deterministic regardless of
    # whether the machine actually running these tests happens to be
    # domain-joined - individual tests that want to exercise the
    # default-to-user-domain behavior set it explicitly themselves.
    $script:originalUserDnsDomain = $env:USERDNSDOMAIN
    $env:USERDNSDOMAIN = $null
}

AfterAll {
    $env:USERDNSDOMAIN = $script:originalUserDnsDomain
}

Describe 'Test-ADMachineAccountQuota' {
    It 'queries AD directly and produces no finding for a hardened quota of 0' {
        function Get-ADDomain { [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com' } }
        function Get-ADObject { param($Identity, $Properties) [PSCustomObject]@{ 'ms-DS-MachineAccountQuota' = 0 } }

        $findings = Test-ADMachineAccountQuota
        $findings.Count | Should -Be 0
    }

    It 'flags the unmodified default quota of 10 as High' {
        function Get-ADDomain { [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com' } }
        function Get-ADObject { param($Identity, $Properties) [PSCustomObject]@{ 'ms-DS-MachineAccountQuota' = 10 } }

        $findings = Test-ADMachineAccountQuota
        $findings.Count | Should -Be 1
        $findings[0].Issue | Should -Be 'Default Machine Account Quota Not Restricted'
        $findings[0].Severity | Should -Be 'High'
        $findings[0].Details.MachineAccountQuota | Should -Be 10
    }

    It 'flags a lowered but non-zero quota as Medium' {
        function Get-ADDomain { [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com' } }
        function Get-ADObject { param($Identity, $Properties) [PSCustomObject]@{ 'ms-DS-MachineAccountQuota' = 3 } }

        $findings = Test-ADMachineAccountQuota
        $findings.Count | Should -Be 1
        $findings[0].Issue | Should -Be 'Non-Zero Machine Account Quota'
        $findings[0].Severity | Should -Be 'Medium'
    }
}

Describe 'Test-ADMachineAccountQuota (-Server override, multi-domain-forest fix)' {
    It 'passes -Server through to both Get-ADDomain and Get-ADObject when supplied' {
        $script:capturedDomainServer = $null
        $script:capturedObjectServer = $null

        function Get-ADDomain {
            param($Server, $ErrorAction)
            $script:capturedDomainServer = $Server
            [PSCustomObject]@{ DistinguishedName = 'DC=domainb,DC=corp,DC=com' }
        }
        function Get-ADObject {
            param($Identity, $Properties, $Server, $ErrorAction)
            $script:capturedObjectServer = $Server
            [PSCustomObject]@{ 'ms-DS-MachineAccountQuota' = 10 }
        }

        $findings = Test-ADMachineAccountQuota -Server 'domainb.corp.com'

        $script:capturedDomainServer | Should -Be 'domainb.corp.com'
        $script:capturedObjectServer | Should -Be 'domainb.corp.com'
        $findings[0].AffectedObject | Should -Be 'DC=domainb,DC=corp,DC=com'
    }

    It 'does not pass a -Server parameter at all when none is supplied and $env:USERDNSDOMAIN is empty (backward compatible)' {
        function Get-ADDomain { [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com' } }
        function Get-ADObject { param($Identity, $Properties) [PSCustomObject]@{ 'ms-DS-MachineAccountQuota' = 0 } }

        # These shadow functions declare no -Server parameter at all; if the
        # code under test always spliced -Server (even $null/empty) onto the
        # splat, this would throw a parameter-binding error.
        { Test-ADMachineAccountQuota } | Should -Not -Throw
    }
}

Describe 'Test-ADMachineAccountQuota (default to current user domain when -Server is omitted)' {
    AfterEach {
        $env:USERDNSDOMAIN = $null
    }

    It 'defaults -Server to $env:USERDNSDOMAIN when -Server is not supplied' {
        $env:USERDNSDOMAIN = 'domaina.corp.com'
        $script:capturedDomainServer = $null
        $script:capturedObjectServer = $null

        function Get-ADDomain {
            param($Server, $ErrorAction)
            $script:capturedDomainServer = $Server
            [PSCustomObject]@{ DistinguishedName = 'DC=domaina,DC=corp,DC=com' }
        }
        function Get-ADObject {
            param($Identity, $Properties, $Server, $ErrorAction)
            $script:capturedObjectServer = $Server
            [PSCustomObject]@{ 'ms-DS-MachineAccountQuota' = 10 }
        }

        $findings = Test-ADMachineAccountQuota

        $script:capturedDomainServer | Should -Be 'domaina.corp.com'
        $script:capturedObjectServer | Should -Be 'domaina.corp.com'
    }

    It 'an explicit -Server still wins over $env:USERDNSDOMAIN' {
        $env:USERDNSDOMAIN = 'domaina.corp.com'
        $script:capturedDomainServer = $null

        function Get-ADDomain {
            param($Server, $ErrorAction)
            $script:capturedDomainServer = $Server
            [PSCustomObject]@{ DistinguishedName = 'DC=domainb,DC=corp,DC=com' }
        }
        function Get-ADObject { param($Identity, $Properties, $Server, $ErrorAction) [PSCustomObject]@{ 'ms-DS-MachineAccountQuota' = 0 } }

        Test-ADMachineAccountQuota -Server 'domainb.corp.com' | Out-Null

        $script:capturedDomainServer | Should -Be 'domainb.corp.com'
    }
}
