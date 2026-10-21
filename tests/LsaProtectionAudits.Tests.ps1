#Requires -Modules Pester
<#
    Unit tests for Test-ADLsaProtection (LsaProtectionAudits.ps1) - the
    LSA Protection (RunAsPPL) check, named in ASD/CISA/NSA/CCCS/NCSC-NZ/
    NCSC-UK's "Detecting and mitigating Active Directory compromises"
    (Sept 2026) as the primary Skeleton Key mitigation.

    Live-mode tests shadow Get-ADDomain and Get-ADDomainController (via the
    real Get-ADSecurityAuditDomainController) and Invoke-Command (used
    both for the RunAsPPL registry read and the separate reachability
    probe). No real Active Directory or remote registry access is used.

    Run from the repo root:  Invoke-Pester ./tests/LsaProtectionAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/LsaProtectionAudits.ps1')

    function Get-ADDomain {
        param([switch]$ErrorAction, $Server)
        [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' }
    }
}

Describe 'Test-ADLsaProtection' {
    BeforeEach {
        function Get-ADDomainController {
            param($Filter, $Server, $Identity, $ErrorAction)
            @(
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'DC01.contoso.com'; Domain = 'contoso.com' }
                [PSCustomObject]@{ Name = 'DC02'; HostName = 'DC02.contoso.com'; Domain = 'contoso.com' }
            )
        }
    }

    It 'flags a DC where RunAsPPL is absent (registry value not set)' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            # Both the RunAsPPL read and the reachability probe go through
            # this same mock; the reachability probe's script block takes
            # no meaningful action and just needs a truthy return, which
            # $null (RunAsPPL absent) is NOT - so branch on whether the
            # script block references RunAsPPL to tell the two probes
            # apart.
            if ($ScriptBlock.ToString() -match 'RunAsPPL') {
                return $null
            }
            return $true
        }

        $findings = Test-ADLsaProtection
        $hit = $findings | Where-Object { $_.Issue -eq 'LSA Protection (RunAsPPL) Not Enabled on Domain Controller' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Severity | Should -Be 'High'
        $hit.Details.AffectedDomainControllers | Should -Contain 'DC01.contoso.com'
        $hit.Details.AffectedDomainControllers | Should -Contain 'DC02.contoso.com'
    }

    It 'flags a DC where RunAsPPL is explicitly 0' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            if ($ScriptBlock.ToString() -match 'RunAsPPL') { return 0 }
            return $true
        }

        $findings = Test-ADLsaProtection
        ($findings | Where-Object { $_.Issue -eq 'LSA Protection (RunAsPPL) Not Enabled on Domain Controller' }) | Should -Not -BeNullOrEmpty
    }

    It 'does not flag a DC where RunAsPPL is 1' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            if ($ScriptBlock.ToString() -match 'RunAsPPL') { return 1 }
            return $true
        }

        $findings = Test-ADLsaProtection
        ($findings | Where-Object { $_.Issue -eq 'LSA Protection (RunAsPPL) Not Enabled on Domain Controller' }) | Should -BeNullOrEmpty
    }

    It 'does not flag a DC where RunAsPPL is 2' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            if ($ScriptBlock.ToString() -match 'RunAsPPL') { return 2 }
            return $true
        }

        $findings = Test-ADLsaProtection
        ($findings | Where-Object { $_.Issue -eq 'LSA Protection (RunAsPPL) Not Enabled on Domain Controller' }) | Should -BeNullOrEmpty
    }

    It 'only lists the non-compliant DC when one of two DCs has RunAsPPL enabled and the other does not' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            if ($ScriptBlock.ToString() -match 'RunAsPPL') {
                if ($ComputerName -eq 'DC01.contoso.com') { return 1 }
                return $null
            }
            return $true
        }

        $findings = Test-ADLsaProtection
        $hit = $findings | Where-Object { $_.Issue -eq 'LSA Protection (RunAsPPL) Not Enabled on Domain Controller' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Details.AffectedDomainControllers | Should -Not -Contain 'DC01.contoso.com'
        $hit.Details.AffectedDomainControllers | Should -Contain 'DC02.contoso.com'
    }

    It 'does not throw and skips an unreachable DC without flagging it' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            throw 'WinRM cannot complete the operation'
        }

        { Test-ADLsaProtection } | Should -Not -Throw
        $findings = Test-ADLsaProtection
        $findings | Should -BeNullOrEmpty
    }

    It 'returns cleanly when there are no Domain Controllers to evaluate' {
        function Get-ADDomainController { param($Filter, $Server, $Identity, $ErrorAction) @() }

        { Test-ADLsaProtection } | Should -Not -Throw
        Test-ADLsaProtection | Should -BeNullOrEmpty
    }
}
