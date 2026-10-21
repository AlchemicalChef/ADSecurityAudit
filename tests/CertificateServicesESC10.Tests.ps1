#Requires -Modules Pester
<#
    Unit tests for Test-ADCSWeakCertificateBinding (ESC10,
    CertificateServicesExtendedAudits.ps1) - checks CertificateBackdatingCompensation
    on Domain Controllers, the registry lever that still genuinely re-opens
    weak certificate-mapping authentication even on a fully patched DC
    (StrongCertificateBindingEnforcement itself became permanently
    unconditional as of the September 9, 2025 security update, so it is
    deliberately NOT what this check reads).

    Live-mode tests shadow Get-ADDomain, Get-ADDomainController (via the
    real Get-ADSecurityAuditDomainController), and Invoke-Command. No real
    Active Directory or remote registry access is used.

    Run from the repo root:  Invoke-Pester ./tests/CertificateServicesESC10.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/CertificateServicesExtendedAudits.ps1')

    function Get-ADDomain {
        param([switch]$ErrorAction, $Server)
        [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' }
    }
}

Describe 'Test-ADCSWeakCertificateBinding' {
    BeforeEach {
        function Get-ADDomainController {
            param($Filter, $Server, $Identity, $ErrorAction)
            @([PSCustomObject]@{ Name = 'DC01'; HostName = 'DC01.contoso.com'; Domain = 'contoso.com' })
        }
    }

    It 'flags a DC with a non-zero CertificateBackdatingCompensation' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            50
        }

        $findings = Test-ADCSWeakCertificateBinding
        $hit = $findings | Where-Object { $_.Issue -eq 'Weak Certificate Binding Compensation Enabled (ESC10)' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Severity | Should -Be 'High'
        $hit.Details.AffectedDomainControllers[0].Days | Should -Be 50
    }

    It 'does not flag a DC with no CertificateBackdatingCompensation value set' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            $null
        }

        $findings = Test-ADCSWeakCertificateBinding
        $findings | Should -BeNullOrEmpty
    }

    It 'does not flag a DC with CertificateBackdatingCompensation explicitly 0' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            0
        }

        $findings = Test-ADCSWeakCertificateBinding
        $findings | Should -BeNullOrEmpty
    }

    It 'does not throw and skips an unreachable DC without flagging it' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            throw 'WinRM cannot complete the operation'
        }

        { Test-ADCSWeakCertificateBinding } | Should -Not -Throw
        Test-ADCSWeakCertificateBinding | Should -BeNullOrEmpty
    }

    It 'returns cleanly when there are no Domain Controllers to evaluate' {
        function Get-ADDomainController { param($Filter, $Server, $Identity, $ErrorAction) @() }

        { Test-ADCSWeakCertificateBinding } | Should -Not -Throw
        Test-ADCSWeakCertificateBinding | Should -BeNullOrEmpty
    }
}
