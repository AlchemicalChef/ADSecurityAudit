#Requires -Modules Pester
<#
    Unit tests for Test-ADCSChaseFallback (CVE-2026-54121 / "Certighost"
    CA chase-fallback exposure), added as a new sibling function in
    src/CertificateServicesExtendedAudits.ps1.

    Like the existing ESC8 check, this is live-only: it reads a registry
    value (policy\EditFlags) on the CA host itself via Invoke-Command. These
    tests shadow every live cmdlet it touches: Get-ADRootDSE (via
    Get-ADRootDSEValue), Get-ADObject, and Invoke-Command. No real Active
    Directory, CA host, or network access is used - Invoke-Command's
    -ScriptBlock is invoked directly against a fake registry-shaped object
    rather than actually running remotely.

    Run from the repo root:  Invoke-Pester ./tests/ADCSChaseFallback.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/CertificateServicesExtendedAudits.ps1')
}

Describe 'Test-ADCSChaseFallback (CVE-2026-54121 / Certighost)' {
    BeforeEach {
        function Get-ADRootDSE {
            param([switch]$ErrorAction, [string]$Server)
            [PSCustomObject]@{ configurationNamingContext = 'CN=Configuration,DC=contoso,DC=com' }
        }
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Properties, $Server, [switch]$ErrorAction)
            @(
                [PSCustomObject]@{
                    Name              = 'CONTOSO-CA'
                    DistinguishedName = 'CN=CONTOSO-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    dNSHostName       = 'ca01.contoso.com'
                }
            )
        }
    }

    It 'produces no finding when EDITF_ENABLECHASECLIENTDC is not set' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            # EditFlags with only EDITF_ATTRIBUTESUBJECTALTNAME2 (0x40000) set -
            # chase-client-dc bit (0x100000) absent.
            [PSCustomObject]@{ EditFlagsRead = $true; EditFlags = 0x40000; Error = $null }
        }

        $findings = Test-ADCSChaseFallback
        ($findings | Where-Object { $_.Issue -eq 'CA Chase-Fallback Enabled (CVE-2026-54121 / Certighost Exposure)' }) | Should -BeNullOrEmpty
    }

    It 'fires Critical when EDITF_ENABLECHASECLIENTDC is set, naming the CA and citing the CVE' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            # EDITF_ENABLECHASECLIENTDC (0x100000) set, alongside other
            # unrelated flags - matches a realistic EditFlags value.
            [PSCustomObject]@{ EditFlagsRead = $true; EditFlags = 0x15014e -bor 0x100000; Error = $null }
        }

        $findings = Test-ADCSChaseFallback
        $finding = $findings | Where-Object { $_.Issue -eq 'CA Chase-Fallback Enabled (CVE-2026-54121 / Certighost Exposure)' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Category | Should -Be 'Certificate Services'
        $finding.Severity | Should -Be 'Critical'
        $finding.SeverityLevel | Should -Be 4
        $finding.AffectedObject | Should -Match 'CONTOSO-CA'
        $finding.AffectedObject | Should -Match 'ca01.contoso.com'
        $finding.Description | Should -Match 'EDITF_ENABLECHASECLIENTDC'
        $finding.Impact | Should -Match 'CVE-2026-54121'
        $finding.Remediation | Should -Match 'certutil'
        $finding.Remediation | Should -Match 'July 14, 2026'
        $finding.Details.CVE | Should -Be 'CVE-2026-54121'
        $finding.Details.CAHost | Should -Be 'ca01.contoso.com'
    }

    It 'fires Critical for CA-Wide SAN Attribute Flag Enabled (ESC6) when EDITF_ATTRIBUTESUBJECTALTNAME2 is set, independent of the chase-fallback bit' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            # EDITF_ATTRIBUTESUBJECTALTNAME2 (0x40000) set; chase-fallback
            # bit (0x100000) explicitly absent, to confirm the two checks
            # are independent (reusing the same registry read, not
            # conflated into one condition).
            [PSCustomObject]@{ EditFlagsRead = $true; EditFlags = 0x40000; Error = $null }
        }

        $findings = Test-ADCSChaseFallback
        $escFinding = $findings | Where-Object { $_.Issue -eq 'CA-Wide SAN Attribute Flag Enabled (ESC6)' }

        $escFinding | Should -Not -BeNullOrEmpty
        $escFinding.Category | Should -Be 'Certificate Services'
        $escFinding.Severity | Should -Be 'Critical'
        $escFinding.SeverityLevel | Should -Be 4
        $escFinding.Description | Should -Match 'EDITF_ATTRIBUTESUBJECTALTNAME2'
        $escFinding.Details.EditFlagBit | Should -Match 'EDITF_ATTRIBUTESUBJECTALTNAME2'
        ($findings | Where-Object { $_.Issue -eq 'CA Chase-Fallback Enabled (CVE-2026-54121 / Certighost Exposure)' }) | Should -BeNullOrEmpty
    }

    It 'fires both CA-Wide SAN Attribute Flag Enabled (ESC6) and the chase-fallback finding when both bits are set (one registry read, two independent checks)' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            [PSCustomObject]@{ EditFlagsRead = $true; EditFlags = (0x40000 -bor 0x100000); Error = $null }
        }

        $findings = Test-ADCSChaseFallback
        ($findings | Where-Object { $_.Issue -eq 'CA-Wide SAN Attribute Flag Enabled (ESC6)' }) | Should -Not -BeNullOrEmpty
        ($findings | Where-Object { $_.Issue -eq 'CA Chase-Fallback Enabled (CVE-2026-54121 / Certighost Exposure)' }) | Should -Not -BeNullOrEmpty
    }

    It 'produces neither finding when neither EditFlags bit is set' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            [PSCustomObject]@{ EditFlagsRead = $true; EditFlags = 0; Error = $null }
        }

        $findings = Test-ADCSChaseFallback
        $findings | Should -BeNullOrEmpty
    }

    It 'still fires when the flag is set even if the CA host reports no error (patched-but-still-flagged case)' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            [PSCustomObject]@{ EditFlagsRead = $true; EditFlags = 0x100000; Error = $null }
        }

        $findings = Test-ADCSChaseFallback
        $finding = $findings | Where-Object { $_.Issue -eq 'CA Chase-Fallback Enabled (CVE-2026-54121 / Certighost Exposure)' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Impact | Should -Match 'independent of the CA''s patch level'
    }

    It 'skips a CA with no dNSHostName without throwing' {
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Properties, $Server, [switch]$ErrorAction)
            @(
                [PSCustomObject]@{
                    Name              = 'CONTOSO-CA'
                    DistinguishedName = 'CN=CONTOSO-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    dNSHostName       = $null
                }
            )
        }
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            throw "should not be called - CA has no dNSHostName"
        }

        { Test-ADCSChaseFallback } | Should -Not -Throw
        $findings = Test-ADCSChaseFallback
        $findings | Should -BeNullOrEmpty
    }

    It 'produces no finding and does not throw when the registry read fails/errors on the CA host' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            [PSCustomObject]@{ EditFlagsRead = $false; EditFlags = $null; Error = 'CertSvc policy module registry key not found.' }
        }

        { Test-ADCSChaseFallback } | Should -Not -Throw
        $findings = Test-ADCSChaseFallback
        $findings | Should -BeNullOrEmpty
    }

    It 'returns no findings when AD CS is not installed (live path)' {
        function Get-ADRootDSE {
            param([switch]$ErrorAction, [string]$Server)
            throw "AD CS not present"
        }

        { Test-ADCSChaseFallback } | Should -Not -Throw
        $findings = Test-ADCSChaseFallback
        $findings | Should -BeNullOrEmpty
    }

    It 'fires Critical for ESC11 when IF_ENFORCEENCRYPTICERTREQUEST is absent from InterfaceFlags' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            [PSCustomObject]@{ EditFlagsRead = $true; EditFlags = 0; InterfaceFlagsRead = $true; InterfaceFlags = 0; DisableExtensionListRead = $true; DisableExtensionList = @(); Error = $null }
        }

        $findings = Test-ADCSChaseFallback
        $hit = $findings | Where-Object { $_.Issue -eq 'CA RPC Enrollment Encryption Not Enforced (ESC11)' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Severity | Should -Be 'Critical'
        $hit.Details.RequiredBit | Should -Match 'IF_ENFORCEENCRYPTICERTREQUEST'
    }

    It 'does not flag ESC11 when IF_ENFORCEENCRYPTICERTREQUEST (0x200) is set' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            [PSCustomObject]@{ EditFlagsRead = $true; EditFlags = 0; InterfaceFlagsRead = $true; InterfaceFlags = 0x200; DisableExtensionListRead = $true; DisableExtensionList = @(); Error = $null }
        }

        $findings = Test-ADCSChaseFallback
        ($findings | Where-Object { $_.Issue -eq 'CA RPC Enrollment Encryption Not Enforced (ESC11)' }) | Should -BeNullOrEmpty
    }

    It 'does not evaluate ESC11 at all when InterfaceFlags could not be read (avoids a false positive on a read failure)' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            [PSCustomObject]@{ EditFlagsRead = $true; EditFlags = 0; InterfaceFlagsRead = $false; InterfaceFlags = $null; DisableExtensionListRead = $true; DisableExtensionList = @(); Error = $null }
        }

        $findings = Test-ADCSChaseFallback
        ($findings | Where-Object { $_.Issue -eq 'CA RPC Enrollment Encryption Not Enforced (ESC11)' }) | Should -BeNullOrEmpty
    }

    It 'fires Critical for ESC16 when szOID_NTDS_CA_SECURITY_EXT is in DisableExtensionList' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            [PSCustomObject]@{ EditFlagsRead = $true; EditFlags = 0; InterfaceFlagsRead = $true; InterfaceFlags = 0x200; DisableExtensionListRead = $true; DisableExtensionList = @('1.3.6.1.4.1.311.25.2'); Error = $null }
        }

        $findings = Test-ADCSChaseFallback
        $hit = $findings | Where-Object { $_.Issue -eq 'CA-Wide Security Extension Disabled (ESC16)' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Severity | Should -Be 'Critical'
        $hit.Details.DisabledExtension | Should -Match 'szOID_NTDS_CA_SECURITY_EXT'
    }

    It 'does not flag ESC16 when DisableExtensionList does not contain the security extension OID' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            [PSCustomObject]@{ EditFlagsRead = $true; EditFlags = 0; InterfaceFlagsRead = $true; InterfaceFlags = 0x200; DisableExtensionListRead = $true; DisableExtensionList = @('1.2.3.4.5'); Error = $null }
        }

        $findings = Test-ADCSChaseFallback
        ($findings | Where-Object { $_.Issue -eq 'CA-Wide Security Extension Disabled (ESC16)' }) | Should -BeNullOrEmpty
    }

    It 'fires all four independent findings together when every bit/OID is present (one registry connection, four checks)' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            [PSCustomObject]@{
                EditFlagsRead            = $true
                EditFlags                = (0x00100000 -bor 0x00040000)
                InterfaceFlagsRead       = $true
                InterfaceFlags           = 0
                DisableExtensionListRead = $true
                DisableExtensionList     = @('1.3.6.1.4.1.311.25.2')
                Error                    = $null
            }
        }

        $findings = Test-ADCSChaseFallback
        @($findings.Issue) | Should -Contain 'CA Chase-Fallback Enabled (CVE-2026-54121 / Certighost Exposure)'
        @($findings.Issue) | Should -Contain 'CA-Wide SAN Attribute Flag Enabled (ESC6)'
        @($findings.Issue) | Should -Contain 'CA RPC Enrollment Encryption Not Enforced (ESC11)'
        @($findings.Issue) | Should -Contain 'CA-Wide Security Extension Disabled (ESC16)'
    }
}
