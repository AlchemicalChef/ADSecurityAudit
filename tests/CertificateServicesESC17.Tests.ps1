#Requires -Modules Pester
<#
    Unit tests for the ESC17 addition to Test-ADCertificateServices
    (CertificateServicesAudits.ps1): a certificate template with Server
    Authentication EKU + enrollee-supplied SAN + low-privileged enrollment
    + no manager approval, disclosed by the Digitrace team (Alexander Neff
    & Phil Knüfer) in early 2026.

    Live-mode tests shadow Get-ADRootDSE (via Get-ADRootDSEValue) and
    Get-ADObject (template enumeration, CA enumeration, and per-object ACL
    reads, branched by -SearchBase/-Identity). No real Active Directory
    access is used.

    Run from the repo root:  Invoke-Pester ./tests/CertificateServicesESC17.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/CertificateServicesAudits.ps1')

    function Get-ADRootDSE {
        param([switch]$ErrorAction, [string]$Server)
        [PSCustomObject]@{ configurationNamingContext = 'CN=Configuration,DC=contoso,DC=com' }
    }

    function New-TestTemplateAce {
        param([string]$Principal, [string]$Rights = 'ExtendedRight')
        [PSCustomObject]@{
            IdentityReference     = [PSCustomObject]@{ Value = $Principal }
            ActiveDirectoryRights = $Rights
            ObjectType            = '00000000-0000-0000-0000-000000000000'
            IsInherited           = $false
        }
    }
}

Describe 'Test-ADCertificateServices - ESC17' {
    BeforeEach {
        # No CAs by default - keeps ESC7/ESC-CA-permission checks quiet
        # and isolates these tests to the template-level ESC17 check.
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($Identity) { return $null }
            if ($SearchBase -match 'Enrollment Services') { return @() }
            return @()
        }
    }

    It 'flags a template with Server Auth EKU, enrollee-supplied SAN, low-priv enrollment, and no manager approval' {
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($Identity -eq 'CN=WebServerTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com') {
                return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @(New-TestTemplateAce -Principal 'CONTOSO\Domain Users') } }
            }
            if ($SearchBase -match 'Certificate Templates') {
                return @([PSCustomObject]@{
                    Name                                       = 'WebServerTemplate'
                    DistinguishedName                          = 'CN=WebServerTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    'msPKI-Enrollment-Flag'                     = 0  # no manager approval bit (0x2) set
                    'msPKI-Certificate-Name-Flag'               = 1  # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                    'msPKI-Certificate-Application-Policy'      = @('1.3.6.1.5.5.7.3.1')  # Server Authentication
                    'pKIExtendedKeyUsage'                       = @('1.3.6.1.5.5.7.3.1')
                    'msPKI-RA-Signature'                        = 0
                })
            }
            return @()
        }

        $findings = Test-ADCertificateServices
        $hit = $findings | Where-Object { $_.Issue -eq 'Certificate Template Allows Arbitrary Server Certificate (ESC17)' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Severity | Should -Be 'Critical'
        $hit.Details.ESCType | Should -Be 'ESC17'
    }

    It 'does not flag ESC17 when manager approval is required' {
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($Identity -eq 'CN=WebServerTemplate2,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com') {
                return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @(New-TestTemplateAce -Principal 'CONTOSO\Domain Users') } }
            }
            if ($SearchBase -match 'Certificate Templates') {
                return @([PSCustomObject]@{
                    Name                                       = 'WebServerTemplate2'
                    DistinguishedName                          = 'CN=WebServerTemplate2,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    'msPKI-Enrollment-Flag'                     = 0x2  # CT_FLAG_PEND_ALL_REQUESTS set - manager approval required
                    'msPKI-Certificate-Name-Flag'               = 1
                    'msPKI-Certificate-Application-Policy'      = @('1.3.6.1.5.5.7.3.1')
                    'pKIExtendedKeyUsage'                       = @('1.3.6.1.5.5.7.3.1')
                    'msPKI-RA-Signature'                        = 0
                })
            }
            return @()
        }

        $findings = Test-ADCertificateServices
        ($findings | Where-Object { $_.Issue -eq 'Certificate Template Allows Arbitrary Server Certificate (ESC17)' }) | Should -BeNullOrEmpty
    }

    It 'does not flag ESC17 when the EKU is Client (not Server) Authentication - that is ESC1''s territory instead' {
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($Identity -eq 'CN=UserTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com') {
                return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @(New-TestTemplateAce -Principal 'CONTOSO\Domain Users') } }
            }
            if ($SearchBase -match 'Certificate Templates') {
                return @([PSCustomObject]@{
                    Name                                       = 'UserTemplate'
                    DistinguishedName                          = 'CN=UserTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    'msPKI-Enrollment-Flag'                     = 0
                    'msPKI-Certificate-Name-Flag'               = 1
                    'msPKI-Certificate-Application-Policy'      = @('1.3.6.1.5.5.7.3.2')  # Client Authentication only
                    'pKIExtendedKeyUsage'                       = @('1.3.6.1.5.5.7.3.2')
                    'msPKI-RA-Signature'                        = 0
                })
            }
            return @()
        }

        $findings = Test-ADCertificateServices
        ($findings | Where-Object { $_.Issue -eq 'Certificate Template Allows Arbitrary Server Certificate (ESC17)' }) | Should -BeNullOrEmpty
        # This shape IS expected to fire ESC1 instead - confirms the two checks stay distinct.
        ($findings | Where-Object { $_.Issue -eq 'Certificate Template Allows Subject Alternative Name (ESC1)' }) | Should -Not -BeNullOrEmpty
    }

    It 'does not flag ESC17 when enrollment is restricted to trusted administrators only' {
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($Identity -eq 'CN=RestrictedTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com') {
                return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @(New-TestTemplateAce -Principal 'CONTOSO\PKI Admins') } }
            }
            if ($SearchBase -match 'Certificate Templates') {
                return @([PSCustomObject]@{
                    Name                                       = 'RestrictedTemplate'
                    DistinguishedName                          = 'CN=RestrictedTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    'msPKI-Enrollment-Flag'                     = 0
                    'msPKI-Certificate-Name-Flag'               = 1
                    'msPKI-Certificate-Application-Policy'      = @('1.3.6.1.5.5.7.3.1')
                    'pKIExtendedKeyUsage'                       = @('1.3.6.1.5.5.7.3.1')
                    'msPKI-RA-Signature'                        = 0
                })
            }
            return @()
        }

        $findings = Test-ADCertificateServices
        ($findings | Where-Object { $_.Issue -eq 'Certificate Template Allows Arbitrary Server Certificate (ESC17)' }) | Should -BeNullOrEmpty
    }
}
