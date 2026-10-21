#Requires -Modules Pester
<#
    Unit tests for three additions to Test-ADCSExtended
    (CertificateServicesExtendedAudits.ps1):
      - ESC5: weak ACLs on non-template PKI container objects.
      - ESC9: CT_FLAG_NO_SECURITY_EXTENSION combined with low-priv
        enrollment.
      - ESC13: a template's Issuance Policy OID linked (msDS-OIDToGroupLink)
        to a privileged group, combined with a client-auth-capable EKU and
        low-priv enrollment.

    Live-mode tests shadow Get-ADRootDSE (via Get-ADRootDSEValue) and
    Get-ADObject, branched by -SearchBase/-Identity/-Filter. Enrollment
    Services (CAs) returns empty by default so the unrelated ESC8/ROCA/
    weak-signature sections of this large function safely no-op. No real
    Active Directory access is used.

    Run from the repo root:  Invoke-Pester ./tests/CertificateServicesESC5-9-13.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/CertificateServicesExtendedAudits.ps1')

    function Get-ADRootDSE {
        param([switch]$ErrorAction, [string]$Server)
        [PSCustomObject]@{ configurationNamingContext = 'CN=Configuration,DC=contoso,DC=com' }
    }

    function New-TestAce {
        param([string]$Principal, [string]$Rights = 'GenericAll')
        [PSCustomObject]@{
            IdentityReference     = [PSCustomObject]@{ Value = $Principal }
            ActiveDirectoryRights = $Rights
            ObjectType            = '00000000-0000-0000-0000-000000000000'
            IsInherited           = $false
        }
    }

    $script:PkiBase = 'CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
}

Describe 'Test-ADCSExtended - ESC5 (PKI container ACLs)' {
    BeforeEach {
        # No templates, no OID objects, no CAs by default - isolates
        # these tests to the ESC5 container-ACL check.
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($SearchBase -match 'Certificate Templates') { return @() }
            if ($SearchBase -match 'Enrollment Services') { return @() }
            if ($SearchBase -match 'CN=OID,') { return @() }
            if ($Identity -eq "CN=Enrollment Services,$script:PkiBase") {
                return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @(New-TestAce -Principal 'CONTOSO\Domain Users' -Rights 'GenericWrite') } }
            }
            if ($Identity) { return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @() } } }
            return @()
        }
    }

    It 'flags the Enrollment Services container when Domain Users holds GenericWrite' {
        $findings = Test-ADCSExtended
        $hit = $findings | Where-Object { $_.Issue -eq 'Weak ACL on PKI Container Object (ESC5)' -and $_.AffectedObject -eq 'Enrollment Services' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Severity | Should -Be 'Critical'
        $hit.Details.DangerousAces | Should -Match 'Domain Users'
    }

    It 'does not flag a PKI container whose only ACEs belong to trusted administrative principals' {
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($SearchBase -match 'Certificate Templates') { return @() }
            if ($SearchBase -match 'Enrollment Services') { return @() }
            if ($SearchBase -match 'CN=OID,') { return @() }
            if ($Identity) { return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @(New-TestAce -Principal 'CONTOSO\Domain Admins' -Rights 'GenericAll') } } }
            return @()
        }

        $findings = Test-ADCSExtended
        ($findings | Where-Object { $_.Issue -eq 'Weak ACL on PKI Container Object (ESC5)' }) | Should -BeNullOrEmpty
    }
}

Describe 'Test-ADCSExtended - ESC9 (missing security extension)' {
    BeforeEach {
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($SearchBase -match 'Enrollment Services') { return @() }
            if ($SearchBase -match 'CN=OID,') { return @() }
            if ($Identity) { return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @() } } }
            return @()
        }
    }

    It 'flags a template with CT_FLAG_NO_SECURITY_EXTENSION and low-privileged enrollment' {
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($Identity -eq 'CN=NoSecExtTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com') {
                return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @(New-TestAce -Principal 'CONTOSO\Authenticated Users' -Rights 'ExtendedRight') } }
            }
            if ($SearchBase -match 'Certificate Templates') {
                return @([PSCustomObject]@{
                    Name                     = 'NoSecExtTemplate'
                    DistinguishedName        = 'CN=NoSecExtTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    'msPKI-Enrollment-Flag'  = 0x80000
                })
            }
            if ($SearchBase -match 'Enrollment Services') { return @() }
            if ($SearchBase -match 'CN=OID,') { return @() }
            return @()
        }

        $findings = Test-ADCSExtended
        $hit = $findings | Where-Object { $_.Issue -eq 'Certificate Template Missing Security Extension (ESC9)' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Severity | Should -Be 'High'
    }

    It 'does not flag ESC9 when the template restricts enrollment to trusted administrators' {
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($Identity -eq 'CN=RestrictedNoSecExt,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com') {
                return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @(New-TestAce -Principal 'CONTOSO\PKI Admins' -Rights 'ExtendedRight') } }
            }
            if ($SearchBase -match 'Certificate Templates') {
                return @([PSCustomObject]@{
                    Name                     = 'RestrictedNoSecExt'
                    DistinguishedName        = 'CN=RestrictedNoSecExt,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    'msPKI-Enrollment-Flag'  = 0x80000
                })
            }
            if ($SearchBase -match 'Enrollment Services') { return @() }
            if ($SearchBase -match 'CN=OID,') { return @() }
            return @()
        }

        $findings = Test-ADCSExtended
        ($findings | Where-Object { $_.Issue -eq 'Certificate Template Missing Security Extension (ESC9)' }) | Should -BeNullOrEmpty
    }

    It 'does not flag ESC9 when CT_FLAG_NO_SECURITY_EXTENSION is not set' {
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($Identity -eq 'CN=NormalTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com') {
                return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @(New-TestAce -Principal 'CONTOSO\Authenticated Users' -Rights 'ExtendedRight') } }
            }
            if ($SearchBase -match 'Certificate Templates') {
                return @([PSCustomObject]@{
                    Name                     = 'NormalTemplate'
                    DistinguishedName        = 'CN=NormalTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    'msPKI-Enrollment-Flag'  = 0
                })
            }
            if ($SearchBase -match 'Enrollment Services') { return @() }
            if ($SearchBase -match 'CN=OID,') { return @() }
            return @()
        }

        $findings = Test-ADCSExtended
        ($findings | Where-Object { $_.Issue -eq 'Certificate Template Missing Security Extension (ESC9)' }) | Should -BeNullOrEmpty
    }
}

Describe 'Test-ADCSExtended - ESC13 (Issuance Policy group link)' {
    It 'flags a template whose Issuance Policy OID is linked to a group, with a client-auth EKU and low-priv enrollment' {
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($Identity -eq 'CN=PolicyLinkedTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com') {
                return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @(New-TestAce -Principal 'CONTOSO\Domain Users' -Rights 'ExtendedRight') } }
            }
            if ($SearchBase -match 'Certificate Templates') {
                return @([PSCustomObject]@{
                    Name                                  = 'PolicyLinkedTemplate'
                    DistinguishedName                     = 'CN=PolicyLinkedTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    'msPKI-Enrollment-Flag'                = 0
                    'msPKI-Certificate-Policy'             = @('1.2.3.4.5.6.7')
                    'msPKI-Certificate-Application-Policy' = @('1.3.6.1.5.5.7.3.2')
                    'pKIExtendedKeyUsage'                  = @('1.3.6.1.5.5.7.3.2')
                })
            }
            if ($SearchBase -match 'Enrollment Services') { return @() }
            if ($SearchBase -match 'CN=OID,') {
                return @([PSCustomObject]@{
                    'msPKI-Cert-Template-OID' = '1.2.3.4.5.6.7'
                    'msDS-OIDToGroupLink'     = 'CN=Enterprise Admins,CN=Users,DC=contoso,DC=com'
                })
            }
            return @()
        }

        $findings = Test-ADCSExtended
        $hit = $findings | Where-Object { $_.Issue -eq 'Certificate Template Issuance Policy Linked to Privileged Group (ESC13)' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Severity | Should -Be 'Critical'
        $hit.Details.LinkedGroups | Should -Match 'Enterprise Admins'
    }

    It 'does not flag ESC13 when no Issuance Policy OID is linked to a group' {
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($Identity -eq 'CN=UnlinkedTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com') {
                return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @(New-TestAce -Principal 'CONTOSO\Domain Users' -Rights 'ExtendedRight') } }
            }
            if ($SearchBase -match 'Certificate Templates') {
                return @([PSCustomObject]@{
                    Name                                  = 'UnlinkedTemplate'
                    DistinguishedName                     = 'CN=UnlinkedTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    'msPKI-Enrollment-Flag'                = 0
                    'msPKI-Certificate-Policy'             = @('1.2.3.4.5.6.7')
                    'msPKI-Certificate-Application-Policy' = @('1.3.6.1.5.5.7.3.2')
                    'pKIExtendedKeyUsage'                  = @('1.3.6.1.5.5.7.3.2')
                })
            }
            if ($SearchBase -match 'Enrollment Services') { return @() }
            # OID object exists but has no msDS-OIDToGroupLink at all.
            if ($SearchBase -match 'CN=OID,') {
                return @([PSCustomObject]@{ 'msPKI-Cert-Template-OID' = '1.2.3.4.5.6.7'; 'msDS-OIDToGroupLink' = $null })
            }
            return @()
        }

        $findings = Test-ADCSExtended
        ($findings | Where-Object { $_.Issue -eq 'Certificate Template Issuance Policy Linked to Privileged Group (ESC13)' }) | Should -BeNullOrEmpty
    }
}
