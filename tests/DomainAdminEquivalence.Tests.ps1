#Requires -Modules Pester
<#
    Unit tests for the extended constrained-delegation-target check in
    Test-ADDomainAdminEquivalence (DomainAdminEquivalence.ps1): the
    existing "AllowedToDelegate to a Domain Controller" evidence edge is
    joined by a new one matching a delegation target's SPN host component
    against the FULL Get-ADTier0Principal set (built-in privileged groups
    plus any user-declared -AdditionalTier0DN scope), so delegation to a
    Tier-0 principal that is NOT a DC computer object (a Domain Admin's own
    workstation, a Tier-0 service account, or an -AdditionalTier0DN
    addition) is caught too - not just delegation to a literal DC.

    Test-ADDomainAdminEquivalence is a large function performing many
    largely-independent AD queries and correlations; these tests provide
    harmless empty-returning stubs for every Get-AD* cmdlet it calls (so
    the whole function completes without throwing) and override only the
    specific queries the delegation-target check depends on -
    Get-ADObject's msDS-AllowedToDelegateTo LDAP filter and
    Get-ADTier0Principal. No real Active Directory access is used.

    Run from the repo root:  Invoke-Pester ./tests/DomainAdminEquivalence.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/DomainAdminEquivalence.ps1')

    # Harmless empty-returning defaults for every Get-AD* cmdlet this
    # function calls, so it runs to completion with nothing to
    # correlate except whatever a specific test overrides below.
    function Get-ADDomain {
        param($Server, [switch]$ErrorAction)
        [PSCustomObject]@{
            DistinguishedName          = 'DC=contoso,DC=com'
            DomainSID                  = [PSCustomObject]@{ Value = 'S-1-5-21-1111-2222-3333' }
            NetBIOSName                = 'CONTOSO'
            DomainControllersContainer = 'OU=Domain Controllers,DC=contoso,DC=com'
            DNSRoot                    = 'contoso.com'
        }
    }
    function Get-ADRootDSE {
        param($Server)
        [PSCustomObject]@{ ConfigurationNamingContext = 'CN=Configuration,DC=contoso,DC=com' }
    }
    function Get-ADComputer { param($Filter, $Server, $Properties, $ErrorAction) @() }
    function Get-ADUser { param($Filter, $LDAPFilter, $Server, $Properties, $ErrorAction, $Identity) @() }
    function Get-ADGroup { param($Filter, $Server, $ErrorAction) $null }
    function Get-ADGroupMember { param($Identity, [switch]$Recursive, $Server, $ErrorAction) @() }
    function Get-ADObject { param($Filter, $LDAPFilter, $Identity, $Properties, $Server, $ErrorAction) @() }
    function Get-ADTier0Principal { @() }
}

Describe 'Test-ADDomainAdminEquivalence - constrained-delegation-to-Tier-0 extension' {
    It 'flags delegation to a Tier-0 principal that is NOT a Domain Controller' {
        function Get-ADObject {
            param($Filter, $LDAPFilter, $Identity, $Properties, $Server, $ErrorAction)
            if ($LDAPFilter -match 'msDS-AllowedToDelegateTo') {
                return @([PSCustomObject]@{
                    Name                       = 'svc-webapp'
                    DistinguishedName          = 'CN=svc-webapp,CN=Users,DC=contoso,DC=com'
                    'msDS-AllowedToDelegateTo' = @('HOST/tier0-jumpbox.contoso.com')
                    samAccountName             = 'svc-webapp'
                })
            }
            return @()
        }
        function Get-ADTier0Principal {
            @([PSCustomObject]@{
                DistinguishedName = 'CN=tier0-jumpbox,OU=Tier0,DC=contoso,DC=com'
                SID               = 'S-1-5-21-1111-2222-3333-9001'
                SamAccountName    = 'tier0-jumpbox$'
            })
        }

        $findings = Test-ADDomainAdminEquivalence
        $hit = $findings | Where-Object { $_.AffectedObject -eq 'svc-webapp' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Issue | Should -Be 'Domain Admin Equivalent Access Detected'
        ($hit.Details.Evidence.Reason -join '; ') | Should -Match 'AllowedToDelegate to Tier-0 Principal tier0-jumpbox'
    }

    It 'does not flag delegation to a target that is not in the Tier-0 set' {
        function Get-ADObject {
            param($Filter, $LDAPFilter, $Identity, $Properties, $Server, $ErrorAction)
            if ($LDAPFilter -match 'msDS-AllowedToDelegateTo') {
                return @([PSCustomObject]@{
                    Name                       = 'svc-webapp2'
                    DistinguishedName          = 'CN=svc-webapp2,CN=Users,DC=contoso,DC=com'
                    'msDS-AllowedToDelegateTo' = @('HTTP/app-server.contoso.com')
                    samAccountName             = 'svc-webapp2'
                })
            }
            return @()
        }
        function Get-ADTier0Principal { @() }

        $findings = Test-ADDomainAdminEquivalence
        ($findings | Where-Object { $_.AffectedObject -eq 'svc-webapp2' }) | Should -BeNullOrEmpty
    }

    It 'does not double-count delegation to an actual Domain Controller under both the DC check and the Tier-0 check' {
        function Get-ADComputer {
            param($Filter, $Server, $Properties, $ErrorAction)
            if ($Filter -match 'primaryGroupID') {
                return @([PSCustomObject]@{ Name = 'DC01'; DistinguishedName = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com'; OperatingSystem = 'Windows Server 2022' })
            }
            return @()
        }
        function Get-ADObject {
            param($Filter, $LDAPFilter, $Identity, $Properties, $Server, $ErrorAction)
            if ($LDAPFilter -match 'msDS-AllowedToDelegateTo') {
                return @([PSCustomObject]@{
                    Name                       = 'svc-legacy'
                    DistinguishedName          = 'CN=svc-legacy,CN=Users,DC=contoso,DC=com'
                    'msDS-AllowedToDelegateTo' = @('HOST/DC01.contoso.com')
                    samAccountName             = 'svc-legacy'
                })
            }
            return @()
        }
        # DC01 also happens to satisfy the Tier-0 lookup (DCs are
        # themselves Tier-0 principals via Get-ADTier0Principal in a real
        # run) - the guard in DomainAdminEquivalence.ps1 should prevent a
        # second, redundant evidence entry for the same delegation edge.
        function Get-ADTier0Principal {
            @([PSCustomObject]@{ DistinguishedName = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com'; SID = 'S-1-5-21-1111-2222-3333-1000'; SamAccountName = 'DC01$' })
        }

        $findings = Test-ADDomainAdminEquivalence
        $hit = $findings | Where-Object { $_.AffectedObject -eq 'svc-legacy' }

        $hit | Should -Not -BeNullOrEmpty
        ($hit.Details.Evidence.Reason -join '; ') | Should -Match 'AllowedToDelegate \(Constrained Delegation\) to Domain Controller DC01'
        ($hit.Details.Evidence.Reason -join '; ') | Should -Not -Match 'AllowedToDelegate to Tier-0 Principal DC01'
    }
}

Describe 'Test-ADDomainAdminEquivalence - sIDHistory checks' {
    It 'flags SID History Injection (Same Domain) for a same-domain SID, not the catch-all' {
        function Get-ADUser {
            param($Filter, $LDAPFilter, $Server, $Properties, $ErrorAction, $Identity)
            if ($LDAPFilter -match 'sIDHistory') {
                return @([PSCustomObject]@{ SamAccountName = 'compromised1'; DistinguishedName = 'CN=compromised1,CN=Users,DC=contoso,DC=com'; sIDHistory = @('S-1-5-21-1111-2222-3333-9999') })
            }
            return @()
        }

        $findings = Test-ADDomainAdminEquivalence
        $issues = @($findings | Where-Object { $_.AffectedObject -eq 'compromised1' } | Select-Object -ExpandProperty Issue)
        $issues | Should -Contain 'SID History Injection (Same Domain)'
    }

    It 'flags Privileged SID in History for a foreign-domain SID ending in a well-known privileged RID (512), not the catch-all' {
        function Get-ADUser {
            param($Filter, $LDAPFilter, $Server, $Properties, $ErrorAction, $Identity)
            if ($LDAPFilter -match 'sIDHistory') {
                return @([PSCustomObject]@{ SamAccountName = 'compromised2'; DistinguishedName = 'CN=compromised2,CN=Users,DC=contoso,DC=com'; sIDHistory = @('S-1-5-21-9999-8888-7777-512') })
            }
            return @()
        }

        $findings = Test-ADDomainAdminEquivalence
        $issues = @($findings | Where-Object { $_.AffectedObject -eq 'compromised2' } | Select-Object -ExpandProperty Issue)
        $issues | Should -Contain 'Privileged SID in History'
    }

    It 'flags the SID History Attribute Populated catch-all for a foreign-domain SID with a non-privileged RID' {
        function Get-ADUser {
            param($Filter, $LDAPFilter, $Server, $Properties, $ErrorAction, $Identity)
            if ($LDAPFilter -match 'sIDHistory') {
                return @([PSCustomObject]@{ SamAccountName = 'migrateduser'; DistinguishedName = 'CN=migrateduser,CN=Users,DC=contoso,DC=com'; sIDHistory = @('S-1-5-21-9999-8888-7777-1105') })
            }
            return @()
        }

        $findings = Test-ADDomainAdminEquivalence
        $issues = @($findings | Where-Object { $_.AffectedObject -eq 'migrateduser' } | Select-Object -ExpandProperty Issue)
        $issues | Should -Contain 'SID History Attribute Populated'
        $issues | Should -Not -Contain 'SID History Injection (Same Domain)'
        $issues | Should -Not -Contain 'Privileged SID in History'
    }

    It 'does not fire the catch-all for a same-domain SID (already covered by the more specific same-domain finding)' {
        function Get-ADUser {
            param($Filter, $LDAPFilter, $Server, $Properties, $ErrorAction, $Identity)
            if ($LDAPFilter -match 'sIDHistory') {
                return @([PSCustomObject]@{ SamAccountName = 'compromised3'; DistinguishedName = 'CN=compromised3,CN=Users,DC=contoso,DC=com'; sIDHistory = @('S-1-5-21-1111-2222-3333-1105') })
            }
            return @()
        }

        $findings = Test-ADDomainAdminEquivalence
        $issues = @($findings | Where-Object { $_.AffectedObject -eq 'compromised3' } | Select-Object -ExpandProperty Issue)
        $issues | Should -Not -Contain 'SID History Attribute Populated'
    }
}

Describe 'Test-ADDomainAdminEquivalence - ESC14 (weak/writable altSecurityIdentities)' {
    BeforeEach {
        function Get-ADGroup {
            param($Filter, $Server, [switch]$ErrorAction)
            if ($Filter -match 'Domain Admins') {
                return [PSCustomObject]@{ Name = 'Domain Admins'; DistinguishedName = 'CN=Domain Admins,CN=Users,DC=contoso,DC=com' }
            }
            return $null
        }
        function Get-ADGroupMember {
            param($Identity, [switch]$Recursive, $Server, [switch]$ErrorAction)
            if ($Identity.Name -eq 'Domain Admins') {
                return @([PSCustomObject]@{ DistinguishedName = 'CN=svcadmin,CN=Users,DC=contoso,DC=com'; SamAccountName = 'svcadmin'; objectClass = 'user'; SID = [PSCustomObject]@{ Value = 'S-1-5-21-1111-2222-3333-1105' } })
            }
            return @()
        }
    }

    It 'flags a privileged account with a weak (Issuer+Subject) explicit certificate mapping' {
        function Get-ADUser {
            param($Filter, $LDAPFilter, $Server, $Properties, $ErrorAction, $Identity)
            if ($Identity -eq 'CN=svcadmin,CN=Users,DC=contoso,DC=com') {
                return [PSCustomObject]@{
                    nTSecurityDescriptor = [PSCustomObject]@{ Access = @() }
                    altSecurityIdentities = @('X509:<I>DC=com,DC=contoso,CN=contoso-CA<S>DC=com,DC=contoso,CN=Users,CN=svcadmin')
                }
            }
            return @()
        }

        $findings = Test-ADDomainAdminEquivalence
        $hit = $findings | Where-Object { $_.Issue -eq 'Weak Explicit Certificate Mapping on Privileged Account (ESC14)' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.AffectedObject | Should -Be 'svcadmin'
        $hit.Severity | Should -Be 'High'
    }

    It 'does not flag ESC14 for a key-bound (SKI) mapping' {
        function Get-ADUser {
            param($Filter, $LDAPFilter, $Server, $Properties, $ErrorAction, $Identity)
            if ($Identity -eq 'CN=svcadmin,CN=Users,DC=contoso,DC=com') {
                return [PSCustomObject]@{
                    nTSecurityDescriptor  = [PSCustomObject]@{ Access = @() }
                    altSecurityIdentities = @('X509:<SKI>1234567890abcdef1234567890abcdef12345678')
                }
            }
            return @()
        }

        $findings = Test-ADDomainAdminEquivalence
        ($findings | Where-Object { $_.Issue -eq 'Weak Explicit Certificate Mapping on Privileged Account (ESC14)' }) | Should -BeNullOrEmpty
    }

    It 'flags a non-legitimate principal with write access to altSecurityIdentities on a privileged account (attribute-scoped ACE)' {
        function Get-ADUser {
            param($Filter, $LDAPFilter, $Server, $Properties, $ErrorAction, $Identity)
            if ($Identity -eq 'CN=svcadmin,CN=Users,DC=contoso,DC=com') {
                return [PSCustomObject]@{
                    nTSecurityDescriptor = [PSCustomObject]@{
                        Access = @([PSCustomObject]@{
                            IdentityReference     = [PSCustomObject]@{ Value = 'CONTOSO\Helpdesk' }
                            ActiveDirectoryRights = 'WriteProperty'
                            ObjectType            = '00fbf30c-91fe-11d1-aebc-0000f80367c1'
                            IsInherited           = $false
                        })
                    }
                    altSecurityIdentities = @()
                }
            }
            return @()
        }

        $findings = Test-ADDomainAdminEquivalence
        $hit = $findings | Where-Object { $_.AffectedObject -eq 'CONTOSO\Helpdesk' }

        $hit | Should -Not -BeNullOrEmpty
        ($hit.Details.Evidence.Reason -join '; ') | Should -Match 'altSecurityIdentities on privileged user'
    }

    It 'flags write access granted via the broader Public-Information property-set GUID, not just the attribute-specific GUID' {
        function Get-ADUser {
            param($Filter, $LDAPFilter, $Server, $Properties, $ErrorAction, $Identity)
            if ($Identity -eq 'CN=svcadmin,CN=Users,DC=contoso,DC=com') {
                return [PSCustomObject]@{
                    nTSecurityDescriptor = [PSCustomObject]@{
                        Access = @([PSCustomObject]@{
                            IdentityReference     = [PSCustomObject]@{ Value = 'CONTOSO\ExchangeTrusted' }
                            ActiveDirectoryRights = 'WriteProperty'
                            ObjectType            = 'e48d0154-bcf8-11d1-8702-00c04fb96050'
                            IsInherited           = $false
                        })
                    }
                    altSecurityIdentities = @()
                }
            }
            return @()
        }

        $findings = Test-ADDomainAdminEquivalence
        $hit = $findings | Where-Object { $_.AffectedObject -eq 'CONTOSO\ExchangeTrusted' }

        $hit | Should -Not -BeNullOrEmpty
        ($hit.Details.Evidence.Reason -join '; ') | Should -Match 'altSecurityIdentities on privileged user'
    }
}
