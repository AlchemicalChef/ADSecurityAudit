#Requires -Modules Pester
<#
    Unit tests for Test-ADManagedServiceAccountSecurity (gMSA/dMSA
    managed-password retrieval-rights audit), added to close a real
    detection gap: nothing in the module previously checked
    PrincipalsAllowedToRetrieveManagedPassword - the AD-native equivalent
    of a BloodHound "ReadGMSAPassword" edge.

    Live-mode tests shadow Get-ADServiceAccount and Get-ADObject (the
    cmdlets the function actually calls) plus Get-ADTier0Principal itself
    (rather than every cmdlet Get-ADTier0Principal internally calls -
    Get-ADGroup/Get-ADGroupMember/Get-ADForest - since these tests are
    about Test-ADManagedServiceAccountSecurity's own logic, not
    Get-ADTier0Principal's, and the function's only real dependency on it
    is "which principals count as Tier-0"). No real Active Directory
    access is used.

    Run from the repo root:  Invoke-Pester ./tests/ManagedServiceAccountAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/ManagedServiceAccountAudits.ps1')

    $script:__gmsaSidCounter = 5000
    function New-TestGmsa {
        param(
            [string]$Name,
            [string]$DistinguishedName,
            [string[]]$Retrievers = @()
        )
        $script:__gmsaSidCounter++
        [PSCustomObject]@{
            Name                                          = $Name
            DistinguishedName                              = $DistinguishedName
            SamAccountName                                 = "$Name`$"
            SID                                            = [PSCustomObject]@{ Value = "S-1-5-21-1111-2222-3333-$script:__gmsaSidCounter" }
            PrincipalsAllowedToRetrieveManagedPassword     = $Retrievers
            ServicePrincipalNames                          = @()
            Enabled                                        = $true
        }
    }

    # Default: no Tier-0 principals at all, so tests only exercise the
    # broad-principal check unless a test overrides this to also cover
    # the privileged-gMSA path.
    function Get-ADTier0Principal { @() }
}

Describe 'Test-ADManagedServiceAccountSecurity' {
    BeforeEach {
        # Reset to the no-Tier-0-principals default before each test;
        # individual tests override as needed.
        function Get-ADTier0Principal { @() }
    }

    It 'flags a gMSA whose password is retrievable by Domain Users' {
        function Get-ADServiceAccount {
            param($Filter, $Properties, $Server, $ErrorAction)
            @(New-TestGmsa -Name 'svc-webapp' -DistinguishedName 'CN=svc-webapp,CN=Managed Service Accounts,DC=contoso,DC=com' -Retrievers @('CN=Domain Users,CN=Users,DC=contoso,DC=com'))
        }
        function Get-ADObject {
            param($Identity, $Properties, $Server, $ErrorAction)
            [PSCustomObject]@{ DistinguishedName = $Identity; sAMAccountName = 'Domain Users'; objectSID = [PSCustomObject]@{ Value = 'S-1-5-21-1111-2222-3333-513' } }
        }

        $findings = Test-ADManagedServiceAccountSecurity
        $hit = $findings | Where-Object { $_.Issue -eq 'gMSA Password Retrievable by Broad Principal' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Severity | Should -Be 'Critical'
        $hit.AffectedObject | Should -Be 'svc-webapp'
        $hit.Details.BroadPrincipals | Should -Match 'Domain Users'
    }

    It 'does not flag a gMSA whose retrieval list is scoped to a specific, non-broad group' {
        function Get-ADServiceAccount {
            param($Filter, $Properties, $Server, $ErrorAction)
            @(New-TestGmsa -Name 'svc-sql' -DistinguishedName 'CN=svc-sql,CN=Managed Service Accounts,DC=contoso,DC=com' -Retrievers @('CN=SQL Hosts,OU=Groups,DC=contoso,DC=com'))
        }
        function Get-ADObject {
            param($Identity, $Properties, $Server, $ErrorAction)
            [PSCustomObject]@{ DistinguishedName = $Identity; sAMAccountName = 'SQL Hosts'; objectSID = [PSCustomObject]@{ Value = 'S-1-5-21-1111-2222-3333-2001' } }
        }

        $findings = Test-ADManagedServiceAccountSecurity
        ($findings | Where-Object { $_.Issue -eq 'gMSA Password Retrievable by Broad Principal' }) | Should -BeNullOrEmpty
        ($findings | Where-Object { $_.Issue -eq 'Privileged gMSA Password Retrieval Not Tightly Scoped' }) | Should -BeNullOrEmpty
    }

    It 'flags a Tier-0 gMSA whose password can be retrieved by a non-Tier-0 principal' {
        function Get-ADServiceAccount {
            param($Filter, $Properties, $Server, $ErrorAction)
            @(New-TestGmsa -Name 'svc-tier0' -DistinguishedName 'CN=svc-tier0,CN=Managed Service Accounts,DC=contoso,DC=com' -Retrievers @('CN=Helpdesk Servers,OU=Groups,DC=contoso,DC=com'))
        }
        function Get-ADObject {
            param($Identity, $Properties, $Server, $ErrorAction)
            [PSCustomObject]@{ DistinguishedName = $Identity; sAMAccountName = 'Helpdesk Servers'; objectSID = [PSCustomObject]@{ Value = 'S-1-5-21-1111-2222-3333-3001' } }
        }
        # Mark the gMSA itself as Tier-0 (matched by DN), but NOT the
        # retriever - this is exactly the "privileged service identity,
        # non-privileged retriever" gap the check exists to catch.
        function Get-ADTier0Principal {
            @([PSCustomObject]@{
                DistinguishedName = 'CN=svc-tier0,CN=Managed Service Accounts,DC=contoso,DC=com'
                SID               = 'S-1-5-21-1111-2222-3333-9999'
                SamAccountName    = 'svc-tier0$'
            })
        }

        $findings = Test-ADManagedServiceAccountSecurity
        $hit = $findings | Where-Object { $_.Issue -eq 'Privileged gMSA Password Retrieval Not Tightly Scoped' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Severity | Should -Be 'High'
        $hit.Details.NonTier0Retrievers | Should -Match 'Helpdesk Servers'
    }

    It 'does not flag a Tier-0 gMSA when every retriever is itself Tier-0' {
        function Get-ADServiceAccount {
            param($Filter, $Properties, $Server, $ErrorAction)
            @(New-TestGmsa -Name 'svc-tier0-clean' -DistinguishedName 'CN=svc-tier0-clean,CN=Managed Service Accounts,DC=contoso,DC=com' -Retrievers @('CN=Tier0 Hosts,OU=Groups,DC=contoso,DC=com'))
        }
        function Get-ADObject {
            param($Identity, $Properties, $Server, $ErrorAction)
            [PSCustomObject]@{ DistinguishedName = $Identity; sAMAccountName = 'Tier0 Hosts'; objectSID = [PSCustomObject]@{ Value = 'S-1-5-21-1111-2222-3333-4001' } }
        }
        function Get-ADTier0Principal {
            @(
                [PSCustomObject]@{ DistinguishedName = 'CN=svc-tier0-clean,CN=Managed Service Accounts,DC=contoso,DC=com'; SID = 'S-1-5-21-1111-2222-3333-9998'; SamAccountName = 'svc-tier0-clean$' }
                [PSCustomObject]@{ DistinguishedName = 'CN=Tier0 Hosts,OU=Groups,DC=contoso,DC=com'; SID = 'S-1-5-21-1111-2222-3333-4001'; SamAccountName = 'Tier0 Hosts' }
            )
        }

        $findings = Test-ADManagedServiceAccountSecurity
        $findings | Should -BeNullOrEmpty
    }

    It 'produces no findings for a gMSA with no retrieval principals configured' {
        function Get-ADServiceAccount {
            param($Filter, $Properties, $Server, $ErrorAction)
            @(New-TestGmsa -Name 'svc-empty' -DistinguishedName 'CN=svc-empty,CN=Managed Service Accounts,DC=contoso,DC=com' -Retrievers @())
        }

        $findings = Test-ADManagedServiceAccountSecurity
        $findings | Should -BeNullOrEmpty
    }

    It 'returns cleanly when there are no gMSAs in the domain' {
        function Get-ADServiceAccount { param($Filter, $Properties, $Server, $ErrorAction) @() }

        { Test-ADManagedServiceAccountSecurity } | Should -Not -Throw
        Test-ADManagedServiceAccountSecurity | Should -BeNullOrEmpty
    }
}
