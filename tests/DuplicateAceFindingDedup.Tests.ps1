#Requires -Modules Pester
<#
    Regression tests for v1.24.0: several ACE-iterating checks emitted one
    finding per raw ACE instead of one per (identity, rights) combination.
    Real AD ACLs commonly carry more than one ACE for the same trustee -
    one per property set/object type - even when ActiveDirectoryRights is
    identical, which produced fully-duplicate findings (same Category,
    Issue, AffectedObject, and Description) in the exported report. Found
    via a live lab run: 74 of 262 findings were exact duplicates, 60 of
    them from a single AdminSDHolder ACL with repeated ACEs per trustee.

    REWRITTEN (offline/-Snapshot mode removal): this file used to invoke
    each function with -Snapshot and a hand-built ACL hashtable. Now that
    -Snapshot no longer exists, these tests shadow the live
    Get-ADDomain/Get-ADObject cmdlets each function actually calls, with
    ACE objects shaped the way the .NET ActiveDirectorySecurity type
    returns them (IdentityReference as an object exposing .Value, not a
    plain string) rather than the flattened snapshot shape. No real Active
    Directory access is used.

    Note this is the ONLY remaining regression coverage for the 74/262
    duplicate-finding bug: the full-pipeline ForcedFail-fixture smoke test
    that also guarded it (tests/ForcedFailFixture.Tests.ps1) was correctly
    removed along with -FromSnapshot/Invoke-ADRuleSet, since it depended
    entirely on that pipeline.

    Run from the repo root:  Invoke-Pester ./tests/DuplicateAceFindingDedup.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/AdminSDAudits.ps1')
    . (Join-Path $root 'src/ExchangeEscalationAudits.ps1')
    . (Join-Path $root 'src/ReplicationAudits.ps1')
    . (Join-Path $root 'src/DomainAdminEquivalence.ps1')

    # All four functions read ACEs off a real .NET ActiveDirectorySecurity
    # object's .Access collection, where IdentityReference is an
    # NTAccount/SecurityIdentifier object (accessed via .Value in three of
    # the four functions, and via plain string interpolation in the
    # fourth) - not the flattened plain-string shape the old snapshot
    # fixtures used. This wrapper reproduces that shape for both access
    # patterns.
    function New-LiveIdentityReference {
        param([string]$Name)
        $obj = [PSCustomObject]@{ Value = $Name }
        Add-Member -InputObject $obj -MemberType ScriptMethod -Name ToString -Value { $this.Value } -Force
        return $obj
    }

    function New-DuplicateAce {
        param(
            [string]$Identity,
            [string]$Rights,
            [string]$AccessControlType = 'Allow',
            [string]$ObjectType = '00000000-0000-0000-0000-000000000000'
        )
        # Two ACEs for the same trustee/rights but different ObjectType -
        # exactly the shape real AD ACLs produce (separate ACEs per
        # property set) that the dedup fix must collapse into one finding.
        @(
            [PSCustomObject]@{
                IdentityReference     = (New-LiveIdentityReference -Name $Identity)
                ActiveDirectoryRights = $Rights
                AccessControlType     = $AccessControlType
                IsInherited           = $false
                InheritanceType       = 'None'
                ObjectType            = $ObjectType
                InheritedObjectType   = '00000000-0000-0000-0000-000000000000'
            }
            [PSCustomObject]@{
                IdentityReference     = (New-LiveIdentityReference -Name $Identity)
                ActiveDirectoryRights = $Rights
                AccessControlType     = $AccessControlType
                IsInherited           = $false
                InheritanceType       = 'None'
                ObjectType            = 'bf967a86-0de6-11d0-a285-00aa003049e2'
                InheritedObjectType   = '00000000-0000-0000-0000-000000000000'
            }
        )
    }
}

Describe 'Test-AdminSDHolder (duplicate ACE dedup)' {
    BeforeEach {
        function Get-ADDomain { [PSCustomObject]@{ NetBIOSName = 'CONTOSO'; DistinguishedName = 'DC=contoso,DC=com' } }
    }

    It 'emits exactly one Non-Standard Permissions finding for a trustee with two identical-rights ACEs' {
        $aces = New-DuplicateAce -Identity 'CONTOSO\Exchange Trusted Subsystem' -Rights 'WriteProperty'
        function Get-ADObject {
            param($Identity, $Properties, $Server)
            [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = $aces } }
        }

        $findings = Test-AdminSDHolder
        $hits = @($findings | Where-Object { $_.Issue -eq 'Non-Standard Permissions on AdminSDHolder' })

        $hits.Count | Should -Be 1
        $hits[0].AffectedObject | Should -Match 'Exchange Trusted Subsystem'
    }

    It 'emits exactly one Deny ACE finding for a trustee with two identical Deny ACEs' {
        $aces = New-DuplicateAce -Identity 'CONTOSO\Exchange Servers' -Rights 'GenericAll' -AccessControlType 'Deny'
        function Get-ADObject {
            param($Identity, $Properties, $Server)
            [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = $aces } }
        }

        $findings = Test-AdminSDHolder
        $hits = @($findings | Where-Object { $_.Issue -eq 'Deny ACE on AdminSDHolder' })

        $hits.Count | Should -Be 1
    }

    It 'still reports two separate findings for two genuinely different trustees' {
        $aces = @(New-DuplicateAce -Identity 'CONTOSO\Exchange Trusted Subsystem' -Rights 'WriteProperty')[0], `
                @(New-DuplicateAce -Identity 'CONTOSO\Organization Management' -Rights 'GenericAll')[0]
        function Get-ADObject {
            param($Identity, $Properties, $Server)
            [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = $aces } }
        }

        $findings = Test-AdminSDHolder
        $hits = @($findings | Where-Object { $_.Issue -eq 'Non-Standard Permissions on AdminSDHolder' })

        $hits.Count | Should -Be 2
    }
}

Describe 'Test-ADExchangeEscalation (duplicate ACE dedup)' {
    BeforeEach {
        function Get-ADDomain { param($Server, $ErrorAction) [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com' } }
    }

    It 'emits exactly one finding per (identity, rights) pair on the domain root, not one per ACE' {
        $aces = New-DuplicateAce -Identity 'CONTOSO\Exchange Trusted Subsystem' -Rights 'WriteDacl'
        function Get-ADObject {
            param($Identity, $Properties, $Server, $ErrorAction)
            if ($Identity -eq 'DC=contoso,DC=com') {
                return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = $aces } }
            }
            return $null
        }

        $findings = Test-ADExchangeEscalation
        $hits = @($findings | Where-Object { $_.Issue -eq 'Exchange Group Holds WriteDACL on Domain Object' })

        $hits.Count | Should -Be 1
    }

    It 'emits exactly one AdminSDHolder-related finding per (identity, rights) pair, not one per ACE' {
        $aces = New-DuplicateAce -Identity 'CONTOSO\Exchange Trusted Subsystem' -Rights 'GenericAll'
        function Get-ADObject {
            param($Identity, $Properties, $Server, $ErrorAction)
            if ($Identity -eq 'CN=AdminSDHolder,CN=System,DC=contoso,DC=com') {
                return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = $aces } }
            }
            return $null
        }

        $findings = Test-ADExchangeEscalation
        $hits = @($findings | Where-Object { $_.Issue -eq 'Exchange-Related AdminSDHolder ACE' })

        $hits.Count | Should -Be 1
    }
}

Describe 'Test-ADReplicationSecurity (duplicate ACE dedup - DCSync)' {
    BeforeEach {
        function Get-ADDomain { param($Server) [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com'; NetBIOSName = 'CONTOSO' } }
    }

    It 'emits exactly one Unauthorized DCSync Permissions finding for a trustee with two GenericAll ACEs (matches the observed lab duplicate)' {
        # Mirrors the real duplicate found in a lab run: the same trustee
        # held multiple GenericAll ACEs on the domain root (one per object
        # type), each independently matching all three DCSync rights and
        # producing three fully-duplicate findings before the fix.
        $aces = New-DuplicateAce -Identity 'CONTOSO\Exchange Trusted Subsystem' -Rights 'GenericAll'
        function Get-ADObject {
            param($Identity, $Properties, $Server)
            [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = $aces } }
        }

        $findings = Test-ADReplicationSecurity
        $hits = @($findings | Where-Object { $_.Issue -eq 'Unauthorized DCSync Permissions' })

        $hits.Count | Should -Be 1
        $hits[0].Details.Rights | Should -Match 'DS-Replication-Get-Changes'
        $hits[0].Details.Rights | Should -Match 'DS-Replication-Get-Changes-All'
    }

    It 'aggregates two different specific replication rights (via different ObjectTypes) on the same trustee into ONE finding, not two' {
        # v1.24.0 follow-up fix: two ACEs each granting a different
        # specific DCSync right (rather than a single GenericAll ACE
        # granting all of them at once) used to each produce their own
        # finding with an identical, generic Description that didn't name
        # the specific right - reading as an exact duplicate in the
        # report even though dedup correctly treated them as distinct.
        # Since the two rights combine on this one principal exactly the
        # way a single GenericAll ACE would, they're now aggregated into
        # one finding listing both rights.
        $aces = @(
            [PSCustomObject]@{
                IdentityReference     = (New-LiveIdentityReference -Name 'CONTOSO\Sync Service')
                ActiveDirectoryRights = 'ExtendedRight'
                AccessControlType     = 'Allow'
                IsInherited           = $false
                ObjectType            = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # Get-Changes only
            }
            [PSCustomObject]@{
                IdentityReference     = (New-LiveIdentityReference -Name 'CONTOSO\Sync Service')
                ActiveDirectoryRights = 'ExtendedRight'
                AccessControlType     = 'Allow'
                IsInherited           = $false
                ObjectType            = '89e95b76-444d-4c62-991a-0facbeda640c'  # Get-Changes-In-Filtered-Set only
            }
        )
        function Get-ADObject {
            param($Identity, $Properties, $Server)
            [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = $aces } }
        }

        $findings = Test-ADReplicationSecurity
        $hits = @($findings | Where-Object { $_.Issue -eq 'Unauthorized DCSync Permissions' })

        $hits.Count | Should -Be 1
        $hits[0].Details.Rights | Should -Match 'DS-Replication-Get-Changes\b'
        $hits[0].Details.Rights | Should -Match 'DS-Replication-Get-Changes-In-Filtered-Set'
        # The specific rights are now named in the top-level Description
        # too, not just buried in Details - so the report doesn't look
        # like a duplicate at a glance.
        $hits[0].Description | Should -Match 'DS-Replication-Get-Changes'
    }

    It 'still reports two separate findings for two genuinely different trustees' {
        $aces = @(
            [PSCustomObject]@{
                IdentityReference     = (New-LiveIdentityReference -Name 'CONTOSO\Sync Service A')
                ActiveDirectoryRights = 'GenericAll'
                AccessControlType     = 'Allow'
                IsInherited           = $false
                ObjectType            = '00000000-0000-0000-0000-000000000000'
            }
            [PSCustomObject]@{
                IdentityReference     = (New-LiveIdentityReference -Name 'CONTOSO\Sync Service B')
                ActiveDirectoryRights = 'GenericAll'
                AccessControlType     = 'Allow'
                IsInherited           = $false
                ObjectType            = '00000000-0000-0000-0000-000000000000'
            }
        )
        function Get-ADObject {
            param($Identity, $Properties, $Server)
            [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = $aces } }
        }

        $findings = Test-ADReplicationSecurity
        $hits = @($findings | Where-Object { $_.Issue -eq 'Unauthorized DCSync Permissions' })

        $hits.Count | Should -Be 2
    }
}

Describe 'Test-ADDomainAdminEquivalence (Add-Evidence dedup)' {
    It 'lists a repeated piece of evidence once, not once per contributing ACE (regression, v1.24.0)' {
        # Reproduces the exact pattern found in a live lab run: a
        # principal with two ACEs granting the same right on the domain
        # root (one per object type) produced the same evidence bullet
        # ("Domain Root control via GenericAll") twice inside a single
        # "Domain Admin Equivalent Access Detected" finding's Description.
        function Get-ADDomain {
            [PSCustomObject]@{
                DistinguishedName = 'DC=contoso,DC=com'
                NetBIOSName       = 'CONTOSO'
                DNSRoot           = 'contoso.com'
                DomainSID         = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3' }
            }
        }
        function Get-ADRootDSE { param($Server) [PSCustomObject]@{ ConfigurationNamingContext = 'CN=Configuration,DC=contoso,DC=com' } }

        $aces = @(
            [PSCustomObject]@{
                IdentityReference     = (New-LiveIdentityReference -Name 'CONTOSO\Organization Management')
                ActiveDirectoryRights = 'GenericAll'
                AccessControlType     = 'Allow'
                IsInherited           = $false
                ObjectType            = '00000000-0000-0000-0000-000000000000'
            }
            [PSCustomObject]@{
                IdentityReference     = (New-LiveIdentityReference -Name 'CONTOSO\Organization Management')
                ActiveDirectoryRights = 'GenericAll'
                AccessControlType     = 'Allow'
                IsInherited           = $false
                ObjectType            = 'bf967a86-0de6-11d0-a285-00aa003049e2'
            }
        )
        # Every other Get-ADComputer/Get-ADUser/Get-ADGroup/Get-ADGroupMember/
        # Get-ADObject call this function makes is independently wrapped in
        # its own try/catch (see DomainAdminEquivalence.ps1) and left
        # unstubbed here - each one harmlessly no-ops as an unrecognized
        # command, contributing no extra evidence. Only the domain-root
        # control-target ACL read (Identity -eq the domain DN) is stubbed.
        function Get-ADObject {
            param($Identity, $Properties, $Server, $ErrorAction)
            if ($Identity -eq 'DC=contoso,DC=com') {
                return [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = $aces } }
            }
            return $null
        }

        $findings = Test-ADDomainAdminEquivalence
        $hit = $findings | Where-Object { $_.Issue -eq 'Domain Admin Equivalent Access Detected' -and $_.AffectedObject -eq 'CONTOSO\Organization Management' }

        $hit | Should -Not -BeNullOrEmpty
        $bulletCount = ([regex]::Matches($hit.Description, 'Domain Root control via GenericAll')).Count
        $bulletCount | Should -Be 1
        @($hit.Details.Evidence).Count | Should -Be 1
    }
}
