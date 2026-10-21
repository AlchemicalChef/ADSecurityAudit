#Requires -Modules Pester
<#
    Unit tests for two additions to Test-ADGroupPolicies (GpoAudits.ps1):

      1. 'Non-Standard GPO Owner' - flags a GPO whose owner isn't a
         standard administrative principal, resolved by SID (via the new
         Resolve-ADPrincipalNameToSid helper in Common.ps1) rather than by
         name-regex, so a custom-named non-admin group ending in the word
         "Administrators" is no longer silently treated as legitimate.
      2. Dynamic DC-containing-OU resolution for the existing 'GPO Linked
         to Domain Controllers with Weak Permissions' check, replacing the
         previous hardcoded 'OU=Domain Controllers' string match - so a
         renamed/reorganized DC OU is still caught.

    Live-mode tests shadow Import-Module (no-op), Get-GPO, Get-GPPermission,
    Get-ADDomain, Get-ADObject (gPLink lookups), Get-ADDomainController
    (DC-OU resolution, via the real Get-ADSecurityAuditDomainController),
    Get-ADGroup (protected-group SID resolution for the owner allowlist),
    Get-ADTier0Principal (shadowed directly rather than its own
    Get-ADGroup/Get-ADGroupMember dependencies), and
    Resolve-ADPrincipalNameToSid (shadowed directly for deterministic
    owner-SID results, since the real helper wraps a raw .NET call whose
    success depends on the live security-provider context). SYSVOL
    permission checks are exercised as-is: Test-Path against the
    fabricated UNC path naturally returns $false in this environment, so
    that section cleanly no-ops without any mocking. No real Active
    Directory access is used.

    Run from the repo root:  Invoke-Pester ./tests/GpoAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/GpoAudits.ps1')

    function Import-Module { param($Name, [switch]$ErrorAction) }

    function Get-ADDomain {
        param([switch]$ErrorAction, $Server)
        [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' }
    }

    function Get-ADDomainController {
        param($Filter, $Server, $Identity, $ErrorAction)
        # Domain-scoping filter inside Get-ADSecurityAuditDomainController
        # matches on .Domain -eq the resolved DNSRoot.
        @([PSCustomObject]@{ Name = 'DC01'; HostName = 'DC01.contoso.com'; Domain = 'contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
    }

    # Empty by default (no Tier-0 principals); not exercised by these
    # tests directly, but Get-ADTier0Principal is called while building
    # the owner-SID allowlist, so it needs a harmless stub.
    function Get-ADTier0Principal { @() }

    # Only 'Domain Admins' resolves to a real SID by default (used by the
    # owner-SID-allowlist build-up); every other protected group name
    # resolves to nothing, same as an empty/not-found domain lookup.
    function Get-ADGroup {
        param($Filter, $Server, $ErrorAction)
        if ($Filter -match "Domain Admins") {
            return [PSCustomObject]@{ Name = 'Domain Admins'; SID = [PSCustomObject]@{ Value = 'S-1-5-21-1111-2222-3333-512' } }
        }
        return $null
    }

    function New-TestGpo {
        param(
            [string]$Id = 'AAAAAAAA-0000-0000-0000-000000000001',
            [string]$DisplayName = 'Test GPO',
            [string]$Owner = 'CONTOSO\Domain Admins'
        )
        [PSCustomObject]@{ Id = $Id; DisplayName = $DisplayName; Owner = $Owner; Path = "cn={$Id}"; CreationTime = (Get-Date); ModificationTime = (Get-Date) }
    }
}

Describe 'Test-ADGroupPolicies - Non-Standard GPO Owner' {
    BeforeEach {
        # Default: no GPO links, no permissions - isolates the ownership
        # check from the edit-rights/DC-OU checks in most tests below.
        function Get-GPPermission { param($Guid, [switch]$All, $Server) @() }
        function Get-ADObject { param($Filter, $Properties, $Server) @() }
    }

    It 'flags a GPO owned by a principal that does not resolve to a standard admin SID' {
        function Get-GPO { param([switch]$All, $Server) @(New-TestGpo -Owner 'CONTOSO\Help Desk Administrators') }
        function Resolve-ADPrincipalNameToSid { param($Name) 'S-1-5-21-1111-2222-3333-9001' }

        $findings = Test-ADGroupPolicies
        $hit = $findings | Where-Object { $_.Issue -eq 'Non-Standard GPO Owner' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Severity | Should -Be 'High'
        $hit.Details.Owner | Should -Be 'CONTOSO\Help Desk Administrators'
    }

    It 'does not flag a GPO owned by Domain Admins (resolves to an allowlisted SID)' {
        function Get-GPO { param([switch]$All, $Server) @(New-TestGpo -Owner 'CONTOSO\Domain Admins') }
        function Resolve-ADPrincipalNameToSid { param($Name) 'S-1-5-21-1111-2222-3333-512' }

        $findings = Test-ADGroupPolicies
        ($findings | Where-Object { $_.Issue -eq 'Non-Standard GPO Owner' }) | Should -BeNullOrEmpty
    }

    It 'falls back to the name-based check when SID translation fails outright, and does not flag a literal "Domain Admins" owner' {
        function Get-GPO { param([switch]$All, $Server) @(New-TestGpo -Owner 'CONTOSO\Domain Admins') }
        function Resolve-ADPrincipalNameToSid { param($Name) $null }

        $findings = Test-ADGroupPolicies
        ($findings | Where-Object { $_.Issue -eq 'Non-Standard GPO Owner' }) | Should -BeNullOrEmpty
    }

    It 'falls back to the name-based check and flags a non-admin owner when SID translation fails outright' {
        function Get-GPO { param([switch]$All, $Server) @(New-TestGpo -Owner 'CONTOSO\Some Random Group') }
        function Resolve-ADPrincipalNameToSid { param($Name) $null }

        $findings = Test-ADGroupPolicies
        ($findings | Where-Object { $_.Issue -eq 'Non-Standard GPO Owner' }) | Should -Not -BeNullOrEmpty
    }

    It 'escalates to Critical when the non-standard-owner GPO is linked to an OU containing a Domain Controller' {
        function Get-GPO { param([switch]$All, $Server) @(New-TestGpo -Id 'BBBBBBBB-0000-0000-0000-000000000002' -Owner 'CONTOSO\Random Owner') }
        function Resolve-ADPrincipalNameToSid { param($Name) 'S-1-5-21-1111-2222-3333-9002' }
        function Get-ADObject {
            param($Filter, $Properties, $Server)
            @([PSCustomObject]@{ DistinguishedName = 'OU=Domain Controllers,DC=contoso,DC=com' })
        }

        $findings = Test-ADGroupPolicies
        $hit = $findings | Where-Object { $_.Issue -eq 'Non-Standard GPO Owner' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Severity | Should -Be 'Critical'
        $hit.Details.LinkedToDCOU | Should -Be $true
    }
}

Describe 'Test-ADGroupPolicies - dynamic DC-containing-OU resolution' {
    BeforeEach {
        function Resolve-ADPrincipalNameToSid { param($Name) 'S-1-5-21-1111-2222-3333-512' }  # Domain Admins - keeps ownership check quiet
        function Get-ADGroup { param($Filter, $Server, $ErrorAction) if ($Filter -match 'Domain Admins') { return [PSCustomObject]@{ Name = 'Domain Admins'; SID = [PSCustomObject]@{ Value = 'S-1-5-21-1111-2222-3333-512' } } }; return $null }
    }

    It 'still flags a GPO linked to a RENAMED DC-containing OU with non-admin edit rights (the literal-name match alone would miss this)' {
        function Get-GPO { param([switch]$All, $Server) @(New-TestGpo -Id 'CCCCCCCC-0000-0000-0000-000000000003' -Owner 'CONTOSO\Domain Admins') }
        function Get-GPPermission {
            param($Guid, [switch]$All, $Server)
            @([PSCustomObject]@{ Permission = 'GpoEdit'; Trustee = [PSCustomObject]@{ Name = 'CONTOSO\Helpdesk' } })
        }
        # This DC computer object lives under a renamed OU - NOT the
        # literal 'OU=Domain Controllers' string.
        function Get-ADDomainController {
            param($Filter, $Server, $Identity, $ErrorAction)
            @([PSCustomObject]@{ Name = 'DC01'; HostName = 'DC01.contoso.com'; Domain = 'contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers - Renamed,DC=contoso,DC=com' })
        }
        function Get-ADObject {
            param($Filter, $Properties, $Server)
            @([PSCustomObject]@{ DistinguishedName = 'OU=Domain Controllers - Renamed,DC=contoso,DC=com' })
        }

        $findings = Test-ADGroupPolicies
        $hit = $findings | Where-Object { $_.Issue -eq 'GPO Linked to Domain Controllers with Weak Permissions' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Severity | Should -Be 'Critical'
        $hit.Details.LinkedOU | Should -Be 'OU=Domain Controllers - Renamed,DC=contoso,DC=com'
    }

    It 'does not flag a GPO linked to an OU that does not contain a Domain Controller' {
        function Get-GPO { param([switch]$All, $Server) @(New-TestGpo -Id 'DDDDDDDD-0000-0000-0000-000000000004' -Owner 'CONTOSO\Domain Admins') }
        function Get-GPPermission {
            param($Guid, [switch]$All, $Server)
            @([PSCustomObject]@{ Permission = 'GpoEdit'; Trustee = [PSCustomObject]@{ Name = 'CONTOSO\Helpdesk' } })
        }
        function Get-ADObject {
            param($Filter, $Properties, $Server)
            @([PSCustomObject]@{ DistinguishedName = 'OU=Workstations,DC=contoso,DC=com' })
        }

        $findings = Test-ADGroupPolicies
        ($findings | Where-Object { $_.Issue -eq 'GPO Linked to Domain Controllers with Weak Permissions' }) | Should -BeNullOrEmpty
    }
}
