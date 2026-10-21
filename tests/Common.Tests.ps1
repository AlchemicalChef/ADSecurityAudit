#Requires -Modules Pester
<#
    Unit tests for two additions to Common.ps1:

      1. Get-ADTier0Principal's new user-declarable additional Tier-0
         scope, fed either via $Script:AdditionalTier0DistinguishedNames
         (the normal path, set by Start-ADSecurityAudit's
         -AdditionalTier0DN) or directly via the function's own
         -AdditionalTier0DN parameter (mainly for direct/test use).
      2. Resolve-ADPrincipalNameToSid - the small helper extracted so the
         GPO-ownership check (GpoAudits.ps1) doesn't depend on an inline,
         unmockable .NET Translate() call. Only the failure path is
         exercised deterministically here; the success path depends on
         the live security-provider context and is covered instead by
         GpoAudits.Tests.ps1 shadowing this function directly.

    Live-mode tests shadow Get-ADGroup, Get-ADGroupMember, and Get-ADObject
    (the cmdlets Get-ADTier0Principal calls). No real Active Directory
    access is used.

    Run from the repo root:  Invoke-Pester ./tests/Common.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')

    # No protected group resolves to anything by default, so
    # Get-ADTier0Principal's built-in-group expansion contributes nothing
    # unless a specific test overrides this - isolating these tests to
    # just the additional-scope behavior being tested.
    function Get-ADGroup { param($Filter, $Server, $ErrorAction) $null }
    function Get-ADGroupMember { param($Identity, [switch]$Recursive, $Server, $ErrorAction) @() }
}

Describe 'Get-ADTier0Principal - additional Tier-0 scope' {
    AfterEach {
        # Reset the shared script-scoped list after every test, same
        # reasoning as Main.ps1 resetting it at the start of each
        # Start-ADSecurityAudit run: a value from one test must never
        # leak into the next.
        $Script:AdditionalTier0DistinguishedNames = @()
    }

    It 'includes a DN from $Script:AdditionalTier0DistinguishedNames (the normal Start-ADSecurityAudit -AdditionalTier0DN path)' {
        $Script:AdditionalTier0DistinguishedNames = @('CN=svc-backup,OU=ServiceAccounts,DC=contoso,DC=com')
        function Get-ADObject {
            param($Identity, $Properties, $Server)
            [PSCustomObject]@{ DistinguishedName = $Identity; objectSID = [PSCustomObject]@{ Value = 'S-1-5-21-1111-2222-3333-5001' }; sAMAccountName = 'svc-backup'; objectClass = 'user' }
        }

        $result = Get-ADTier0Principal
        $hit = $result | Where-Object { $_.DistinguishedName -eq 'CN=svc-backup,OU=ServiceAccounts,DC=contoso,DC=com' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.SamAccountName | Should -Be 'svc-backup'
        $hit.PrivilegedGroupsString | Should -Match 'Additional Tier-0 Scope \(user-defined\)'
    }

    It 'includes a DN passed directly via -AdditionalTier0DN, in addition to the script-scoped list' {
        $Script:AdditionalTier0DistinguishedNames = @('CN=svc-backup,OU=ServiceAccounts,DC=contoso,DC=com')
        function Get-ADObject {
            param($Identity, $Properties, $Server)
            [PSCustomObject]@{ DistinguishedName = $Identity; objectSID = [PSCustomObject]@{ Value = "S-1-5-21-1111-2222-3333-$($Identity.Length)" }; sAMAccountName = ($Identity -split ',')[0].TrimStart('CN='); objectClass = 'group' }
        }

        $result = Get-ADTier0Principal -AdditionalTier0DN @('CN=Tier0-Admins,OU=Groups,DC=contoso,DC=com')

        ($result | Where-Object { $_.DistinguishedName -eq 'CN=svc-backup,OU=ServiceAccounts,DC=contoso,DC=com' }) | Should -Not -BeNullOrEmpty
        ($result | Where-Object { $_.DistinguishedName -eq 'CN=Tier0-Admins,OU=Groups,DC=contoso,DC=com' }) | Should -Not -BeNullOrEmpty
    }

    It 'does not duplicate a principal already present via built-in-group membership, and appends the additional-scope tag to it' {
        function Get-ADGroup {
            param($Filter, $Server, $ErrorAction)
            if ($Filter -match 'Domain Admins') {
                return [PSCustomObject]@{ Name = 'Domain Admins'; DistinguishedName = 'CN=Domain Admins,CN=Users,DC=contoso,DC=com' }
            }
            return $null
        }
        function Get-ADGroupMember {
            param($Identity, [switch]$Recursive, $Server, $ErrorAction)
            if ($Identity.Name -eq 'Domain Admins') {
                return @([PSCustomObject]@{ DistinguishedName = 'CN=jdoe,CN=Users,DC=contoso,DC=com'; SID = [PSCustomObject]@{ Value = 'S-1-5-21-1111-2222-3333-1105' }; SamAccountName = 'jdoe'; objectClass = 'user' })
            }
            return @()
        }
        $Script:AdditionalTier0DistinguishedNames = @('CN=jdoe,CN=Users,DC=contoso,DC=com')
        function Get-ADObject {
            param($Identity, $Properties, $Server)
            [PSCustomObject]@{ DistinguishedName = $Identity; objectSID = [PSCustomObject]@{ Value = 'S-1-5-21-1111-2222-3333-1105' }; sAMAccountName = 'jdoe'; objectClass = 'user' }
        }

        $result = @(Get-ADTier0Principal | Where-Object { $_.DistinguishedName -eq 'CN=jdoe,CN=Users,DC=contoso,DC=com' })

        $result.Count | Should -Be 1
        $result[0].PrivilegedGroupsString | Should -Match 'Domain Admins'
        $result[0].PrivilegedGroupsString | Should -Match 'Additional Tier-0 Scope \(user-defined\)'
    }

    It 'skips (rather than throws for) an additional DN that no longer resolves' {
        $Script:AdditionalTier0DistinguishedNames = @('CN=deleted-object,OU=ServiceAccounts,DC=contoso,DC=com')
        function Get-ADObject { param($Identity, $Properties, $Server) throw 'ADIdentityNotFoundException: object not found' }

        { Get-ADTier0Principal } | Should -Not -Throw
        (Get-ADTier0Principal) | Should -BeNullOrEmpty
    }

    It 'returns an empty set when there is no additional scope and no built-in-group membership' {
        $Script:AdditionalTier0DistinguishedNames = @()
        Get-ADTier0Principal | Should -BeNullOrEmpty
    }
}

Describe 'Resolve-ADPrincipalNameToSid' {
    It 'returns $null (rather than throwing) for a name that cannot be translated' {
        { Resolve-ADPrincipalNameToSid -Name 'THIS-DOMAIN-DOES-NOT-EXIST\NoSuchAccount-4f8c2a' } | Should -Not -Throw
        Resolve-ADPrincipalNameToSid -Name 'THIS-DOMAIN-DOES-NOT-EXIST\NoSuchAccount-4f8c2a' | Should -BeNullOrEmpty
    }
}
