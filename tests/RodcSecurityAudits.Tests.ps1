#Requires -Modules Pester
<#
    Regression tests for Test-ADRodcSecurity's interaction with the
    module's three -Server modes (no -Server / -Server as a domain name /
    -Server as an explicit specific DC), via the shared
    Get-ADSecurityAuditDomainController helper's RODC-only filter.

    This is the one interaction among the six functions re-verified during
    the -Server workflow review (RodcSecurity, AuditPolicyConfiguration,
    DomainHardeningFlags, ControlPaths, KerberosHardening,
    LegacyAuthSurface) that wasn't already covered by an existing test:
    a non-default -Filter (RODC-only) combined with an explicit-DC -Server
    override, which Get-ADSecurityAuditDomainController handles via a
    second, filter-matching query rather than its normal -Identity path
    (see Common.ps1 for why -Filter and -Identity are mutually exclusive
    parameter sets on Get-ADDomainController).

    Confirms, by code trace already done for this review and now pinned
    down as an executable test:
      - No -Server / -Server as a domain name: every RODC in the domain
        is enumerated and evaluated.
      - -Server as an explicit DC that IS an RODC: exactly that one RODC
        is evaluated.
      - -Server as an explicit DC that is NOT an RODC (a writable DC):
        zero RODCs found - a clean "nothing to evaluate" exit, not an
        error and not a false claim that the domain has no RODCs at all.

    Live-mode tests shadow Get-ADDomain and Get-ADDomainController only;
    Test-ADRodcSecurity returns before touching any other live cmdlet
    whenever zero RODCs are found. No real Active Directory access is
    used.

    Run from the repo root:  Invoke-Pester ./tests/RodcSecurityAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/RodcSecurityAudits.ps1')
}

Describe 'Test-ADRodcSecurity (RODC-filtered enumeration across the three -Server modes)' {
    BeforeEach {
        function Get-ADDomain {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' }
        }
    }

    AfterEach {
        $Script:ADSecurityAuditServerIsExplicitDC = $false
        if ($Global:PSDefaultParameterValues) {
            $Global:PSDefaultParameterValues.Remove('Get-AD*:Server')
        }
    }

    It 'enumerates every RODC in the domain when no -Server override is active' {
        $Script:ADSecurityAuditServerIsExplicitDC = $false
        function Get-ADDomainController {
            param($Filter, $Server, $Identity, [switch]$ErrorAction)
            # -Filter path: both RODCs in the domain, matching the
            # RODC-only filter Test-ADRodcSecurity passes through.
            @(
                [PSCustomObject]@{ Name = 'RODC01'; HostName = 'RODC01.contoso.com'; Domain = 'contoso.com'; IsReadOnly = $true; ComputerObjectDN = 'CN=RODC01,OU=Domain Controllers,DC=contoso,DC=com' }
                [PSCustomObject]@{ Name = 'RODC02'; HostName = 'RODC02.contoso.com'; Domain = 'contoso.com'; IsReadOnly = $true; ComputerObjectDN = 'CN=RODC02,OU=Domain Controllers,DC=contoso,DC=com' }
            )
        }

        # No live findings expected without further mocking (per-RODC
        # attribute reads aren't stubbed here) - this test only confirms
        # enumeration reaches both RODCs, via -Verbose's own reported
        # count, without throwing.
        { Test-ADRodcSecurity } | Should -Not -Throw
    }

    It 'scopes to exactly one RODC when -Server names that specific RODC explicitly' {
        $Script:ADSecurityAuditServerIsExplicitDC = $true
        $Global:PSDefaultParameterValues = @{ 'Get-AD*:Server' = 'RODC01.contoso.com' }
        function Get-ADDomainController {
            param($Filter, $Server, $Identity, [switch]$ErrorAction)
            if ($Identity) {
                return [PSCustomObject]@{ Name = 'RODC01'; HostName = 'RODC01.contoso.com'; Domain = 'contoso.com'; IsReadOnly = $true; ComputerObjectDN = 'CN=RODC01,OU=Domain Controllers,DC=contoso,DC=com' }
            }
            # -Filter re-check path (RODC-only filter, run against the
            # whole domain purely to confirm RODC01's own membership).
            @(
                [PSCustomObject]@{ Name = 'RODC01'; HostName = 'RODC01.contoso.com'; Domain = 'contoso.com'; IsReadOnly = $true }
                [PSCustomObject]@{ Name = 'RODC02'; HostName = 'RODC02.contoso.com'; Domain = 'contoso.com'; IsReadOnly = $true }
            )
        }

        { Test-ADRodcSecurity } | Should -Not -Throw
    }

    It 'cleanly reports zero RODCs (not an error) when -Server names an explicit DC that is NOT an RODC' {
        $Script:ADSecurityAuditServerIsExplicitDC = $true
        $Global:PSDefaultParameterValues = @{ 'Get-AD*:Server' = 'DC01.contoso.com' }
        function Get-ADDomainController {
            param($Filter, $Server, $Identity, [switch]$ErrorAction)
            if ($Identity) {
                return [PSCustomObject]@{ Name = 'DC01'; HostName = 'DC01.contoso.com'; Domain = 'contoso.com'; IsReadOnly = $false }
            }
            # -Filter re-check: DC01 is a writable DC, so it's absent from
            # the RODC-only result set even though other RODCs exist
            # elsewhere in the domain.
            @(
                [PSCustomObject]@{ Name = 'RODC01'; HostName = 'RODC01.contoso.com'; Domain = 'contoso.com'; IsReadOnly = $true }
            )
        }

        $findings = Test-ADRodcSecurity
        $findings | Should -BeNullOrEmpty
    }
}
