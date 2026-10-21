#Requires -Modules Pester
<#
    Unit tests for Test-ConstrainedDelegation's "Computer Account with
    Unconstrained Delegation" check.

    Found via tracing the ForcedFail fixtures (tests/fixtures/) against the
    codebase: Test-ADUserSecurity already flagged bare, unconstrained
    delegation (TrustedForDelegation=$true, no msDS-AllowedToDelegateTo) on
    USER accounts as "Unconstrained Delegation Enabled" (UserAudits.ps1),
    but no equivalent check existed anywhere for COMPUTER accounts - despite
    unconstrained delegation being overwhelmingly found on computer objects
    in real environments (legacy print/app/file servers), not user
    accounts, and being one of the most consequential, well-known AD
    misconfigurations (a compromised host with this flag can capture and
    replay the TGT of any user who authenticates to it).

    Added as "Computer Account with Unconstrained Delegation" in
    Test-ConstrainedDelegation (DelegationAudits.ps1, the existing home for
    computer-level delegation checks).

    REWRITTEN (offline/-Snapshot mode removal): this file used to invoke
    Test-ConstrainedDelegation -Snapshot with hand-built fixture hashtables.
    Now that -Snapshot no longer exists, these tests shadow the live
    Get-ADComputer/Get-ADUser/Get-ADObject cmdlets the function actually
    calls instead. No real Active Directory access is used.

    Domain Controller exclusion (PrimaryGroupID -ne 516/521) happens
    entirely inside the -Filter clause passed to Get-ADComputer - it is
    evaluated server-side by Active Directory, not by any PowerShell code
    in this module. A mocked Get-ADComputer does not evaluate -Filter at
    all, so "does this computer get excluded" cannot be exercised
    behaviorally here the way it could against a real (or snapshotted)
    result set. Instead, the regression-guard test below asserts the
    -Filter clause itself still contains both exclusions, which is the
    only thing that actually protects against a DC (or a TrustedForDelegation
    -eq $false computer) being flagged.

    Run from the repo root:  Invoke-Pester ./tests/ConstrainedDelegation.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/DelegationAudits.ps1')

    # Stubs so Pester can mock cmdlets that don't exist outside a real
    # Active Directory module. Test-ConstrainedDelegation calls
    # Get-ADUser/Get-ADComputer/Get-ADObject four separate times (user
    # constrained-delegation, computer constrained-delegation, computer
    # unconstrained-delegation, and RBCD) - each is given a harmless empty
    # default here so a test only needs to override the call(s) it cares
    # about.
    function Get-ADUser { param($Filter, $Properties, $Server) @() }
    function Get-ADComputer { param($Filter, $Properties, $Server) @() }
    function Get-ADObject { param($Filter, $Properties, $Server) @() }

    function New-UnconstrainedDelegationComputer {
        param(
            [string]$Name,
            [string]$DistinguishedName,
            [string]$OperatingSystem = 'Windows Server 2022',
            [string[]]$ServicePrincipalNames = @()
        )
        [PSCustomObject]@{
            Name                  = $Name
            DistinguishedName     = $DistinguishedName
            TrustedForDelegation  = $true
            OperatingSystem       = $OperatingSystem
            ServicePrincipalNames = $ServicePrincipalNames
        }
    }
}

Describe 'Test-ConstrainedDelegation - Computer Account with Unconstrained Delegation' {
    It 'flags a non-DC computer with TrustedForDelegation=$true' {
        function Get-ADComputer {
            param($Filter, $Properties, $Server)
            if ($Filter.ToString() -match 'TrustedForDelegation') {
                return @(New-UnconstrainedDelegationComputer -Name 'LEGACY-SRV01' `
                    -DistinguishedName 'CN=LEGACY-SRV01,CN=Computers,DC=contoso,DC=com' `
                    -OperatingSystem 'Windows Server 2008 R2' `
                    -ServicePrincipalNames @('HOST/legacy-srv01.contoso.com'))
            }
            return @()
        }

        $findings = Test-ConstrainedDelegation
        $hit = $findings | Where-Object { $_.Issue -eq 'Computer Account with Unconstrained Delegation' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.AffectedObject | Should -Be 'LEGACY-SRV01'
        $hit.Severity | Should -Be 'Critical'
    }

    It 'does not double-flag a computer returned by both the constrained- and unconstrained-delegation queries' {
        # A computer with TrustedForDelegation=$true AND a populated
        # msDS-AllowedToDelegateTo is a real, if unusual, edge case - AD
        # could plausibly return the same computer object from both the
        # constrained-delegation query (Filter: msDS-AllowedToDelegateTo
        # -like '*') and the unconstrained-delegation query (Filter:
        # TrustedForDelegation -eq $true ...). This only confirms the
        # unconstrained finding itself doesn't appear more than once for
        # that computer.
        function Get-ADComputer {
            param($Filter, $Properties, $Server)
            $filterText = $Filter.ToString()
            if ($filterText -match 'TrustedForDelegation') {
                return @(New-UnconstrainedDelegationComputer -Name 'MIXED01' `
                    -DistinguishedName 'CN=MIXED01,CN=Computers,DC=contoso,DC=com')
            }
            if ($filterText -match 'msDS-AllowedToDelegateTo') {
                return @([PSCustomObject]@{
                    Name                        = 'MIXED01'
                    DistinguishedName           = 'CN=MIXED01,CN=Computers,DC=contoso,DC=com'
                    'msDS-AllowedToDelegateTo'  = @('HTTP/app.contoso.com')
                    TrustedForDelegation        = $true
                    TrustedToAuthForDelegation  = $false
                    ServicePrincipalNames       = @()
                    Enabled                     = $true
                })
            }
            return @()
        }

        $findings = Test-ConstrainedDelegation
        $hits = @($findings | Where-Object {
            $_.Issue -eq 'Computer Account with Unconstrained Delegation' -and $_.AffectedObject -eq 'MIXED01'
        })

        $hits.Count | Should -Be 1
    }

    It 'guards the -Filter passed to Get-ADComputer against ever including a Domain Controller or a TrustedForDelegation=$false computer' {
        # Domain Controllers (PrimaryGroupID 516/521) are excluded, and only
        # TrustedForDelegation -eq $true computers are requested, entirely
        # via this -Filter clause - there is no downstream PowerShell check
        # that would catch a regression here (see file header). This is the
        # only test that actually protects the "does not flag a DC" /
        # "does not flag TrustedForDelegation=$false" behavior.
        $script:capturedFilter = $null
        function Get-ADComputer {
            param($Filter, $Properties, $Server)
            $filterText = $Filter.ToString()
            if ($filterText -match 'TrustedForDelegation') {
                $script:capturedFilter = $filterText
            }
            return @()
        }

        Test-ConstrainedDelegation | Out-Null

        $script:capturedFilter | Should -Not -BeNullOrEmpty
        $script:capturedFilter | Should -Match 'TrustedForDelegation -eq \$true'
        $script:capturedFilter | Should -Match 'PrimaryGroupID -ne 516'
        $script:capturedFilter | Should -Match 'PrimaryGroupID -ne 521'
    }
}
