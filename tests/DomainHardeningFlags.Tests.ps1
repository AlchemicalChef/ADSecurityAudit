#Requires -Modules Pester
<#
    Unit tests for Test-ADDomainHardeningFlags (feature 04): dSHeuristics
    parsing and Pre-Windows 2000 Compatible Access membership detection.

    REWRITTEN (offline/-Snapshot mode removal): this file used to invoke
    Test-ADDomainHardeningFlags -Snapshot with hand-built fixture
    hashtables. Now that -Snapshot no longer exists, these tests shadow the
    live Get-ADRootDSE/Get-ADObject/Get-ADGroup/Get-ADGroupMember cmdlets
    Checks 1 and 2 actually call. No real Active Directory access is used.

    Check 3 (the live anonymous-bind probe) and Check 4 (the null-session
    GPO/registry check) are both live-only and are deliberately isolated
    from Checks 1/2 here by shadowing Get-ADSecurityAuditDomainController
    to return no Domain Controllers, so neither attempts any live network
    or GPO call while these tests run. Check 4 already has its own
    dedicated live-mode coverage in NullSessionAudit.Tests.ps1; the
    anonymous-bind probe (Check 3) has no PowerShell-side logic beyond
    "no DCs found -> skip", which the last test in this file asserts
    directly.

    Run from the repo root:  Invoke-Pester ./tests/DomainHardeningFlags.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/DomainHardeningAudits.ps1')

    # Isolates Checks 1/2 from Check 3 (anonymous-bind probe) - see file
    # header. Overridden with a real (non-empty) list only in the
    # dedicated "Check 3" Describe block below.
    function Get-ADSecurityAuditDomainController { param($Server) @() }

    # Harmless defaults for Check 1 (dSHeuristics). Every test in the
    # "dSHeuristics" Describe block below overrides Get-ADObject with the
    # specific dSHeuristics value it wants to test.
    #
    # NOTE: $ErrorAction is deliberately left UNTYPED below, not
    # [switch]$ErrorAction - the real calls pass -ErrorAction Stop (a
    # string value), and a [switch]-typed parameter would mis-parse that
    # as "-ErrorAction" (switch on) followed by a stray positional 'Stop'
    # argument, throwing a binding error instead of a clean no-op.
    function Get-ADRootDSE {
        param($Server, $ErrorAction)
        [PSCustomObject]@{ configurationNamingContext = 'CN=Configuration,DC=contoso,DC=com' }
    }
    function Get-ADObject { param($Identity, $Properties, $Server, $ErrorAction) $null }

    # Harmless defaults for Check 2 (Pre-Windows 2000 Compatible Access).
    # Every test in that Describe block below overrides Get-ADGroup/
    # Get-ADGroupMember with the specific membership it wants to test.
    function Get-ADGroup { param($Filter, $Server, $ErrorAction) $null }
    function Get-ADGroupMember { param($Identity, $Server, $ErrorAction) @() }
}

Describe 'Test-ADDomainHardeningFlags (dSHeuristics)' {
    It 'flags anonymous access when character 7 is 2' {
        function Get-ADObject { param($Identity, $Properties, $Server) [PSCustomObject]@{ dSHeuristics = '0000002' } }

        $findings = Test-ADDomainHardeningFlags
        $findings.Count | Should -Be 1
        $findings[0].Issue | Should -Be 'Dangerous dsHeuristics Flag Set'
        $findings[0].Severity | Should -Be 'High'
        ($findings[0].Details.FlaggedPositions | Where-Object { $_.Position -eq 7 }).Count | Should -Be 1
    }

    It 'flags List Object mode when character 1 is 1' {
        function Get-ADObject { param($Identity, $Properties, $Server) [PSCustomObject]@{ dSHeuristics = '1' } }

        $findings = Test-ADDomainHardeningFlags
        $findings.Count | Should -Be 1
        ($findings[0].Details.FlaggedPositions | Where-Object { $_.Position -eq 1 }).Count | Should -Be 1
    }

    It 'flags AdminSDHolder exclusion mask weakening when character 16 is non-zero' {
        function Get-ADObject { param($Identity, $Properties, $Server) [PSCustomObject]@{ dSHeuristics = '000000000000000f' } }

        $findings = Test-ADDomainHardeningFlags
        $findings.Count | Should -Be 1
        ($findings[0].Details.FlaggedPositions | Where-Object { $_.Position -eq 16 }).Count | Should -Be 1
    }

    It 'produces no finding for a benign dsHeuristics value' {
        function Get-ADObject { param($Identity, $Properties, $Server) [PSCustomObject]@{ dSHeuristics = '0000000' } }

        $findings = Test-ADDomainHardeningFlags
        ($findings | Where-Object { $_.Issue -eq 'Dangerous dsHeuristics Flag Set' }) | Should -BeNullOrEmpty
    }

    It 'produces no finding when dSHeuristics is not set' {
        function Get-ADObject { param($Identity, $Properties, $Server) [PSCustomObject]@{ dSHeuristics = $null } }

        $findings = Test-ADDomainHardeningFlags
        ($findings | Where-Object { $_.Issue -eq 'Dangerous dsHeuristics Flag Set' }) | Should -BeNullOrEmpty
    }
}

Describe 'Test-ADDomainHardeningFlags (Pre-Windows 2000 Compatible Access)' {
    It 'flags Authenticated Users membership as High' {
        function Get-ADGroup {
            param($Filter, $Server)
            [PSCustomObject]@{ DistinguishedName = 'CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=contoso,DC=com' }
        }
        function Get-ADGroupMember {
            param($Identity, $Server)
            @([PSCustomObject]@{ SID = [PSCustomObject]@{ Value = 'S-1-5-11' } })
        }

        $findings = Test-ADDomainHardeningFlags
        $finding = $findings | Where-Object { $_.Issue -eq 'Broad Membership in Pre-Windows 2000 Compatible Access' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'High'
        $finding.Details.BroadPrincipals | Should -Contain 'Authenticated Users'
    }

    It 'does not fire for narrow/legitimate members' {
        function Get-ADGroup {
            param($Filter, $Server)
            [PSCustomObject]@{ DistinguishedName = 'CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=contoso,DC=com' }
        }
        function Get-ADGroupMember {
            param($Identity, $Server)
            @([PSCustomObject]@{ SID = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-1001' } })
        }

        $findings = Test-ADDomainHardeningFlags
        ($findings | Where-Object { $_.Issue -eq 'Broad Membership in Pre-Windows 2000 Compatible Access' }) | Should -BeNullOrEmpty
    }
}

Describe 'Test-ADDomainHardeningFlags (Check 3 - anonymous-bind probe skip)' {
    It 'skips the anonymous-bind probe (and never attempts a live LDAP connection) when no Domain Controllers are found' {
        function Get-ADSecurityAuditDomainController { @() }
        function Get-ADObject { param($Identity, $Properties, $Server) [PSCustomObject]@{ dSHeuristics = $null } }

        { Test-ADDomainHardeningFlags } | Should -Not -Throw
        $findings = Test-ADDomainHardeningFlags
        $findings | Where-Object { $_.Issue -eq 'Anonymous LDAP / RootDSE Binding Permitted' } | Should -BeNullOrEmpty
    }
}
