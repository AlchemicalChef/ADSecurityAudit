#Requires -Modules Pester
<#
    Unit tests for the addition of 'Domain Computers' to
    $Script:ControlPathBroadPrincipalPattern (ControlPaths.ps1), per ASD/
    CISA/NSA/CCCS/NCSC-NZ/NCSC-UK's "Detecting and mitigating Active
    Directory compromises" (Sept 2026), which calls out Domain Computers
    by name in both the MachineAccountQuota-compromise and Silver-Ticket
    sections: every computer object in the domain - including one a
    low-privileged user creates via the default MachineAccountQuota=10 -
    is a member of Domain Computers, so a dangerous ACE or Tier-0-group
    membership held by Domain Computers is as broad a path as one held by
    Domain Users, and previously was NOT classified as broad here.

    This tests the pattern directly (the same way Test-ADControlPaths
    itself uses it: `$source -match $Script:ControlPathBroadPrincipalPattern`)
    rather than exercising the full control-path graph end-to-end, since
    Test-ADControlPaths' own graph construction has no existing test
    harness to build on and mocking a realistic nTSecurityDescriptor/ACE
    object graph for this one pattern change would be disproportionate to
    what's being verified. Consistent with this project's existing
    approach of testing exposed scope/classification helpers directly
    (see CrossDomainHelpers.Tests.ps1).

    Run from the repo root:  Invoke-Pester ./tests/ControlPaths.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/ControlPaths.ps1')
}

Describe '$Script:ControlPathBroadPrincipalPattern' {
    It 'classifies "Domain Computers" (bare) as broad' {
        'Domain Computers' -match $Script:ControlPathBroadPrincipalPattern | Should -BeTrue
    }

    It 'classifies "CONTOSO\Domain Computers" (domain-qualified) as broad' {
        'CONTOSO\Domain Computers' -match $Script:ControlPathBroadPrincipalPattern | Should -BeTrue
    }

    It 'still classifies the pre-existing broad principals as broad (no regression)' {
        'Everyone' -match $Script:ControlPathBroadPrincipalPattern | Should -BeTrue
        'Authenticated Users' -match $Script:ControlPathBroadPrincipalPattern | Should -BeTrue
        'Domain Users' -match $Script:ControlPathBroadPrincipalPattern | Should -BeTrue
        'ANONYMOUS LOGON' -match $Script:ControlPathBroadPrincipalPattern | Should -BeTrue
    }

    It 'does not classify a specific, non-broad group or user as broad' {
        'Domain Admins' -match $Script:ControlPathBroadPrincipalPattern | Should -BeFalse
        'jdoe' -match $Script:ControlPathBroadPrincipalPattern | Should -BeFalse
        'IT-Helpdesk-Staff' -match $Script:ControlPathBroadPrincipalPattern | Should -BeFalse
    }

    It 'does not partially match a group whose name merely contains "Domain Computers" as a substring' {
        # The pattern anchors on '$' (end of string), so a group like
        # "Non-Domain Computers Workaround" should NOT match - only an
        # exact (optionally domain-qualified) "Domain Computers" name.
        'Non-Domain Computers Workaround' -match $Script:ControlPathBroadPrincipalPattern | Should -BeFalse
    }
}
