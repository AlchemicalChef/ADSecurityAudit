#Requires -Modules Pester
<#
    Unit tests for the new "run scope note" mechanism (Common.ps1):
    Add-ADRunScopeNote / Get-ADRunScopeNotes / Reset-ADRunScopeNotes, and
    the detection logic in Resolve-ADSecurityAuditTargetServer that records
    a note whenever -Server names an explicit, specific Domain Controller
    that is NOT the domain's PDC Emulator - surfacing that a "PDC-only"
    check (Test-ADMachineAccountQuota, Test-ADDomainSecurity) queried that
    DC directly rather than the PDC, instead of leaving this silent.

    Live cmdlets shadowed: Get-ADDomainController, Get-ADDomain,
    Get-ADRootDSE. No real Active Directory access is used.

    Run from the repo root:  Invoke-Pester ./tests/RunScopeNotes.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
}

Describe 'Add-ADRunScopeNote / Get-ADRunScopeNotes / Reset-ADRunScopeNotes' {
    It 'starts empty and accumulates notes in order' {
        Reset-ADRunScopeNotes
        Get-ADRunScopeNotes | Should -BeNullOrEmpty

        Add-ADRunScopeNote -Category 'PDC Scope' -Message 'first note'
        Add-ADRunScopeNote -Category 'PDC Scope' -Message 'second note'

        $notes = @(Get-ADRunScopeNotes)
        $notes.Count | Should -Be 2
        $notes[0].Message | Should -Be 'first note'
        $notes[1].Message | Should -Be 'second note'
    }

    It 'clears all notes on Reset-ADRunScopeNotes' {
        Add-ADRunScopeNote -Category 'PDC Scope' -Message 'will be cleared'
        Reset-ADRunScopeNotes
        Get-ADRunScopeNotes | Should -BeNullOrEmpty
    }
}

Describe 'Resolve-ADSecurityAuditTargetServer (PDC-scope run-scope note)' {
    BeforeEach {
        Reset-ADRunScopeNotes
        $Script:ADSecurityAuditServerIsExplicitDC = $false
    }

    It 'adds a run-scope note when -Server names an explicit DC that is NOT the PDC Emulator' {
        function Get-ADDomainController {
            param([string]$Identity, [switch]$ErrorAction)
            [PSCustomObject]@{ HostName = 'dc02.contoso.com'; Name = 'DC02' }
        }
        function Get-ADDomain {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{ PDCEmulator = 'dc01.contoso.com' }
        }

        $result = Resolve-ADSecurityAuditTargetServer -Server 'dc02.contoso.com'

        $result | Should -Be 'dc02.contoso.com'
        $notes = @(Get-ADRunScopeNotes)
        $notes.Count | Should -Be 1
        $notes[0].Category | Should -Be 'PDC Scope'
        $notes[0].Message | Should -Match 'dc02\.contoso\.com'
        $notes[0].Message | Should -Match 'dc01\.contoso\.com'
        $notes[0].Message | Should -Match 'PDC Emulator'
    }

    It 'STILL adds a run-scope note when -Server names an explicit DC that IS the PDC Emulator (reported gap: a single-DC scope is a coverage gap for every OTHER per-DC check regardless of whether the named DC happens to be the PDC)' {
        function Get-ADDomainController {
            param([string]$Identity, [switch]$ErrorAction)
            [PSCustomObject]@{ HostName = 'dc01.contoso.com'; Name = 'DC01' }
        }
        function Get-ADDomain {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{ PDCEmulator = 'dc01.contoso.com' }
        }

        $result = Resolve-ADSecurityAuditTargetServer -Server 'dc01.contoso.com'

        $result | Should -Be 'dc01.contoso.com'
        $notes = @(Get-ADRunScopeNotes)
        $notes.Count | Should -Be 1
        $notes[0].Category | Should -Be 'PDC Scope'
        $notes[0].Message | Should -Match 'dc01\.contoso\.com'
        $notes[0].Message | Should -Match 'also happens to be the domain''s PDC Emulator'
        $notes[0].Message | Should -Match 'other Domain Controller'
    }

    It 'the PDC comparison is case-insensitive (still notes the single-DC scope, but with the "is the PDC" wording)' {
        function Get-ADDomainController {
            param([string]$Identity, [switch]$ErrorAction)
            [PSCustomObject]@{ HostName = 'DC01.CONTOSO.COM'; Name = 'DC01' }
        }
        function Get-ADDomain {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{ PDCEmulator = 'dc01.contoso.com' }
        }

        Resolve-ADSecurityAuditTargetServer -Server 'DC01.CONTOSO.COM' | Out-Null
        $notes = @(Get-ADRunScopeNotes)
        $notes.Count | Should -Be 1
        $notes[0].Message | Should -Match 'also happens to be the domain''s PDC Emulator'
    }

    It 'adds NO run-scope note (and does not throw) when -Server is a domain name, not an explicit DC' {
        function Get-ADDomainController {
            param([string]$Identity, [switch]$ErrorAction)
            throw "Cannot find directory server with identity: 'contoso.com'"
        }
        function Get-ADDomain {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{ PDCEmulator = 'dc01.contoso.com' }
        }

        { Resolve-ADSecurityAuditTargetServer -Server 'contoso.com' } | Should -Not -Throw
        Get-ADRunScopeNotes | Should -BeNullOrEmpty
    }

    It 'does not throw when the PDC lookup itself fails, and still notes the single-DC scope (with an "unconfirmed PDC status" wording)' {
        function Get-ADDomainController {
            param([string]$Identity, [switch]$ErrorAction)
            [PSCustomObject]@{ HostName = 'dc02.contoso.com'; Name = 'DC02' }
        }
        function Get-ADDomain {
            param([switch]$ErrorAction, $Server)
            throw "domain unreachable"
        }

        { Resolve-ADSecurityAuditTargetServer -Server 'dc02.contoso.com' } | Should -Not -Throw
        $notes = @(Get-ADRunScopeNotes)
        $notes.Count | Should -Be 1
        $notes[0].Message | Should -Match 'dc02\.contoso\.com'
        $notes[0].Message | Should -Match 'could not be confirmed'
    }
}
