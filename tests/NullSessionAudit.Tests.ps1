#Requires -Modules Pester
<#
    Unit tests for the null-session pipe/share check (RestrictNullSessAccess /
    NullSessionPipes / NullSessionShares - PingCastle A-NullSession-comparable)
    added as "Check 4" to Test-ADDomainHardeningFlags.

    This check is live-only (GPO-linked registry policy state and per-DC
    registry reads). These tests shadow every live AD/GPO/registry cmdlet
    the check touches:
    Import-Module, Get-ADDomain, Get-ADDomainController, Get-GPInheritance,
    Get-GPO, Get-GPRegistryValue, and Invoke-Command. No real Active
    Directory, GroupPolicy module, or network access is used.

    Check 1 (dSHeuristics) and Check 2 (Pre-Win2000 membership) also run in
    this mode, but both fail fast and
    harmlessly: Check 1's raw ADSI RootDSE bind throws immediately with no
    real directory service present, and Check 2's Get-ADGroup call is an
    unrecognized command - both are caught by their own existing try/catch
    blocks and produce no findings. Check 3 (anonymous bind) is short-
    circuited by the shadowed Get-ADDomainController below returning no
    -Discover target.

    Run from the repo root:  Invoke-Pester ./tests/NullSessionAudit.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/LegacyAuthAudits.ps1')
    . (Join-Path $root 'src/DomainHardeningAudits.ps1')
}

Describe 'Test-ADDomainHardeningFlags (Null-Session Pipe/Share Access - GPO-enforced)' {
    BeforeEach {
        function Import-Module { param($Name, [switch]$ErrorAction) }
        function Get-ADDomain { [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com'; DNSRoot = 'contoso.com' } }
        function Get-ADDomainController {
            param([switch]$Discover, [string]$Filter, [switch]$ErrorAction)
            if ($Discover) { return $null }
            return @([PSCustomObject]@{ HostName = 'dc1.contoso.com'; Name = 'DC1'; ComputerObjectDN = 'CN=DC1,OU=Domain Controllers,DC=contoso,DC=com' })
        }
        function Get-GPInheritance {
            param($Target, [switch]$ErrorAction)
            [PSCustomObject]@{ GpoLinks = @([PSCustomObject]@{ GpoId = 'AAAAAAAA-0000-0000-0000-000000000010'; Order = 1 }) }
        }
        function Get-GPO { param($Guid, [switch]$ErrorAction) [PSCustomObject]@{ Id = $Guid; DisplayName = 'NullSessionPolicy' } }
    }

    It 'produces no finding when RestrictNullSessAccess is enabled (1) via GPO (case a)' {
        function Get-GPRegistryValue {
            param($Guid, $Key, $ValueName, [switch]$ErrorAction)
            if ($ValueName -eq 'RestrictNullSessAccess') { return [PSCustomObject]@{ Value = 1 } }
            throw "not set"
        }

        $findings = Test-ADDomainHardeningFlags
        ($findings | Where-Object { $_.Issue -eq 'Null-Session Pipe/Share Access Permitted' }) | Should -BeNullOrEmpty
    }

    It 'fires when RestrictNullSessAccess is disabled (0) via GPO, naming the GPO source (case b)' {
        function Get-GPRegistryValue {
            param($Guid, $Key, $ValueName, [switch]$ErrorAction)
            if ($ValueName -eq 'RestrictNullSessAccess') { return [PSCustomObject]@{ Value = 0 } }
            if ($ValueName -eq 'NullSessionPipes')  { return [PSCustomObject]@{ Value = @('COMCALL', 'NETLOGON') } }
            if ($ValueName -eq 'NullSessionShares') { return [PSCustomObject]@{ Value = @() } }
            throw "not set"
        }

        $findings = Test-ADDomainHardeningFlags
        $finding = $findings | Where-Object { $_.Issue -eq 'Null-Session Pipe/Share Access Permitted' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'Medium'
        $finding.SeverityLevel | Should -Be 2
        $finding.Category | Should -Be 'Domain Hardening'
        $finding.Details.Source | Should -Match 'GPO: NullSessionPolicy'
        $finding.Details.NullSessionPipes | Should -Contain 'COMCALL'
        $finding.Description | Should -Match 'RestrictNullSessAccess'
    }
}

Describe 'Test-ADDomainHardeningFlags (Null-Session Pipe/Share Access - live per-DC fallback)' {
    BeforeEach {
        function Import-Module { param($Name, [switch]$ErrorAction) }
        function Get-ADDomain { [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com'; DNSRoot = 'contoso.com' } }
        function Get-ADDomainController {
            param([switch]$Discover, [string]$Filter, [switch]$ErrorAction)
            if ($Discover) { return $null }
            return @([PSCustomObject]@{ HostName = 'dc1.contoso.com'; Name = 'DC1'; ComputerObjectDN = 'CN=DC1,OU=Domain Controllers,DC=contoso,DC=com' })
        }
        # No linked GPOs anywhere - forces the live per-DC fallback path.
        function Get-GPInheritance { param($Target, [switch]$ErrorAction) [PSCustomObject]@{ GpoLinks = @() } }
        function Get-GPO { param($Guid, [switch]$ErrorAction) $null }
    }

    It 'fires via the live per-DC fallback when no GPO defines the value and a DC reports it disabled (case c)' {
        function Invoke-Command {
            param($ComputerName, $ScriptBlock, $ArgumentList, [switch]$ErrorAction)
            $valueName = $ArgumentList[1]
            switch ($valueName) {
                'RestrictNullSessAccess' { return 0 }
                default { return $null }
            }
        }

        $findings = Test-ADDomainHardeningFlags
        $finding = $findings | Where-Object { $_.Issue -eq 'Null-Session Pipe/Share Access Permitted' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'Medium'
        $finding.Details.Source | Should -Match 'No enforcing GPO found'
        $finding.Details.AffectedDomainControllers | Should -Contain 'dc1.contoso.com'
    }

    It 'produces no finding when no GPO defines the value and the live per-DC read is unavailable (case d)' {
        function Invoke-Command {
            param($ComputerName, $ScriptBlock, $ArgumentList, [switch]$ErrorAction)
            throw "The RPC server is unavailable."
        }

        { Test-ADDomainHardeningFlags } | Should -Not -Throw
        $findings = Test-ADDomainHardeningFlags
        ($findings | Where-Object { $_.Issue -eq 'Null-Session Pipe/Share Access Permitted' }) | Should -BeNullOrEmpty
    }

    It 'produces no finding when the live per-DC read reports RestrictNullSessAccess already enabled' {
        function Invoke-Command {
            param($ComputerName, $ScriptBlock, $ArgumentList, [switch]$ErrorAction)
            $valueName = $ArgumentList[1]
            switch ($valueName) {
                'RestrictNullSessAccess' { return 1 }
                default { return $null }
            }
        }

        $findings = Test-ADDomainHardeningFlags
        ($findings | Where-Object { $_.Issue -eq 'Null-Session Pipe/Share Access Permitted' }) | Should -BeNullOrEmpty
    }
}
