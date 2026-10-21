#Requires -Modules Pester
<#
    Unit tests for the new Check 6 in Test-ADLegacyAuthSurface
    (LegacyAuthAudits.ps1): 'NTLM Authentication Not Restricted in Domain'
    (RestrictNTLMInDomain), distinct from the existing Check 3
    (LmCompatibilityLevel, which only restricts which NTLM *version* is
    permitted).

    These tests shadow Get-ADPolicyRegistryValue and
    Get-ADLiveRegistryValuePerDc directly (both plain functions dot-sourced
    from this same file) rather than their own GPO/registry internals, so
    each of the six checks' registry value can be controlled directly by
    -ValueName without needing to fake Get-GPRegistryValue/Invoke-Command.
    Get-ADLinkedGposOrdered is shadowed to return no linked GPOs, so every
    check exercises its live per-DC fallback path. No real Active
    Directory, GPO, or registry access is used.

    Run from the repo root:  Invoke-Pester ./tests/LegacyAuthAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/LegacyAuthAudits.ps1')

    function Import-Module { param($Name, [switch]$ErrorAction) }
    function Get-ADDomain {
        param([switch]$ErrorAction, $Server)
        [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com'; DNSRoot = 'contoso.com' }
    }
    function Get-ADDomainController {
        param($Filter, $Server, $Identity, $ErrorAction)
        @([PSCustomObject]@{ Name = 'DC01'; HostName = 'DC01.contoso.com'; Domain = 'contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com' })
    }
    # No linked GPOs at all - forces every check onto its live per-DC
    # registry fallback, which is the path these tests exercise.
    function Get-ADLinkedGposOrdered { param($TargetDn, $Server) @() }

    # Safe/clean live values for every check OTHER than the NTLM-
    # restriction one, so a test focused on Check 6 doesn't also trip
    # Checks 1-5 and complicate result filtering. Overridden per-test only
    # for RestrictNTLMInDomain.
    function Get-ADLiveRegistryValuePerDc {
        param($DomainControllers, $Key, $ValueName)
        $cleanValue = switch ($ValueName) {
            'SMB1'                      { 0 }     # disabled
            'RequireSecuritySignature'  { 1 }     # required
            'LmCompatibilityLevel'      { 5 }     # NTLMv2-only
            'EnableMulticast'           { 0 }     # LLMNR disabled
            'WUServer'                  { $null } # not configured
            'RestrictNTLMInDomain'      { 5 }     # partially restricted (deny some), overridden per test
            default                     { $null }
        }
        @($DomainControllers | ForEach-Object {
            $dcName = if ($_.HostName) { $_.HostName } else { $_.Name }
            [PSCustomObject]@{ DomainController = $dcName; Value = $cleanValue; Error = $null }
        })
    }
}

Describe 'Test-ADLegacyAuthSurface - NTLM Authentication Not Restricted in Domain' {
    It 'flags when RestrictNTLMInDomain is 0 (Allow all) via live per-DC read' {
        function Get-ADLiveRegistryValuePerDc {
            param($DomainControllers, $Key, $ValueName)
            $cleanValue = switch ($ValueName) {
                'SMB1'                      { 0 }
                'RequireSecuritySignature'  { 1 }
                'LmCompatibilityLevel'      { 5 }
                'EnableMulticast'           { 0 }
                'WUServer'                  { $null }
                'RestrictNTLMInDomain'      { 0 }
                default                     { $null }
            }
            @($DomainControllers | ForEach-Object {
                [PSCustomObject]@{ DomainController = $_.HostName; Value = $cleanValue; Error = $null }
            })
        }

        $findings = Test-ADLegacyAuthSurface
        $hit = $findings | Where-Object { $_.Issue -eq 'NTLM Authentication Not Restricted in Domain' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Severity | Should -Be 'Medium'
        $hit.Details.AffectedDomainControllers | Should -Contain 'DC01.contoso.com'
    }

    It 'flags when RestrictNTLMInDomain has no value on any DC and no enforcing GPO (unset defaults to unrestricted)' {
        function Get-ADLiveRegistryValuePerDc {
            param($DomainControllers, $Key, $ValueName)
            $cleanValue = switch ($ValueName) {
                'SMB1'                      { 0 }
                'RequireSecuritySignature'  { 1 }
                'LmCompatibilityLevel'      { 5 }
                'EnableMulticast'           { 0 }
                'WUServer'                  { $null }
                'RestrictNTLMInDomain'      { $null }
                default                     { $null }
            }
            @($DomainControllers | ForEach-Object {
                [PSCustomObject]@{ DomainController = $_.HostName; Value = $cleanValue; Error = $null }
            })
        }

        $findings = Test-ADLegacyAuthSurface
        ($findings | Where-Object { $_.Issue -eq 'NTLM Authentication Not Restricted in Domain' }) | Should -Not -BeNullOrEmpty
    }

    It 'does not flag when RestrictNTLMInDomain is enforced via GPO at a non-zero (at least partially restricted) level' {
        function Get-ADPolicyRegistryValue {
            param($Gpos, $Key, $ValueName, $Server)
            if ($ValueName -eq 'RestrictNTLMInDomain') {
                return [PSCustomObject]@{ Value = 7; Source = 'Default Domain Policy' }
            }
            return $null
        }

        $findings = Test-ADLegacyAuthSurface
        ($findings | Where-Object { $_.Issue -eq 'NTLM Authentication Not Restricted in Domain' }) | Should -BeNullOrEmpty
    }

    It 'flags when RestrictNTLMInDomain is enforced via GPO at 0 (Allow all), naming the enforcing GPO as the source' {
        function Get-ADPolicyRegistryValue {
            param($Gpos, $Key, $ValueName, $Server)
            if ($ValueName -eq 'RestrictNTLMInDomain') {
                return [PSCustomObject]@{ Value = 0; Source = 'Default Domain Policy' }
            }
            return $null
        }

        $findings = Test-ADLegacyAuthSurface
        $hit = $findings | Where-Object { $_.Issue -eq 'NTLM Authentication Not Restricted in Domain' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.Description | Should -Match 'Default Domain Policy'
    }

    It 'does not flag when RestrictNTLMInDomain is at least partially restricted (non-zero) on every DC via live read' {
        # Uses the BeforeAll default (RestrictNTLMInDomain = 5 live, no GPO).
        $findings = Test-ADLegacyAuthSurface
        ($findings | Where-Object { $_.Issue -eq 'NTLM Authentication Not Restricted in Domain' }) | Should -BeNullOrEmpty
    }

    It 'remains distinct from the existing LM/NTLMv1 (LmCompatibilityLevel) check - flags one without the other' {
        function Get-ADLiveRegistryValuePerDc {
            param($DomainControllers, $Key, $ValueName)
            $cleanValue = switch ($ValueName) {
                'SMB1'                      { 0 }
                'RequireSecuritySignature'  { 1 }
                'LmCompatibilityLevel'      { 5 }     # NTLMv2-only: this check should NOT fire
                'EnableMulticast'           { 0 }
                'WUServer'                  { $null }
                'RestrictNTLMInDomain'      { 0 }     # unrestricted: this check SHOULD fire
                default                     { $null }
            }
            @($DomainControllers | ForEach-Object {
                [PSCustomObject]@{ DomainController = $_.HostName; Value = $cleanValue; Error = $null }
            })
        }

        $findings = Test-ADLegacyAuthSurface
        ($findings | Where-Object { $_.Issue -eq 'NTLM Authentication Not Restricted in Domain' }) | Should -Not -BeNullOrEmpty
        ($findings | Where-Object { $_.Issue -eq 'LM/NTLMv1 Authentication Permitted' }) | Should -BeNullOrEmpty
    }
}
