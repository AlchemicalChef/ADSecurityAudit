#Requires -Modules Pester
<#
    Unit tests for Test-LAPSDeployment (src/LapsAudits.ps1).

    This module previously had NO Pester coverage at all - a real gap
    found while reviewing v1.30.0's new 'Legacy LAPS SearchFlags Exposes
    Password' check (files/17-key-material-exposure.md), which was added
    to this file but shipped with no regression test protecting it or the
    pre-existing checks in the same function.

    This file intentionally focuses on the new SearchFlags check only -
    it does not attempt full coverage of Test-LAPSDeployment's existing
    schema-presence/coverage/expiration checks, which would need their
    own, separate pass. Get-ADComputer is stubbed to return no computers
    so the (unrelated) coverage checks stay quiet and don't add noise to
    these assertions.

    Shadows Get-ADDomain, Get-ADRootDSE, Get-ADObject, and Get-ADComputer
    with local functions - no real Active Directory or connectivity is
    required.

    Run from the repo root:  Invoke-Pester ./tests/LapsAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/LapsAudits.ps1')

    function Get-ADDomain {
        param($Server)
        [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com'; NetBIOSName = 'CONTOSO' }
    }

    function Get-ADRootDSE {
        param($Server)
        [PSCustomObject]@{ schemaNamingContext = 'CN=Schema,CN=Configuration,DC=contoso,DC=com' }
    }

    # No computers to evaluate for the (unrelated) coverage/expiration
    # checks, per the file header above.
    function Get-ADComputer {
        param($Filter, $Properties, $ResultPageSize, $Server)
        @()
    }
}

Describe 'Test-LAPSDeployment / Legacy LAPS SearchFlags Exposes Password' {
    It 'flags ms-Mcs-AdmPwd when the confidential (fCONFIDENTIAL, 0x80) bit is NOT set' {
        function Get-ADObject {
            param($Identity, $Properties, $Server, $ErrorAction)
            if ($Identity -like 'CN=ms-Mcs-AdmPwd,*') {
                # searchFlags = 0 (no bits set at all) - fCONFIDENTIAL missing.
                return [PSCustomObject]@{ DistinguishedName = $Identity; searchFlags = 0 }
            }
            throw "not found: $Identity"
        }

        $findings = Test-LAPSDeployment
        $finding = $findings | Where-Object { $_.Issue -eq 'Legacy LAPS SearchFlags Exposes Password' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'High'
        $finding.Details.SearchFlags | Should -Be 0
    }

    It 'does NOT flag ms-Mcs-AdmPwd when the confidential (fCONFIDENTIAL, 0x80) bit IS set' {
        function Get-ADObject {
            param($Identity, $Properties, $Server, $ErrorAction)
            if ($Identity -like 'CN=ms-Mcs-AdmPwd,*') {
                # searchFlags = 0x80 (fCONFIDENTIAL) | 0x200 (fRODCFilteredAttribute)
                # = 0x280 = 640 - a correctly locked-down deployment.
                return [PSCustomObject]@{ DistinguishedName = $Identity; searchFlags = 640 }
            }
            throw "not found: $Identity"
        }

        $findings = Test-LAPSDeployment
        ($findings | Where-Object { $_.Issue -eq 'Legacy LAPS SearchFlags Exposes Password' }) | Should -BeNullOrEmpty
    }

    It 'does NOT run the SearchFlags check at all for a Windows-LAPS-only deployment (no legacy attribute)' {
        function Get-ADObject {
            param($Identity, $Properties, $Server, $ErrorAction)
            if ($Identity -like 'CN=ms-Mcs-AdmPwd,*') {
                throw "legacy LAPS schema attribute not present"
            }
            if ($Identity -like 'CN=ms-LAPS-Password,*') {
                return [PSCustomObject]@{ DistinguishedName = $Identity }
            }
            throw "not found: $Identity"
        }

        { Test-LAPSDeployment } | Should -Not -Throw
        $findings = Test-LAPSDeployment
        ($findings | Where-Object { $_.Issue -eq 'Legacy LAPS SearchFlags Exposes Password' }) | Should -BeNullOrEmpty
        ($findings | Where-Object { $_.Issue -eq 'LAPS Not Deployed' }) | Should -BeNullOrEmpty
    }
}
