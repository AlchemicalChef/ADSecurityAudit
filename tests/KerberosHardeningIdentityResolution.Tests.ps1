#Requires -Modules Pester
<#
    Regression test for v1.24.0: Test-ADKerberosHardening's live-mode RC4
    account check preferred each Tier-0 principal's SID over its
    DistinguishedName when calling Get-ADObject. In a lab run, this caused
    all 8 of 8 Tier-0 principal lookups to fail with "Cannot find an object
    with identity: '<SID>'" even though the same objects resolved fine by
    DistinguishedName elsewhere in the very same run - silently skipping
    the RC4 check for every privileged account.

    This test shadows Get-ADObject to throw for any SID-shaped -Identity
    (reproducing the failure mode) and succeed for a DistinguishedName, then
    asserts the check completes and flags an RC4-permitted account rather
    than silently finding nothing.

    Run from the repo root:  Invoke-Pester ./tests/KerberosHardeningIdentityResolution.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/KerberosHardeningAudits.ps1')
}

Describe 'Test-ADKerberosHardening (Tier-0 identity resolution, live mode)' {
    BeforeEach {
        function Get-ADGroup {
            param($Filter, $Server, [switch]$ErrorAction)
            # Only 'Domain Admins' resolves - enough to exercise the
            # Tier-0 resolution path once; every other protected group
            # legitimately returns nothing in this minimal fixture.
            if ("$Filter" -match 'Domain Admins') {
                return [PSCustomObject]@{ Name = 'Domain Admins'; DistinguishedName = 'CN=Domain Admins,CN=Users,DC=contoso,DC=com' }
            }
            $null
        }
        function Get-ADForest { param([switch]$ErrorAction) $null }
        function Get-ADUser {
            param($Filter, $Server, $Properties, [switch]$ErrorAction)
            # krbtgt lookup - AES-only, not part of what this test asserts.
            [PSCustomObject]@{
                SamAccountName            = 'krbtgt'
                DistinguishedName         = 'CN=krbtgt,CN=Users,DC=contoso,DC=com'
                'msDS-SupportedEncryptionTypes' = 24  # AES128+AES256, no RC4
            }
        }
        function Get-ADObject {
            param($Identity, $Server, $Properties, [switch]$ErrorAction)
            # Reproduces the lab failure mode: a SID-shaped identity fails,
            # exactly as observed live; a DistinguishedName succeeds.
            if ("$Identity" -match '^S-1-5-21-') {
                throw "Cannot find an object with identity: '$Identity' under: 'DC=contoso,DC=com'."
            }
            [PSCustomObject]@{
                DistinguishedName = "$Identity"
                objectClass       = 'user'
                'msDS-SupportedEncryptionTypes' = 4  # RC4 only - should be flagged
            }
        }
        function Get-ADTrust { param($Filter, $Server, $Properties, [switch]$ErrorAction) throw "not relevant to this test" }
        function Import-Module { param($Name, [switch]$ErrorAction) throw "not relevant to this test" }
    }

    It 'still detects an RC4-permitted Tier-0 account when Get-ADObject rejects SID-based lookups (regression, v1.24.0)' {
        function Get-ADGroupMember {
            param($Identity, [switch]$Recursive, $Server, [switch]$ErrorAction)
            @(
                [PSCustomObject]@{
                    SID               = [PSCustomObject]@{ Value = 'S-1-5-21-1111111111-2222222222-3333333333-500' }
                    SamAccountName    = 'Administrator'
                    DistinguishedName = 'CN=Administrator,CN=Users,DC=contoso,DC=com'
                    objectClass       = 'user'
                }
            )
        }

        $findings = Test-ADKerberosHardening
        $finding = $findings | Where-Object { $_.Issue -eq 'RC4 Kerberos Encryption Still Permitted' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Details.PrivilegedAndKrbtgtAccountsPermittingRC4 |
            Where-Object { $_.SamAccountName -eq 'Administrator' } |
            Should -Not -BeNullOrEmpty
    }
}
