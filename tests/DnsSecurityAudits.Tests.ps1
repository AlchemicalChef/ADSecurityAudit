#Requires -Modules Pester
<#
    Unit tests for the "Stale/Dangling DNS Zone Delegation" check (PingCastle
    P-DNSDelegation-comparable) added as a fifth check to Test-ADDnsSecurity
    in src/DnsSecurityAudits.ps1.

    This check (like the zone-transfer/dynamic-update/ADIDNS checks it sits
    alongside) is live-only: it reads zone-level attributes/ACLs/delegation
    records. These tests shadow every live AD/DNS cmdlet the function
    touches: Get-ADGroup, Get-ADDomain,
    Get-ADForest, Get-ADObject, Get-Module, Get-ADDomainController,
    Import-Module, Get-DnsServerZone, Get-DnsServerZoneDelegation,
    Get-ADReplicationSubnet, and Resolve-DnsName. No real Active Directory,
    DnsServer module, or network access is used.

    Run from the repo root:  Invoke-Pester ./tests/DnsSecurityAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    # Test-ADIpInCidrRange (used for the "outside known AD subnets"
    # informational signal) lives in StaleObjectDepthAudits.ps1 and is
    # shared module-scope, exactly as it is at runtime via ADSecurityAudit.psm1.
    . (Join-Path $root 'src/StaleObjectDepthAudits.ps1')
    . (Join-Path $root 'src/DnsSecurityAudits.ps1')
}

Describe 'Test-ADDnsSecurity (Stale/Dangling DNS Zone Delegation)' {
    BeforeEach {
        function Get-ADGroup { param($Filter, [switch]$ErrorAction) $null }
        function Get-ADDomain {
            param([switch]$ErrorAction)
            [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com'; DNSRoot = 'contoso.com' }
        }
        function Get-ADForest { param([switch]$ErrorAction) $null }
        function Get-ADObject {
            param($SearchBase, $Filter, $Properties, [switch]$ErrorAction)
            @(
                [PSCustomObject]@{
                    Name                 = 'contoso.com'
                    DistinguishedName    = 'DC=contoso.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=contoso,DC=com'
                    dNSProperty          = @()
                    nTSecurityDescriptor = $null
                }
            )
        }
        function Get-Module {
            param([switch]$ListAvailable, $Name, [switch]$ErrorAction)
            [PSCustomObject]@{ Name = 'DnsServer' }
        }
        function Get-ADDomainController {
            param([switch]$Discover, [switch]$ErrorAction)
            [PSCustomObject]@{ HostName = 'dc1.contoso.com' }
        }
        function Import-Module { param($Name, [switch]$ErrorAction) }
        function Get-DnsServerZone {
            param($Name, $ComputerName, [switch]$ErrorAction)
            $null
        }
        function Get-ADReplicationSubnet {
            param($Filter, $Properties, [switch]$ErrorAction)
            @()
        }
    }

    It 'produces no finding when zero delegations exist for the zone' {
        function Get-DnsServerZoneDelegation { param($ZoneName, $ComputerName, [switch]$ErrorAction) @() }
        function Resolve-DnsName { param($Name, $Server, $Type, [switch]$DnsOnly, [switch]$ErrorAction) throw "should not be called" }

        { Test-ADDnsSecurity } | Should -Not -Throw
        $findings = Test-ADDnsSecurity
        ($findings | Where-Object { $_.Issue -eq 'Stale/Dangling DNS Zone Delegation' }) | Should -BeNullOrEmpty
    }

    It 'produces no finding when the delegation glue server still answers an SOA query' {
        function Get-DnsServerZoneDelegation {
            param($ZoneName, $ComputerName, [switch]$ErrorAction)
            @(
                [PSCustomObject]@{
                    ChildZoneName = 'child.contoso.com'
                    NameServer    = @([PSCustomObject]@{ Name = 'ns1.contoso.com'; IPAddress = @('10.0.0.5') })
                }
            )
        }
        function Resolve-DnsName {
            param($Name, $Server, $Type, [switch]$DnsOnly, [switch]$ErrorAction)
            [PSCustomObject]@{ Type = 'SOA'; Name = $Name }
        }

        $findings = Test-ADDnsSecurity
        ($findings | Where-Object { $_.Issue -eq 'Stale/Dangling DNS Zone Delegation' }) | Should -BeNullOrEmpty
    }

    It 'fires when the delegation glue server does not answer (stale), naming the NS/glue IP, and rates Medium for a private glue IP' {
        function Get-DnsServerZoneDelegation {
            param($ZoneName, $ComputerName, [switch]$ErrorAction)
            @(
                [PSCustomObject]@{
                    ChildZoneName = 'child.contoso.com'
                    NameServer    = @([PSCustomObject]@{ Name = 'ns1.contoso.com'; IPAddress = @('10.0.0.5') })
                }
            )
        }
        function Resolve-DnsName {
            param($Name, $Server, $Type, [switch]$DnsOnly, [switch]$ErrorAction)
            throw "DNS name does not exist"
        }

        $findings = Test-ADDnsSecurity
        $finding = $findings | Where-Object { $_.Issue -eq 'Stale/Dangling DNS Zone Delegation' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Category | Should -Be 'DNS Security'
        $finding.Severity | Should -Be 'Medium'
        $finding.SeverityLevel | Should -Be 2
        $finding.AffectedObject | Should -Match 'child.contoso.com'
        $finding.Details.StaleDelegations.NameServer | Should -Contain 'ns1.contoso.com'
        $finding.Details.StaleDelegations.GlueIpAddress | Should -Contain '10.0.0.5'
        $finding.Details.StaleDelegations.IsPublicIpAddress | Should -Contain $false
    }

    It 'rates High when the unresponsive glue server sits on a public IP address' {
        function Get-DnsServerZoneDelegation {
            param($ZoneName, $ComputerName, [switch]$ErrorAction)
            @(
                [PSCustomObject]@{
                    ChildZoneName = 'child.contoso.com'
                    NameServer    = @([PSCustomObject]@{ Name = 'ns1.example.net'; IPAddress = @('203.0.113.5') })
                }
            )
        }
        function Resolve-DnsName {
            param($Name, $Server, $Type, [switch]$DnsOnly, [switch]$ErrorAction)
            throw "timed out"
        }

        $findings = Test-ADDnsSecurity
        $finding = $findings | Where-Object { $_.Issue -eq 'Stale/Dangling DNS Zone Delegation' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'High'
        $finding.SeverityLevel | Should -Be 3
        $finding.Details.StaleDelegations.IsPublicIpAddress | Should -Contain $true
    }

    It 'does NOT flag a delegation that answers correctly merely because its glue IP is outside known AD subnets' {
        function Get-ADReplicationSubnet {
            param($Filter, $Properties, [switch]$ErrorAction)
            @([PSCustomObject]@{ Name = '10.0.0.0/24' })
        }
        function Get-DnsServerZoneDelegation {
            param($ZoneName, $ComputerName, [switch]$ErrorAction)
            @(
                [PSCustomObject]@{
                    ChildZoneName = 'child.contoso.com'
                    NameServer    = @([PSCustomObject]@{ Name = 'ns1.cloud-dns.example'; IPAddress = @('198.51.100.9') })
                }
            )
        }
        function Resolve-DnsName {
            param($Name, $Server, $Type, [switch]$DnsOnly, [switch]$ErrorAction)
            [PSCustomObject]@{ Type = 'SOA'; Name = $Name }
        }

        $findings = Test-ADDnsSecurity
        ($findings | Where-Object { $_.Issue -eq 'Stale/Dangling DNS Zone Delegation' }) | Should -BeNullOrEmpty
    }

    It 'does not double-append the parent zone when ChildZoneName has a trailing root dot (regression, v1.24.0)' {
        # Get-DnsServerZoneDelegation can return an FQDN with a trailing
        # root dot (e.g. '_msdcs.contoso.com.'). Before the fix this broke
        # the "already fully-qualified" match and produced a malformed,
        # doubled zone name like '_msdcs.contoso.com..contoso.com', which
        # then got queried via Resolve-DnsName -Name <malformed name>.
        function Get-DnsServerZoneDelegation {
            param($ZoneName, $ComputerName, [switch]$ErrorAction)
            @(
                [PSCustomObject]@{
                    ChildZoneName = '_msdcs.contoso.com.'
                    NameServer    = @([PSCustomObject]@{ Name = 'ns1.contoso.com'; IPAddress = @('10.0.0.5') })
                }
            )
        }
        $Script:__resolvedNames = [System.Collections.ArrayList]::new()
        function Resolve-DnsName {
            param($Name, $Server, $Type, [switch]$DnsOnly, [switch]$ErrorAction)
            [void]$Script:__resolvedNames.Add($Name)
            [PSCustomObject]@{ Type = 'SOA'; Name = $Name }
        }

        $findings = Test-ADDnsSecurity
        $Script:__resolvedNames | Should -Contain '_msdcs.contoso.com'
        $Script:__resolvedNames | Should -Not -Contain '_msdcs.contoso.com..contoso.com'
        ($findings | Where-Object { $_.Issue -eq 'Stale/Dangling DNS Zone Delegation' }) | Should -BeNullOrEmpty
    }
}
