#Requires -Modules Pester
<#
    Unit tests for two related bug fixes in Test-ADStaleObjectDepth
    (src/StaleObjectDepthAudits.ps1):

      1. "Insufficient Domain Controller Count" previously reused the
         -Server-SCOPED $domainControllers list for its count, so a run
         with -Server narrowed to one specific DC always reported "only 1
         Domain Controller" regardless of the domain's true DC total.
      2. The primaryGroupID=516 (Domain Controllers) legitimacy check used
         that same -Server-scoped list to decide which computer objects
         are legitimately DCs - narrowing it to one explicitly-named DC
         caused every OTHER real DC's computer object to be misclassified
         as a non-DC holding a suspicious primaryGroupID (a false
         positive).

    Both are now driven by a separately-collected, always-unscoped DC
    inventory (Get-ADSecurityAuditDomainController -IgnoreExplicitDCScope),
    independent of whatever -Server scoping narrowed the
    per-DC-probe list used elsewhere in the same function.

    These tests shadow every live AD cmdlet touched: Get-ADUser,
    Get-ADComputer, Get-ADDomain, Get-ADDomainController,
    Get-ADReplicationSubnet. No real Active Directory access is used.

    Run from the repo root:  Invoke-Pester ./tests/StaleObjectDepthAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/StaleObjectDepthAudits.ps1')
}

Describe 'Test-ADStaleObjectDepth (true DC count / primaryGroupID legitimacy)' {
    BeforeEach {
        function Get-ADUser {
            param($Filter, $ResultPageSize, $Server, [switch]$ErrorAction, $Properties)
            @()
        }
        function Get-ADComputer {
            param($Filter, $ResultPageSize, $Server, [switch]$ErrorAction, $Properties)
            @(
                [PSCustomObject]@{ SamAccountName = 'DC01$'; DistinguishedName = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com'; Enabled = $true; userAccountControl = 532480; PrimaryGroupID = 516; ServicePrincipalNames = @() }
                [PSCustomObject]@{ SamAccountName = 'DC02$'; DistinguishedName = 'CN=DC02,OU=Domain Controllers,DC=contoso,DC=com'; Enabled = $true; userAccountControl = 532480; PrimaryGroupID = 516; ServicePrincipalNames = @() }
            )
        }
        function Get-ADDomain {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' }
        }
        function Get-ADReplicationSubnet {
            param($Filter, $Properties, [switch]$ErrorAction)
            @()
        }
    }

    It 'reports the TRUE domain-wide DC count (2) even though -Server (simulated via the explicit-DC flag) narrows the per-DC-probe list to one DC' {
        # Simulate an active "-Server named one specific DC" override: the
        # explicit-DC flag is what Get-ADSecurityAuditDomainController
        # checks to decide whether to narrow its result.
        $Script:ADSecurityAuditServerIsExplicitDC = $true
        try {
            function Get-ADDomainController {
                param($Filter, $Server, $Identity, [switch]$ErrorAction)
                if ($Identity) {
                    return [PSCustomObject]@{ Name = 'DC01'; HostName = 'DC01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com'; Domain = 'contoso.com'; IsReadOnly = $false }
                }
                # -Filter path (used both by the normal enumeration and by
                # -IgnoreExplicitDCScope): returns BOTH real DCs, since the
                # forest-wide Configuration container is fully replicated
                # and reachable regardless of which DC answers.
                @(
                    [PSCustomObject]@{ Name = 'DC01'; HostName = 'DC01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com'; Domain = 'contoso.com'; IsReadOnly = $false }
                    [PSCustomObject]@{ Name = 'DC02'; HostName = 'DC02.contoso.com'; ComputerObjectDN = 'CN=DC02,OU=Domain Controllers,DC=contoso,DC=com'; Domain = 'contoso.com'; IsReadOnly = $false }
                )
            }

            $findings = Test-ADStaleObjectDepth
            ($findings | Where-Object { $_.Issue -eq 'Insufficient Domain Controller Count' }) | Should -BeNullOrEmpty
            ($findings | Where-Object { $_.Issue -eq 'Non-Default primaryGroupID (Membership Hiding)' }) | Should -BeNullOrEmpty
        }
        finally {
            $Script:ADSecurityAuditServerIsExplicitDC = $false
        }
    }

    It 'fires Insufficient Domain Controller Count with the true count when the domain genuinely has only one DC' {
        $Script:ADSecurityAuditServerIsExplicitDC = $false
        function Get-ADComputer {
            param($Filter, $ResultPageSize, $Server, [switch]$ErrorAction, $Properties)
            @([PSCustomObject]@{ SamAccountName = 'DC01$'; DistinguishedName = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com'; Enabled = $true; userAccountControl = 532480; PrimaryGroupID = 516; ServicePrincipalNames = @() })
        }
        function Get-ADDomainController {
            param($Filter, $Server, $Identity, [switch]$ErrorAction)
            @([PSCustomObject]@{ Name = 'DC01'; HostName = 'DC01.contoso.com'; ComputerObjectDN = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com'; Domain = 'contoso.com'; IsReadOnly = $false })
        }

        $findings = Test-ADStaleObjectDepth
        $finding = $findings | Where-Object { $_.Issue -eq 'Insufficient Domain Controller Count' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Details.DomainControllerCount | Should -Be 1
    }
}

Describe 'Get-ADSecurityAuditDomainController -IgnoreExplicitDCScope' {
    BeforeEach {
        function Get-ADDomain {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{ DNSRoot = 'contoso.com' }
        }
        function Get-ADDomainController {
            param($Filter, $Server, $Identity, [switch]$ErrorAction)
            if ($Identity) {
                return [PSCustomObject]@{ Name = 'DC07'; HostName = 'DC07.contoso.com'; Domain = 'contoso.com' }
            }
            @(
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'DC01.contoso.com'; Domain = 'contoso.com' }
                [PSCustomObject]@{ Name = 'DC07'; HostName = 'DC07.contoso.com'; Domain = 'contoso.com' }
            )
        }
    }

    It 'narrows to one DC by default when the server override is an explicit DC' {
        $Script:ADSecurityAuditServerIsExplicitDC = $true
        try {
            $result = @(Get-ADSecurityAuditDomainController -Server 'DC07.contoso.com')
            $result.Count | Should -Be 1
            $result[0].Name | Should -Be 'DC07'
        }
        finally {
            $Script:ADSecurityAuditServerIsExplicitDC = $false
        }
    }

    It 'returns every DC in the domain when -IgnoreExplicitDCScope is set, even though the server override is an explicit DC' {
        $Script:ADSecurityAuditServerIsExplicitDC = $true
        try {
            $result = @(Get-ADSecurityAuditDomainController -Server 'DC07.contoso.com' -IgnoreExplicitDCScope)
            $result.Count | Should -Be 2
        }
        finally {
            $Script:ADSecurityAuditServerIsExplicitDC = $false
        }
    }
}

Describe 'Get-ADTargetDomainController (PDC preference)' {
    BeforeEach {
        function Get-ADDomainController {
            param($Filter, $Server, $Identity, [switch]$ErrorAction)
            @(
                [PSCustomObject]@{ Name = 'DC02'; HostName = 'DC02.contoso.com'; Domain = 'contoso.com' }
                [PSCustomObject]@{ Name = 'DC01'; HostName = 'DC01.contoso.com'; Domain = 'contoso.com' }
            )
        }
    }

    It 'prefers the domain PDC Emulator over the first enumerated DC when the target is a domain name' {
        $Global:PSDefaultParameterValues = @{ 'Get-AD*:Server' = 'contoso.com' }
        $Script:ADSecurityAuditServerIsExplicitDC = $false
        try {
            function Get-ADDomain {
                param([switch]$ErrorAction, $Server)
                [PSCustomObject]@{ PDCEmulator = 'DC01.contoso.com' }
            }

            $result = Get-ADTargetDomainController
            $result.HostName | Should -Be 'DC01.contoso.com'
        }
        finally {
            $Global:PSDefaultParameterValues.Remove('Get-AD*:Server')
        }
    }

    It 'honors an explicit specific DC exactly as given, without substituting the PDC' {
        $Global:PSDefaultParameterValues = @{ 'Get-AD*:Server' = 'DC02.contoso.com' }
        $Script:ADSecurityAuditServerIsExplicitDC = $true
        try {
            function Get-ADDomainController {
                param($Filter, $Server, $Identity, [switch]$ErrorAction)
                if ($Identity) {
                    return [PSCustomObject]@{ Name = 'DC02'; HostName = 'DC02.contoso.com'; Domain = 'contoso.com' }
                }
                @([PSCustomObject]@{ Name = 'DC02'; HostName = 'DC02.contoso.com'; Domain = 'contoso.com' })
            }

            $result = Get-ADTargetDomainController
            $result.HostName | Should -Be 'DC02.contoso.com'
        }
        finally {
            $Global:PSDefaultParameterValues.Remove('Get-AD*:Server')
            $Script:ADSecurityAuditServerIsExplicitDC = $false
        }
    }
}
