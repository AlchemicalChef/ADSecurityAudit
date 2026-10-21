#Requires -Modules Pester
<#
    Unit tests for Test-ADDomainTrusts (src/DomainTrustAudits.ps1).

    This module previously had no Pester coverage at all. Added as part of
    investigating a PingCastle-comparable bug-fix candidate (3.5.x: "New
    CrossRef-based filtering logic correctly identifies within-forest
    trusts and no longer flags them as insecure") - which turned up a real,
    analogous gap here: 'Bidirectional Domain Trust' had no TrustType
    scoping at all, so it fired on every normal, by-design-bidirectional
    intra-forest trust (ParentChild/TreeRoot/CrossLink/Shortcut) in any
    multi-domain forest. The SID-filtering and selective-authentication
    checks in this same function already scoped correctly by TrustType;
    only the bidirectional-trust check was missing it.

    Shadows Get-ADDomain and Get-ADTrust with local functions - no real
    Active Directory or connectivity is required.

    Run from the repo root:  Invoke-Pester ./tests/DomainTrustAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/DomainTrustAudits.ps1')

    function Get-ADDomain {
        param($Server)
        [PSCustomObject]@{ DNSRoot = 'contoso.com'; DistinguishedName = 'DC=contoso,DC=com' }
    }
}

Describe 'Test-ADDomainTrusts / Bidirectional Domain Trust - intra-forest exclusion (regression)' {
    It 'does NOT flag a bidirectional ParentChild trust' {
        function Get-ADTrust {
            param($Filter, $Properties, $Server)
            @([PSCustomObject]@{ Target = 'child.contoso.com'; Direction = 'Bidirectional'; TrustType = 'ParentChild'; SIDFilteringQuarantined = $true; SelectiveAuthentication = $false; Modified = (Get-Date) })
        }
        $findings = Test-ADDomainTrusts
        ($findings | Where-Object { $_.Issue -eq 'Bidirectional Domain Trust' }) | Should -BeNullOrEmpty
    }

    It 'does NOT flag a bidirectional TreeRoot trust' {
        function Get-ADTrust {
            param($Filter, $Properties, $Server)
            @([PSCustomObject]@{ Target = 'treeroot.fabrikam.com'; Direction = 'Bidirectional'; TrustType = 'TreeRoot'; SIDFilteringQuarantined = $true; SelectiveAuthentication = $false; Modified = (Get-Date) })
        }
        $findings = Test-ADDomainTrusts
        ($findings | Where-Object { $_.Issue -eq 'Bidirectional Domain Trust' }) | Should -BeNullOrEmpty
    }

    It 'does NOT flag a bidirectional CrossLink trust' {
        function Get-ADTrust {
            param($Filter, $Properties, $Server)
            @([PSCustomObject]@{ Target = 'shortcut.contoso.com'; Direction = 'Bidirectional'; TrustType = 'CrossLink'; SIDFilteringQuarantined = $true; SelectiveAuthentication = $false; Modified = (Get-Date) })
        }
        $findings = Test-ADDomainTrusts
        ($findings | Where-Object { $_.Issue -eq 'Bidirectional Domain Trust' }) | Should -BeNullOrEmpty
    }

    It 'does NOT flag a bidirectional Shortcut trust' {
        function Get-ADTrust {
            param($Filter, $Properties, $Server)
            @([PSCustomObject]@{ Target = 'shortcut2.contoso.com'; Direction = 'Bidirectional'; TrustType = 'Shortcut'; SIDFilteringQuarantined = $true; SelectiveAuthentication = $false; Modified = (Get-Date) })
        }
        $findings = Test-ADDomainTrusts
        ($findings | Where-Object { $_.Issue -eq 'Bidirectional Domain Trust' }) | Should -BeNullOrEmpty
    }

    It 'STILL flags a bidirectional External trust' {
        function Get-ADTrust {
            param($Filter, $Properties, $Server)
            @([PSCustomObject]@{ Target = 'partner.example.com'; Direction = 'Bidirectional'; TrustType = 'External'; SIDFilteringQuarantined = $true; SelectiveAuthentication = $false; Modified = (Get-Date) })
        }
        $findings = Test-ADDomainTrusts
        ($findings | Where-Object { $_.Issue -eq 'Bidirectional Domain Trust' }) | Should -Not -BeNullOrEmpty
    }

    It 'STILL flags a bidirectional Forest trust' {
        function Get-ADTrust {
            param($Filter, $Properties, $Server)
            @([PSCustomObject]@{ Target = 'otherforest.example.com'; Direction = 'Bidirectional'; TrustType = 'Forest'; SIDFilteringQuarantined = $true; SelectiveAuthentication = $true; Modified = (Get-Date) })
        }
        $findings = Test-ADDomainTrusts
        ($findings | Where-Object { $_.Issue -eq 'Bidirectional Domain Trust' }) | Should -Not -BeNullOrEmpty
    }

    It 'does not flag a one-way (non-bidirectional) intra-forest trust either way - direction alone governs' {
        function Get-ADTrust {
            param($Filter, $Properties, $Server)
            @([PSCustomObject]@{ Target = 'child2.contoso.com'; Direction = 'Outbound'; TrustType = 'ParentChild'; SIDFilteringQuarantined = $true; SelectiveAuthentication = $false; Modified = (Get-Date) })
        }
        $findings = Test-ADDomainTrusts
        ($findings | Where-Object { $_.Issue -eq 'Bidirectional Domain Trust' }) | Should -BeNullOrEmpty
    }
}

Describe 'Test-ADDomainTrusts / SID filtering' {
    It 'flags SID filtering disabled on an External trust' {
        function Get-ADTrust {
            param($Filter, $Properties, $Server)
            @([PSCustomObject]@{ Target = 'partner.example.com'; Direction = 'Outbound'; TrustType = 'External'; SIDFilteringQuarantined = $false; SelectiveAuthentication = $false; Modified = (Get-Date) })
        }
        $findings = Test-ADDomainTrusts
        ($findings | Where-Object { $_.Issue -eq 'SID Filtering Disabled on External Trust' }) | Should -Not -BeNullOrEmpty
    }

    It 'does NOT flag SID filtering on a ParentChild trust even when the property reads false (not applicable intra-forest)' {
        function Get-ADTrust {
            param($Filter, $Properties, $Server)
            @([PSCustomObject]@{ Target = 'child.contoso.com'; Direction = 'Outbound'; TrustType = 'ParentChild'; SIDFilteringQuarantined = $false; SelectiveAuthentication = $false; Modified = (Get-Date) })
        }
        $findings = Test-ADDomainTrusts
        ($findings | Where-Object { $_.Issue -eq 'SID Filtering Disabled on External Trust' }) | Should -BeNullOrEmpty
    }
}

Describe 'Test-ADDomainTrusts / Selective authentication' {
    It 'flags a Forest trust without selective authentication' {
        function Get-ADTrust {
            param($Filter, $Properties, $Server)
            @([PSCustomObject]@{ Target = 'otherforest.example.com'; Direction = 'Outbound'; TrustType = 'Forest'; SIDFilteringQuarantined = $true; SelectiveAuthentication = $false; Modified = (Get-Date) })
        }
        $findings = Test-ADDomainTrusts
        ($findings | Where-Object { $_.Issue -eq 'Forest Trust Without Selective Authentication' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-ADDomainTrusts / Trust password rotation' {
    It 'flags a trust not modified in over 30 days' {
        function Get-ADTrust {
            param($Filter, $Properties, $Server)
            @([PSCustomObject]@{ Target = 'partner.example.com'; Direction = 'Outbound'; TrustType = 'External'; SIDFilteringQuarantined = $true; SelectiveAuthentication = $false; Modified = (Get-Date).AddDays(-45) })
        }
        $findings = Test-ADDomainTrusts
        ($findings | Where-Object { $_.Issue -eq 'Trust Password Not Recently Rotated' }) | Should -Not -BeNullOrEmpty
    }

    It 'does not flag a recently-modified trust' {
        function Get-ADTrust {
            param($Filter, $Properties, $Server)
            @([PSCustomObject]@{ Target = 'partner.example.com'; Direction = 'Outbound'; TrustType = 'External'; SIDFilteringQuarantined = $true; SelectiveAuthentication = $false; Modified = (Get-Date).AddDays(-5) })
        }
        $findings = Test-ADDomainTrusts
        ($findings | Where-Object { $_.Issue -eq 'Trust Password Not Recently Rotated' }) | Should -BeNullOrEmpty
    }
}

Describe 'Test-ADDomainTrusts / no trusts' {
    It 'returns no findings when the domain has no trusts' {
        function Get-ADTrust {
            param($Filter, $Properties, $Server)
            $null
        }
        $findings = Test-ADDomainTrusts
        $findings | Should -BeNullOrEmpty
    }
}
