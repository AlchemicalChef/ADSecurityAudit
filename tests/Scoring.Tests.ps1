#Requires -Modules Pester
<#
    Unit tests for the v1.2.0 scoring / ANSSI maturity / MITRE contract layer.

    These tests do NOT touch Active Directory. They feed a fixed set of
    ADSecurityFinding objects to the scoring functions and assert the computed
    total, per-category sub-scores, and maturity bucket - satisfying the
    "no regression / deterministic scoring" acceptance criteria.

    Run from the repo root:  Invoke-Pester ./tests/Scoring.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')

    function New-TestFinding {
        param([string]$Issue, [string]$Category, [string]$Severity, [int]$SeverityLevel)
        $f = [ADSecurityFinding]::new()
        $f.Issue = $Issue
        $f.Category = $Category
        $f.Severity = $Severity
        $f.SeverityLevel = $SeverityLevel
        return $f
    }

    $script:Fixture = @(
        New-TestFinding 'KRBTGT Password Age Exceeds Recommended Threshold' 'Kerberos Security'   'Critical' 4
        New-TestFinding 'Unauthorized DCSync Permissions'                   'Replication Security' 'Critical' 4
        New-TestFinding 'User Account with SPN (Kerberoasting Risk)'        'User Account'        'Medium'   2
        New-TestFinding 'Password Never Expires'                            'User Account'        'Medium'   2
        New-TestFinding 'Inactive Enabled Account'                          'User Account'        'Low'      1
        New-TestFinding 'Weak Minimum Password Length'                      'Domain Security'     'High'     3
        New-TestFinding 'Unlinked GPO'                                      'Group Policy'        'Info'     0
    )
}

Describe 'Set-ADFindingMetadata' {
    It 'tags a known finding with MITRE, ANSSI, and weight from the central table' {
        $f = [ADSecurityFinding]::new(); $f.Issue = 'Unauthorized DCSync Permissions'; $f.SeverityLevel = 4
        $tagged = Set-ADFindingMetadata -Finding $f
        $tagged.MitreTechnique | Should -Be 'T1003.006'
        $tagged.AnssiControl   | Should -Be 'vuln1_dcsync'
        $tagged.Weight         | Should -Be 40
    }

    It 'falls back to severity-derived defaults for an unmapped issue' {
        $f = [ADSecurityFinding]::new(); $f.Issue = 'Some Brand New Check'; $f.SeverityLevel = 3
        $tagged = Set-ADFindingMetadata -Finding $f
        $tagged.Weight       | Should -Be 20
        $tagged.AnssiControl | Should -Match '^vuln2_'
    }

    It 'is idempotent' {
        $f = [ADSecurityFinding]::new(); $f.Issue = 'Shadow Credentials Detected'; $f.SeverityLevel = 4
        Set-ADFindingMetadata -Finding $f | Out-Null
        $w1 = $f.Weight
        Set-ADFindingMetadata -Finding $f | Out-Null
        $f.Weight | Should -Be $w1
    }
}

Describe 'Get-ADRiskScore (fixed fixture)' {
    BeforeAll { $script:Result = Get-ADRiskScore -Findings $script:Fixture }

    It 'computes the global total as the worst category (weakest-link, similar in spirit to PingCastle)' {
        $script:Result.TotalScore | Should -Be 40
    }

    It 'computes ANSSI maturity as the lowest level present (1)' {
        $script:Result.MaturityLevel | Should -Be 1
    }

    It 'sums weighted points across all findings' {
        $script:Result.WeightedPoints | Should -Be 125
    }

    It 'computes correct per-category sub-scores (diminishing returns: single-finding categories are unaffected; User Account has 3 findings at weights 10/10/4, so factor = 0.9*0.9*0.96 = 0.7776, Score = round(100*(1-0.7776)) = 22)' {
        ($script:Result.CategoryScores | Where-Object Category -eq 'User Account').Score        | Should -Be 22
        ($script:Result.CategoryScores | Where-Object Category -eq 'Kerberos Security').Score    | Should -Be 40
        ($script:Result.CategoryScores | Where-Object Category -eq 'Replication Security').Score | Should -Be 40
        ($script:Result.CategoryScores | Where-Object Category -eq 'Group Policy').Score         | Should -Be 1
    }

    It 'aggregates MITRE techniques (T1078.002 appears twice)' {
        ($script:Result.MitreSummary | Where-Object Technique -eq 'T1078.002').Count | Should -Be 2
    }

    It 'caps the total at 0-100' {
        $script:Result.TotalScore | Should -BeGreaterOrEqual 0
        $script:Result.TotalScore | Should -BeLessOrEqual 100
    }
}

Describe 'Get-ADRiskScore (edge cases)' {
    It 'returns score 0 / maturity 5 for an empty environment' {
        $r = Get-ADRiskScore -Findings @()
        $r.TotalScore    | Should -Be 0
        $r.MaturityLevel | Should -Be 5
    }

    It 'tags raw (untagged) findings on the fly' {
        $f = [ADSecurityFinding]::new(); $f.Issue = 'Reversible Password Encryption'; $f.Category = 'User Account'; $f.SeverityLevel = 4
        $r = Get-ADRiskScore -Findings @($f)
        $r.TotalScore | Should -Be 40   # weight 40, single finding: diminishing-returns formula degenerates to the same value as a plain weight for exactly one finding
        $f.MitreTechnique | Should -Be 'T1003'
    }
}

Describe 'Get-ADRiskScore - jagged/nested findings array (defensive flattening)' {
    <#
        Regression coverage for a real crash: a jagged $Findings array (an
        element that is itself a sub-array of several findings, e.g.
        surfaced via Get-ADRetestComparison reading a findings export back
        offline) made every property read on that element return an array
        instead of a scalar - "Cannot convert the System.Object[] value ...
        to type System.Int32" at the $w = [int]$finding.Weight line, plus
        several other failures further down the same loop.
    #>
    BeforeAll {
        function New-TaggedFinding {
            param([string]$Category, [string]$Issue, [string]$Severity, [int]$SeverityLevel, [string]$AffectedObject, [int]$Weight, [string]$Anssi)
            $f = [ADSecurityFinding]::new()
            $f.Category = $Category; $f.Issue = $Issue; $f.Severity = $Severity; $f.SeverityLevel = $SeverityLevel
            $f.AffectedObject = $AffectedObject
            # Pre-populate Weight/AnssiControl exactly as real production
            # findings already do after a prior live run (this is what makes
            # Get-ADRiskScore's own re-tagging pre-check skip Set-ADFindingMetadata
            # and fall straight into the arithmetic where the crash occurs).
            $f.Weight = $Weight
            $f.AnssiControl = $Anssi
            return $f
        }
    }

    It 'does not throw when one array element is itself a sub-array of multiple findings' {
        $f1 = New-TaggedFinding -Category 'User Account' -Issue 'I1' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'o1' -Weight 4 -Anssi 'vuln4_test'
        $f2 = New-TaggedFinding -Category 'User Account' -Issue 'I2' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'o2' -Weight 4 -Anssi 'vuln4_test'
        $f3 = New-TaggedFinding -Category 'Privileged Groups' -Issue 'I3' -Severity 'High' -SeverityLevel 3 -AffectedObject 'o3' -Weight 20 -Anssi 'vuln2_test'

        $jagged = @( @($f1, $f2), $f3 )

        { Get-ADRiskScore -Findings $jagged } | Should -Not -Throw
    }

    It 'produces the same FindingCount/TotalScore as the equivalent flat array' {
        $f1 = New-TaggedFinding -Category 'User Account' -Issue 'I1' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'o1' -Weight 4 -Anssi 'vuln4_test'
        $f2 = New-TaggedFinding -Category 'User Account' -Issue 'I2' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'o2' -Weight 4 -Anssi 'vuln4_test'
        $f3 = New-TaggedFinding -Category 'Privileged Groups' -Issue 'I3' -Severity 'High' -SeverityLevel 3 -AffectedObject 'o3' -Weight 20 -Anssi 'vuln2_test'

        $flat = @($f1, $f2, $f3)
        $jagged = @( @($f1, $f2), $f3 )

        $flatResult = Get-ADRiskScore -Findings $flat
        $jaggedResult = Get-ADRiskScore -Findings $jagged

        $jaggedResult.FindingCount | Should -Be $flatResult.FindingCount
        $jaggedResult.TotalScore | Should -Be $flatResult.TotalScore
    }
}

Describe 'ConvertTo-ADFlatFindingsArray' {
    It 'is a no-op on an already-flat array' {
        $f1 = [ADSecurityFinding]::new(); $f1.Issue = 'A'
        $f2 = [ADSecurityFinding]::new(); $f2.Issue = 'B'
        $flat = ConvertTo-ADFlatFindingsArray -Findings @($f1, $f2)
        $flat.Count | Should -Be 2
    }

    It 'flattens one level of nesting' {
        $f1 = [ADSecurityFinding]::new(); $f1.Issue = 'A'
        $f2 = [ADSecurityFinding]::new(); $f2.Issue = 'B'
        $f3 = [ADSecurityFinding]::new(); $f3.Issue = 'C'
        $jagged = @( @($f1, $f2), $f3 )
        $flat = ConvertTo-ADFlatFindingsArray -Findings $jagged
        $flat.Count | Should -Be 3
        ($flat.Issue | Sort-Object) | Should -Be @('A', 'B', 'C')
    }

    It 'flattens multiple levels of nesting' {
        $f1 = [ADSecurityFinding]::new(); $f1.Issue = 'A'
        $f2 = [ADSecurityFinding]::new(); $f2.Issue = 'B'
        $deeplyNested = @( @( @($f1), $f2 ) )
        $flat = ConvertTo-ADFlatFindingsArray -Findings $deeplyNested
        $flat.Count | Should -Be 2
    }

    It 'treats a Details hashtable as a leaf value, not something to recurse into' {
        $f1 = [ADSecurityFinding]::new(); $f1.Issue = 'A'; $f1.Details = @{ SomeArray = @(1, 2, 3) }
        $flat = ConvertTo-ADFlatFindingsArray -Findings @($f1)
        $flat.Count | Should -Be 1
        $flat[0].Details.SomeArray.Count | Should -Be 3
    }

    It 'handles an empty input array' {
        $flat = ConvertTo-ADFlatFindingsArray -Findings @()
        $flat.Count | Should -Be 0
    }
}

Describe 'Mapping table integrity' {
    It 'exposes a clone via Get-ADFindingMetadataMap (does not mutate source)' {
        $map = Get-ADFindingMetadataMap
        $map['Unauthorized DCSync Permissions'].Mitre | Should -Be 'T1003.006'
        $map['__injected__'] = @{ Mitre='X'; Anssi='y'; Weight=1 }
        (Get-ADFindingMetadataMap).ContainsKey('__injected__') | Should -BeFalse
    }

    It 'every ANSSI control encodes a 1-5 maturity level prefix' {
        $map = Get-ADFindingMetadataMap
        foreach ($k in $map.Keys) {
            $map[$k].Anssi | Should -Match '^vuln[1-5]_'
        }
    }
}
