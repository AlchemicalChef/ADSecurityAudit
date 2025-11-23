#region Domain Admin Equivalence Audit

function Test-ADDomainAdminEquivalence {
    [CmdletBinding()]
    param()

    Write-Verbose "Starting domain admin equivalence detection..."
    $findings = @()

    try {
        $domain = Get-ADDomain
        $domainDN = $domain.DistinguishedName
        $netBIOSName = $domain.NetBIOSName

        # Explicitly trusted principals that normally require broad control
        $legitimatePrincipals = @(
            'NT AUTHORITY\\SYSTEM',
            'BUILTIN\\Administrators',
            "$netBIOSName\\Administrators",
            "$netBIOSName\\Domain Admins",
            "$netBIOSName\\Enterprise Admins",
            "$netBIOSName\\Schema Admins",
            "$netBIOSName\\Domain Controllers",
            "$netBIOSName\\Enterprise Domain Controllers",
            "$netBIOSName\\Read-only Domain Controllers"
        )

        $principalEvidence = @{}

        function Add-Evidence {
            param(
                [string]$Principal,
                [string]$Reason,
                [hashtable]$Context
            )

            if (-not $principalEvidence.ContainsKey($Principal)) {
                $principalEvidence[$Principal] = [System.Collections.ArrayList]::new()
            }

            $entry = [PSCustomObject]@{
                Reason  = $Reason
                Context = $Context
            }

            [void]$principalEvidence[$Principal].Add($entry)
        }

        # Check direct control over the domain naming context and AdminSDHolder
        $controlTargets = @(
            @{ Name = 'Domain Root'; DistinguishedName = $domainDN; RiskType = 'DomainRootControl' },
            @{ Name = 'AdminSDHolder'; DistinguishedName = "CN=AdminSDHolder,CN=System,$domainDN"; RiskType = 'AdminSDHolderControl' }
        )

        foreach ($target in $controlTargets) {
            $object = Get-ADObject -Identity $target.DistinguishedName -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $object) {
                Write-Verbose "Unable to read ACL for $($target.Name) at $($target.DistinguishedName)"
                continue
            }

            foreach ($ace in $object.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) {
                    continue
                }

                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|AllExtendedRights') {
                    Add-Evidence -Principal $principal -Reason "$($target.Name) control via $($ace.ActiveDirectoryRights)" -Context @{
                        Target             = $target.Name
                        DistinguishedName  = $target.DistinguishedName
                        Rights             = $ace.ActiveDirectoryRights.ToString()
                        AccessControlType  = $ace.AccessControlType
                        Inheritance        = if ($ace.IsInherited) { 'Inherited' } else { 'Explicit' }
                    }
                }
            }
        }

        # Track replication rights to identify full DCSync capability
        $dcsyncRights = @{
            'DS-Replication-Get-Changes'              = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            'DS-Replication-Get-Changes-All'          = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
            'DS-Replication-Get-Changes-In-Filtered-Set' = '89e95b76-444d-4c62-991a-0facbeda640c'
        }

        $replicationAccess = @{}
        $domainObject = Get-ADObject -Identity $domainDN -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue

        if ($domainObject) {
            foreach ($ace in $domainObject.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) {
                    continue
                }

                if (-not $replicationAccess.ContainsKey($principal)) {
                    $replicationAccess[$principal] = [System.Collections.Generic.HashSet[string]]::new()
                }

                if ($ace.ActiveDirectoryRights -match 'GenericAll') {
                    [void]$replicationAccess[$principal].Add('GenericAll')
                }

                if ($ace.ActiveDirectoryRights -match 'ExtendedRight|GenericAll') {
                    $objectType = $ace.ObjectType.ToString()

                    foreach ($rightName in $dcsyncRights.Keys) {
                        if ($ace.ActiveDirectoryRights -match 'GenericAll' -or $objectType -eq $dcsyncRights[$rightName]) {
                            [void]$replicationAccess[$principal].Add($rightName)
                        }
                    }
                }
            }

            foreach ($principal in $replicationAccess.Keys) {
                $rights = $replicationAccess[$principal]

                if ($rights.Contains('GenericAll') -or (
                        $rights.Contains('DS-Replication-Get-Changes') -and
                        $rights.Contains('DS-Replication-Get-Changes-All')
                    )) {
                    Add-Evidence -Principal $principal -Reason "DCSync replication rights: $($rights -join ', ')" -Context @{
                        Target            = 'Domain Root'
                        DistinguishedName = $domainDN
                        Rights            = $rights -join ', '
                        Requirement       = 'DCSync requires Get-Changes and Get-Changes-All or GenericAll'
                    }
                }
            }
        }

        # Detect ability to change membership of privileged groups
        $memberAttributeGuid = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
        $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')

        foreach ($groupName in $privilegedGroups) {
            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $group) {
                continue
            }

            foreach ($ace in $group.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) {
                    continue
                }

                $objectType = $ace.ObjectType.ToString().ToLower()
                $hasMembershipControl = $false

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                    if ($ace.ObjectType -eq [Guid]::Empty -or $objectType -eq $memberAttributeGuid) {
                        $hasMembershipControl = $true
                    }
                }

                if ($ace.ActiveDirectoryRights -match 'WriteDacl|WriteOwner|GenericAll') {
                    $hasMembershipControl = $true
                }

                if ($hasMembershipControl) {
                    Add-Evidence -Principal $principal -Reason "Modify membership of $groupName via $($ace.ActiveDirectoryRights)" -Context @{
                        Group              = $groupName
                        DistinguishedName  = $group.DistinguishedName
                        Rights             = $ace.ActiveDirectoryRights.ToString()
                        ObjectType         = $ace.ObjectType
                        AccessControlType  = $ace.AccessControlType
                    }
                }
            }
        }

        foreach ($principal in $principalEvidence.Keys) {
            $evidence = $principalEvidence[$principal]
            $criticalEvidence = $evidence | Where-Object { $_.Reason -match 'Domain Root|AdminSDHolder|DCSync' }

            $severity = if ($criticalEvidence.Count -gt 0) { 'Critical' } else { 'High' }
            $severityLevel = if ($severity -eq 'Critical') { 4 } else { 3 }

            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Admin Equivalence'
            $finding.Issue = 'Domain Admin Equivalent Access Detected'
            $finding.Severity = $severity
            $finding.SeverityLevel = $severityLevel
            $finding.AffectedObject = $principal
            $finding.Description = "Principal '$principal' holds permissions that provide Domain Admin-equivalent control: $($evidence.Reason -join '; ')."
            $finding.Impact = 'Compromise of this principal would allow attackers to seize control of protected groups, the domain naming context, or perform DCSync, leading to full domain compromise.'
            $finding.Remediation = @"
Review and remove the excessive permissions listed in the evidence:
1. Restrict Domain Naming Context and AdminSDHolder control to Domain/Enterprise Admins only.
2. Remove Write/Generic control over privileged group membership and reapply correct ACLs using ADSIEdit or DSACLS.
3. For DCSync rights, remove replication ExtendedRights and verify only DC computer accounts retain them.
4. Re-evaluate delegation design to ensure least privilege and monitor for reintroduction of risky ACEs.
"@
            $finding.Details = @{
                Evidence = $evidence
                Domain   = $domain.DNSRoot
            }

            $findings += $finding
        }

        Write-Verbose "Domain admin equivalence detection complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during domain admin equivalence audit: $_"
        throw
    }
}

#endregion
