#region Replication and DCSync Audit

function Test-ADReplicationSecurity {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting replication security audit (DCSync detection)..."
    $findings = @()
    
    try {
        $domain = Get-ADDomain
        $domainDN = $domain.DistinguishedName
        
        # Get the domain object with ACL
        $domainObject = Get-ADObject -Identity $domainDN -Properties nTSecurityDescriptor
        $acl = $domainObject.nTSecurityDescriptor
        
        # Define legitimate replication principals
        $legitimateReplicators = @(
            'NT AUTHORITY\SYSTEM'
            'BUILTIN\Administrators'
            "$($domain.NetBIOSName)\Domain Controllers"
            "$($domain.NetBIOSName)\Enterprise Domain Controllers"
            "$($domain.NetBIOSName)\Domain Admins"
            "$($domain.NetBIOSName)\Enterprise Admins"
            "$($domain.NetBIOSName)\Read-only Domain Controllers"
        )
        
        $dcsyncRights = @{
            'DS-Replication-Get-Changes' = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            'DS-Replication-Get-Changes-All' = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
            'DS-Replication-Get-Changes-In-Filtered-Set' = '89e95b76-444d-4c62-991a-0facbeda640c'
        }
        
        # Check each ACE for dangerous replication rights
        foreach ($ace in $acl.Access) {
            $identityReference = $ace.IdentityReference.Value
            
            # Skip inherited ACEs and legitimate replicators
            if ($ace.IsInherited -or $identityReference -in $legitimateReplicators) {
                continue
            }
            
            # Check for DCSync-enabling rights
            $hasDCSyncRight = $false
            $rightsFound = @()
            
            if ($ace.ActiveDirectoryRights -match 'ExtendedRight' -or 
                $ace.ActiveDirectoryRights -match 'GenericAll') {
                
                # Check ObjectType GUID
                $objectTypeGuid = $ace.ObjectType.ToString().ToLower()
                
                foreach ($rightName in $dcsyncRights.Keys) {
                    if ($objectTypeGuid -eq $dcsyncRights[$rightName].ToLower() -or 
                        $ace.ActiveDirectoryRights -match 'GenericAll') {
                        $hasDCSyncRight = $true
                        $rightsFound += $rightName
                    }
                }
            }
            
            if ($hasDCSyncRight) {
                # Try to resolve the identity to determine if it's a user or group
                $principal = $null
                $principalClass = 'Unknown'
                
                try {
                    # First try to translate the identity reference to a SID
                    $sid = $null
                    
                    # Check if it's already a SID string
                    if ($identityReference -match '^S-1-') {
                        $sid = $identityReference
                    }
                    else {
                        # Try to translate account name to SID
                        try {
                            $ntAccount = New-Object System.Security.Principal.NTAccount($identityReference)
                            $sidObj = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
                            $sid = $sidObj.Value
                        }
                        catch {
                            Write-Verbose "Could not translate '$identityReference' to SID: $_"
                        }
                    }
                    
                    # If we have a SID, look up the AD object
                    if ($sid) {
                        $principal = Get-ADObject -Filter "objectSid -eq '$sid'" -Properties objectClass -ErrorAction SilentlyContinue
                        if ($principal) {
                            $principalClass = $principal.objectClass
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not resolve principal: $identityReference - $_"
                }
                
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Replication Security'
                $finding.Issue = 'Unauthorized DCSync Permissions'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $identityReference
                $finding.Description = "Non-standard principal '$identityReference' has DCSync replication rights on the domain."
                $finding.Impact = "This principal can perform DCSync attacks to retrieve password hashes for any account, including KRBTGT and Domain Admins. Attackers can then create Golden Tickets for persistent, unrestricted domain access."
                $finding.Remediation = "Remove replication rights immediately: `$acl = Get-Acl 'AD:\$domainDN'; Find and remove the ACE for '$identityReference'; Set-Acl -Path 'AD:\$domainDN' -AclObject `$acl"
                $finding.Details = @{
                    Identity = $identityReference
                    ObjectClass = $principalClass
                    ActiveDirectoryRights = $ace.ActiveDirectoryRights.ToString()
                    Rights = $rightsFound -join ', '
                    ObjectType = $ace.ObjectType.ToString()
                }
                $findings += $finding
            }
        }
        
        # Check for accounts with explicit DCSync-enabling group memberships
        Write-Verbose "Checking for suspicious group memberships..."
        
        # Get members of groups that might have replication rights
        $suspiciousGroups = @('Backup Operators', 'Account Operators', 'Server Operators')
        
        foreach ($groupName in $suspiciousGroups) {
            try {
                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
                if ($group) {
                    $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                    
                    if ($members) {
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Replication Security'
                        $finding.Issue = "Membership in Privileged Operations Group"
                        $finding.Severity = 'Medium'
                        $finding.SeverityLevel = 2
                        $finding.AffectedObject = $groupName
                        $finding.Description = "Group '$groupName' has $($members.Count) member(s). These groups have powerful rights that could be leveraged for privilege escalation or data exfiltration."
                        $finding.Impact = "Members of this group may have rights that can be leveraged for privilege escalation or data exfiltration."
                        $finding.Remediation = "Review membership and remove unnecessary accounts. Members: $($members.SamAccountName -join ', ')"
                        $finding.Details = @{
                            GroupDN = $group.DistinguishedName
                            Members = ($members | Select-Object Name, SamAccountName, DistinguishedName)
                        }
                        $findings += $finding
                    }
                }
            }
            catch {
                Write-Warning "Could not check group '$groupName': $_"
            }
        }
        
        Write-Verbose "Replication security audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during replication security audit: $_"
        throw
    }
}

#endregion
