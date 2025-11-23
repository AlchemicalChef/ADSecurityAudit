#region Dangerous Permissions Audit

function Test-ADDangerousPermissions {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting dangerous permissions audit..."
    $findings = @()
    
    try {
        $domain = Get-ADDomain
        $domainDN = $domain.DistinguishedName
        
        # Check Enterprise Key Admins for overly permissive rights (CVE misconfiguration)
        Write-Verbose "Checking Enterprise Key Admins permissions on Domain Naming Context..."
        
        $domainObject = Get-ADObject -Identity $domainDN -Properties nTSecurityDescriptor
        $domainAcl = $domainObject.nTSecurityDescriptor
        
        # Get Enterprise Key Admins group (if it exists - only in Windows Server 2016+)
        try {
            $ekaGroup = Get-ADGroup -Filter "Name -eq 'Enterprise Key Admins'" -ErrorAction SilentlyContinue
            
            if ($ekaGroup) {
                Write-Verbose "Found Enterprise Key Admins group, checking for over-privileged ACEs..."
                
                # msDS-KeyCredentialLink attribute GUID
                $keyCredentialLinkGuid = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
                
                foreach ($ace in $domainAcl.Access) {
                    # Check if this ACE is for Enterprise Key Admins
                    if ($ace.IdentityReference.Value -match 'Enterprise Key Admins') {
                        
                        # EKA should only have ReadProperty and WriteProperty for msDS-KeyCredentialLink
                        # If it has GenericAll, WriteDacl, or other excessive rights, that's a vulnerability
                        if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite') {
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = 'Dangerous Permissions'
                            $finding.Issue = 'Enterprise Key Admins Over-Privileged (Misconfiguration Bug)'
                            $finding.Severity = 'Critical'
                            $finding.SeverityLevel = 4
                            $finding.AffectedObject = 'Enterprise Key Admins - Domain Naming Context'
                            $finding.Description = "Enterprise Key Admins group has excessive permissions '$($ace.ActiveDirectoryRights)' on the Domain Naming Context. This is a known misconfiguration bug where EKA was granted full access instead of just ReadProperty/WriteProperty for msDS-KeyCredentialLink."
                            $finding.Impact = "This misconfiguration can unintentionally grant DCSync permissions, allowing members of Enterprise Key Admins to extract password hashes for all domain accounts. Attackers can exploit this for full domain compromise."
                            $finding.Remediation = @"
Remove the over-privileged ACE and grant only the required permissions:
1. Remove the current ACE: Use ADSIEdit or dsacls.exe to remove the ACE for Enterprise Key Admins
2. Grant only required rights: Ensure EKA only has ReadProperty and WriteProperty for msDS-KeyCredentialLink (GUID: $keyCredentialLinkGuid)
3. Verify no GenericAll or WriteDacl rights remain
4. Monitor for DCSync attempts: Check Event ID 4662 for DS-Replication-Get-Changes operations
"@
                            $finding.Details = @{
                                GroupDN = $ekaGroup.DistinguishedName
                                DomainDN = $domainDN
                                ActiveDirectoryRights = $ace.ActiveDirectoryRights
                                AccessControlType = $ace.AccessControlType
                                ObjectType = $ace.ObjectType
                                IsInherited = $ace.IsInherited
                                ExpectedRights = 'ReadProperty, WriteProperty for msDS-KeyCredentialLink only'
                            }
                            $findings += $finding
                        }
                        
                        # Also check if the ObjectType is not restricted to msDS-KeyCredentialLink
                        elseif ($ace.ObjectType -eq '00000000-0000-0000-0000-000000000000' -or 
                                ($ace.ObjectType.ToString() -ne $keyCredentialLinkGuid -and 
                                 $ace.ActiveDirectoryRights -match 'WriteProperty')) {
                            
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = 'Dangerous Permissions'
                            $finding.Issue = 'Enterprise Key Admins Permissions Not Scoped to msDS-KeyCredentialLink'
                            $finding.Severity = 'High'
                            $finding.SeverityLevel = 3
                            $finding.AffectedObject = 'Enterprise Key Admins - Domain Naming Context'
                            $finding.Description = "Enterprise Key Admins has WriteProperty rights that are not scoped to the msDS-KeyCredentialLink attribute only."
                            $finding.Impact = "Excessive property write permissions may allow unintended modifications to domain objects beyond the intended key credential management scope."
                            $finding.Remediation = "Scope Enterprise Key Admins permissions specifically to msDS-KeyCredentialLink attribute (GUID: $keyCredentialLinkGuid) only."
                            $finding.Details = @{
                                GroupDN = $ekaGroup.DistinguishedName
                                DomainDN = $domainDN
                                ActiveDirectoryRights = $ace.ActiveDirectoryRights
                                ObjectType = $ace.ObjectType
                                ExpectedObjectType = $keyCredentialLinkGuid
                            }
                            $findings += $finding
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Enterprise Key Admins group not found or not accessible (expected in pre-2016 domains)"
        }
        
        # Critical OUs to check
        $criticalOUs = @(
            "OU=Domain Controllers,$domainDN"
            "CN=Users,$domainDN"
            "CN=Computers,$domainDN"
        )
        
        foreach ($ouDN in $criticalOUs) {
            try {
                $ou = Get-ADObject -Identity $ouDN -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
                
                if (-not $ou) {
                    continue
                }
                
                $acl = $ou.nTSecurityDescriptor
                
                foreach ($ace in $acl.Access) {
                    # Skip inherited and SYSTEM/Administrators
                    if ($ace.IsInherited -or 
                        $ace.IdentityReference -match 'SYSTEM' -or
                        $ace.IdentityReference -match 'Domain Admins' -or
                        $ace.IdentityReference -match 'Enterprise Admins') {
                        continue
                    }
                    
                    # Check for dangerous rights
                    $dangerousRights = @('GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite')
                    $hasDangerousRight = $false
                    
                    foreach ($right in $dangerousRights) {
                        if ($ace.ActiveDirectoryRights -match $right) {
                            $hasDangerousRight = $true
                            break
                        }
                    }
                    
                    if ($hasDangerousRight) {
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Dangerous Permissions'
                        $finding.Issue = 'Dangerous Rights on Critical OU'
                        $finding.Severity = 'High'
                        $finding.SeverityLevel = 3
                        $finding.AffectedObject = "$ouDN - $($ace.IdentityReference)"
                        $finding.Description = "Principal '$($ace.IdentityReference)' has dangerous rights '$($ace.ActiveDirectoryRights)' on critical OU."
                        $finding.Impact = "Attackers who compromise this principal can create/modify objects in this OU, potentially adding rogue Domain Controllers or admin accounts."
                        $finding.Remediation = "Review and restrict permissions. Remove unnecessary rights using Active Directory Users and Computers > Advanced Security Settings."
                        $finding.Details = @{
                            OU = $ouDN
                            Identity = $ace.IdentityReference
                            ActiveDirectoryRights = $ace.ActiveDirectoryRights
                            AccessControlType = $ace.AccessControlType
                        }
                        $findings += $finding
                    }
                }
            }
            catch {
                Write-Warning "Could not check OU '$ouDN': $_"
            }
        }
        
        Write-Verbose "Dangerous permissions audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during dangerous permissions audit: $_"
        throw
    }
}

#endregion

