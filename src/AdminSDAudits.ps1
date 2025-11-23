#region AdminSDHolder Audit

function Test-AdminSDHolder {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting AdminSDHolder audit..."
    $findings = @()
    
    try {
        # Get the domain DN
        $domain = Get-ADDomain
        $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)"
        
        Write-Verbose "Checking AdminSDHolder at: $adminSDHolderDN"
        
        # Get AdminSDHolder object with ACL
        $adminSDHolder = Get-ADObject -Identity $adminSDHolderDN -Properties nTSecurityDescriptor
        $acl = $adminSDHolder.nTSecurityDescriptor
        
        $acceptableTrustees = @(
            'NT AUTHORITY\SYSTEM'
            'BUILTIN\Administrators'
            "$($domain.NetBIOSName)\Domain Admins"
            "$($domain.NetBIOSName)\Enterprise Admins"
            'NT AUTHORITY\SELF'
        )
        
        # Check each ACE
        foreach ($ace in $acl.Access) {
            $identityReference = $ace.IdentityReference.Value
            
            # Skip inherited ACEs
            if ($ace.IsInherited) {
                continue
            }
            
            # Check for non-standard trustees with dangerous rights
            if ($identityReference -notin $acceptableTrustees -and 
                $identityReference -notmatch '^S-1-5-32-544$') { # BUILTIN\Administrators SID
                
                $dangerousRights = @('GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite', 'WriteProperty')
                $hasRiskyPermission = $false
                
                foreach ($right in $dangerousRights) {
                    if ($ace.ActiveDirectoryRights -match $right) {
                        $hasRiskyPermission = $true
                        break
                    }
                }
                
                if ($hasRiskyPermission -or $ace.ActiveDirectoryRights -match 'ExtendedRight') {
                    $severity = 'Critical'
                    $severityLevel = 4
                    
                    # Lower severity for some built-in groups
                    if ($identityReference -match 'BUILTIN\\' -or 
                        $identityReference -match 'NT AUTHORITY\\') {
                        $severity = 'Medium'
                        $severityLevel = 2
                    }
                    
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'AdminSDHolder'
                    $finding.Issue = 'Non-Standard Permissions on AdminSDHolder'
                    $finding.Severity = $severity
                    $finding.SeverityLevel = $severityLevel
                    $finding.AffectedObject = "AdminSDHolder - $identityReference"
                    $finding.Description = "Non-standard trustee '$identityReference' has '$($ace.ActiveDirectoryRights)' rights on AdminSDHolder."
                    $finding.Impact = "Attackers who compromise this principal can modify AdminSDHolder ACL to grant persistent domain-wide rights, create shadow admins, or bypass privilege escalation controls. SDProp will propagate these malicious permissions every 60 minutes."
                    $finding.Remediation = "Review and remove unauthorized ACE. Use: `$acl = Get-Acl 'AD:\$adminSDHolderDN'; Review `$acl.Access; Remove unauthorized entries using Set-Acl."
                    $finding.Details = @{
                        Identity = $identityReference
                        AccessControlType = $ace.AccessControlType
                        ActiveDirectoryRights = $ace.ActiveDirectoryRights
                        InheritanceType = $ace.InheritanceType
                        ObjectType = $ace.ObjectType
                        InheritedObjectType = $ace.InheritedObjectType
                    }
                    $findings += $finding
                }
            }
            
            # Check for Deny ACEs (unusual and potentially problematic)
            if ($ace.AccessControlType -eq 'Deny') {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'AdminSDHolder'
                $finding.Issue = 'Deny ACE on AdminSDHolder'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = "AdminSDHolder - $identityReference"
                $finding.Description = "Deny ACE found on AdminSDHolder for '$identityReference'."
                $finding.Impact = "Deny ACEs on AdminSDHolder are unusual and may cause unexpected permission issues for protected accounts."
                $finding.Remediation = "Review the deny ACE and determine if it's intentional. Remove if unnecessary."
                $finding.Details = @{
                    Identity = $identityReference
                    ActiveDirectoryRights = $ace.ActiveDirectoryRights
                }
                $findings += $finding
            }
        }
        
        # Check for accounts with adminCount=1 that shouldn't have it
        Write-Verbose "Checking for orphaned adminCount attributes..."
        $protectedUsers = Get-ADUser -Filter 'adminCount -eq 1' -Properties adminCount, MemberOf
        
        foreach ($user in $protectedUsers) {
            $isInProtectedGroup = $false
            
            foreach ($group in $Script:ProtectedGroups) {
                if ($user.MemberOf -match "CN=$group,") {
                    $isInProtectedGroup = $true
                    break
                }
            }
            
            if (-not $isInProtectedGroup) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'AdminSDHolder'
                $finding.Issue = 'Orphaned adminCount Attribute'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User has adminCount=1 but is not a member of any protected group."
                $finding.Impact = "User retains AdminSDHolder permissions after being removed from protected groups, potentially granting unintended privileges."
                $finding.Remediation = "Clear adminCount and fix ACL: Set-ADUser -Identity '$($user.SamAccountName)' -Clear adminCount; Then manually review and reset the user's ACL to remove AdminSDHolder permissions."
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                    AdminCount = $user.adminCount
                }
                $findings += $finding
            }
        }
        
        Write-Verbose "AdminSDHolder audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during AdminSDHolder audit: $_"
        throw
    }
}

#endregion

