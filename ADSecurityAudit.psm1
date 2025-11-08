<#
.SYNOPSIS
    Comprehensive Active Directory Audit and Reporting
    
.DESCRIPTION
    This module provides extensive capabilities to audit Active Directory environments
    for misconfigurations and security vulnerabilities. It evaluates user accounts,
    group policies, permissions, replication configurations, and AdminSDHolder objects. (More to be added later)
    
.NOTES
    Author: AlchemicalChef
    Version: 1.0.0
    Requires: Active Directory PowerShell Module, Windows Server 2016+
    
.EXAMPLE
    Import-Module .\ADSecurityAudit.psm1
    Start-ADSecurityAudit -Verbose -ExportPath "C:\Reports"
#>

#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

# Module-level variables
$Script:SeverityLevels = @{
    Critical = 4
    High = 3
    Medium = 2
    Low = 1
    Info = 0
}

$Script:ProtectedGroups = @(
    'Domain Admins'
    'Enterprise Admins'
    'Schema Admins'
    'Administrators'
    'Account Operators'
    'Server Operators'
    'Backup Operators'
    'Print Operators'
    'Domain Controllers'
    'Read-only Domain Controllers'
    'Group Policy Creator Owners'
    'Cryptographic Operators'
    'Distributed COM Users'
)

# Known dangerous rights GUIDs
$Script:DangerousRights = @{
    'GenericAll' = '00000000-0000-0000-0000-000000000000'
    'WriteDacl' = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    'WriteOwner' = '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes' = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes-All' = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes-In-Filtered-Set' = '89e95b76-444d-4c62-991a-0facbeda640c'
    'User-Force-Change-Password' = '00299570-246d-11d0-a768-00aa006e0529'
    'AllExtendedRights' = '00000000-0000-0000-0000-000000000000'
}

class ADSecurityFinding {
    [string]$Category
    [string]$Issue
    [string]$Severity
    [int]$SeverityLevel
    [string]$Description
    [string]$Impact
    [string]$Remediation
    [string]$AffectedObject
    [hashtable]$Details
    [datetime]$DetectedDate
    
    ADSecurityFinding() {
        $this.DetectedDate = Get-Date
        $this.Details = @{}
    }
}

#region User Account Audits

<#
.SYNOPSIS
    Audits user accounts for security misconfigurations
#>
function Test-ADUserSecurity {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$SearchBase,
        
        [Parameter()]
        [int]$InactiveDaysThreshold = 90,
        
        [Parameter()]
        [int]$PasswordAgeThreshold = 180
    )
    
    Write-Verbose "Starting user account security audit..."
    $findings = @()
    
    try {
        # Get all user accounts
        $users = Get-ADUser -Filter * -Properties * -SearchBase $SearchBase -ErrorAction Stop
        
        Write-Verbose "Analyzing $($users.Count) user accounts..."
        
        foreach ($user in $users) {
            # Check for disabled Kerberos pre-authentication (AS-REP Roasting vulnerability)
            if ($user.DoesNotRequirePreAuth -eq $true) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'User Account'
                $finding.Issue = 'Kerberos Pre-Authentication Disabled'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User account has Kerberos pre-authentication disabled, making it vulnerable to AS-REP Roasting attacks."
                $finding.Impact = "Attackers can request authentication data for this account and crack the password offline without any authentication."
                $finding.Remediation = "Enable Kerberos pre-authentication: Set-ADUser -Identity '$($user.SamAccountName)' -DoesNotRequirePreAuth `$false"
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                    UserPrincipalName = $user.UserPrincipalName
                    Enabled = $user.Enabled
                }
                $findings += $finding
            }
            
            # Check for use of DES encryption (deprecated and insecure)
            if ($user.UseDESKeyOnly -eq $true) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'User Account'
                $finding.Issue = 'DES Encryption Enabled'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User account is configured to use DES encryption, which is deprecated and easily crackable."
                $finding.Impact = "DES encryption provides minimal security and can be cracked quickly by modern tools."
                $finding.Remediation = "Disable DES encryption: Set-ADUser -Identity '$($user.SamAccountName)' -UseDESKeyOnly `$false"
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                }
                $findings += $finding
            }
            
            # Check for reversible encryption (stores passwords in plaintext equivalent)
            if ($user.AllowReversiblePasswordEncryption -eq $true) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'User Account'
                $finding.Issue = 'Reversible Password Encryption'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User account has reversible password encryption enabled, storing passwords in a format equivalent to plaintext."
                $finding.Impact = "An attacker with access to the AD database can easily retrieve the plaintext password."
                $finding.Remediation = "Disable reversible encryption: Set-ADUser -Identity '$($user.SamAccountName)' -AllowReversiblePasswordEncryption `$false; Then force password change."
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                }
                $findings += $finding
            }
            
            # Check for password never expires on privileged accounts
            if ($user.PasswordNeverExpires -eq $true -and $user.Enabled -eq $true) {
                $isPrivileged = Test-PrivilegedUser -User $user
                
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'User Account'
                $finding.Issue = 'Password Never Expires'
                $finding.Severity = if ($isPrivileged) { 'High' } else { 'Medium' }
                $finding.SeverityLevel = if ($isPrivileged) { 3 } else { 2 }
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User account is configured with a password that never expires."
                $finding.Impact = "Stale passwords increase the risk of compromise and violate security best practices."
                $finding.Remediation = "Set password to expire: Set-ADUser -Identity '$($user.SamAccountName)' -PasswordNeverExpires `$false"
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                    IsPrivileged = $isPrivileged
                    PasswordLastSet = $user.PasswordLastSet
                }
                $findings += $finding
            }
            
            # Check for accounts with Unconstrained Delegation
            if ($user.TrustedForDelegation -eq $true) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'User Account'
                $finding.Issue = 'Unconstrained Delegation Enabled'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User account has unconstrained delegation enabled, which can be exploited for privilege escalation."
                $finding.Impact = "Attackers can use this account to impersonate any user in the domain and escalate privileges to Domain Admin."
                $finding.Remediation = "Disable unconstrained delegation: Set-ADUser -Identity '$($user.SamAccountName)' -TrustedForDelegation `$false; Consider using constrained delegation instead."
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                    ServicePrincipalNames = $user.ServicePrincipalNames -join '; '
                }
                $findings += $finding
            }
            
            # Check for inactive accounts
            if ($user.Enabled -eq $true -and $user.LastLogonDate) {
                $daysSinceLogon = (Get-Date) - $user.LastLogonDate
                if ($daysSinceLogon.Days -gt $InactiveDaysThreshold) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'User Account'
                    $finding.Issue = 'Inactive Enabled Account'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $user.SamAccountName
                    $finding.Description = "Enabled user account has not logged in for $($daysSinceLogon.Days) days."
                    $finding.Impact = "Inactive accounts increase attack surface and may have weak or compromised credentials."
                    $finding.Remediation = "Disable or delete the account: Disable-ADAccount -Identity '$($user.SamAccountName)'"
                    $finding.Details = @{
                        DistinguishedName = $user.DistinguishedName
                        LastLogonDate = $user.LastLogonDate
                        DaysSinceLogon = $daysSinceLogon.Days
                    }
                    $findings += $finding
                }
            }
            
            # Check for old passwords
            if ($user.PasswordLastSet -and $user.Enabled -eq $true) {
                $passwordAge = (Get-Date) - $user.PasswordLastSet
                if ($passwordAge.Days -gt $PasswordAgeThreshold) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'User Account'
                    $finding.Issue = 'Old Password'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $user.SamAccountName
                    $finding.Description = "User password has not been changed in $($passwordAge.Days) days."
                    $finding.Impact = "Old passwords are more likely to be compromised through various attack vectors."
                    $finding.Remediation = "Force password change: Set-ADUser -Identity '$($user.SamAccountName)' -ChangePasswordAtLogon `$true"
                    $finding.Details = @{
                        DistinguishedName = $user.DistinguishedName
                        PasswordLastSet = $user.PasswordLastSet
                        PasswordAgeDays = $passwordAge.Days
                    }
                    $findings += $finding
                }
            }
            
            # Check for accounts with SPN set (potential Kerberoasting targets)
            if ($user.ServicePrincipalNames.Count -gt 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'User Account'
                $finding.Issue = 'User Account with SPN (Kerberoasting Risk)'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User account has Service Principal Names (SPNs) configured, making it vulnerable to Kerberoasting attacks."
                $finding.Impact = "Attackers can request service tickets for this account and crack the password offline."
                $finding.Remediation = "Ensure this account uses a strong (25+ character) password, or migrate the service to a Group Managed Service Account (gMSA)."
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                    ServicePrincipalNames = $user.ServicePrincipalNames -join '; '
                    PasswordLastSet = $user.PasswordLastSet
                }
                $findings += $finding
            }
            
            # Check for accounts not in Protected Users group
            $isHighlyPrivileged = $Script:ProtectedGroups | Where-Object {
                $user.MemberOf -match "CN=$_,"
            } | Where-Object { $_ -in @('Domain Admins', 'Enterprise Admins', 'Schema Admins') }
            
            if ($isHighlyPrivileged -and $user.MemberOf -notmatch 'CN=Protected Users,') {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'User Account'
                $finding.Issue = 'Privileged Account Not in Protected Users Group'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "Highly privileged account is not a member of the Protected Users security group."
                $finding.Impact = "Account lacks additional protections against credential theft attacks like pass-the-hash."
                $finding.Remediation = "Add to Protected Users group: Add-ADGroupMember -Identity 'Protected Users' -Members '$($user.SamAccountName)'"
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                    PrivilegedGroups = $isHighlyPrivileged -join '; '
                }
                $findings += $finding
            }
        }
        
        Write-Verbose "User account audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during user account audit: $_"
        throw
    }
}

<#
.SYNOPSIS
    Tests if a user is a member of privileged groups
#>
function Test-PrivilegedUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User
    )
    
    foreach ($group in $Script:ProtectedGroups) {
        if ($User.MemberOf -match "CN=$group,") {
            return $true
        }
    }
    return $false
}

#endregion

#region Group and Privilege Audits

<#
.SYNOPSIS
    Audits privileged groups for overly permissive membership
#>
function Test-ADPrivilegedGroups {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$AdditionalGroups = @()
    )
    
    Write-Verbose "Starting privileged group audit..."
    $findings = @()
    
    $groupsToCheck = $Script:ProtectedGroups + $AdditionalGroups
    
    try {
        foreach ($groupName in $groupsToCheck) {
            try {
                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Properties Members, MemberOf -ErrorAction Stop
                
                if (-not $group) {
                    continue
                }
                
                $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop
                
                # Check for excessive membership
                $memberCount = ($members | Measure-Object).Count
                
                $criticalGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
                $threshold = if ($groupName -in $criticalGroups) { 5 } else { 10 }
                
                if ($memberCount -gt $threshold) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Privileged Groups'
                    $finding.Issue = 'Excessive Privileged Group Membership'
                    $finding.Severity = if ($groupName -in $criticalGroups) { 'Critical' } else { 'High' }
                    $finding.SeverityLevel = if ($groupName -in $criticalGroups) { 4 } else { 3 }
                    $finding.AffectedObject = $groupName
                    $finding.Description = "The '$groupName' group has $memberCount members, exceeding the recommended threshold of $threshold."
                    $finding.Impact = "Over-privileged accounts increase the attack surface and make it harder to maintain accountability."
                    $finding.Remediation = "Review and reduce membership. Remove unnecessary accounts and implement role-based access with custom delegated groups. Use temporary privileged access where possible."
                    $finding.Details = @{
                        GroupDN = $group.DistinguishedName
                        MemberCount = $memberCount
                        Members = ($members | Select-Object -ExpandProperty SamAccountName) -join '; '
                    }
                    $findings += $finding
                }
                
                # Check for nested groups in critical groups
                $nestedGroups = $members | Where-Object { $_.objectClass -eq 'group' }
                if ($nestedGroups -and $groupName -in $criticalGroups) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Privileged Groups'
                    $finding.Issue = 'Nested Groups in Critical Privileged Group'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $groupName
                    $finding.Description = "The critical group '$groupName' contains $($nestedGroups.Count) nested group(s), which complicates access management."
                    $finding.Impact = "Nested groups create choke points and can lead to unintentional privileged access. They make it difficult to audit who has access."
                    $finding.Remediation = "Remove nested groups and add users directly, or create custom delegated groups instead. Nested groups: $($nestedGroups.Name -join ', ')"
                    $finding.Details = @{
                        GroupDN = $group.DistinguishedName
                        NestedGroups = ($nestedGroups | Select-Object Name, DistinguishedName)
                    }
                    $findings += $finding
                }
                
                # Check for disabled or inactive users in privileged groups
                $userMembers = $members | Where-Object { $_.objectClass -eq 'user' }
                foreach ($member in $userMembers) {
                    $userDetails = Get-ADUser -Identity $member -Properties Enabled, LastLogonDate -ErrorAction SilentlyContinue
                    
                    if ($userDetails.Enabled -eq $false) {
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Privileged Groups'
                        $finding.Issue = 'Disabled User in Privileged Group'
                        $finding.Severity = 'Medium'
                        $finding.SeverityLevel = 2
                        $finding.AffectedObject = "$groupName - $($userDetails.SamAccountName)"
                        $finding.Description = "Disabled user '$($userDetails.SamAccountName)' is still a member of privileged group '$groupName'."
                        $finding.Impact = "Disabled accounts in privileged groups should be removed to maintain clean access control."
                        $finding.Remediation = "Remove the disabled user: Remove-ADGroupMember -Identity '$groupName' -Members '$($userDetails.SamAccountName)' -Confirm:`$false"
                        $finding.Details = @{
                            UserDN = $userDetails.DistinguishedName
                            GroupDN = $group.DistinguishedName
                        }
                        $findings += $finding
                    }
                }
                
            }
            catch {
                Write-Warning "Could not audit group '$groupName': $_"
            }
        }
        
        Write-Verbose "Privileged group audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during privileged group audit: $_"
        throw
    }
}

#endregion

#region AdminSDHolder Audit

<#
.SYNOPSIS
    Audits the AdminSDHolder object for risky permissions
#>
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
        
        # Define acceptable trustees (these should be the only ones with significant rights)
        $acceptableTrustees = @(
            'NT AUTHORITY\SYSTEM'
            'BUILTIN\Administrators'
            'BUILTIN\Account Operators'
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

#region GPO Audit

<#
.SYNOPSIS
    Audits Group Policy Objects for security misconfigurations
#>
function Test-ADGroupPolicies {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting Group Policy audit..."
    $findings = @()
    
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        
        $allGPOs = Get-GPO -All
        $domain = Get-ADDomain
        
        Write-Verbose "Analyzing $($allGPOs.Count) GPOs..."
        
        foreach ($gpo in $allGPOs) {
            # Get GPO permissions
            $gpoPermissions = Get-GPPermission -Guid $gpo.Id -All
            
            # Check for dangerous permissions granted to non-admin users/groups
            foreach ($permission in $gpoPermissions) {
                $isDangerous = $false
                $dangerousRight = ""
                
                if ($permission.Permission -match 'GpoEditDeleteModifySecurity') {
                    $isDangerous = $true
                    $dangerousRight = "Full Control (GpoEditDeleteModifySecurity)"
                }
                elseif ($permission.Permission -match 'GpoEdit') {
                    $isDangerous = $true
                    $dangerousRight = "Edit Settings (GpoEdit)"
                }
                
                if ($isDangerous) {
                    # Check if trustee is a privileged group
                    $trustee = $permission.Trustee.Name
                    $isPrivilegedTrustee = $Script:ProtectedGroups | Where-Object { $trustee -match $_ }
                    
                    if (-not $isPrivilegedTrustee -and 
                        $trustee -notmatch 'SYSTEM' -and 
                        $trustee -notmatch 'Domain Admins' -and
                        $trustee -notmatch 'Enterprise Admins') {
                        
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Group Policy'
                        $finding.Issue = 'Over-Permissioned GPO'
                        $finding.Severity = 'High'
                        $finding.SeverityLevel = 3
                        $finding.AffectedObject = $gpo.DisplayName
                        $finding.Description = "GPO '$($gpo.DisplayName)' grants '$dangerousRight' to non-privileged principal '$trustee'."
                        $finding.Impact = "Low-privileged users or groups can modify the GPO, leading to privilege escalation, malware deployment, or persistence mechanisms."
                        $finding.Remediation = "Remove dangerous permission: Set-GPPermission -Guid $($gpo.Id) -TargetName '$trustee' -TargetType User -PermissionLevel None"
                        $finding.Details = @{
                            GPOID = $gpo.Id
                            GPOPath = $gpo.Path
                            Trustee = $trustee
                            Permission = $permission.Permission
                        }
                        $findings += $finding
                    }
                }
            }
            
            # Check for GPOs linked to sensitive OUs
            $gpoLinks = Get-ADObject -Filter "gPLink -like '*$($gpo.Id)*'" -Properties gPLink, DistinguishedName
            
            foreach ($link in $gpoLinks) {
                # Check if linked to Domain Controllers OU
                if ($link.DistinguishedName -match 'OU=Domain Controllers') {
                    # Verify this GPO has restricted permissions
                    $nonAdminEditRights = $gpoPermissions | Where-Object {
                        $_.Permission -match 'Edit' -and
                        $_.Trustee.Name -notmatch 'Domain Admins' -and
                        $_.Trustee.Name -notmatch 'Enterprise Admins' -and
                        $_.Trustee.Name -notmatch 'SYSTEM'
                    }
                    
                    if ($nonAdminEditRights) {
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Group Policy'
                        $finding.Issue = 'GPO Linked to Domain Controllers with Weak Permissions'
                        $finding.Severity = 'Critical'
                        $finding.SeverityLevel = 4
                        $finding.AffectedObject = $gpo.DisplayName
                        $finding.Description = "GPO '$($gpo.DisplayName)' is linked to Domain Controllers OU but has edit rights granted to non-admin principals."
                        $finding.Impact = "Attackers can deploy malicious packages or configurations to Domain Controllers with SYSTEM-level rights, leading to full domain compromise."
                        $finding.Remediation = "Restrict GPO permissions to only Domain Admins and Enterprise Admins. Remove all non-admin edit rights immediately."
                        $finding.Details = @{
                            GPOID = $gpo.Id
                            LinkedOU = $link.DistinguishedName
                            NonAdminTrustees = ($nonAdminEditRights.Trustee.Name -join '; ')
                        }
                        $findings += $finding
                    }
                }
            }
            
            # Check for unlinked GPOs (security hygiene)
            if (-not $gpoLinks) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Group Policy'
                $finding.Issue = 'Unlinked GPO'
                $finding.Severity = 'Low'
                $finding.SeverityLevel = 1
                $finding.AffectedObject = $gpo.DisplayName
                $finding.Description = "GPO '$($gpo.DisplayName)' is not linked to any OU or domain."
                $finding.Impact = "Unlinked GPOs create clutter and may contain misconfigurations that could cause issues if accidentally linked."
                $finding.Remediation = "Review the GPO and delete if no longer needed: Remove-GPO -Guid $($gpo.Id)"
                $finding.Details = @{
                    GPOID = $gpo.Id
                    CreatedDate = $gpo.CreationTime
                    ModifiedDate = $gpo.ModificationTime
                }
                $findings += $finding
            }
        }
        
        # Check SYSVOL permissions
        Write-Verbose "Checking SYSVOL permissions..."
        $sysvolPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)"
        
        if (Test-Path $sysvolPath) {
            $sysvolAcl = Get-Acl $sysvolPath
            
            foreach ($ace in $sysvolAcl.Access) {
                # Check for write/modify rights granted to non-admin groups
                if ($ace.FileSystemRights -match 'Write|Modify|FullControl' -and
                    $ace.AccessControlType -eq 'Allow' -and
                    $ace.IdentityReference -notmatch 'SYSTEM' -and
                    $ace.IdentityReference -notmatch 'Administrators' -and
                    $ace.IdentityReference -notmatch 'Domain Admins' -and
                    $ace.IdentityReference -notmatch 'Enterprise Admins' -and
                    $ace.IdentityReference -notmatch 'CREATOR OWNER') {
                    
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Group Policy'
                    $finding.Issue = 'Insecure SYSVOL Permissions'
                    $finding.Severity = 'Critical'
                    $finding.SeverityLevel = 4
                    $finding.AffectedObject = "SYSVOL - $($ace.IdentityReference)"
                    $finding.Description = "SYSVOL has write permissions granted to '$($ace.IdentityReference)'."
                    $finding.Impact = "Attackers can tamper with GPO files, scripts, and policies that apply to all domain members, leading to widespread compromise."
                    $finding.Remediation = "Restrict SYSVOL permissions. Remove write access for non-admin principals. Only Domain Admins and SYSTEM should have write access."
                    $finding.Details = @{
                        Path = $sysvolPath
                        Identity = $ace.IdentityReference
                        FileSystemRights = $ace.FileSystemRights
                        AccessControlType = $ace.AccessControlType
                    }
                    $findings += $finding
                }
            }
        }
        
        Write-Verbose "Group Policy audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during Group Policy audit: $_"
        throw
    }
}

#endregion

#region Replication and DCSync Audit

<#
.SYNOPSIS
    Audits AD replication permissions for DCSync attack vectors
#>
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
        
        # DCSync requires specific extended rights
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
                $objectTypeGuid = $ace.ObjectType.ToString()
                
                foreach ($rightName in $dcsyncRights.Keys) {
                    if ($objectTypeGuid -eq $dcsyncRights[$rightName] -or 
                        $ace.ActiveDirectoryRights -match 'GenericAll') {
                        $hasDCSyncRight = $true
                        $rightsFound += $rightName
                    }
                }
            }
            
            if ($hasDCSyncRight) {
                # Try to resolve the identity to determine if it's a user or group
                try {
                    $principal = Get-ADObject -Filter "objectSid -eq '$identityReference'" -Properties objectClass -ErrorAction SilentlyContinue
                    
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
                        ObjectClass = if ($principal) { $principal.objectClass } else { 'Unknown' }
                        ActiveDirectoryRights = $ace.ActiveDirectoryRights
                        Rights = $rightsFound -join ', '
                        ObjectType = $ace.ObjectType
                    }
                    $findings += $finding
                }
                catch {
                    Write-Warning "Could not resolve principal: $identityReference"
                }
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
                        $finding.Description = "Group '$groupName' has $($members.Count) member(s). These groups have powerful rights that could be abused."
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

#region Domain Security Settings

<#
.SYNOPSIS
    Audits domain-wide security settings and configurations
#>
function Test-ADDomainSecurity {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting domain security settings audit..."
    $findings = @()
    
    try {
        $domain = Get-ADDomain
        
        # Check password policy
        $defaultPasswordPolicy = Get-ADDefaultDomainPasswordPolicy
        
        if ($defaultPasswordPolicy.MinPasswordLength -lt 14) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Weak Minimum Password Length'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = 'Default Domain Password Policy'
            $finding.Description = "Minimum password length is set to $($defaultPasswordPolicy.MinPasswordLength) characters."
            $finding.Impact = "Short passwords are easier to crack through brute-force and dictionary attacks."
            $finding.Remediation = "Increase minimum password length to at least 14 characters: Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 -Identity $($domain.DNSRoot)"
            $finding.Details = @{
                CurrentLength = $defaultPasswordPolicy.MinPasswordLength
                RecommendedLength = 14
            }
            $findings += $finding
        }
        
        if ($defaultPasswordPolicy.ComplexityEnabled -eq $false) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Password Complexity Disabled'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.AffectedObject = 'Default Domain Password Policy'
            $finding.Description = "Password complexity requirements are disabled."
            $finding.Impact = "Users can set simple, easily guessable passwords, significantly increasing the risk of compromise."
            $finding.Remediation = "Enable password complexity: Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled `$true -Identity $($domain.DNSRoot)"
            $finding.Details = @{
                ComplexityEnabled = $defaultPasswordPolicy.ComplexityEnabled
            }
            $findings += $finding
        }
        
        if ($defaultPasswordPolicy.ReversibleEncryptionEnabled -eq $true) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Reversible Encryption Enabled Domain-Wide'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.AffectedObject = 'Default Domain Password Policy'
            $finding.Description = "Reversible password encryption is enabled at the domain level."
            $finding.Impact = "All passwords are stored in a format equivalent to plaintext, making them easily retrievable by attackers."
            $finding.Remediation = "Disable reversible encryption immediately: Set-ADDefaultDomainPasswordPolicy -ReversibleEncryptionEnabled `$false -Identity $($domain.DNSRoot)"
            $finding.Details = @{
                ReversibleEncryptionEnabled = $defaultPasswordPolicy.ReversibleEncryptionEnabled
            }
            $findings += $finding
        }
        
        # Check domain functional level
        $domainLevel = $domain.DomainMode
        $forestLevel = (Get-ADForest).ForestMode
        
        $deprecatedLevels = @('Windows2000Domain', 'Windows2003Domain', 'Windows2008Domain', 'Windows2008R2Domain', 'Windows2012Domain')
        
        if ($domainLevel -in $deprecatedLevels) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Outdated Domain Functional Level'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = 'Domain Functional Level'
            $finding.Description = "Domain functional level is set to '$domainLevel', which is outdated."
            $finding.Impact = "Older functional levels lack modern security features and may support deprecated authentication protocols."
            $finding.Remediation = "Raise domain functional level after ensuring all DCs are running a supported OS: Set-ADDomainMode -Identity $($domain.DNSRoot) -DomainMode Windows2016Domain (or higher)"
            $finding.Details = @{
                CurrentLevel = $domainLevel
                ForestLevel = $forestLevel
                RecommendedLevel = 'Windows2016Domain or higher'
            }
            $findings += $finding
        }
        
        # Check for Recycle Bin (best practice)
        $recycleBinFeature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'"
        if ($recycleBinFeature.EnabledScopes.Count -eq 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'AD Recycle Bin Not Enabled'
            $finding.Severity = 'Low'
            $finding.SeverityLevel = 1
            $finding.AffectedObject = 'AD Recycle Bin Feature'
            $finding.Description = "Active Directory Recycle Bin is not enabled."
            $finding.Impact = "Deleted AD objects cannot be easily restored, making recovery from accidental deletions or attacks more difficult."
            $finding.Remediation = "Enable AD Recycle Bin: Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $($domain.Forest)"
            $finding.Details = @{
                Feature = 'Recycle Bin'
                Status = 'Disabled'
            }
            $findings += $finding
        }
        
        # Check for computers with old OS versions
        Write-Verbose "Checking for legacy operating systems..."
        $computers = Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate
        
        $legacyOS = @('Windows XP', 'Windows Vista', 'Windows 7', 'Windows 8', 'Windows Server 2003', 'Windows Server 2008', 'Windows Server 2012')
        $legacyComputers = $computers | Where-Object {
            $os = $_.OperatingSystem
            $legacyOS | Where-Object { $os -match $_ }
        }
        
        if ($legacyComputers) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Legacy Operating Systems in Domain'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = 'Domain Computers'
            $finding.Description = "Found $($legacyComputers.Count) computer(s) running unsupported/legacy operating systems."
            $finding.Impact = "Legacy systems lack security updates and are vulnerable to known exploits, providing easy entry points for attackers."
            $finding.Remediation = "Upgrade or isolate legacy systems. Remove computer accounts for decommissioned systems."
            $finding.Details = @{
                Count = $legacyComputers.Count
                Computers = ($legacyComputers | Select-Object Name, OperatingSystem, LastLogonDate | Format-Table | Out-String)
            }
            $findings += $finding
        }
        
        Write-Verbose "Domain security settings audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during domain security audit: $_"
        throw
    }
}

#endregion

#region Dangerous Permissions Audit

<#
.SYNOPSIS
    Audits for dangerous permissions on critical AD objects
#>
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

#region Privileged Users Enumeration

<#
.SYNOPSIS
    Enumerates all users in privileged roles across the domain
    
.DESCRIPTION
    Returns a comprehensive list of all users who are members of privileged groups,
    including nested group memberships. This provides visibility into who has
    elevated access in the environment.
    
.OUTPUTS
    Returns an array of custom objects containing user details and their privileged group memberships
    
.EXAMPLE
    $privilegedUsers = Get-ADPrivilegedUsers
    $privilegedUsers | Export-Csv -Path "C:\Reports\PrivilegedUsers.csv" -NoTypeInformation
#>
function Get-ADPrivilegedUsers {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Enumerating all privileged users..."
    
    try {
        $domain = Get-ADDomain
        $privilegedUsersList = @()
        $processedUsers = @{}
        
        foreach ($groupName in $Script:ProtectedGroups) {
            try {
                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Properties Members, Description -ErrorAction SilentlyContinue
                
                if (-not $group) {
                    Write-Verbose "Group '$groupName' not found, skipping..."
                    continue
                }
                
                Write-Verbose "Processing group: $groupName"
                
                # Get all members recursively
                $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
                
                # Filter to only user objects
                $userMembers = $members | Where-Object { $_.objectClass -eq 'user' }
                
                foreach ($member in $userMembers) {
                    # Get full user details
                    $user = Get-ADUser -Identity $member -Properties * -ErrorAction SilentlyContinue
                    
                    if (-not $user) {
                        continue
                    }
                    
                    $userSID = $user.SID.Value
                    
                    # Check if we've already processed this user
                    if (-not $processedUsers.ContainsKey($userSID)) {
                        # First time seeing this user, create new entry
                        $privilegedUsersList += [PSCustomObject]@{
                            SamAccountName = $user.SamAccountName
                            DisplayName = $user.DisplayName
                            UserPrincipalName = $user.UserPrincipalName
                            DistinguishedName = $user.DistinguishedName
                            Enabled = $user.Enabled
                            PasswordLastSet = $user.PasswordLastSet
                            PasswordNeverExpires = $user.PasswordNeverExpires
                            LastLogonDate = $user.LastLogonDate
                            WhenCreated = $user.WhenCreated
                            AdminCount = $user.adminCount
                            PrivilegedGroups = @($groupName)
                            PrivilegedGroupsString = $groupName
                            Title = $user.Title
                            Department = $user.Department
                            EmailAddress = $user.EmailAddress
                            DoesNotRequirePreAuth = $user.DoesNotRequirePreAuth
                            TrustedForDelegation = $user.TrustedForDelegation
                            HasSPN = ($user.ServicePrincipalNames.Count -gt 0)
                            SPNCount = $user.ServicePrincipalNames.Count
                            SID = $userSID
                        }
                        
                        $processedUsers[$userSID] = $privilegedUsersList.Count - 1
                    }
                    else {
                        # We've seen this user before, add this group to their list
                        $index = $processedUsers[$userSID]
                        $privilegedUsersList[$index].PrivilegedGroups += $groupName
                        $privilegedUsersList[$index].PrivilegedGroupsString = $privilegedUsersList[$index].PrivilegedGroups -join '; '
                    }
                }
            }
            catch {
                Write-Warning "Error processing group '$groupName': $_"
            }
        }
        
        Write-Verbose "Found $($privilegedUsersList.Count) unique privileged users across $($Script:ProtectedGroups.Count) protected groups"
        
        return $privilegedUsersList | Sort-Object SamAccountName
    }
    catch {
        Write-Error "Error enumerating privileged users: $_"
        throw
    }
}

#endregion

#region Main Audit Function

<#
.SYNOPSIS
    Runs comprehensive Active Directory security audit
    
.DESCRIPTION
    Executes all security checks and generates a detailed report with findings,
    severity ratings, and remediation recommendations.
    
.PARAMETER ExportPath
    Path to export the audit report
    
.PARAMETER IncludeTests
    Specific tests to run. If not specified, runs all tests.
    
.PARAMETER ExcludeTests
    Tests to exclude from the audit
    
.PARAMETER IncludePrivilegedUsersReport
    Generates a separate report listing all users in privileged roles
    
.PARAMETER InactiveDaysThreshold
    Number of days to consider an account inactive (default: 90)
    
.PARAMETER PasswordAgeThreshold
    Number of days to consider a password old (default: 180)
    
.EXAMPLE
    Start-ADSecurityAudit -Verbose -ExportPath "C:\Reports"
    
.EXAMPLE
    Start-ADSecurityAudit -IncludeTests UserAccounts, AdminSDHolder -ExportPath "C:\Reports"

.EXAMPLE
    Start-ADSecurityAudit -IncludePrivilegedUsersReport -ExportPath "C:\Reports"
#>
function Start-ADSecurityAudit {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ExportPath = ".",
        
        [Parameter()]
        [ValidateSet('UserAccounts', 'PrivilegedGroups', 'AdminSDHolder', 'GroupPolicies', 'ReplicationSecurity', 'DomainSecurity', 'DangerousPermissions')]
        [string[]]$IncludeTests,
        
        [Parameter()]
        [ValidateSet('UserAccounts', 'PrivilegedGroups', 'AdminSDHolder', 'GroupPolicies', 'ReplicationSecurity', 'DomainSecurity', 'DangerousPermissions')]
        [string[]]$ExcludeTests = @(),
        
        [Parameter()]
        [switch]$IncludePrivilegedUsersReport,
        
        [Parameter()]
        [int]$InactiveDaysThreshold = 90,
        
        [Parameter()]
        [int]$PasswordAgeThreshold = 180
    )
    
    $startTime = Get-Date
    Write-Host "`n==================================================" -ForegroundColor Cyan
    Write-Host "Active Directory Security Assessment" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "Start Time: $startTime`n" -ForegroundColor Gray
    
    # Verify AD module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "Active Directory PowerShell module is not installed. Please install RSAT tools."
        return
    }
    
    Import-Module ActiveDirectory -ErrorAction Stop
    
    # Get domain info
    $domain = Get-ADDomain
    Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Green
    Write-Host "Domain DN: $($domain.DistinguishedName)`n" -ForegroundColor Green
    
    # Define all tests
    $allTests = @{
        'UserAccounts' = { Test-ADUserSecurity -InactiveDaysThreshold $InactiveDaysThreshold -PasswordAgeThreshold $PasswordAgeThreshold }
        'PrivilegedGroups' = { Test-ADPrivilegedGroups }
        'AdminSDHolder' = { Test-AdminSDHolder }
        'GroupPolicies' = { Test-ADGroupPolicies }
        'ReplicationSecurity' = { Test-ADReplicationSecurity }
        'DomainSecurity' = { Test-ADDomainSecurity }
        'DangerousPermissions' = { Test-ADDangerousPermissions }
    }
    
    # Determine which tests to run
    if ($IncludeTests) {
        $testsToRun = $allTests.Keys | Where-Object { $_ -in $IncludeTests -and $_ -notin $ExcludeTests }
    }
    else {
        $testsToRun = $allTests.Keys | Where-Object { $_ -notin $ExcludeTests }
    }
    
    # Run tests and collect findings
    $allFindings = @()
    
    foreach ($testName in $testsToRun) {
        Write-Host "Running test: $testName..." -ForegroundColor Yellow
        
        try {
            $testResults = & $allTests[$testName]
            $allFindings += $testResults
            
            $criticalCount = ($testResults | Where-Object { $_.Severity -eq 'Critical' }).Count
            $highCount = ($testResults | Where-Object { $_.Severity -eq 'High' }).Count
            $mediumCount = ($testResults | Where-Object { $_.Severity -eq 'Medium' }).Count
            $lowCount = ($testResults | Where-Object { $_.Severity -eq 'Low' }).Count
            
            Write-Host "  Found: $criticalCount Critical, $highCount High, $mediumCount Medium, $lowCount Low`n" -ForegroundColor Gray
        }
        catch {
            Write-Warning "Test '$testName' failed: $_"
        }
    }
    
    # Enumerate privileged users if requested
    $privilegedUsers = $null
    if ($IncludePrivilegedUsersReport) {
        Write-Host "Enumerating privileged users..." -ForegroundColor Yellow
        try {
            $privilegedUsers = Get-ADPrivilegedUsers
            Write-Host "  Found: $($privilegedUsers.Count) privileged users`n" -ForegroundColor Gray
        }
        catch {
            Write-Warning "Failed to enumerate privileged users: $_"
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    # Generate summary
    Write-Host "`n==================================================" -ForegroundColor Cyan
    Write-Host "Audit Summary" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    
    $summary = @{
        Critical = ($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
        High = ($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
        Medium = ($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
        Low = ($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    }
    
    Write-Host "Total Findings: $($allFindings.Count)" -ForegroundColor White
    Write-Host "  Critical: $($summary.Critical)" -ForegroundColor Red
    Write-Host "  High: $($summary.High)" -ForegroundColor DarkRed
    Write-Host "  Medium: $($summary.Medium)" -ForegroundColor Yellow
    Write-Host "  Low: $($summary.Low)" -ForegroundColor Gray
    
    if ($privilegedUsers) {
        Write-Host "`nPrivileged Users: $($privilegedUsers.Count)" -ForegroundColor White
    }
    
    Write-Host "`nDuration: $($duration.TotalSeconds) seconds" -ForegroundColor Gray
    
    # Export results
    if ($allFindings.Count -gt 0) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        
        # Export to JSON
        $jsonPath = Join-Path $ExportPath "AD_Security_Audit_$timestamp.json"
        $allFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Host "`nDetailed report exported to: $jsonPath" -ForegroundColor Green
        
        # Export to HTML
        $htmlPath = Join-Path $ExportPath "AD_Security_Audit_$timestamp.html"
        Export-ADSecurityReportHTML -Findings $allFindings -OutputPath $htmlPath -Domain $domain.DNSRoot -Summary $summary -Duration $duration -PrivilegedUsers $privilegedUsers
        Write-Host "HTML report exported to: $htmlPath" -ForegroundColor Green
        
        # Export to CSV
        $csvPath = Join-Path $ExportPath "AD_Security_Audit_$timestamp.csv"
        $allFindings | Select-Object Category, Issue, Severity, AffectedObject, Description, Impact, Remediation, DetectedDate | 
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "CSV report exported to: $csvPath" -ForegroundColor Green
    }
    
    # Export privileged users report
    if ($privilegedUsers -and $privilegedUsers.Count -gt 0) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $privilegedUsersCsvPath = Join-Path $ExportPath "AD_Privileged_Users_$timestamp.csv"
        
        $privilegedUsers | Select-Object SamAccountName, DisplayName, UserPrincipalName, Enabled, PasswordLastSet, `
            PasswordNeverExpires, LastLogonDate, AdminCount, PrivilegedGroupsString, Title, Department, `
            DoesNotRequirePreAuth, TrustedForDelegation, HasSPN, SPNCount | 
            Export-Csv -Path $privilegedUsersCsvPath -NoTypeInformation -Encoding UTF8
        
        Write-Host "Privileged users report exported to: $privilegedUsersCsvPath" -ForegroundColor Green
    }
    
    Write-Host "`n==================================================" -ForegroundColor Cyan
    Write-Host "Audit Complete" -ForegroundColor Cyan
    Write-Host "==================================================`n" -ForegroundColor Cyan
    
    return $allFindings
}

<#
.SYNOPSIS
    Exports audit findings to HTML report
#>
function Export-ADSecurityReportHTML {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Findings,
        
        [Parameter(Mandatory)]
        [string]$OutputPath,
        
        [Parameter(Mandatory)]
        [string]$Domain,
        
        [Parameter(Mandatory)]
        [hashtable]$Summary,
        
        [Parameter(Mandatory)]
        [timespan]$Duration,
        
        [Parameter()]
        [array]$PrivilegedUsers = $null
    )
    
    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Group findings by severity
    $criticalFindings = $Findings | Where-Object { $_.Severity -eq 'Critical' } | Sort-Object Category
    $highFindings = $Findings | Where-Object { $_.Severity -eq 'High' } | Sort-Object Category
    $mediumFindings = $Findings | Where-Object { $_.Severity -eq 'Medium' } | Sort-Object Category
    $lowFindings = $Findings | Where-Object { $_.Severity -eq 'Low' } | Sort-Object Category
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Security Assessment Report - $Domain</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 20px rgba(0,0,0,0.1); border-radius: 8px; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 15px; margin-bottom: 20px; }
        h2 { color: #34495e; margin-top: 30px; margin-bottom: 15px; padding: 10px; background: #ecf0f1; border-left: 4px solid #3498db; }
        h3 { color: #555; margin-top: 20px; margin-bottom: 10px; }
        .header-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px; }
        .header-info div { padding: 10px; }
        .header-info strong { display: block; color: #7f8c8d; font-size: 0.9em; margin-bottom: 5px; }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .summary-card { padding: 25px; border-radius: 8px; color: white; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .summary-card .count { font-size: 3em; font-weight: bold; margin-bottom: 10px; }
        .summary-card .label { font-size: 1.1em; text-transform: uppercase; letter-spacing: 1px; }
        .critical-card { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
        .high-card { background: linear-gradient(135deg, #e67e22 0%, #d35400 100%); }
        .medium-card { background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); }
        .low-card { background: linear-gradient(135deg, #95a5a6 0%, #7f8c8d 100%); }
        .finding { margin-bottom: 25px; padding: 20px; border-radius: 5px; border-left: 5px solid; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .finding.critical { border-left-color: #e74c3c; background: #fef5f5; }
        .finding.high { border-left-color: #e67e22; background: #fef9f5; }
        .finding.medium { border-left-color: #f39c12; background: #fffcf5; }
        .finding.low { border-left-color: #95a5a6; background: #f9fafb; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 10px; }
        .finding-title { font-size: 1.3em; font-weight: 600; color: #2c3e50; }
        .severity-badge { padding: 6px 15px; border-radius: 20px; font-weight: bold; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }
        .severity-critical { background: #e74c3c; color: white; }
        .severity-high { background: #e67e22; color: white; }
        .severity-medium { background: #f39c12; color: white; }
        .severity-low { background: #95a5a6; color: white; }
        .finding-meta { display: flex; gap: 20px; margin-bottom: 15px; font-size: 0.9em; color: #7f8c8d; flex-wrap: wrap; }
        .finding-meta span { display: flex; align-items: center; }
        .finding-meta strong { margin-right: 5px; color: #555; }
        .finding-section { margin: 15px 0; padding: 15px; background: white; border-radius: 4px; }
        .finding-section h4 { color: #555; margin-bottom: 10px; font-size: 1em; text-transform: uppercase; letter-spacing: 0.5px; }
        .finding-section p { color: #666; line-height: 1.7; }
        .code-block { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 4px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 0.9em; margin-top: 10px; }
        .privileged-users-table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; }
        .privileged-users-table th { background: #34495e; color: white; padding: 12px; text-align: left; font-weight: 600; }
        .privileged-users-table td { padding: 10px; border-bottom: 1px solid #ecf0f1; }
        .privileged-users-table tr:nth-child(even) { background: #f8f9fa; }
        .privileged-users-table tr:hover { background: #e8f4f8; }
        .status-enabled { color: #27ae60; font-weight: bold; }
        .status-disabled { color: #e74c3c; font-weight: bold; }
        .footer { margin-top: 50px; padding-top: 20px; border-top: 2px solid #ecf0f1; text-align: center; color: #7f8c8d; font-size: 0.9em; }
        @media print { body { background: white; padding: 0; } .container { box-shadow: none; } }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Active Directory Security Assessment Report</h1>
        
        <div class="header-info">
            <div><strong>DOMAIN</strong><span style="font-size: 1.2em; color: #2c3e50;">$Domain</span></div>
            <div><strong>REPORT DATE</strong><span style="font-size: 1.2em; color: #2c3e50;">$reportDate</span></div>
            <div><strong>SCAN DURATION</strong><span style="font-size: 1.2em; color: #2c3e50;">$([math]::Round($Duration.TotalSeconds, 2)) seconds</span></div>
            <div><strong>TOTAL FINDINGS</strong><span style="font-size: 1.2em; color: #2c3e50;">$($Findings.Count)</span></div>
        </div>
        
        <h2>📊 Executive Summary</h2>
        <div class="summary-cards">
            <div class="summary-card critical-card">
                <div class="count">$($Summary.Critical)</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high-card">
                <div class="count">$($Summary.High)</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium-card">
                <div class="count">$($Summary.Medium)</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low-card">
                <div class="count">$($Summary.Low)</div>
                <div class="label">Low</div>
            </div>
        </div>
"@
    
    # Add privileged users section if available
    if ($PrivilegedUsers -and $PrivilegedUsers.Count -gt 0) {
        $html += @"
        <h2>👥 Privileged Users Summary</h2>
        <p style="margin-bottom: 15px; color: #555;">The following $($PrivilegedUsers.Count) user accounts have membership in one or more privileged groups. Review these accounts regularly to ensure appropriate access levels.</p>
        <div style="overflow-x: auto;">
            <table class="privileged-users-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Display Name</th>
                        <th>Enabled</th>
                        <th>Privileged Groups</th>
                        <th>Password Last Set</th>
                        <th>Last Logon</th>
                        <th>Security Flags</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($user in ($PrivilegedUsers | Sort-Object -Property @{Expression={$_.PrivilegedGroups.Count}; Descending=$true}, SamAccountName)) {
            $enabledClass = if ($user.Enabled) { 'status-enabled' } else { 'status-disabled' }
            $enabledText = if ($user.Enabled) { 'Yes' } else { 'No' }
            
            $securityFlags = @()
            if ($user.PasswordNeverExpires) { $securityFlags += '🔓 Pwd Never Expires' }
            if ($user.DoesNotRequirePreAuth) { $securityFlags += '⚠️ No PreAuth' }
            if ($user.TrustedForDelegation) { $securityFlags += '🔑 Delegation' }
            if ($user.HasSPN) { $securityFlags += "🎯 SPN($($user.SPNCount))" }
            $flagsText = if ($securityFlags.Count -gt 0) { $securityFlags -join ' ' } else { '-' }
            
            $passwordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'Never' }
            $lastLogon = if ($user.LastLogonDate) { $user.LastLogonDate.ToString('yyyy-MM-dd') } else { 'Never' }
            
            $html += @"
                    <tr>
                        <td><strong>$($user.SamAccountName)</strong></td>
                        <td>$($user.DisplayName)</td>
                        <td class="$enabledClass">$enabledText</td>
                        <td style="font-size: 0.85em;">$($user.PrivilegedGroupsString)</td>
                        <td>$passwordLastSet</td>
                        <td>$lastLogon</td>
                        <td style="font-size: 0.85em;">$flagsText</td>
                    </tr>
"@
        }
        
        $html += @"
                </tbody>
            </table>
        </div>
"@
    }
    
    # Add findings by severity
    if ($criticalFindings) {
        $html += "<h2>🔴 Critical Severity Findings</h2>"
        foreach ($finding in $criticalFindings) {
            $html += Get-FindingHTML -Finding $finding
        }
    }
    
    if ($highFindings) {
        $html += "<h2>🟠 High Severity Findings</h2>"
        foreach ($finding in $highFindings) {
            $html += Get-FindingHTML -Finding $finding
        }
    }
    
    if ($mediumFindings) {
        $html += "<h2>🟡 Medium Severity Findings</h2>"
        foreach ($finding in $mediumFindings) {
            $html += Get-FindingHTML -Finding $finding
        }
    }
    
    if ($lowFindings) {
        $html += "<h2>⚪ Low Severity Findings</h2>"
        foreach ($finding in $lowFindings) {
            $html += Get-FindingHTML -Finding $finding
        }
    }
    
    $html += @"
        <div class="footer">
            <p>Generated by ADSecurityAudit Module v1.0.0</p>
            <p>This report should be treated as confidential and shared only with authorized personnel.</p>
        </div>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

<#
.SYNOPSIS
    Generates HTML for a single finding
#>
function Get-FindingHTML {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ADSecurityFinding]$Finding
    )
    
    $severityClass = $Finding.Severity.ToLower()
    
    return @"
        <div class="finding $severityClass">
            <div class="finding-header">
                <div class="finding-title">$($Finding.Issue)</div>
                <span class="severity-badge severity-$severityClass">$($Finding.Severity)</span>
            </div>
            <div class="finding-meta">
                <span><strong>Category:</strong> $($Finding.Category)</span>
                <span><strong>Affected Object:</strong> $($Finding.AffectedObject)</span>
                <span><strong>Detected:</strong> $($Finding.DetectedDate.ToString('yyyy-MM-dd HH:mm'))</span>
            </div>
            <div class="finding-section">
                <h4>📝 Description</h4>
                <p>$($Finding.Description)</p>
            </div>
            <div class="finding-section">
                <h4>⚠️ Impact</h4>
                <p>$($Finding.Impact)</p>
            </div>
            <div class="finding-section">
                <h4>✅ Remediation</h4>
                <p>$($Finding.Remediation)</p>
            </div>
        </div>
"@
}

#endregion

#region Export Module Members

Export-ModuleMember -Function @(
    'Start-ADSecurityAudit'
    'Test-ADUserSecurity'
    'Test-ADPrivilegedGroups'
    'Test-AdminSDHolder'
    'Test-ADGroupPolicies'
    'Test-ADReplicationSecurity'
    'Test-ADDomainSecurity'
    'Test-ADDangerousPermissions'
    'Get-ADPrivilegedUsers'
)

#endregion
