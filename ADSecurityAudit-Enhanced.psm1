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

$Script:ThresholdCriticalGroupSize = 5
$Script:ThresholdStandardGroupSize = 10
$Script:ThresholdInactiveDays = 90
$Script:ThresholdPasswordAgeDays = 180

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

$Script:DangerousRights = @{
    'GenericAll' = '00000000-0000-0000-0000-000000000000'
    'WriteOwner' = '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes' = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes-All' = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes-In-Filtered-Set' = '89e95b76-444d-4c62-991a-0facbeda640c'
    'User-Force-Change-Password' = '00299570-246d-11d0-a768-00aa006e0529'
}

class ADSecurityFinding {
    [string]$Category
    [string]$Issue
    [string]$Severity
    [int]$SeverityLevel
    [string]$Description
    [string]$Impact
    [string]$Remediation
    [string]$DocumentationLink
    [string]$AffectedObject
    [hashtable]$Details
    [datetime]$DetectedDate
    
    ADSecurityFinding() {
        $this.DetectedDate = Get-Date
        $this.Details = @{}
        $this.DocumentationLink = ""
    }
}

#region User Account Audits

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
        $getUserParams = @{
            Filter = '*'
            ErrorAction = 'Stop'
            Properties = @(
                'DoesNotRequirePreAuth', 'UseDESKeyOnly', 'AllowReversiblePasswordEncryption',
                'PasswordNeverExpires', 'TrustedForDelegation', 'LastLogonDate', 'PasswordLastSet',
                'ServicePrincipalNames', 'MemberOf', 'Enabled', 'DistinguishedName', 
                'UserPrincipalName', 'adminCount', 'SamAccountName', 'SID'
            )
        }
        
        if ($SearchBase) {
            $getUserParams['SearchBase'] = $SearchBase
        }
        
        $users = Get-ADUser @getUserParams
        
        Write-Verbose "Analyzing $($users.Count) user accounts..."
        
        $protectedUsersGroup = Get-ADGroup -Filter "Name -eq 'Protected Users'" -ErrorAction SilentlyContinue
        
        $userCount = $users.Count
        $currentUser = 0
        
        foreach ($user in $users) {
            $currentUser++
            
            if ($currentUser % 100 -eq 0 -or $currentUser -eq $userCount) {
                Write-Progress -Activity "Scanning User Accounts" -Status "Processing $($user.SamAccountName)" `
                    -PercentComplete (($currentUser / $userCount) * 100)
            }
            
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
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change"
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
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"
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
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption"
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
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/password-policy"
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
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
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
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/disable-adaccount"
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
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models"
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
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview"
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                    ServicePrincipalNames = $user.ServicePrincipalNames -join '; '
                    PasswordLastSet = $user.PasswordLastSet
                }
                $findings += $finding
            }
            
            if ($protectedUsersGroup) {
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
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"
                    $finding.Details = @{
                        DistinguishedName = $user.DistinguishedName
                        PrivilegedGroups = $isHighlyPrivileged -join '; '
                    }
                    $findings += $finding
                }
            }
        }
        
        Write-Progress -Activity "Scanning User Accounts" -Completed
        Write-Verbose "User account audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during user account audit: $_"
        throw
    }
}

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
        $groupCount = $groupsToCheck.Count
        $currentGroup = 0
        
        foreach ($groupName in $groupsToCheck) {
            $currentGroup++
            Write-Progress -Activity "Scanning Privileged Groups" -Status "Processing $groupName" `
                -PercentComplete (($currentGroup / $groupCount) * 100)
            
            try {
                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Properties Members, MemberOf -ErrorAction SilentlyContinue
                
                if (-not $group) {
                    continue
                }
                
                $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
                
                if (-not $members) {
                    continue
                }
                
                # Check for excessive membership
                $memberCount = ($members | Measure-Object).Count
                
                $criticalGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
                $threshold = if ($groupName -in $criticalGroups) { $Script:ThresholdCriticalGroupSize } else { $Script:ThresholdStandardGroupSize }
                
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
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models"
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
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups"
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
                    
                    if (-not $userDetails) {
                        continue
                    }
                    
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
                        $finding.DocumentationLink = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adgroupmember"
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
        
        Write-Progress -Activity "Scanning Privileged Groups" -Completed
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
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"
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
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists"
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
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"
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
        
        $gpoCount = $allGPOs.Count
        $currentGpo = 0
        
        foreach ($gpo in $allGPOs) {
            $currentGpo++
            Write-Progress -Activity "Scanning Group Policies" -Status "Processing $($gpo.DisplayName)" `
                -PercentComplete (($currentGpo / $gpoCount) * 100)
            
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
                        $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/securing-group-policy"
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
                        $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/set-group-policy-object-security"
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
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/powershell/module/grouppolicy/remove-gpo"
                $finding.Details = @{
                    GPOID = $gpo.Id
                    CreatedDate = $gpo.CreationTime
                    ModifiedDate = $gpo.ModificationTime
                }
                $findings += $finding
            }
        }
        
        Write-Progress -Activity "Scanning Group Policies" -Completed
        
        # Check SYSVOL permissions
        Write-Verbose "Checking SYSVOL permissions..."
        $sysvolPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)"
        
        if (Test-Path $sysvolPath) {
            try {
                $sysvolAcl = Get-Acl $sysvolPath -ErrorAction Stop
                
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
                        $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/sysvol-permissions-not-set-correctly"
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
            catch {
                Write-Warning "Could not access SYSVOL ACL: $_"
            }
        }
        else {
            Write-Warning "SYSVOL path not accessible at expected location: $sysvolPath"
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
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/defender-for-identity/lateral-movement-alerts#suspected-dcsync-attack-replication-of-directory-services-external-id-2006"
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
                        $finding.Description = "Group '$groupName' has $($members.Count) member(s). These groups have powerful rights that could be leveraged for privilege escalation or data exfiltration."
                        $finding.Impact = "Members of this group may have rights that can be leveraged for privilege escalation or data exfiltration."
                        $finding.Remediation = "Review membership and remove unnecessary accounts. Members: $($members.SamAccountName -join ', ')"
                        $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#server-operators"
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
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/minimum-password-length"
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
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements"
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
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption"
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
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels"
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
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#ad_recycle_bin_mgmt"
            $finding.Details = @{
                Feature = 'Recycle Bin'
                Status = 'Disabled'
            }
            $findings += $finding
        }
        
        # Check for computers with old OS versions
        Write-Verbose "Checking for legacy operating systems..."
        $computers = Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate
        
        $legacyOS = @(
            'Windows XP', 'Windows Vista', 'Windows 7', 'Windows 8', 'Windows 8.1',
            'Windows Server 2003', 'Windows Server 2008', 'Windows Server 2012', 'Windows Server 2012 R2'
        )
        
        $legacyComputers = $computers | Where-Object {
            $os = $_.OperatingSystem
            if ($os) {
                foreach ($legacyPattern in $legacyOS) {
                    if ($os -match [regex]::Escape($legacyPattern)) {
                        return $true
                    }
                }
            }
            return $false
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
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/plan-for-the-operations-master-role#operations-master-roles"
            $finding.Details = @{
                Count = $legacyComputers.Count
                Computers = ($legacyComputers | Select-Object Name, OperatingSystem, LastLogonDate -First 50)
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
                            # Added documentation for Enterprise Key Admins
                            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"
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
                            # Added documentation for Enterprise Key Admins
                            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"
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
                        # Added OU security documentation
                        $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/delegating-permissions-in-active-directory"
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

function Get-ADPrivilegedUsers {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Enumerating all privileged users..."
    
    try {
        $domain = Get-ADDomain
        $privilegedUsersList = [System.Collections.ArrayList]::new()
        $processedUsers = @{}
        
        $groupCount = $Script:ProtectedGroups.Count
        $currentGroup = 0
        
        foreach ($groupName in $Script:ProtectedGroups) {
            $currentGroup++
            Write-Progress -Activity "Enumerating Privileged Users" -Status "Processing group: $groupName" `
                -PercentComplete (($currentGroup / $groupCount) * 100)
            
            try {
                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Properties Members, Description -ErrorAction SilentlyContinue
                
                if (-not $group) {
                    Write-Verbose "Group '$groupName' not found, skipping..."
                    continue
                }
                
                Write-Verbose "Processing group: $groupName"
                
                # Get all members recursively
                $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
                
                if (-not $members) {
                    continue
                }
                
                # Filter to only user objects
                $userMembers = $members | Where-Object { $_.objectClass -eq 'user' }
                
                foreach ($member in $userMembers) {
                    # Get full user details
                    $user = Get-ADUser -Identity $member -Properties * -ErrorAction SilentlyContinue
                    
                    if (-not $user) {
                        continue
                    }
                    
                    $userSID = $user.SID.Value
                    
                    if (-not $processedUsers.ContainsKey($userSID)) {
                        # First time seeing this user, create new entry
                        $userObj = [PSCustomObject]@{
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
                            PrivilegedGroups = [System.Collections.ArrayList]@($groupName)
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
                        
                        $index = $privilegedUsersList.Add($userObj)
                        $processedUsers[$userSID] = $index
                    }
                    else {
                        # We've seen this user before, add this group to their list
                        $index = $processedUsers[$userSID]
                        [void]$privilegedUsersList[$index].PrivilegedGroups.Add($groupName)
                        $privilegedUsersList[$index].PrivilegedGroupsString = $privilegedUsersList[$index].PrivilegedGroups -join '; '
                    }
                }
            }
            catch {
                Write-Warning "Error processing group '$groupName': $_"
            }
        }
        
        Write-Progress -Activity "Enumerating Privileged Users" -Completed
        Write-Verbose "Found $($privilegedUsersList.Count) unique privileged users across $($Script:ProtectedGroups.Count) protected groups"
        
        return $privilegedUsersList | Sort-Object SamAccountName
    }
    catch {
        Write-Error "Error enumerating privileged users: $_"
        throw
    }
}

#endregion

#region Certificate Services (AD CS) Audits

function Test-ADCertificateServices {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting AD Certificate Services security audit..."
    $findings = @()
    
    try {
        # Check if AD CS is installed
        $configContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
        $pkiContainer = "CN=Public Key Services,CN=Services,$configContext"
        
        try {
            $certTemplates = Get-ADObject -SearchBase "CN=Certificate Templates,$pkiContainer" -Filter * -Properties * -ErrorAction Stop
        }
        catch {
            Write-Verbose "AD Certificate Services not found or accessible. Skipping AD CS audit."
            return $findings
        }
        
        Write-Verbose "Analyzing $($certTemplates.Count) certificate templates..."
        
        foreach ($template in $certTemplates) {
            # ESC1: Template allows SAN and has overly permissive enrollment rights
            $enrollmentFlag = $template.'msPKI-Enrollment-Flag'
            $certNameFlag = $template.'msPKI-Certificate-Name-Flag'
            
            # Check if template allows Subject Alternative Name (SAN)
            if ($certNameFlag -band 1) {  # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Certificate Services'
                $finding.Issue = 'Certificate Template Allows Subject Alternative Name (ESC1)'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $template.Name
                $finding.Description = "Certificate template '$($template.Name)' allows enrollees to specify Subject Alternative Names, which can be exploited for privilege escalation."
                $finding.Impact = "Attackers can request certificates for arbitrary accounts (including Domain Admins) and authenticate as those users."
                $finding.Remediation = "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag or restrict enrollment permissions to only trusted administrators."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-prevent-users-request-certificate"
                $finding.Details = @{
                    DistinguishedName = $template.DistinguishedName
                    CertificateNameFlag = $certNameFlag
                    EnrollmentFlag = $enrollmentFlag
                }
                $findings += $finding
            }
            
            # ESC2: Template can be used for any purpose
            $ekus = $template.'msPKI-Certificate-Application-Policy'
            if (-not $ekus -or $ekus.Count -eq 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Certificate Services'
                $finding.Issue = 'Certificate Template with No EKU Restrictions (ESC2)'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $template.Name
                $finding.Description = "Certificate template '$($template.Name)' has no Extended Key Usage (EKU) restrictions, allowing certificates to be used for any purpose."
                $finding.Impact = "Certificates can be used for unintended purposes including authentication, code signing, or encryption."
                $finding.Remediation = "Configure specific EKUs for the template to limit certificate usage to intended purposes only."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/configure-server-certificate-templates"
                $finding.Details = @{
                    DistinguishedName = $template.DistinguishedName
                }
                $findings += $finding
            }
            
            # Check for low RA signatures required
            $raSignatures = $template.'msPKI-RA-Signature'
            if ($raSignatures -and $raSignatures -eq 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Certificate Services'
                $finding.Issue = 'Certificate Template Does Not Require RA Signatures'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $template.Name
                $finding.Description = "Certificate template '$($template.Name)' does not require Registration Authority signatures for high-value certificates."
                $finding.Impact = "Reduces oversight for certificate issuance and increases risk of unauthorized certificate requests."
                $finding.Remediation = "For sensitive templates, require at least one RA signature to add an approval layer."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/server-certificate-deployment-overview"
                $finding.Details = @{
                    DistinguishedName = $template.DistinguishedName
                }
                $findings += $finding
            }
        }
        
        # Check Certificate Authority permissions
        try {
            $certAuthorities = Get-ADObject -SearchBase "CN=Enrollment Services,$pkiContainer" -Filter * -Properties * -ErrorAction Stop
            
            foreach ($ca in $certAuthorities) {
                $acl = Get-Acl -Path "AD:$($ca.DistinguishedName)" -ErrorAction SilentlyContinue
                
                if ($acl) {
                    foreach ($access in $acl.Access) {
                        # Check for dangerous permissions on CA
                        if ($access.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner' -and 
                            $access.IdentityReference -notmatch 'Enterprise Admins|Domain Admins|SYSTEM') {
                            
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = 'Certificate Services'
                            $finding.Issue = 'Overly Permissive CA Permissions'
                            $finding.Severity = 'Critical'
                            $finding.SeverityLevel = 4
                            $finding.AffectedObject = $ca.Name
                            $finding.Description = "Certificate Authority '$($ca.Name)' has overly permissive access granted to $($access.IdentityReference)."
                            $finding.Impact = "Unauthorized users could modify CA configuration, issue fraudulent certificates, or compromise the entire PKI infrastructure."
                            $finding.Remediation = "Remove excessive permissions and ensure only Enterprise Admins and CA administrators have full control."
                            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage-ca-security"
                            $finding.Details = @{
                                DistinguishedName = $ca.DistinguishedName
                                Identity = $access.IdentityReference
                                Rights = $access.ActiveDirectoryRights
                            }
                            $findings += $finding
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not enumerate Certificate Authorities: $_"
        }
        
        Write-Verbose "AD Certificate Services audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during AD CS audit: $_"
        throw
    }
}

#endregion

#region KRBTGT Account Audits

function Test-KRBTGTAccount {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$MaxPasswordAgeDays = 180
    )
    
    Write-Verbose "Starting KRBTGT account security audit..."
    $findings = @()
    
    try {
        # Get KRBTGT account
        $krbtgtAccount = Get-ADUser -Filter "SamAccountName -eq 'krbtgt'" -Properties PasswordLastSet, Enabled, Description -ErrorAction Stop
        
        if ($krbtgtAccount.PasswordLastSet) {
            $passwordAge = (Get-Date) - $krbtgtAccount.PasswordLastSet
            
            # Critical finding if KRBTGT password is too old
            if ($passwordAge.Days -gt $MaxPasswordAgeDays) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Security'
                $finding.Issue = 'KRBTGT Password Exceeds Recommended Age'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.Description = "The KRBTGT account password was last changed $passwordAge.Days days ago, exceeding the recommended 180-day maximum."
                $finding.Impact = "Stale KRBTGT passwords enable Golden Ticket attacks, allowing indefinite domain compromise even after remediation."
                $finding.AffectedObject = "KRBTGT"
                $finding.Remediation = "Reset the KRBTGT password twice (with appropriate intervals) using the official Microsoft script. WARNING: This is a sensitive operation that requires careful planning."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password"
                $finding.Details = @{
                    DistinguishedName = $krbtgtAccount.DistinguishedName
                    PasswordLastSet = $krbtgtAccount.PasswordLastSet
                    PasswordAgeDays = $passwordAge.Days
                    RecommendedMaxAgeDays = $MaxPasswordAgeDays
                }
                $findings += $finding
            }
            elseif ($passwordAge.Days -gt 120) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Security'
                $finding.Issue = 'KRBTGT Password Approaching Recommended Maximum Age'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.Description = "The KRBTGT account password was last changed $passwordAge.Days days ago. Should be reset before reaching 180 days."
                $finding.Impact = "Aging KRBTGT passwords increase the window for Golden Ticket attack persistence."
                $finding.AffectedObject = "KRBTGT"
                $finding.Remediation = "Plan to reset the KRBTGT password twice using the official Microsoft script before it exceeds 180 days."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password"
                $finding.Details = @{
                    DistinguishedName = $krbtgtAccount.DistinguishedName
                    PasswordLastSet = $krbtgtAccount.PasswordLastSet
                    PasswordAgeDays = $passwordAge.Days
                }
                $findings += $finding
            }
        }
        else {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Kerberos Security'
            $finding.Issue = 'KRBTGT Password Last Set Date Unknown'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = 'krbtgt'
            $finding.Description = "Unable to determine when the KRBTGT password was last changed."
            $finding.Impact = "Cannot assess risk of Golden Ticket attacks without knowing KRBTGT password age."
            $finding.Remediation = "Investigate why PasswordLastSet is not populated and reset the KRBTGT password."
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows/win32/adschema/a-pwdlastset"
            $finding.Details = @{
                DistinguishedName = $krbtgtAccount.DistinguishedName
            }
            $findings += $finding
        }
        
        Write-Verbose "KRBTGT account audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during KRBTGT audit: $_"
        throw
    }
}

#endregion

#region Domain Trust Audits

function Test-ADDomainTrusts {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting domain trust security audit..."
    $findings = @()
    
    try {
        $domain = Get-ADDomain
        $trusts = Get-ADTrust -Filter * -Properties *
        
        if (-not $trusts) {
            Write-Verbose "No domain trusts found."
            return $findings
        }
        
        Write-Verbose "Analyzing $($trusts.Count) domain trust(s)..."
        
        foreach ($trust in $trusts) {
            # Check for bidirectional trusts
            if ($trust.Direction -match 'Bidirectional') {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Trust Security'
                $finding.Issue = 'Bidirectional Trust Detected'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.Description = "A bidirectional trust exists with domain '$($trust.Target)', allowing authentication in both directions."
                $finding.Impact = "Increases attack surface. A compromise in either domain can affect the other."
                $finding.AffectedObject = $trust.Target
                $finding.Remediation = "Review if bidirectional trust is required. If not, convert to one-way trust or implement selective authentication."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/understanding-when-to-create-a-forest-trust"
                $finding.Details = @{
                    Target = $trust.Target
                    Direction = $trust.Direction
                    TrustType = $trust.TrustType
                    Created = $trust.Created
                }
                $findings += $finding
            }
            
            # Check if SID filtering is disabled (critical security issue)
            if ($trust.SIDFilteringQuarantined -eq $false -and $trust.TrustType -eq 'External') {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Trust Security'
                $finding.Issue = 'SID Filtering Disabled on External Trust'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.Description = "SID filtering is disabled on external trust to '$($trust.Target)', allowing SID history attacks."
                $finding.Impact = "Attackers can inject arbitrary SIDs and elevate privileges across the trust."
                $finding.AffectedObject = $trust.Target
                $finding.Remediation = "Enable SID filtering: netdom trust $($domain.DNSRoot) /domain:$($trust.Target) /quarantine:yes"
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772633(v=ws.10)"
                $finding.Details = @{
                    Target = $trust.Target
                    TrustType = $trust.TrustType
                    SIDFilteringQuarantined = $trust.SIDFilteringQuarantined
                }
                $findings += $finding
            }
            
            # Check for trusts without selective authentication
            if ($trust.SelectiveAuthentication -eq $false -and $trust.TrustType -eq 'Forest') {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Trust Security'
                $finding.Issue = 'Selective Authentication Not Enabled'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.Description = "Selective authentication is not enabled on forest trust to '$($trust.Target)'."
                $finding.Impact = "All users in the trusted forest have automatic access to resources without explicit permission."
                $finding.AffectedObject = $trust.Target
                $finding.Remediation = "Enable selective authentication to require explicit permission for cross-forest access."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc755844(v=ws.10)"
                $finding.Details = @{
                    Target = $trust.Target
                    TrustType = $trust.TrustType
                    SelectiveAuthentication = $trust.SelectiveAuthentication
                }
                $findings += $finding
            }
            
            # Check trust password age
            if ($trust.Modified) {
                $trustAge = (Get-Date) - $trust.Modified
                if ($trustAge.Days -gt 30) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Trust Security'
                    $finding.Issue = 'Trust Password Not Recently Rotated'
                    $finding.Severity = 'Low'
                    $finding.SeverityLevel = 1
                    $finding.AffectedObject = $trust.Target
                    $finding.Description = "Trust with '$($trust.Target)' has not been modified in $($trustAge.Days) days. Trust passwords should rotate automatically every 30 days."
                    $finding.Impact = "May indicate trust relationship issues or lack of maintenance."
                    $finding.Remediation = "Verify trust health: netdom trust $($domain.DNSRoot) /domain:$($trust.Target) /verify"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/security/netdom-trust-command-not-work"
                    $finding.Details = @{
                        Target = $trust.Target
                        LastModified = $trust.Modified
                        DaysSinceModified = $trustAge.Days
                    }
                    $findings += $finding
                }
            }
        }
        
        Write-Verbose "Domain trust audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during domain trust audit: $_"
        throw
    }
}

#endregion

#region LAPS Deployment Audits

function Test-LAPSDeployment {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting LAPS deployment audit..."
    $findings = @()
    
    try {
        $domain = Get-ADDomain
        $schemaPath = "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$($domain.DistinguishedName)"
        
        # Check if LAPS schema is extended
        try {
            $lapsSchema = Get-ADObject -Identity $schemaPath -ErrorAction Stop
            $lapsInstalled = $true
            Write-Verbose "LAPS schema extension detected."
        }
        catch {
            $lapsInstalled = $false
            
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'LAPS Security'
            $finding.Issue = 'LAPS Not Deployed'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.Description = "Local Administrator Password Solution (LAPS) schema attributes are not present in Active Directory."
            $finding.Impact = "Local administrator passwords are likely identical across computers, enabling lateral movement via Pass-the-Hash attacks."
            $finding.AffectedObject = "Domain"
            $finding.Remediation = "Deploy LAPS to randomize and manage local administrator passwords across all domain computers. Install LAPS schema: Update-AdmPwdADSchema"
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"
            $finding.Details = @{
                Domain = $domain.DNSRoot
            }
            $findings += $finding
            
            Write-Verbose "LAPS not deployed. Skipping computer-level checks."
            return $findings
        }
        
        # If LAPS is installed, check computer coverage
        if ($lapsInstalled) {
            $computers = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime, OperatingSystem -ErrorAction Stop
            $computersWithLAPS = $computers | Where-Object { $_.'ms-Mcs-AdmPwdExpirationTime' }
            $computersWithoutLAPS = $computers | Where-Object { -not $_.'ms-Mcs-AdmPwdExpirationTime' }
            
            $totalComputers = $computers.Count
            $coveragePercent = if ($totalComputers -gt 0) { 
                [math]::Round(($computersWithLAPS.Count / $totalComputers) * 100, 2) 
            } else { 0 }
            
            Write-Verbose "LAPS coverage: $coveragePercent% ($($computersWithLAPS.Count)/$totalComputers computers)"
            
            # Alert if coverage is below 100%
            if ($coveragePercent -lt 100) {
                $severity = if ($coveragePercent -lt 50) { 'Critical' } 
                           elseif ($coveragePercent -lt 80) { 'High' } 
                           else { 'Medium' }
                           
                $severityLevel = if ($coveragePercent -lt 50) { 4 } 
                                elseif ($coveragePercent -lt 80) { 3 } 
                                else { 2 }
                
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'LAPS Security'
                $finding.Issue = 'Incomplete LAPS Coverage'
                $finding.Severity = $severity
                $finding.SeverityLevel = $severityLevel
                $finding.AffectedObject = "$($computersWithoutLAPS.Count) Computers"
                $finding.Description = "Only $coveragePercent% of domain computers have LAPS passwords set. $($computersWithoutLAPS.Count) computers are missing LAPS coverage."
                $finding.Impact = "Computers without LAPS retain static local administrator passwords, creating lateral movement opportunities for attackers."
                $finding.Remediation = "Deploy LAPS Group Policy to all OUs containing computers. Verify LAPS client is installed and GPO is applied. Check: gpresult /r"
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings"
                $finding.Details = @{
                    TotalComputers = $totalComputers
                    ComputersWithLAPS = $computersWithLAPS.Count
                    ComputersWithoutLAPS = $computersWithoutLAPS.Count
                    CoveragePercent = $coveragePercent
                    SampleComputersWithoutLAPS = ($computersWithoutLAPS | Select-Object -First 10 -ExpandProperty Name) -join ', '
                }
                $findings += $finding
            }
            
            # Check for expired LAPS passwords
            $now = [DateTime]::UtcNow
            $expiredLAPSComputers = $computersWithLAPS | Where-Object {
                $expirationTime = [DateTime]::FromFileTimeUtc($_.'ms-Mcs-AdmPwdExpirationTime')
                $expirationTime -lt $now
            }
            
            if ($expiredLAPSComputers.Count -gt 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'LAPS Security'
                $finding.Issue = 'Expired LAPS Passwords'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = "$($expiredLAPSComputers.Count) Computers"
                $finding.Description = "$($expiredLAPSComputers.Count) computers have expired LAPS passwords that have not been rotated."
                $finding.Impact = "Expired passwords may indicate computers that are offline, not receiving GPO updates, or have LAPS client issues."
                $finding.Remediation = "Investigate why LAPS passwords are not rotating. Ensure computers are online and receiving Group Policy updates."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/laps-troubleshooting-guidance"
                $finding.Details = @{
                    ExpiredCount = $expiredLAPSComputers.Count
                    SampleComputers = ($expiredLAPSComputers | Select-Object -First 10 -ExpandProperty Name) -join ', '
                }
                $findings += $finding
            }
        }
        
        Write-Verbose "LAPS deployment audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during LAPS audit: $_"
        throw
    }
}

#endregion

#region Audit Policy Configuration Audits

function Test-AuditPolicyConfiguration {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting audit policy configuration audit..."
    $findings = @()
    
    try {
        # Get domain controllers to check audit policies
        $domainControllers = Get-ADDomainController -Filter *
        
        Write-Verbose "Checking audit policies on $($domainControllers.Count) domain controller(s)..."
        
        # Critical audit policies that should be enabled
        $requiredAuditPolicies = @{
            'Account Logon' = @('Audit Credential Validation')
            'Account Management' = @('Audit User Account Management', 'Audit Security Group Management')
            'DS Access' = @('Audit Directory Service Access', 'Audit Directory Service Changes')
            'Logon/Logoff' = @('Audit Logon', 'Audit Logoff', 'Audit Account Lockout')
            'Object Access' = @('Audit File Share', 'Audit File System')
            'Policy Change' = @('Audit Policy Change', 'Audit Authentication Policy Change')
            'Privilege Use' = @('Audit Sensitive Privilege Use')
            'System' = @('Audit Security State Change', 'Audit Security System Extension')
        }
        
        foreach ($dc in $domainControllers) {
            try {
                # Check if we can query the DC (in a real scenario, you'd use Invoke-Command)
                # For this script, we'll check local/default domain policy
                
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Audit Policy'
                $finding.Issue = 'Advanced Audit Policy Verification Required'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $dc.Name
                $finding.Description = "Advanced audit policies should be verified on domain controller '$($dc.Name)' to ensure proper security event logging."
                $finding.Impact = "Without proper audit policies, security incidents cannot be detected or investigated effectively. Critical events may go unlogged."
                $finding.Remediation = @"
Verify and enable advanced audit policies on all DCs:
1. Account Logon: Audit Credential Validation (Success, Failure)
2. Account Management: Audit User/Security Group Management (Success, Failure)
3. DS Access: Audit Directory Service Access/Changes (Success, Failure)
4. Logon/Logoff: Audit Logon/Logoff/Account Lockout (Success, Failure)
5. Object Access: Audit File Share/System (Success, Failure)
6. Policy Change: Audit Policy/Auth Policy Change (Success, Failure)
7. Privilege Use: Audit Sensitive Privilege Use (Success, Failure)
8. System: Audit Security State Change/System Extension (Success, Failure)

Use: auditpol /get /category:* to view current settings
Configure via Group Policy: Computer Config > Windows Settings > Security Settings > Advanced Audit Policy
"@
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations"
                $finding.Details = @{
                    DomainController = $dc.Name
                    RequiredCategories = $requiredAuditPolicies.Keys -join ', '
                }
                $findings += $finding
                
            }
            catch {
                Write-Warning "Could not check audit policy on $($dc.Name): $_"
            }
        }
        
        # Check for SACL on sensitive AD objects
        try {
            $domain = Get-ADDomain
            $domainRoot = $domain.DistinguishedName
            
            # Check if AdminSDHolder has auditing configured
            $adminSDHolder = Get-ADObject "CN=AdminSDHolder,CN=System,$domainRoot" -Properties nTSecurityDescriptor -ErrorAction Stop
            $acl = $adminSDHolder.nTSecurityDescriptor
            
            $hasAuditRules = $acl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]).Count -gt 0
            
            if (-not $hasAuditRules) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Audit Policy'
                $finding.Issue = 'No Auditing on AdminSDHolder Object'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = 'AdminSDHolder'
                $finding.Description = "The AdminSDHolder object does not have audit rules (SACL) configured to log access attempts."
                $finding.Impact = "Changes to privileged group permissions and access attempts to critical AD objects will not be logged, hindering incident detection."
                $finding.Remediation = "Configure SACL on AdminSDHolder to audit 'Write all properties' and 'Modify permissions' for 'Everyone' (Success and Failure)."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows/win32/secauthz/audit-generation"
                $finding.Details = @{
                    DistinguishedName = $adminSDHolder.DistinguishedName
                }
                $findings += $finding
            }
        }
        catch {
            Write-Verbose "Could not check AdminSDHolder SACL: $_"
        }
        
        Write-Verbose "Audit policy configuration audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during audit policy audit: $_"
        throw
    }
}

#endregion

#region Constrained Delegation Audits

function Test-ConstrainedDelegation {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting constrained delegation security audit..."
    $findings = @()
    
    try {
        # Check user accounts with constrained delegation
        $usersWithConstrainedDelegation = Get-ADUser -Filter {msDS-AllowedToDelegateTo -like '*'} `
            -Properties msDS-AllowedToDelegateTo, TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalNames, Enabled
        
        foreach ($user in $usersWithConstrainedDelegation) {
            # Check for protocol transition (most dangerous)
            if ($user.TrustedToAuthForDelegation -eq $true) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Delegation'
                $finding.Issue = 'User Account with Protocol Transition (T2A4D)'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User account '$($user.SamAccountName)' has constrained delegation with protocol transition enabled (TrustedToAuthForDelegation)."
                $finding.Impact = "Can impersonate ANY user to specified services without requiring their credentials. Highly exploitable for privilege escalation."
                $finding.Remediation = "Disable protocol transition if not absolutely required. If needed, ensure the account has a very strong password (30+ characters) and is closely monitored. Consider migrating to Group Managed Service Accounts."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                    AllowedToDelegateTo = $user.'msDS-AllowedToDelegateTo' -join '; '
                    TrustedToAuthForDelegation = $user.TrustedToAuthForDelegation
                    Enabled = $user.Enabled
                }
                $findings += $finding
            }
            else {
                # Standard constrained delegation
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Delegation'
                $finding.Issue = 'User Account with Constrained Delegation'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User account '$($user.SamAccountName)' has constrained delegation configured to specific services."
                $finding.Impact = "Can impersonate authenticated users to specified services. Less risky than unconstrained delegation but still requires strong security controls."
                $finding.Remediation = "Verify this configuration is necessary. Ensure strong password policy and monitoring. Review delegated services: $($user.'msDS-AllowedToDelegateTo' -join ', ')"
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                    AllowedToDelegateTo = $user.'msDS-AllowedToDelegateTo' -join '; '
                    Enabled = $user.Enabled
                }
                $findings += $finding
            }
        }
        
        # Check computer accounts with constrained delegation
        $computersWithConstrainedDelegation = Get-ADComputer -Filter {msDS-AllowedToDelegateTo -like '*'} `
            -Properties msDS-AllowedToDelegateTo, TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalNames, Enabled
        
        foreach ($computer in $computersWithConstrainedDelegation) {
            if ($computer.TrustedToAuthForDelegation -eq $true) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Delegation'
                $finding.Issue = 'Computer Account with Protocol Transition (T2A4D)'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $computer.Name
                $finding.Description = "Computer account '$($computer.Name)' has constrained delegation with protocol transition enabled."
                $finding.Impact = "If compromised, attackers can impersonate any user to specified services. Common on Exchange servers but requires securing the host."
                $finding.Remediation = "Verify this configuration is required (common for Exchange/IIS). Ensure the computer is hardened, patched, and monitored. Services: $($computer.'msDS-AllowedToDelegateTo' -join ', ')"
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
                $finding.Details = @{
                    DistinguishedName = $computer.DistinguishedName
                    AllowedToDelegateTo = $computer.'msDS-AllowedToDelegateTo' -join '; '
                    TrustedToAuthForDelegation = $computer.TrustedToAuthForDelegation
                    Enabled = $computer.Enabled
                }
                $findings += $finding
            }
        }
        
        # Check for Resource-Based Constrained Delegation (RBCD)
        $objectsWithRBCD = Get-ADObject -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} `
            -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, objectClass, Name
        
        foreach ($object in $objectsWithRBCD) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Kerberos Delegation'
            $finding.Issue = 'Resource-Based Constrained Delegation Configured'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = $object.Name
            $finding.Description = "Object '$($object.Name)' has Resource-Based Constrained Delegation (RBCD) configured, allowing other accounts to impersonate users to this resource."
            $finding.Impact = "RBCD can be exploited if an attacker can modify the msDS-AllowedToActOnBehalfOfOtherIdentity attribute or compromise accounts listed in it."
            $finding.Remediation = "Review RBCD configuration and ensure only necessary accounts are allowed. Monitor for unauthorized changes to this attribute."
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview#resource-based-constrained-delegation"
            $finding.Details = @{
                DistinguishedName = $object.DistinguishedName
                ObjectClass = $object.objectClass
            }
            $findings += $finding
        }
        
        Write-Verbose "Constrained delegation audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during constrained delegation audit: $_"
        throw
    }
}

#endregion

#region Computer Account and Delegation Audits

function Test-ComputerAccountDelegation {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$InactiveDaysThreshold = 90
    )
    
    Write-Verbose "Starting computer account delegation audit..."
    $findings = @()
    
    try {
        # Get all computer accounts with delegation-related properties
        $computers = Get-ADComputer -Filter * -Properties `
            TrustedForDelegation, TrustedToAuthForDelegation, `
            msDS-AllowedToDelegateTo, LastLogonDate, OperatingSystem, `
            ServicePrincipalNames, Enabled, DistinguishedName, `
            PrimaryGroupID -ErrorAction Stop
        
        Write-Verbose "Analyzing $($computers.Count) computer accounts..."
        
        $computerCount = $computers.Count
        $currentComputer = 0
        
        foreach ($computer in $computers) {
            $currentComputer++
            
            if ($currentComputer % 50 -eq 0 -or $currentComputer -eq $computerCount) {
                Write-Progress -Activity "Scanning Computer Accounts" -Status "Processing $($computer.Name)" `
                    -PercentComplete (($currentComputer / $computerCount) * 100)
            }
            
            # Check for unconstrained delegation on computer accounts
            if ($computer.TrustedForDelegation -eq $true -and $computer.PrimaryGroupID -ne 516) {
                # PrimaryGroupID 516 = Domain Controllers (DCs are expected to have this)
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Computer Account Security'
                $finding.Issue = 'Unconstrained Delegation Enabled'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $computer.Name
                $finding.Description = "Computer account has unconstrained delegation enabled, which can be exploited to compromise any user credentials."
                $finding.Impact = "An attacker who compromises this computer can impersonate ANY user (including Domain Admins) who authenticates to it. This is a critical privilege escalation path."
                $finding.Remediation = "Disable unconstrained delegation immediately: Set-ADComputer -Identity '$($computer.Name)' -TrustedForDelegation `$false. If delegation is required, use constrained delegation instead."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unconstrained-kerberos"
                $finding.Details = @{
                    DistinguishedName = $computer.DistinguishedName
                    OperatingSystem = $computer.OperatingSystem
                    LastLogonDate = $computer.LastLogonDate
                    ServicePrincipalNames = $computer.ServicePrincipalNames -join '; '
                }
                $findings += $finding
            }
            
            # Check for protocol transition (TrustedToAuthForDelegation)
            if ($computer.TrustedToAuthForDelegation -eq $true) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Computer Account Security'
                $finding.Issue = 'Computer Trusted for Protocol Transition'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $computer.Name
                $finding.Description = "Computer account is trusted for protocol transition (Kerberos S4U2Self), allowing it to obtain service tickets on behalf of any user."
                $finding.Impact = "This computer can impersonate users without requiring their credentials, potentially leading to privilege escalation."
                $finding.Remediation = "Review if protocol transition is necessary. If not required, remove this setting. Ensure only specific services use this feature with constrained delegation."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
                $finding.Details = @{
                    DistinguishedName = $computer.DistinguishedName
                    OperatingSystem = $computer.OperatingSystem
                    AllowedToDelegateTo = $computer.'msDS-AllowedToDelegateTo' -join '; '
                }
                $findings += $finding
            }
            
            # Check for constrained delegation on computers
            if ($computer.'msDS-AllowedToDelegateTo' -and $computer.'msDS-AllowedToDelegateTo'.Count -gt 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Computer Account Security'
                $finding.Issue = 'Computer with Constrained Delegation'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $computer.Name
                $finding.Description = "Computer account has constrained delegation configured for $($computer.'msDS-AllowedToDelegateTo'.Count) service(s)."
                $finding.Impact = "While constrained delegation is safer than unconstrained, it still allows this computer to impersonate users to specific services. Verify this is intentional and necessary."
                $finding.Remediation = "Review delegation targets and ensure they are appropriate. Consider using Resource-Based Constrained Delegation (RBCD) for better security. Monitor for abuse."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
                $finding.Details = @{
                    DistinguishedName = $computer.DistinguishedName
                    OperatingSystem = $computer.OperatingSystem
                    DelegationTargets = $computer.'msDS-AllowedToDelegateTo' -join '; '
                    ProtocolTransition = $computer.TrustedToAuthForDelegation
                }
                $findings += $finding
            }
            
            # Check for stale computer accounts
            if ($computer.Enabled -eq $true -and $computer.LastLogonDate) {
                $daysSinceLogon = (Get-Date) - $computer.LastLogonDate
                if ($daysSinceLogon.Days -gt $InactiveDaysThreshold) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Computer Account Security'
                    $finding.Issue = 'Stale Computer Account'
                    $finding.Severity = 'Low'
                    $finding.SeverityLevel = 1
                    $finding.AffectedObject = $computer.Name
                    $finding.Description = "Enabled computer account has not authenticated to the domain in $($daysSinceLogon.Days) days."
                    $finding.Impact = "Stale computer accounts increase attack surface and may have weak security configurations. They can be used for persistence if compromised."
                    $finding.Remediation = "Verify if this computer is still in use. If not, disable or delete: Disable-ADAccount -Identity '$($computer.Name)'"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/remove-stale-domain-controller"
                    $finding.Details = @{
                        DistinguishedName = $computer.DistinguishedName
                        OperatingSystem = $computer.OperatingSystem
                        LastLogonDate = $computer.LastLogonDate
                        DaysSinceLogon = $daysSinceLogon.Days
                    }
                    $findings += $finding
                }
            }
        }
        
        # Check Machine Account Quota
        $rootDSE = Get-ADRootDSE
        $domainDN = $rootDSE.defaultNamingContext
        $domainObject = Get-ADObject -Identity $domainDN -Properties ms-DS-MachineAccountQuota
        $machineAccountQuota = $domainObject.'ms-DS-MachineAccountQuota'
        
        if ($machineAccountQuota -gt 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Computer Account Security'
            $finding.Issue = 'Machine Account Quota Enabled'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = 'Domain'
            $finding.Description = "The ms-DS-MachineAccountQuota is set to $machineAccountQuota, allowing non-privileged users to join computers to the domain."
            $finding.Impact = "Attackers can add rogue computers to the domain, which can be used for privilege escalation attacks (e.g., resource-based constrained delegation abuse)."
            $finding.Remediation = "Set ms-DS-MachineAccountQuota to 0: Set-ADDomain -Identity '$($domain.DistinguishedName)' -Replace @{'ms-DS-MachineAccountQuota'=0}. Control computer joins through Group Policy or delegated permissions."
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/add-workstations-to-domain"
            $finding.Details = @{
                CurrentQuota = $machineAccountQuota
                DomainDN = $domainDN
            }
            $findings += $finding
        }
        
        Write-Progress -Activity "Scanning Computer Accounts" -Completed
        Write-Verbose "Computer account delegation audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during computer account delegation audit: $_"
        throw
    }
}

#endregion

#region Fine-Grained Password Policy Audits

function Test-FineGrainedPasswordPolicies {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting fine-grained password policy audit..."
    $findings = @()
    
    try {
        # Check domain functional level (FGPP requires Windows Server 2008 or higher)
        $domain = Get-ADDomain
        $domainLevel = $domain.DomainMode
        
        if ($domainLevel -lt 'Windows2008Domain') {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Password Policies'
            $finding.Issue = 'Fine-Grained Password Policies Not Supported'
            $finding.Severity = 'Low'
            $finding.SeverityLevel = 1
            $finding.AffectedObject = 'Domain'
            $finding.Description = "Domain functional level ($domainLevel) does not support Fine-Grained Password Policies (FGPP)."
            $finding.Impact = "Cannot enforce different password policies for different user groups, limiting security flexibility for privileged accounts."
            $finding.Remediation = "Consider raising domain functional level to Windows Server 2008 or higher to enable FGPP support."
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc770394(v=ws.10)"
            $finding.Details = @{
                DomainMode = $domainLevel
                DomainName = $domain.DNSRoot
            }
            $findings += $finding
            return $findings
        }
        
        # Get default domain password policy
        $defaultPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        
        # Audit default domain password policy
        if ($defaultPolicy.MinPasswordLength -lt 14) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Password Policies'
            $finding.Issue = 'Weak Default Password Length'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = 'Default Domain Policy'
            $finding.Description = "Default domain password policy requires only $($defaultPolicy.MinPasswordLength) characters. NIST recommends minimum 14 characters."
            $finding.Impact = "Short passwords are vulnerable to brute-force and password spray attacks."
            $finding.Remediation = "Increase minimum password length to at least 14 characters: Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 -Identity '$($domain.DistinguishedName)'"
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/minimum-password-length"
            $finding.Details = @{
                CurrentMinLength = $defaultPolicy.MinPasswordLength
                RecommendedMinLength = 14
            }
            $findings += $finding
        }
        
        if ($defaultPolicy.ComplexityEnabled -eq $false) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Password Policies'
            $finding.Issue = 'Password Complexity Disabled'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.AffectedObject = 'Default Domain Policy'
            $finding.Description = "Password complexity is disabled in the default domain password policy."
            $finding.Impact = "Users can set simple, easily guessable passwords, significantly increasing risk of compromise."
            $finding.Remediation = "Enable password complexity: Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled `$true -Identity '$($domain.DistinguishedName)'"
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements"
            $finding.Details = @{
                ComplexityEnabled = $defaultPolicy.ComplexityEnabled
            }
            $findings += $finding
        }
        
        if ($defaultPolicy.LockoutThreshold -eq 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Password Policies'
            $finding.Issue = 'Account Lockout Not Configured'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = 'Default Domain Policy'
            $finding.Description = "Account lockout is not enabled (threshold is 0), allowing unlimited password attempts."
            $finding.Impact = "Domain is vulnerable to password brute-force and spray attacks with no automatic account lockout protection."
            $finding.Remediation = "Configure account lockout: Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 -LockoutDuration 00:30:00 -LockoutObservationWindow 00:30:00"
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/account-lockout-threshold"
            $finding.Details = @{
                LockoutThreshold = $defaultPolicy.LockoutThreshold
                RecommendedThreshold = 5
            }
            $findings += $finding
        }
        
        if ($defaultPolicy.MaxPasswordAge.Days -gt 90 -or $defaultPolicy.MaxPasswordAge.Days -eq 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Password Policies'
            $finding.Issue = 'Password Expiration Too Long or Disabled'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = 'Default Domain Policy'
            $finding.Description = "Maximum password age is $($defaultPolicy.MaxPasswordAge.Days) days. Recommended is 60-90 days."
            $finding.Impact = "Long-lived passwords increase the window of opportunity for compromised credentials to be exploited."
            $finding.Remediation = "Set reasonable password expiration: Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 90.00:00:00"
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/maximum-password-age"
            $finding.Details = @{
                CurrentMaxAge = $defaultPolicy.MaxPasswordAge.Days
                RecommendedMaxAge = 90
            }
            $findings += $finding
        }
        
        # Get all Fine-Grained Password Policies (PSOs)
        $psos = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction SilentlyContinue
        
        if (-not $psos -or $psos.Count -eq 0) {
            # Check if privileged accounts exist
            $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
            $hasPrivilegedUsers = $false
            
            foreach ($groupName in $privilegedGroups) {
                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
                if ($group) {
                    $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                    if ($members) {
                        $hasPrivilegedUsers = $true
                        break
                    }
                }
            }
            
            if ($hasPrivilegedUsers) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Password Policies'
                $finding.Issue = 'No Fine-Grained Password Policies for Privileged Accounts'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = 'Domain'
                $finding.Description = "No Fine-Grained Password Policies (PSOs) are configured, but privileged accounts exist in the domain."
                $finding.Impact = "Privileged accounts follow the same password policy as standard users, which may not provide adequate protection for high-value accounts."
                $finding.Remediation = "Create a stricter PSO for privileged accounts with longer passwords (20+ chars), shorter expiration, and stricter lockout policies. Use New-ADFineGrainedPasswordPolicy cmdlet."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc770842(v=ws.10)"
                $finding.Details = @{
                    PSOCount = 0
                    DomainFunctionalLevel = $domainLevel
                }
                $findings += $finding
            }
        }
        else {
            Write-Verbose "Found $($psos.Count) Fine-Grained Password Policy Objects"
            
            foreach ($pso in $psos) {
                # Check PSO password length
                if ($pso.MinPasswordLength -lt 20) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Password Policies'
                    $finding.Issue = 'Weak PSO Password Length'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $pso.Name
                    $finding.Description = "Fine-Grained Password Policy '$($pso.Name)' requires only $($pso.MinPasswordLength) characters. For privileged accounts, 20+ characters recommended."
                    $finding.Impact = "PSOs typically apply to privileged accounts. Weak password requirements reduce protection for high-value targets."
                    $finding.Remediation = "Increase minimum password length for PSO: Set-ADFineGrainedPasswordPolicy -Identity '$($pso.Name)' -MinPasswordLength 20"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adfinegrainedpasswordpolicy"
                    $finding.Details = @{
                        PSOName = $pso.Name
                        CurrentMinLength = $pso.MinPasswordLength
                        RecommendedMinLength = 20
                        AppliesTo = $pso.AppliesTo -join '; '
                        Precedence = $pso.Precedence
                    }
                    $findings += $finding
                }
                
                # Check PSO complexity
                if ($pso.ComplexityEnabled -eq $false) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Password Policies'
                    $finding.Issue = 'PSO Password Complexity Disabled'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $pso.Name
                    $finding.Description = "Fine-Grained Password Policy '$($pso.Name)' has password complexity disabled."
                    $finding.Impact = "Accounts under this PSO can use simple passwords, increasing compromise risk for what are typically privileged accounts."
                    $finding.Remediation = "Enable complexity: Set-ADFineGrainedPasswordPolicy -Identity '$($pso.Name)' -ComplexityEnabled `$true"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adfinegrainedpasswordpolicy"
                    $finding.Details = @{
                        PSOName = $pso.Name
                        ComplexityEnabled = $pso.ComplexityEnabled
                        AppliesTo = $pso.AppliesTo -join '; '
                    }
                    $findings += $finding
                }
                
                # Check if PSO has any objects assigned
                if (-not $pso.AppliesTo -or $pso.AppliesTo.Count -eq 0) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Password Policies'
                    $finding.Issue = 'PSO Not Applied to Any Objects'
                    $finding.Severity = 'Low'
                    $finding.SeverityLevel = 1
                    $finding.AffectedObject = $pso.Name
                    $finding.Description = "Fine-Grained Password Policy '$($pso.Name)' exists but is not applied to any users or groups."
                    $finding.Impact = "The PSO has no effect and represents unused configuration that should be cleaned up."
                    $finding.Remediation = "Either apply the PSO to appropriate users/groups using Add-ADFineGrainedPasswordPolicySubject, or remove it if not needed."
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adfinegrainedpasswordpolicysubject"
                    $finding.Details = @{
                        PSOName = $pso.Name
                        Precedence = $pso.Precedence
                        MinPasswordLength = $pso.MinPasswordLength
                    }
                    $findings += $finding
                }
                
                # Check for conflicting PSos (same precedence)
                $conflictingPSOs = $psos | Where-Object { 
                    $_.Name -ne $pso.Name -and $_.Precedence -eq $pso.Precedence 
                }
                
                if ($conflictingPSOs) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Password Policies'
                    $finding.Issue = 'PSO Precedence Conflict'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $pso.Name
                    $finding.Description = "PSO '$($pso.Name)' has the same precedence ($($pso.Precedence)) as other PSO(s): $($conflictingPSOs.Name -join ', ')"
                    $finding.Impact = "When multiple PSOs apply to the same user with identical precedence, the result is unpredictable and may not enforce intended policies."
                    $finding.Remediation = "Assign unique precedence values to all PSOs. Lower numbers have higher priority. Review and adjust precedence values."
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc770394(v=ws.10)#precedence"
                    $finding.Details = @{
                        PSOName = $pso.Name
                        Precedence = $pso.Precedence
                        ConflictingPSOs = $conflictingPSOs.Name -join '; '
                    }
                    $findings += $finding
                }
            }
        }
        
        Write-Verbose "Fine-grained password policy audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during fine-grained password policy audit: $_"
        throw
    }
}

#endregion

#region DNS Security Audits

function Test-DNSSecurityConfiguration {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting DNS security configuration audit..."
    $findings = @()
    
    try {
        # Get all domain controllers (DNS servers)
        $domainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
        
        Write-Verbose "Analyzing DNS configuration on $($domainControllers.Count) domain controller(s)..."
        
        foreach ($dc in $domainControllers) {
            $dcName = $dc.HostName
            
            Write-Verbose "Checking DNS on $dcName..."
            
            # Check if DNS service is running
            try {
                $dnsService = Get-Service -Name DNS -ComputerName $dcName -ErrorAction Stop
                
                if ($dnsService.Status -ne 'Running') {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'DNS Security'
                    $finding.Issue = 'DNS Service Not Running on DC'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $dcName
                    $finding.Description = "DNS service is not running on domain controller $dcName."
                    $finding.Impact = "Clients may experience authentication and name resolution issues. Domain functionality may be degraded."
                    $finding.Remediation = "Start DNS service: Start-Service -Name DNS -ComputerName '$dcName'. Investigate why the service stopped."
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-server-not-starting"
                    $finding.Details = @{
                        ServiceStatus = $dnsService.Status
                        DomainController = $dcName
                    }
                    $findings += $finding
                }
            }
            catch {
                Write-Verbose "Could not query DNS service on $dcName : $_"
            }
            
            # Check DNS zone security using WMI/CIM
            try {
                $dnsZones = Get-CimInstance -ComputerName $dcName -Namespace root\MicrosoftDNS `
                    -ClassName MicrosoftDNS_Zone -ErrorAction Stop
                
                foreach ($zone in $dnsZones) {
                    # Check for zone transfers allowed to any server
                    if ($zone.SecureSecondaries -eq 0) {
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'DNS Security'
                        $finding.Issue = 'DNS Zone Transfers Unrestricted'
                        $finding.Severity = 'High'
                        $finding.SeverityLevel = 3
                        $finding.AffectedObject = "$dcName - $($zone.Name)"
                        $finding.Description = "DNS zone '$($zone.Name)' on $dcName allows zone transfers to any server."
                        $finding.Impact = "Attackers can enumerate all DNS records, revealing network topology, server names, and potential targets."
                        $finding.Remediation = "Restrict zone transfers to authorized DNS servers only through DNS Manager or Set-DnsServerPrimaryZone cmdlet."
                        $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/networking/dns/zone-transfers"
                        $finding.Details = @{
                            ZoneName = $zone.Name
                            SecureSecondaries = $zone.SecureSecondaries
                            DomainController = $dcName
                            ZoneType = $zone.ZoneType
                        }
                        $findings += $finding
                    }
                    
                    # Check for unsigned zones (DNSSEC)
                    if ($zone.ZoneType -eq 1 -and $zone.IsSigned -eq $false) {
                        # ZoneType 1 = Primary zone
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'DNS Security'
                        $finding.Issue = 'DNS Zone Not Signed (No DNSSEC)'
                        $finding.Severity = 'Medium'
                        $finding.SeverityLevel = 2
                        $finding.AffectedObject = "$dcName - $($zone.Name)"
                        $finding.Description = "DNS zone '$($zone.Name)' on $dcName is not signed with DNSSEC."
                        $finding.Impact = "Zone is vulnerable to DNS spoofing and cache poisoning attacks. Clients cannot verify authenticity of DNS responses."
                        $finding.Remediation = "Consider implementing DNSSEC: Use 'Sign-DnsServerZone' cmdlet or DNS Manager to sign the zone. Note: Requires proper key management."
                        $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/networking/dns/dnssec-overview"
                        $finding.Details = @{
                            ZoneName = $zone.Name
                            IsSigned = $zone.IsSigned
                            DomainController = $dcName
                        }
                        $findings += $finding
                    }
                    
                    # Check for dynamic updates set to non-secure
                    if ($zone.AllowUpdate -eq 1) {
                        # AllowUpdate: 0=None, 1=Non-secure, 2=Secure only
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'DNS Security'
                        $finding.Issue = 'Non-Secure DNS Dynamic Updates Allowed'
                        $finding.Severity = 'Critical'
                        $finding.SeverityLevel = 4
                        $finding.AffectedObject = "$dcName - $($zone.Name)"
                        $finding.Description = "DNS zone '$($zone.Name)' on $dcName allows non-secure dynamic updates."
                        $finding.Impact = "Attackers can register malicious DNS records, hijack existing hostnames, and perform man-in-the-middle attacks. This is a critical security vulnerability."
                        $finding.Remediation = "Change to secure dynamic updates only: Set-DnsServerPrimaryZone -Name '$($zone.Name)' -DynamicUpdate Secure -ComputerName '$dcName'"
                        $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-dns-dynamic-updates-windows-server-2003"
                        $finding.Details = @{
                            ZoneName = $zone.Name
                            AllowUpdate = $zone.AllowUpdate
                            DomainController = $dcName
                        }
                        $findings += $finding
                    }
                }
            }
            catch {
                Write-Verbose "Could not query DNS zones on $dcName : $_"
            }
            
            # Check for DNS scavenging configuration
            try {
                $dnsServer = Get-CimInstance -ComputerName $dcName -Namespace root\MicrosoftDNS `
                    -ClassName MicrosoftDNS_Server -ErrorAction Stop
                
                if ($dnsServer.ScavengingInterval -eq 0) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'DNS Security'
                    $finding.Issue = 'DNS Scavenging Disabled'
                    $finding.Severity = 'Low'
                    $finding.SeverityLevel = 1
                    $finding.AffectedObject = $dcName
                    $finding.Description = "DNS scavenging is disabled on $dcName. Stale DNS records will accumulate over time."
                    $finding.Impact = "Stale records can lead to connectivity issues and provide outdated information to attackers during reconnaissance."
                    $finding.Remediation = "Enable DNS scavenging: Set-DnsServerScavenging -ScavengingState `$true -ScavengingInterval 7.00:00:00 -ComputerName '$dcName'"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-scavenging-setup"
                    $finding.Details = @{
                        ScavengingInterval = $dnsServer.ScavengingInterval
                        DomainController = $dcName
                    }
                    $findings += $finding
                }
            }
            catch {
                Write-Verbose "Could not query DNS server settings on $dcName : $_"
            }
            
            # Check for DNS global query block list (protects against WPAD/ISATAP attacks)
            try {
                $queryBlockList = Invoke-Command -ComputerName $dcName -ScriptBlock {
                    try {
                        $list = Get-DnsServerGlobalQueryBlockList -ErrorAction Stop
                        return $list
                    }
                    catch {
                        return $null
                    }
                } -ErrorAction SilentlyContinue
                
                if ($queryBlockList -and $queryBlockList.Enable -eq $false) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'DNS Security'
                    $finding.Issue = 'DNS Global Query Block List Disabled'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $dcName
                    $finding.Description = "DNS Global Query Block List is disabled on $dcName, which protects against WPAD and ISATAP name hijacking."
                    $finding.Impact = "Domain is vulnerable to WPAD hijacking attacks where attackers can intercept web proxy settings and capture credentials."
                    $finding.Remediation = "Enable global query block list: Set-DnsServerGlobalQueryBlockList -Enable `$true -ComputerName '$dcName'"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverglobalqueryblocklist"
                    $finding.Details = @{
                        Enabled = $queryBlockList.Enable
                        BlockedNames = $queryBlockList.List -join '; '
                        DomainController = $dcName
                    }
                    $findings += $finding
                }
            }
            catch {
                Write-Verbose "Could not query DNS global query block list on $dcName : $_"
            }
        }
        
        # Check for LDAP signing and channel binding (prevents LDAP relay attacks)
        foreach ($dc in $domainControllers) {
            $dcName = $dc.HostName
            
            try {
                $ldapPolicy = Invoke-Command -ComputerName $dcName -ScriptBlock {
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
                    $ldapSigning = Get-ItemProperty -Path $regPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
                    $channelBinding = Get-ItemProperty -Path $regPath -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
                    
                    return @{
                        LDAPServerIntegrity = $ldapSigning.LDAPServerIntegrity
                        LdapEnforceChannelBinding = $channelBinding.LdapEnforceChannelBinding
                    }
                } -ErrorAction SilentlyContinue
                
                if ($ldapPolicy.LDAPServerIntegrity -ne 2) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'DNS Security'
                    $finding.Issue = 'LDAP Signing Not Required'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $dcName
                    $finding.Description = "LDAP signing is not required on domain controller $dcName (current value: $($ldapPolicy.LDAPServerIntegrity))."
                    $finding.Impact = "Domain is vulnerable to LDAP relay attacks where attackers can intercept and modify LDAP traffic, potentially gaining privileged access."
                    $finding.Remediation = "Require LDAP signing via registry: Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity' -Value 2. Or use Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Domain controller: LDAP server signing requirements' = 'Require signing'"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements"
                    $finding.Details = @{
                        CurrentValue = $ldapPolicy.LDAPServerIntegrity
                        RequiredValue = 2
                        DomainController = $dcName
                    }
                    $findings += $finding
                }
                
                if ($ldapPolicy.LdapEnforceChannelBinding -ne 2) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'DNS Security'
                    $finding.Issue = 'LDAP Channel Binding Not Required'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $dcName
                    $finding.Description = "LDAP channel binding is not enforced on domain controller $dcName (current value: $($ldapPolicy.LdapEnforceChannelBinding))."
                    $finding.Impact = "Vulnerable to LDAP relay attacks even over TLS. Channel binding ensures the TLS channel cannot be relayed."
                    $finding.Remediation = "Enforce LDAP channel binding: Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding' -Value 2"
                    $finding.DocumentationLink = "https://support.microsoft.com/en-us/topic/use-the-ldapenforcechannelbinding-registry-entry-to-make-ldap-authentication-over-ssl-tls-more-secure-e9ecfa27-5e57-8519-6ba3-d2c06b38d034"
                    $finding.Details = @{
                        CurrentValue = $ldapPolicy.LdapEnforceChannelBinding
                        RequiredValue = 2
                        DomainController = $dcName
                    }
                    $findings += $finding
                }
            }
            catch {
                Write-Verbose "Could not query LDAP policy on $dcName : $_"
            }
        }
        
        Write-Verbose "DNS security configuration audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during DNS security configuration audit: $_"
        throw
    }
}

#endregion

#region Replication Health Audit

function Test-ADReplicationHealth {
    <#
    .SYNOPSIS
    Audits Active Directory replication health including partners, latency, and failures.
    
    .DESCRIPTION
    Checks replication status across all domain controllers, identifies replication failures,
    measures replication latency, and validates replication partner configurations.
    
    .OUTPUTS
    Array of ADSecurityFinding objects
    #>
    [CmdletBinding()]
    param()
    
    $findings = @()
    Write-Host "Checking AD Replication Health..." -ForegroundColor Cyan
    
    try {
        # Get all domain controllers
        $allDCs = Get-ADDomainController -Filter * -ErrorAction Stop
        
        if ($allDCs.Count -eq 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = "Replication Health"
            $finding.Issue = "No Domain Controllers Found"
            $finding.Severity = "Critical"
            $finding.SeverityLevel = $Script:SeverityLevels.Critical
            $finding.Description = "Unable to enumerate domain controllers for replication health check"
            $finding.Impact = "Cannot assess replication health which is critical for AD availability"
            $finding.Remediation = "Verify domain controller availability and connectivity"
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/troubleshoot-domain-controller-issues"
            $finding.AffectedObject = "Domain Controllers"
            $finding.Details = @{
                'Message' = 'No domain controllers found in the domain.'
            }
            $findings += $finding
            return $findings
        }
        
        Write-Verbose "Found $($allDCs.Count) domain controller(s)"
        
        # Check replication status for each DC
        foreach ($dc in $allDCs) {
            Write-Verbose "Checking replication for: $($dc.HostName)"
            
            try {
                # Test connectivity first
                $pingResult = Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet -ErrorAction SilentlyContinue
                
                if (-not $pingResult) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = "Replication Health"
                    $finding.Issue = "Domain Controller Unreachable"
                    $finding.Severity = "High"
                    $finding.SeverityLevel = $Script:SeverityLevels.High
                    $finding.Description = "Domain Controller $($dc.HostName) is not responding to network requests"
                    $finding.Impact = "Replication may be failing, causing directory inconsistencies"
                    $finding.Remediation = "Verify network connectivity and DC health for $($dc.HostName)"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/troubleshoot-ad-replication-problems"
                    $finding.AffectedObject = $dc.HostName
                    $finding.Details = @{
                        'Site' = $dc.Site
                        'IsGlobalCatalog' = $dc.IsGlobalCatalog
                        'IsReadOnly' = $dc.IsReadOnly
                    }
                    $findings += $finding
                    continue
                }
                
                # Get replication metadata
                $replMetadata = Get-ADReplicationPartnerMetadata -Target $dc.HostName -Scope Domain -ErrorAction SilentlyContinue
                
                if ($replMetadata) {
                    foreach ($metadata in $replMetadata) {
                        # Check for replication failures
                        if ($metadata.LastReplicationResult -ne 0) {
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = "Replication Health"
                            $finding.Issue = "Replication Failure Detected"
                            $finding.Severity = "Critical"
                            $finding.SeverityLevel = $Script:SeverityLevels.Critical
                            $finding.Description = "Replication failure between $($dc.HostName) and $($metadata.Partner)"
                            $finding.Impact = "Directory data may be inconsistent across domain controllers, affecting authentication and authorization"
                            $finding.Remediation = "Investigate replication error code $($metadata.LastReplicationResult) using 'repadmin /showrepl' and resolve network or AD issues"
                            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/active-directory-replication-error-codes"
                            $finding.AffectedObject = "$($dc.HostName) <-> $($metadata.Partner)"
                            $finding.Details = @{
                                'SourceDC' = $dc.HostName
                                'PartnerDC' = $metadata.Partner
                                'Partition' = $metadata.Partition
                                'ErrorCode' = $metadata.LastReplicationResult
                                'LastAttempt' = $metadata.LastReplicationAttempt
                                'LastSuccess' = $metadata.LastReplicationSuccess
                                'ConsecutiveFailures' = $metadata.ConsecutiveReplicationFailures
                            }
                            $findings += $finding
                        }
                        
                        # Check for high replication latency (last success > 12 hours ago)
                        if ($metadata.LastReplicationSuccess) {
                            $timeSinceLastReplication = (Get-Date) - $metadata.LastReplicationSuccess
                            
                            if ($timeSinceLastReplication.TotalHours -gt 24) {
                                $finding = [ADSecurityFinding]::new()
                                $finding.Category = "Replication Health"
                                $finding.Issue = "High Replication Latency"
                                $finding.Severity = "High"
                                $finding.SeverityLevel = $Script:SeverityLevels.High
                                $finding.Description = "Replication between $($dc.HostName) and $($metadata.Partner) has not succeeded in $([math]::Round($timeSinceLastReplication.TotalHours, 2)) hours"
                                $finding.Impact = "Delayed replication can cause authentication failures and directory inconsistencies"
                                $finding.Remediation = "Check network connectivity, investigate replication queue, and review event logs on both domain controllers"
                                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/troubleshoot-ad-replication-problems"
                                $finding.AffectedObject = "$($dc.HostName) <-> $($metadata.Partner)"
                                $finding.Details = @{
                                    'SourceDC' = $dc.HostName
                                    'PartnerDC' = $metadata.Partner
                                    'Partition' = $metadata.Partition
                                    'HoursSinceLastReplication' = [math]::Round($timeSinceLastReplication.TotalHours, 2)
                                    'LastSuccess' = $metadata.LastReplicationSuccess
                                }
                                $findings += $finding
                            }
                            elseif ($timeSinceLastReplication.TotalHours -gt 12) {
                                $finding = [ADSecurityFinding]::new()
                                $finding.Category = "Replication Health"
                                $finding.Issue = "Moderate Replication Latency"
                                $finding.Severity = "Medium"
                                $finding.SeverityLevel = $Script:SeverityLevels.Medium
                                $finding.Description = "Replication between $($dc.HostName) and $($metadata.Partner) has not succeeded in $([math]::Round($timeSinceLastReplication.TotalHours, 2)) hours"
                                $finding.Impact = "May cause delays in directory updates propagating across domain controllers"
                                $finding.Remediation = "Monitor replication status and verify network connectivity between domain controllers"
                                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/replication/active-directory-replication-concepts"
                                $finding.AffectedObject = "$($dc.HostName) <-> $($metadata.Partner)"
                                $finding.Details = @{
                                    'SourceDC' = $dc.HostName
                                    'PartnerDC' = $metadata.Partner
                                    'Partition' = $metadata.Partition
                                    'HoursSinceLastReplication' = [math]::Round($timeSinceLastReplication.TotalHours, 2)
                                    'LastSuccess' = $metadata.LastReplicationSuccess
                                }
                                $findings += $finding
                            }
                        }
                        
                        # Check for consecutive replication failures
                        if ($metadata.ConsecutiveReplicationFailures -gt 5) {
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = "Replication Health"
                            $finding.Issue = "Multiple Consecutive Replication Failures"
                            $finding.Severity = "Critical"
                            $finding.SeverityLevel = $Script:SeverityLevels.Critical
                            $finding.Description = "Replication between $($dc.HostName) and $($metadata.Partner) has failed $($metadata.ConsecutiveReplicationFailures) consecutive times"
                            $finding.Impact = "Persistent replication failures indicate a serious configuration or connectivity issue"
                            $finding.Remediation = "Urgently investigate and resolve replication errors using 'repadmin /showrepl' and 'dcdiag /test:replications'"
                            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/troubleshoot-ad-replication-problems"
                            $finding.AffectedObject = "$($dc.HostName) <-> $($metadata.Partner)"
                            $finding.Details = @{
                                'SourceDC' = $dc.HostName
                                'PartnerDC' = $metadata.Partner
                                'Partition' = $metadata.Partition
                                'ConsecutiveFailures' = $metadata.ConsecutiveReplicationFailures
                                'LastAttempt' = $metadata.LastReplicationAttempt
                            }
                            $findings += $finding
                        }
                    }
                }
                
                # Get replication queue status
                try {
                    $replQueue = Get-ADReplicationQueueOperation -Server $dc.HostName -ErrorAction SilentlyContinue
                    
                    if ($replQueue) {
                        $queueCount = ($replQueue | Measure-Object).Count
                        
                        if ($queueCount -gt 100) {
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = "Replication Health"
                            $finding.Issue = "Large Replication Queue"
                            $finding.Severity = "High"
                            $finding.SeverityLevel = $Script:SeverityLevels.High
                            $finding.Description = "Domain Controller $($dc.HostName) has $queueCount pending replication operations"
                            $finding.Impact = "Large replication queue indicates replication delays or processing issues"
                            $finding.Remediation = "Investigate replication performance, check DC resources (CPU, memory, disk), and review for network issues"
                            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/replication/active-directory-replication-concepts"
                            $finding.AffectedObject = $dc.HostName
                            $finding.Details = @{
                                'QueueLength' = $queueCount
                                'Site' = $dc.Site
                            }
                            $findings += $finding
                        }
                        elseif ($queueCount -gt 50) {
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = "Replication Health"
                            $finding.Issue = "Elevated Replication Queue"
                            $finding.Severity = "Medium"
                            $finding.SeverityLevel = $Script:SeverityLevels.Medium
                            $finding.Description = "Domain Controller $($dc.HostName) has $queueCount pending replication operations"
                            $finding.Impact = "May indicate replication delays during peak load"
                            $finding.Remediation = "Monitor replication queue length and investigate if it continues to grow"
                            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/replication/active-directory-replication-concepts"
                            $finding.AffectedObject = $dc.HostName
                            $finding.Details = @{
                                'QueueLength' = $queueCount
                                'Site' = $dc.Site
                            }
                            $findings += $finding
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not query replication queue for $($dc.HostName): $_"
                }
                
                # Check replication partners
                try {
                    $replPartners = Get-ADReplicationConnection -Filter * -Server $dc.HostName -ErrorAction SilentlyContinue
                    
                    if ($replPartners) {
                        $disabledPartners = $replPartners | Where-Object { $_.ReplicationSchedule -eq $null -or -not $_.Enabled }
                        
                        if ($disabledPartners) {
                            foreach ($partner in $disabledPartners) {
                                $finding = [ADSecurityFinding]::new()
                                $finding.Category = "Replication Health"
                                $finding.Issue = "Disabled Replication Connection"
                                $finding.Severity = "Medium"
                                $finding.SeverityLevel = $Script:SeverityLevels.Medium
                                $finding.Description = "Replication connection '$($partner.Name)' on $($dc.HostName) is disabled"
                                $finding.Impact = "Disabled replication connections prevent directory updates from propagating"
                                $finding.Remediation = "Review why the connection is disabled and enable if appropriate, or remove if no longer needed"
                                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/reviewing-the-active-directory-logical-model"
                                $finding.AffectedObject = $partner.Name
                                $finding.Details = @{
                                    'ConnectionName' = $partner.Name
                                    'Server' = $dc.HostName
                                    'FromServer' = $partner.ReplicateFromDirectoryServer
                                }
                                $findings += $finding
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not query replication connections for $($dc.HostName): $_"
                }
                
            }
            catch {
                Write-Warning "Error checking replication for $($dc.HostName): $_"
                
                $finding = [ADSecurityFinding]::new()
                $finding.Category = "Replication Health"
                $finding.Issue = "Unable to Query Replication Status"
                $finding.Severity = "Medium"
                $finding.SeverityLevel = $Script:SeverityLevels.Medium
                $finding.Description = "Failed to retrieve replication information for $($dc.HostName)"
                $finding.Impact = "Cannot assess replication health for this domain controller"
                $finding.Remediation = "Verify permissions and connectivity to $($dc.HostName). Error: $_"
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/"
                $finding.AffectedObject = $dc.HostName
                $findings += $finding
            }
        }
        
        # Check for isolated domain controllers (no successful replication partners)
        foreach ($dc in $allDCs) {
            try {
                $replMetadata = Get-ADReplicationPartnerMetadata -Target $dc.HostName -Scope Domain -ErrorAction SilentlyContinue
                $successfulReplications = $replMetadata | Where-Object { $_.LastReplicationResult -eq 0 }
                
                if (-not $successfulReplications -and $allDCs.Count -gt 1) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = "Replication Health"
                    $finding.Issue = "Isolated Domain Controller"
                    $finding.Severity = "Critical"
                    $finding.SeverityLevel = $Script:SeverityLevels.Critical
                    $finding.Description = "Domain Controller $($dc.HostName) has no successful replication partners"
                    $finding.Impact = "DC is isolated from replication topology, causing severe directory inconsistencies"
                    $finding.Remediation = "Urgently investigate network connectivity and replication configuration for $($dc.HostName)"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/troubleshoot-ad-replication-problems"
                    $finding.AffectedObject = $dc.HostName
                    $finding.Details = @{
                        'Site' = $dc.Site
                        'IsGlobalCatalog' = $dc.IsGlobalCatalog
                    }
                    $findings += $finding
                }
            }
            catch {
                Write-Verbose "Could not check isolation status for $($dc.HostName): $_"
            }
        }
        
        # Summary finding if no issues detected
        if ($findings.Count -eq 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = "Replication Health"
            $finding.Issue = "Replication Health Check Passed"
            $finding.Severity = "Info"
            $finding.SeverityLevel = $Script:SeverityLevels.Info
            $finding.Description = "All domain controllers are replicating successfully with acceptable latency"
            $finding.Impact = "None - replication is healthy"
            $finding.Remediation = "Continue monitoring replication health regularly"
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/replication/active-directory-replication-concepts"
            $finding.Details = @{
                'DomainControllerCount' = $allDCs.Count
                'CheckDate' = Get-Date
            }
            $findings += $finding
        }
        
        Write-Host "  Found $($findings.Count) replication health finding(s)" -ForegroundColor $(if($findings.Count -gt 1){'Yellow'}else{'Green'})
    }
    catch {
        Write-Warning "Error in replication health check: $_"
        
        $finding = [ADSecurityFinding]::new()
        $finding.Category = "Replication Health"
        $finding.Issue = "Replication Health Check Failed"
        $finding.Severity = "High"
        $finding.SeverityLevel = $Script:SeverityLevels.High
        $finding.Description = "Unable to complete replication health assessment"
        $finding.Impact = "Cannot verify critical replication status"
        $finding.Remediation = "Verify permissions and connectivity. Error: $_"
        $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/troubleshoot-ad-replication-problems"
        $findings += $finding
    }
    
    return $findings
}

#endregion

#region NTLM and Legacy Protocol Audit

function Test-NTLMAndLegacyProtocols {
    <#
    .SYNOPSIS
    Audits NTLM usage and legacy authentication protocols in the domain.
    
    .DESCRIPTION
    Checks for NTLM authentication usage, LM hash storage, NTLMv1 vs NTLMv2 enforcement,
    and validates domain controllers are configured to restrict or audit legacy protocols.
    
    .OUTPUTS
    Array of ADSecurityFinding objects
    #>
    [CmdletBinding()]
    param()
    
    $findings = @()
    Write-Host "Checking NTLM and Legacy Protocol Security..." -ForegroundColor Cyan
    
    try {
        # Get domain and domain controllers
        $domain = Get-ADDomain -ErrorAction Stop
        $domainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
        
        # Check domain-level NTLM settings via Group Policy
        Write-Verbose "Checking domain-level NTLM restrictions..."
        
        # Check LM hash storage (should be disabled)
        foreach ($dc in $domainControllers) {
            $dcName = $dc.HostName
            
            try {
                $lmCompatibility = Invoke-Command -ComputerName $dcName -ScriptBlock {
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                    $noLMHash = Get-ItemProperty -Path $regPath -Name "NoLMHash" -ErrorAction SilentlyContinue
                    $lmCompatLevel = Get-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
                    $ntlmMinClientSec = Get-ItemProperty -Path $regPath -Name "NtlmMinClientSec" -ErrorAction SilentlyContinue
                    $ntlmMinServerSec = Get-ItemProperty -Path $regPath -Name "NtlmMinServerSec" -ErrorAction SilentlyContinue
                    $restrictNTLM = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "AuditNTLMInDomain" -ErrorAction SilentlyContinue
                    
                    return @{
                        NoLMHash = $noLMHash.NoLMHash
                        LmCompatibilityLevel = $lmCompatLevel.LmCompatibilityLevel
                        NtlmMinClientSec = $ntlmMinClientSec.NtlmMinClientSec
                        NtlmMinServerSec = $ntlmMinServerSec.NtlmMinServerSec
                        AuditNTLMInDomain = $restrictNTLM.AuditNTLMInDomain
                    }
                } -ErrorAction SilentlyContinue
                
                # Check if LM hash storage is disabled (NoLMHash should be 1)
                if ($lmCompatibility.NoLMHash -ne 1) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Authentication Security'
                    $finding.Issue = 'LM Hash Storage Not Disabled'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $dcName
                    $finding.Description = "LM hash storage is not explicitly disabled on $dcName. LM hashes are extremely weak and vulnerable to rapid password cracking."
                    $finding.Impact = "Attackers who compromise the AD database can quickly crack LM hashes, exposing user passwords. LM hashes provide no security value in modern environments."
                    $finding.Remediation = "Disable LM hash storage via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Network security: Do not store LAN Manager hash value on next password change' = Enabled. Or set registry: Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change"
                    $finding.Details = @{
                        CurrentValue = $lmCompatibility.NoLMHash
                        RequiredValue = 1
                        DomainController = $dcName
                    }
                    $findings += $finding
                }
                
                # Check LM compatibility level (should be 5 for NTLMv2 only)
                if ($lmCompatibility.LmCompatibilityLevel -lt 5) {
                    $levelDescriptions = @{
                        0 = "Send LM & NTLM responses"
                        1 = "Send LM & NTLM - use NTLMv2 session security if negotiated"
                        2 = "Send NTLM response only"
                        3 = "Send NTLMv2 response only"
                        4 = "Send NTLMv2 response only. Refuse LM"
                        5 = "Send NTLMv2 response only. Refuse LM & NTLM"
                    }
                    
                    $currentLevel = if ($lmCompatibility.LmCompatibilityLevel -ne $null) {
                        $lmCompatibility.LmCompatibilityLevel
                    } else {
                        0  # Default if not set
                    }
                    
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Authentication Security'
                    $finding.Issue = 'Weak LM Compatibility Level'
                    $finding.Severity = if ($currentLevel -le 2) { 'Critical' } else { 'High' }
                    $finding.SeverityLevel = if ($currentLevel -le 2) { 4 } else { 3 }
                    $finding.AffectedObject = $dcName
                    $finding.Description = "LM compatibility level on $dcName is set to $currentLevel - $($levelDescriptions[$currentLevel]). This allows legacy authentication protocols."
                    $finding.Impact = "Domain controllers accept weak authentication protocols (LM/NTLM) which are vulnerable to relay attacks, brute force, and have no mutual authentication. Modern environments should use NTLMv2 minimum or preferably Kerberos only."
                    $finding.Remediation = "Set LM compatibility to level 5 via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Network security: LAN Manager authentication level' = 'Send NTLMv2 response only. Refuse LM & NTLM'. Or registry: Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level"
                    $finding.Details = @{
                        CurrentLevel = $currentLevel
                        CurrentDescription = $levelDescriptions[$currentLevel]
                        RecommendedLevel = 5
                        RecommendedDescription = $levelDescriptions[5]
                        DomainController = $dcName
                    }
                    $findings += $finding
                }
                
                # Check NTLM minimum security settings (should require NTLMv2 and 128-bit encryption)
                # Bit flags: 0x20000000 (NTLMv2 session security) + 0x80000 (128-bit encryption) = 0x20080000
                $recommendedMinSec = 0x20080000
                
                if ($lmCompatibility.NtlmMinClientSec -lt $recommendedMinSec) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Authentication Security'
                    $finding.Issue = 'Weak NTLM Client Security Requirements'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $dcName
                    $finding.Description = "NTLM minimum client security on $dcName does not require NTLMv2 session security and 128-bit encryption."
                    $finding.Impact = "NTLM sessions may use weak encryption or downgrade to less secure protocol versions, making them vulnerable to man-in-the-middle attacks."
                    $finding.Remediation = "Enforce strong NTLM client security via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' = 'Require NTLMv2 session security, Require 128-bit encryption'"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/network-security-minimum-session-security-for-ntlm-ssp-based-including-secure-rpc-clients"
                    $finding.Details = @{
                        CurrentValue = "0x$($lmCompatibility.NtlmMinClientSec.ToString('X'))"
                        RecommendedValue = "0x$($recommendedMinSec.ToString('X'))"
                        DomainController = $dcName
                    }
                    $findings += $finding
                }
                
                if ($lmCompatibility.NtlmMinServerSec -lt $recommendedMinSec) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Authentication Security'
                    $finding.Issue = 'Weak NTLM Server Security Requirements'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $dcName
                    $finding.Description = "NTLM minimum server security on $dcName does not require NTLMv2 session security and 128-bit encryption."
                    $finding.Impact = "Server-side NTLM authentication may accept weak encryption or protocol versions, enabling credential theft and relay attacks."
                    $finding.Remediation = "Enforce strong NTLM server security via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' = 'Require NTLMv2 session security, Require 128-bit encryption'"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/network-security-minimum-session-security-for-ntlm-ssp-based-including-secure-rpc-servers"
                    $finding.Details = @{
                        CurrentValue = "0x$($lmCompatibility.NtlmMinServerSec.ToString('X'))"
                        RecommendedValue = "0x$($recommendedMinSec.ToString('X'))"
                        DomainController = $dcName
                    }
                    $findings += $finding
                }
                
                # Check if NTLM auditing is enabled in the domain
                if ($lmCompatibility.AuditNTLMInDomain -eq $null -or $lmCompatibility.AuditNTLMInDomain -eq 0) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Authentication Security'
                    $finding.Issue = 'NTLM Auditing Not Enabled'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $dcName
                    $finding.Description = "NTLM auditing is not enabled on $dcName. This prevents visibility into which systems and applications are using NTLM authentication."
                    $finding.Impact = "Cannot identify NTLM usage patterns or detect potential NTLM relay attacks. Lack of visibility prevents migration planning to Kerberos-only authentication."
                    $finding.Remediation = "Enable NTLM auditing via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Network security: Restrict NTLM: Audit NTLM authentication in this domain' = 'Enable all'. Or registry: Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'AuditNTLMInDomain' -Value 7"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/network-security-restrict-ntlm-audit-ntlm-authentication-in-this-domain"
                    $finding.Details = @{
                        CurrentValue = $lmCompatibility.AuditNTLMInDomain
                        RecommendedValue = 7
                        DomainController = $dcName
                        Note = "After enabling, review Event IDs 8004 and 8005 in Netlogon logs"
                    }
                    $findings += $finding
                }
            }
            catch {
                Write-Verbose "Could not query NTLM settings on $dcName : $_"
            }
        }
        
        # Check for accounts with DES encryption enabled (legacy Kerberos)
        Write-Verbose "Checking for accounts with weak Kerberos encryption types..."
        
        $desAccounts = Get-ADUser -Filter {UserAccountControl -band 0x200000} -Properties UserAccountControl, Enabled, LastLogonDate -ErrorAction SilentlyContinue
        
        if ($desAccounts) {
            foreach ($account in $desAccounts) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Authentication Security'
                $finding.Issue = 'Account Using DES Encryption'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $account.SamAccountName
                $finding.Description = "User account $($account.SamAccountName) has 'Use DES encryption types for this account' enabled. DES is cryptographically broken."
                $finding.Impact = "Kerberos tickets for this account use weak DES encryption which can be cracked offline, exposing the account password. DES is deprecated and should never be used."
                $finding.Remediation = "Disable DES encryption: Set-ADUser -Identity '$($account.SamAccountName)' -KerberosEncryptionType AES128, AES256. Ensure the account and applications support AES encryption."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"
                $finding.Details = @{
                    DistinguishedName = $account.DistinguishedName
                    Enabled = $account.Enabled
                    LastLogonDate = $account.LastLogonDate
                }
                $findings += $finding
            }
        }
        
        # Check for computers with unconstrained delegation (potential NTLM relay targets)
        Write-Verbose "Checking for computers with unconstrained delegation..."
        
        $unconstrainedComputers = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation, OperatingSystem, LastLogonDate -ErrorAction SilentlyContinue
        
        if ($unconstrainedComputers) {
            foreach ($computer in $unconstrainedComputers) {
                # Skip domain controllers as they have it by design
                if ($computer.DistinguishedName -notmatch 'OU=Domain Controllers') {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Authentication Security'
                    $finding.Issue = 'Computer with Unconstrained Delegation'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $computer.Name
                    $finding.Description = "Computer $($computer.Name) is configured for unconstrained Kerberos delegation."
                    $finding.Impact = "Any user authenticating to this computer has their TGT cached on it. If this computer is compromised, attackers can impersonate any user (including Domain Admins) who authenticated to it."
                    $finding.Remediation = "Change to constrained delegation or remove delegation entirely. Use constrained delegation with protocol transition if needed: Set-ADComputer -Identity '$($computer.Name)' -TrustedForDelegation `$false"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
                    $finding.Details = @{
                        DistinguishedName = $computer.DistinguishedName
                        OperatingSystem = $computer.OperatingSystem
                        LastLogonDate = $computer.LastLogonDate
                    }
                    $findings += $finding
                }
            }
        }
        
        Write-Host "  Found $($findings.Count) NTLM and legacy protocol finding(s)" -ForegroundColor $(if($findings.Count -gt 0){'Yellow'}else{'Green'})
        return $findings
    }
    catch {
        Write-Error "Error during NTLM and legacy protocol audit: $_"
        throw
    }
}

#endregion

#region Protected Users Group Coverage Validation

function Test-ProtectedUsersGroupCoverage {
    <#
    .SYNOPSIS
    Validates Protected Users group membership coverage for privileged accounts.
    
    .DESCRIPTION
    Performs comprehensive analysis of Protected Users group membership, identifies
    privileged accounts that should be members, checks for incompatible configurations,
    and validates proper coverage of tier 0 accounts.
    
    .OUTPUTS
    Array of ADSecurityFinding objects
    #>
    [CmdletBinding()]
    param()
    
    $findings = @()
    Write-Host "Checking Protected Users Group Coverage..." -ForegroundColor Cyan
    
    try {
        # Get the Protected Users group
        $protectedUsersGroup = Get-ADGroup -Filter {Name -eq "Protected Users"} -ErrorAction SilentlyContinue
        
        if (-not $protectedUsersGroup) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Protected Users'
            $finding.Issue = 'Protected Users Group Not Found'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = 'Protected Users Group'
            $finding.Description = "The Protected Users security group does not exist in this domain. This group provides additional protections for privileged accounts."
            $finding.Impact = "Privileged accounts lack critical security protections against credential theft attacks like pass-the-hash, which are critical in modern threat landscape."
            $finding.Remediation = "The Protected Users group should exist by default in domains with Windows Server 2012 R2+ functional level. Verify domain functional level and consider creating the group if appropriate."
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"
            $finding.Details = @{
                DomainFunctionalLevel = (Get-ADDomain).DomainMode
                Note = "Protected Users group requires Windows Server 2012 R2 or higher domain functional level"
            }
            $findings += $finding
            return $findings
        }
        
        Write-Verbose "Protected Users group found: $($protectedUsersGroup.DistinguishedName)"
        
        # Get all members of Protected Users group
        $protectedUsersMembers = Get-ADGroupMember -Identity $protectedUsersGroup -Recursive -ErrorAction SilentlyContinue | Where-Object {$_.objectClass -eq 'user'}
        $protectedUsersDNs = $protectedUsersMembers | ForEach-Object {$_.DistinguishedName}
        
        Write-Verbose "Protected Users group has $($protectedUsersMembers.Count) user member(s)"
        
        # Define highly privileged groups that should be in Protected Users
        $criticalPrivilegedGroups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators'
        )
        
        # Get all users from critical privileged groups
        $privilegedUsers = @()
        foreach ($groupName in $criticalPrivilegedGroups) {
            $group = Get-ADGroup -Filter {Name -eq $groupName} -ErrorAction SilentlyContinue
            if ($group) {
                $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue | Where-Object {$_.objectClass -eq 'user'}
                foreach ($member in $members) {
                    if ($privilegedUsers.DistinguishedName -notcontains $member.DistinguishedName) {
                        $privilegedUsers += $member | Add-Member -NotePropertyName 'PrivilegedGroup' -NotePropertyValue $groupName -PassThru
                    }
                }
            }
        }
        
        Write-Verbose "Found $($privilegedUsers.Count) unique privileged user(s) across critical groups"
        
        # Check each privileged user for Protected Users membership
        foreach ($privUser in $privilegedUsers) {
            $userDetails = Get-ADUser -Identity $privUser.DistinguishedName -Properties Enabled, PasswordNeverExpires, AccountNotDelegated, DoesNotRequirePreAuth, ServicePrincipalNames, LastLogonDate, PasswordLastSet -ErrorAction SilentlyContinue
            
            if (-not $userDetails) { continue }
            
            # Skip disabled accounts
            if (-not $userDetails.Enabled) { continue }
            
            # Check if user is in Protected Users
            if ($protectedUsersDNs -notcontains $userDetails.DistinguishedName) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Protected Users'
                $finding.Issue = 'Privileged Account Not in Protected Users Group'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $userDetails.SamAccountName
                $finding.Description = "Privileged account $($userDetails.SamAccountName) is a member of $($privUser.PrivilegedGroup) but is NOT in the Protected Users security group."
                $finding.Impact = "Account lacks critical protections: NTLM authentication will be allowed, Kerberos DES/RC4 encryption allowed, credentials can be delegated, and TGTs can be cached. This significantly increases risk of credential theft attacks."
                $finding.Remediation = @"
Add to Protected Users group: Add-ADGroupMember -Identity 'Protected Users' -Members '$($userDetails.SamAccountName)'

IMPORTANT: Before adding, verify:
1. Applications/services don't require NTLM authentication for this account
2. No constrained delegation configured (incompatible with Protected Users)
3. No service principal names (SPNs) registered (service accounts incompatible)
4. Account doesn't require DES/RC4 encryption for legacy systems

Protected Users enforces:
- No NTLM, Digest, or CredSSP authentication
- No DES or RC4 in Kerberos pre-auth
- No delegation (constrained or unconstrained)
- TGT lifetime restricted to 4 hours
- No offline password caching
"@
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"
                $finding.Details = @{
                    DistinguishedName = $userDetails.DistinguishedName
                    PrivilegedGroup = $privUser.PrivilegedGroup
                    Enabled = $userDetails.Enabled
                    PasswordNeverExpires = $userDetails.PasswordNeverExpires
                    HasSPN = ($userDetails.ServicePrincipalNames.Count -gt 0)
                    SPNCount = $userDetails.ServicePrincipalNames.Count
                    AccountNotDelegated = $userDetails.AccountNotDelegated
                    LastLogonDate = $userDetails.LastLogonDate
                    PasswordLastSet = $userDetails.PasswordLastSet
                }
                $findings += $finding
            }
            
            # Check for incompatible configurations even if in Protected Users
            if ($protectedUsersDNs -contains $userDetails.DistinguishedName) {
                # Check for SPNs (service accounts incompatible with Protected Users)
                if ($userDetails.ServicePrincipalNames.Count -gt 0) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Protected Users'
                    $finding.Issue = 'Service Account in Protected Users Group'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $userDetails.SamAccountName
                    $finding.Description = "Account $($userDetails.SamAccountName) is in Protected Users group but has $($userDetails.ServicePrincipalNames.Count) Service Principal Name(s) registered. Service accounts should not be in Protected Users."
                    $finding.Impact = "Services using this account may fail to authenticate. Protected Users restrictions (no RC4, no delegation, 4-hour TGT) are incompatible with most service account requirements."
                    $finding.Remediation = "Remove from Protected Users group: Remove-ADGroupMember -Identity 'Protected Users' -Members '$($userDetails.SamAccountName)'. For service accounts, use Group Managed Service Accounts (gMSA) instead and implement other hardening measures."
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview"
                    $finding.Details = @{
                        DistinguishedName = $userDetails.DistinguishedName
                        SPNs = $userDetails.ServicePrincipalNames -join '; '
                        SPNCount = $userDetails.ServicePrincipalNames.Count
                    }
                    $findings += $finding
                }
                
                # Check for password never expires (should be addressed)
                if ($userDetails.PasswordNeverExpires) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Protected Users'
                    $finding.Issue = 'Protected User with Non-Expiring Password'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $userDetails.SamAccountName
                    $finding.Description = "Account $($userDetails.SamAccountName) is in Protected Users group but has 'Password Never Expires' set."
                    $finding.Impact = "While Protected Users provides strong protections, non-expiring passwords reduce the effectiveness of credential rotation. If the password is compromised, it remains valid indefinitely."
                    $finding.Remediation = "Configure password expiration: Set-ADUser -Identity '$($userDetails.SamAccountName)' -PasswordNeverExpires `$false. Implement regular password rotation for privileged accounts (90 days recommended)."
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"
                    $finding.Details = @{
                        DistinguishedName = $userDetails.DistinguishedName
                        PasswordLastSet = $userDetails.PasswordLastSet
                    }
                    $findings += $finding
                }
            }
        }
        
        # Check for accounts in Protected Users that shouldn't be there
        foreach ($protectedMember in $protectedUsersMembers) {
            $userDetails = Get-ADUser -Identity $protectedMember -Properties Enabled, ServicePrincipalNames -ErrorAction SilentlyContinue
            
            if (-not $userDetails -or -not $userDetails.Enabled) { continue }
            
            # Check if this is a service account (has SPNs but not in privileged groups)
            if ($userDetails.ServicePrincipalNames.Count -gt 0) {
                $isPrivileged = $privilegedUsers.DistinguishedName -contains $userDetails.DistinguishedName
                
                if (-not $isPrivileged) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Protected Users'
                    $finding.Issue = 'Non-Privileged Service Account in Protected Users'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $userDetails.SamAccountName
                    $finding.Description = "Service account $($userDetails.SamAccountName) is in Protected Users but is not a member of critical privileged groups."
                    $finding.Impact = "Services may fail due to Protected Users restrictions. Protected Users should typically only contain highly privileged interactive user accounts."
                    $finding.Remediation = "Review whether this service account requires Protected Users membership. If not, remove: Remove-ADGroupMember -Identity 'Protected Users' -Members '$($userDetails.SamAccountName)'"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"
                    $finding.Details = @{
                        DistinguishedName = $userDetails.DistinguishedName
                        SPNCount = $userDetails.ServicePrincipalNames.Count
                        SPNs = $userDetails.ServicePrincipalNames -join '; '
                    }
                    $findings += $finding
                }
            }
        }
        
        # Summary statistics
        $privilegedInProtected = $privilegedUsers | Where-Object {$protectedUsersDNs -contains $_.DistinguishedName}
        $coveragePercent = if ($privilegedUsers.Count -gt 0) {
            [math]::Round(($privilegedInProtected.Count / $privilegedUsers.Count) * 100, 2)
        } else {
            0
        }
        
        Write-Host "  Protected Users Coverage: $coveragePercent% ($($privilegedInProtected.Count)/$($privilegedUsers.Count) privileged accounts)" -ForegroundColor $(if($coveragePercent -lt 80){'Yellow'}else{'Green'})
        Write-Host "  Found $($findings.Count) Protected Users coverage finding(s)" -ForegroundColor $(if($findings.Count -gt 0){'Yellow'}else{'Green'})
        
        return $findings
    }
    catch {
        Write-Error "Error during Protected Users group coverage audit: $_"
        throw
    }
}

#endregion

#region Domain Trust Audits

function Test-ADDomainTrusts {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting domain trust security audit..."
    $findings = @()
    
    try {
        $domain = Get-ADDomain
        $trusts = Get-ADTrust -Filter * -Properties *
        
        if (-not $trusts) {
            Write-Verbose "No domain trusts found."
            return $findings
        }
        
        Write-Verbose "Analyzing $($trusts.Count) domain trust(s)..."
        
        foreach ($trust in $trusts) {
            # Check for bidirectional trusts
            if ($trust.Direction -match 'Bidirectional') {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Trust Security'
                $finding.Issue = 'Bidirectional Trust Detected'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.Description = "A bidirectional trust exists with domain '$($trust.Target)', allowing authentication in both directions."
                $finding.Impact = "Increases attack surface. A compromise in either domain can affect the other."
                $finding.AffectedObject = $trust.Target
                $finding.Remediation = "Review if bidirectional trust is required. If not, convert to one-way trust or implement selective authentication."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/understanding-when-to-create-a-forest-trust"
                $finding.Details = @{
                    Target = $trust.Target
                    Direction = $trust.Direction
                    TrustType = $trust.TrustType
                    Created = $trust.Created
                }
                $findings += $finding
            }
            
            # Check if SID filtering is disabled (critical security issue)
            if ($trust.SIDFilteringQuarantined -eq $false -and $trust.TrustType -eq 'External') {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Trust Security'
                $finding.Issue = 'SID Filtering Disabled on External Trust'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.Description = "SID filtering is disabled on external trust to '$($trust.Target)', allowing SID history attacks."
                $finding.Impact = "Attackers can inject arbitrary SIDs and elevate privileges across the trust."
                $finding.AffectedObject = $trust.Target
                $finding.Remediation = "Enable SID filtering: netdom trust $($domain.DNSRoot) /domain:$($trust.Target) /quarantine:yes"
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772633(v=ws.10)"
                $finding.Details = @{
                    Target = $trust.Target
                    TrustType = $trust.TrustType
                    SIDFilteringQuarantined = $trust.SIDFilteringQuarantined
                }
                $findings += $finding
            }
            
            # Check for trusts without selective authentication
            if ($trust.SelectiveAuthentication -eq $false -and $trust.TrustType -eq 'Forest') {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Trust Security'
                $finding.Issue = 'Selective Authentication Not Enabled'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.Description = "Selective authentication is not enabled on forest trust to '$($trust.Target)'."
                $finding.Impact = "All users in the trusted forest have automatic access to resources without explicit permission."
                $finding.AffectedObject = $trust.Target
                $finding.Remediation = "Enable selective authentication to require explicit permission for cross-forest access."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc755844(v=ws.10)"
                $finding.Details = @{
                    Target = $trust.Target
                    TrustType = $trust.TrustType
                    SelectiveAuthentication = $trust.SelectiveAuthentication
                }
                $findings += $finding
            }
            
            # Check trust password age
            if ($trust.Modified) {
                $trustAge = (Get-Date) - $trust.Modified
                if ($trustAge.Days -gt 30) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Trust Security'
                    $finding.Issue = 'Trust Password Not Recently Rotated'
                    $finding.Severity = 'Low'
                    $finding.SeverityLevel = 1
                    $finding.AffectedObject = $trust.Target
                    $finding.Description = "Trust with '$($trust.Target)' has not been modified in $($trustAge.Days) days. Trust passwords should rotate automatically every 30 days."
                    $finding.Impact = "May indicate trust relationship issues or lack of maintenance."
                    $finding.Remediation = "Verify trust health: netdom trust $($domain.DNSRoot) /domain:$($trust.Target) /verify"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/security/netdom-trust-command-not-work"
                    $finding.Details = @{
                        Target = $trust.Target
                        LastModified = $trust.Modified
                        DaysSinceModified = $trustAge.Days
                    }
                    $findings += $finding
                }
            }
        }
        
        Write-Verbose "Domain trust audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during domain trust audit: $_"
        throw
    }
}

#endregion

#region LAPS Deployment Audits

function Test-LAPSDeployment {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting LAPS deployment audit..."
    $findings = @()
    
    try {
        $domain = Get-ADDomain
        $schemaPath = "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$($domain.DistinguishedName)"
        
        # Check if LAPS schema is extended
        try {
            $lapsSchema = Get-ADObject -Identity $schemaPath -ErrorAction Stop
            $lapsInstalled = $true
            Write-Verbose "LAPS schema extension detected."
        }
        catch {
            $lapsInstalled = $false
            
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'LAPS Security'
            $finding.Issue = 'LAPS Not Deployed'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.Description = "Local Administrator Password Solution (LAPS) schema attributes are not present in Active Directory."
            $finding.Impact = "Local administrator passwords are likely identical across computers, enabling lateral movement via Pass-the-Hash attacks."
            $finding.AffectedObject = "Domain"
            $finding.Remediation = "Deploy LAPS to randomize and manage local administrator passwords across all domain computers. Install LAPS schema: Update-AdmPwdADSchema"
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"
            $finding.Details = @{
                Domain = $domain.DNSRoot
            }
            $findings += $finding
            
            Write-Verbose "LAPS not deployed. Skipping computer-level checks."
            return $findings
        }
        
        # If LAPS is installed, check computer coverage
        if ($lapsInstalled) {
            $computers = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime, OperatingSystem -ErrorAction Stop
            $computersWithLAPS = $computers | Where-Object { $_.'ms-Mcs-AdmPwdExpirationTime' }
            $computersWithoutLAPS = $computers | Where-Object { -not $_.'ms-Mcs-AdmPwdExpirationTime' }
            
            $totalComputers = $computers.Count
            $coveragePercent = if ($totalComputers -gt 0) { 
                [math]::Round(($computersWithLAPS.Count / $totalComputers) * 100, 2) 
            } else { 0 }
            
            Write-Verbose "LAPS coverage: $coveragePercent% ($($computersWithLAPS.Count)/$totalComputers computers)"
            
            # Alert if coverage is below 100%
            if ($coveragePercent -lt 100) {
                $severity = if ($coveragePercent -lt 50) { 'Critical' } 
                           elseif ($coveragePercent -lt 80) { 'High' } 
                           else { 'Medium' }
                           
                $severityLevel = if ($coveragePercent -lt 50) { 4 } 
                                elseif ($coveragePercent -lt 80) { 3 } 
                                else { 2 }
                
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'LAPS Security'
                $finding.Issue = 'Incomplete LAPS Coverage'
                $finding.Severity = $severity
                $finding.SeverityLevel = $severityLevel
                $finding.AffectedObject = "$($computersWithoutLAPS.Count) Computers"
                $finding.Description = "Only $coveragePercent% of domain computers have LAPS passwords set. $($computersWithoutLAPS.Count) computers are missing LAPS coverage."
                $finding.Impact = "Computers without LAPS retain static local administrator passwords, creating lateral movement opportunities for attackers."
                $finding.Remediation = "Deploy LAPS Group Policy to all OUs containing computers. Verify LAPS client is installed and GPO is applied. Check: gpresult /r"
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings"
                $finding.Details = @{
                    TotalComputers = $totalComputers
                    ComputersWithLAPS = $computersWithLAPS.Count
                    ComputersWithoutLAPS = $computersWithoutLAPS.Count
                    CoveragePercent = $coveragePercent
                    SampleComputersWithoutLAPS = ($computersWithoutLAPS | Select-Object -First 10 -ExpandProperty Name) -join ', '
                }
                $findings += $finding
            }
            
            # Check for expired LAPS passwords
            $now = [DateTime]::UtcNow
            $expiredLAPSComputers = $computersWithLAPS | Where-Object {
                $expirationTime = [DateTime]::FromFileTimeUtc($_.'ms-Mcs-AdmPwdExpirationTime')
                $expirationTime -lt $now
            }
            
            if ($expiredLAPSComputers.Count -gt 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'LAPS Security'
                $finding.Issue = 'Expired LAPS Passwords'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = "$($expiredLAPSComputers.Count) Computers"
                $finding.Description = "$($expiredLAPSComputers.Count) computers have expired LAPS passwords that have not been rotated."
                $finding.Impact = "Expired passwords may indicate computers that are offline, not receiving GPO updates, or have LAPS client issues."
                $finding.Remediation = "Investigate why LAPS passwords are not rotating. Ensure computers are online and receiving Group Policy updates."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/laps-troubleshooting-guidance"
                $finding.Details = @{
                    ExpiredCount = $expiredLAPSComputers.Count
                    SampleComputers = ($expiredLAPSComputers | Select-Object -First 10 -ExpandProperty Name) -join ', '
                }
                $findings += $finding
            }
        }
        
        Write-Verbose "LAPS deployment audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during LAPS audit: $_"
        throw
    }
}

#endregion

#region Audit Policy Configuration Audits

function Test-AuditPolicyConfiguration {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting audit policy configuration audit..."
    $findings = @()
    
    try {
        # Get domain controllers to check audit policies
        $domainControllers = Get-ADDomainController -Filter *
        
        Write-Verbose "Checking audit policies on $($domainControllers.Count) domain controller(s)..."
        
        # Critical audit policies that should be enabled
        $requiredAuditPolicies = @{
            'Account Logon' = @('Audit Credential Validation')
            'Account Management' = @('Audit User Account Management', 'Audit Security Group Management')
            'DS Access' = @('Audit Directory Service Access', 'Audit Directory Service Changes')
            'Logon/Logoff' = @('Audit Logon', 'Audit Logoff', 'Audit Account Lockout')
            'Object Access' = @('Audit File Share', 'Audit File System')
            'Policy Change' = @('Audit Policy Change', 'Audit Authentication Policy Change')
            'Privilege Use' = @('Audit Sensitive Privilege Use')
            'System' = @('Audit Security State Change', 'Audit Security System Extension')
        }
        
        foreach ($dc in $domainControllers) {
            try {
                # Check if we can query the DC (in a real scenario, you'd use Invoke-Command)
                # For this script, we'll check local/default domain policy
                
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Audit Policy'
                $finding.Issue = 'Advanced Audit Policy Verification Required'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $dc.Name
                $finding.Description = "Advanced audit policies should be verified on domain controller '$($dc.Name)' to ensure proper security event logging."
                $finding.Impact = "Without proper audit policies, security incidents cannot be detected or investigated effectively. Critical events may go unlogged."
                $finding.Remediation = @"
Verify and enable advanced audit policies on all DCs:
1. Account Logon: Audit Credential Validation (Success, Failure)
2. Account Management: Audit User/Security Group Management (Success, Failure)
3. DS Access: Audit Directory Service Access/Changes (Success, Failure)
4. Logon/Logoff: Audit Logon/Logoff/Account Lockout (Success, Failure)
5. Object Access: Audit File Share/System (Success, Failure)
6. Policy Change: Audit Policy/Auth Policy Change (Success, Failure)
7. Privilege Use: Audit Sensitive Privilege Use (Success, Failure)
8. System: Audit Security State Change/System Extension (Success, Failure)

Use: auditpol /get /category:* to view current settings
Configure via Group Policy: Computer Config > Windows Settings > Security Settings > Advanced Audit Policy
"@
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations"
                $finding.Details = @{
                    DomainController = $dc.Name
                    RequiredCategories = $requiredAuditPolicies.Keys -join ', '
                }
                $findings += $finding
                
            }
            catch {
                Write-Warning "Could not check audit policy on $($dc.Name): $_"
            }
        }
        
        # Check for SACL on sensitive AD objects
        try {
            $domain = Get-ADDomain
            $domainRoot = $domain.DistinguishedName
            
            # Check if AdminSDHolder has auditing configured
            $adminSDHolder = Get-ADObject "CN=AdminSDHolder,CN=System,$domainRoot" -Properties nTSecurityDescriptor -ErrorAction Stop
            $acl = $adminSDHolder.nTSecurityDescriptor
            
            $hasAuditRules = $acl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]).Count -gt 0
            
            if (-not $hasAuditRules) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Audit Policy'
                $finding.Issue = 'No Auditing on AdminSDHolder Object'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = 'AdminSDHolder'
                $finding.Description = "The AdminSDHolder object does not have audit rules (SACL) configured to log access attempts."
                $finding.Impact = "Changes to privileged group permissions and access attempts to critical AD objects will not be logged, hindering incident detection."
                $finding.Remediation = "Configure SACL on AdminSDHolder to audit 'Write all properties' and 'Modify permissions' for 'Everyone' (Success and Failure)."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows/win32/secauthz/audit-generation"
                $finding.Details = @{
                    DistinguishedName = $adminSDHolder.DistinguishedName
                }
                $findings += $finding
            }
        }
        catch {
            Write-Verbose "Could not check AdminSDHolder SACL: $_"
        }
        
        Write-Verbose "Audit policy configuration audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during audit policy audit: $_"
        throw
    }
}

#endregion

#region Constrained Delegation Audits

function Test-ConstrainedDelegation {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting constrained delegation security audit..."
    $findings = @()
    
    try {
        # Check user accounts with constrained delegation
        $usersWithConstrainedDelegation = Get-ADUser -Filter {msDS-AllowedToDelegateTo -like '*'} `
            -Properties msDS-AllowedToDelegateTo, TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalNames, Enabled
        
        foreach ($user in $usersWithConstrainedDelegation) {
            # Check for protocol transition (most dangerous)
            if ($user.TrustedToAuthForDelegation -eq $true) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Delegation'
                $finding.Issue = 'User Account with Protocol Transition (T2A4D)'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User account '$($user.SamAccountName)' has constrained delegation with protocol transition enabled (TrustedToAuthForDelegation)."
                $finding.Impact = "Can impersonate ANY user to specified services without requiring their credentials. Highly exploitable for privilege escalation."
                $finding.Remediation = "Disable protocol transition if not absolutely required. If needed, ensure the account has a very strong password (30+ characters) and is closely monitored. Consider migrating to Group Managed Service Accounts."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                    AllowedToDelegateTo = $user.'msDS-AllowedToDelegateTo' -join '; '
                    TrustedToAuthForDelegation = $user.TrustedToAuthForDelegation
                    Enabled = $user.Enabled
                }
                $findings += $finding
            }
            else {
                # Standard constrained delegation
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Delegation'
                $finding.Issue = 'User Account with Constrained Delegation'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User account '$($user.SamAccountName)' has constrained delegation configured to specific services."
                $finding.Impact = "Can impersonate authenticated users to specified services. Less risky than unconstrained delegation but still requires strong security controls."
                $finding.Remediation = "Verify this configuration is necessary. Ensure strong password policy and monitoring. Review delegated services: $($user.'msDS-AllowedToDelegateTo' -join ', ')"
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                    AllowedToDelegateTo = $user.'msDS-AllowedToDelegateTo' -join '; '
                    Enabled = $user.Enabled
                }
                $findings += $finding
            }
        }
        
        # Check computer accounts with constrained delegation
        $computersWithConstrainedDelegation = Get-ADComputer -Filter {msDS-AllowedToDelegateTo -like '*'} `
            -Properties msDS-AllowedToDelegateTo, TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalNames, Enabled
        
        foreach ($computer in $computersWithConstrainedDelegation) {
            if ($computer.TrustedToAuthForDelegation -eq $true) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Delegation'
                $finding.Issue = 'Computer Account with Protocol Transition (T2A4D)'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $computer.Name
                $finding.Description = "Computer account '$($computer.Name)' has constrained delegation with protocol transition enabled."
                $finding.Impact = "If compromised, attackers can impersonate any user to specified services. Common on Exchange servers but requires securing the host."
                $finding.Remediation = "Verify this configuration is required (common for Exchange/IIS). Ensure the computer is hardened, patched, and monitored. Services: $($computer.'msDS-AllowedToDelegateTo' -join ', ')"
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
                $finding.Details = @{
                    DistinguishedName = $computer.DistinguishedName
                    AllowedToDelegateTo = $computer.'msDS-AllowedToDelegateTo' -join '; '
                    TrustedToAuthForDelegation = $computer.TrustedToAuthForDelegation
                    Enabled = $computer.Enabled
                }
                $findings += $finding
            }
        }
        
        # Check for Resource-Based Constrained Delegation (RBCD)
        $objectsWithRBCD = Get-ADObject -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} `
            -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, objectClass, Name
        
        foreach ($object in $objectsWithRBCD) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Kerberos Delegation'
            $finding.Issue = 'Resource-Based Constrained Delegation Configured'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = $object.Name
            $finding.Description = "Object '$($object.Name)' has Resource-Based Constrained Delegation (RBCD) configured, allowing other accounts to impersonate users to this resource."
            $finding.Impact = "RBCD can be exploited if an attacker can modify the msDS-AllowedToActOnBehalfOfOtherIdentity attribute or compromise accounts listed in it."
            $finding.Remediation = "Review RBCD configuration and ensure only necessary accounts are allowed. Monitor for unauthorized changes to this attribute."
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview#resource-based-constrained-delegation"
            $finding.Details = @{
                DistinguishedName = $object.DistinguishedName
                ObjectClass = $object.objectClass
            }
            $findings += $finding
        }
        
        Write-Verbose "Constrained delegation audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during constrained delegation audit: $_"
        throw
    }
}

#endregion

#region Computer Account and Delegation Audits

function Test-ComputerAccountDelegation {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$InactiveDaysThreshold = 90
    )
    
    Write-Verbose "Starting computer account delegation audit..."
    $findings = @()
    
    try {
        # Get all computer accounts with delegation-related properties
        $computers = Get-ADComputer -Filter * -Properties `
            TrustedForDelegation, TrustedToAuthForDelegation, `
            msDS-AllowedToDelegateTo, LastLogonDate, OperatingSystem, `
            ServicePrincipalNames, Enabled, DistinguishedName, `
            PrimaryGroupID -ErrorAction Stop
        
        Write-Verbose "Analyzing $($computers.Count) computer accounts..."
        
        $computerCount = $computers.Count
        $currentComputer = 0
        
        foreach ($computer in $computers) {
            $currentComputer++
            
            if ($currentComputer % 50 -eq 0 -or $currentComputer -eq $computerCount) {
                Write-Progress -Activity "Scanning Computer Accounts" -Status "Processing $($computer.Name)" `
                    -PercentComplete (($currentComputer / $computerCount) * 100)
            }
            
            # Check for unconstrained delegation on computer accounts
            if ($computer.TrustedForDelegation -eq $true -and $computer.PrimaryGroupID -ne 516) {
                # PrimaryGroupID 516 = Domain Controllers (DCs are expected to have this)
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Computer Account Security'
                $finding.Issue = 'Unconstrained Delegation Enabled'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $computer.Name
                $finding.Description = "Computer account has unconstrained delegation enabled, which can be exploited to compromise any user credentials."
                $finding.Impact = "An attacker who compromises this computer can impersonate ANY user (including Domain Admins) who authenticates to it. This is a critical privilege escalation path."
                $finding.Remediation = "Disable unconstrained delegation immediately: Set-ADComputer -Identity '$($computer.Name)' -TrustedForDelegation `$false. If delegation is required, use constrained delegation instead."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unconstrained-kerberos"
                $finding.Details = @{
                    DistinguishedName = $computer.DistinguishedName
                    OperatingSystem = $computer.OperatingSystem
                    LastLogonDate = $computer.LastLogonDate
                    ServicePrincipalNames = $computer.ServicePrincipalNames -join '; '
                }
                $findings += $finding
            }
            
            # Check for protocol transition (TrustedToAuthForDelegation)
            if ($computer.TrustedToAuthForDelegation -eq $true) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Computer Account Security'
                $finding.Issue = 'Computer Trusted for Protocol Transition'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $computer.Name
                $finding.Description = "Computer account is trusted for protocol transition (Kerberos S4U2Self), allowing it to obtain service tickets on behalf of any user."
                $finding.Impact = "This computer can impersonate users without requiring their credentials, potentially leading to privilege escalation."
                $finding.Remediation = "Review if protocol transition is necessary. If not required, remove this setting. Ensure only specific services use this feature with constrained delegation."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
                $finding.Details = @{
                    DistinguishedName = $computer.DistinguishedName
                    OperatingSystem = $computer.OperatingSystem
                    AllowedToDelegateTo = $computer.'msDS-AllowedToDelegateTo' -join '; '
                }
                $findings += $finding
            }
            
            # Check for constrained delegation on computers
            if ($computer.'msDS-AllowedToDelegateTo' -and $computer.'msDS-AllowedToDelegateTo'.Count -gt 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Computer Account Security'
                $finding.Issue = 'Computer with Constrained Delegation'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $computer.Name
                $finding.Description = "Computer account has constrained delegation configured for $($computer.'msDS-AllowedToDelegateTo'.Count) service(s)."
                $finding.Impact = "While constrained delegation is safer than unconstrained, it still allows this computer to impersonate users to specific services. Verify this is intentional and necessary."
                $finding.Remediation = "Review delegation targets and ensure they are appropriate. Consider using Resource-Based Constrained Delegation (RBCD) for better security. Monitor for abuse."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
                $finding.Details = @{
                    DistinguishedName = $computer.DistinguishedName
                    OperatingSystem = $computer.OperatingSystem
                    DelegationTargets = $computer.'msDS-AllowedToDelegateTo' -join '; '
                    ProtocolTransition = $computer.TrustedToAuthForDelegation
                }
                $findings += $finding
            }
            
            # Check for stale computer accounts
            if ($computer.Enabled -eq $true -and $computer.LastLogonDate) {
                $daysSinceLogon = (Get-Date) - $computer.LastLogonDate
                if ($daysSinceLogon.Days -gt $InactiveDaysThreshold) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Computer Account Security'
                    $finding.Issue = 'Stale Computer Account'
                    $finding.Severity = 'Low'
                    $finding.SeverityLevel = 1
                    $finding.AffectedObject = $computer.Name
                    $finding.Description = "Enabled computer account has not authenticated to the domain in $($daysSinceLogon.Days) days."
                    $finding.Impact = "Stale computer accounts increase attack surface and may have weak security configurations. They can be used for persistence if compromised."
                    $finding.Remediation = "Verify if this computer is still in use. If not, disable or delete: Disable-ADAccount -Identity '$($computer.Name)'"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/remove-stale-domain-controller"
                    $finding.Details = @{
                        DistinguishedName = $computer.DistinguishedName
                        OperatingSystem = $computer.OperatingSystem
                        LastLogonDate = $computer.LastLogonDate
                        DaysSinceLogon = $daysSinceLogon.Days
                    }
                    $findings += $finding
                }
            }
        }
        
        # Check Machine Account Quota
        $rootDSE = Get-ADRootDSE
        $domainDN = $rootDSE.defaultNamingContext
        $domainObject = Get-ADObject -Identity $domainDN -Properties ms-DS-MachineAccountQuota
        $machineAccountQuota = $domainObject.'ms-DS-MachineAccountQuota'
        
        if ($machineAccountQuota -gt 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Computer Account Security'
            $finding.Issue = 'Machine Account Quota Enabled'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = 'Domain'
            $finding.Description = "The ms-DS-MachineAccountQuota is set to $machineAccountQuota, allowing non-privileged users to join computers to the domain."
            $finding.Impact = "Attackers can add rogue computers to the domain, which can be used for privilege escalation attacks (e.g., resource-based constrained delegation abuse)."
            $finding.Remediation = "Set ms-DS-MachineAccountQuota to 0: Set-ADDomain -Identity '$($domain.DistinguishedName)' -Replace @{'ms-DS-MachineAccountQuota'=0}. Control computer joins through Group Policy or delegated permissions."
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/add-workstations-to-domain"
            $finding.Details = @{
                CurrentQuota = $machineAccountQuota
                DomainDN = $domainDN
            }
            $findings += $finding
        }
        
        Write-Progress -Activity "Scanning Computer Accounts" -Completed
        Write-Verbose "Computer account delegation audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during computer account delegation audit: $_"
        throw
    }
}

#endregion

#region Fine-Grained Password Policy Audits

function Test-FineGrainedPasswordPolicies {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting fine-grained password policy audit..."
    $findings = @()
    
    try {
        # Check domain functional level (FGPP requires Windows Server 2008 or higher)
        $domain = Get-ADDomain
        $domainLevel = $domain.DomainMode
        
        if ($domainLevel -lt 'Windows2008Domain') {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Password Policies'
            $finding.Issue = 'Fine-Grained Password Policies Not Supported'
            $finding.Severity = 'Low'
            $finding.SeverityLevel = 1
            $finding.AffectedObject = 'Domain'
            $finding.Description = "Domain functional level ($domainLevel) does not support Fine-Grained Password Policies (FGPP)."
            $finding.Impact = "Cannot enforce different password policies for different user groups, limiting security flexibility for privileged accounts."
            $finding.Remediation = "Consider raising domain functional level to Windows Server 2008 or higher to enable FGPP support."
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc770394(v=ws.10)"
            $finding.Details = @{
                DomainMode = $domainLevel
                DomainName = $domain.DNSRoot
            }
            $findings += $finding
            return $findings
        }
        
        # Get default domain password policy
        $defaultPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        
        # Audit default domain password policy
        if ($defaultPolicy.MinPasswordLength -lt 14) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Password Policies'
            $finding.Issue = 'Weak Default Password Length'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = 'Default Domain Policy'
            $finding.Description = "Default domain password policy requires only $($defaultPolicy.MinPasswordLength) characters. NIST recommends minimum 14 characters."
            $finding.Impact = "Short passwords are vulnerable to brute-force and password spray attacks."
            $finding.Remediation = "Increase minimum password length to at least 14 characters: Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 -Identity '$($domain.DistinguishedName)'"
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/minimum-password-length"
            $finding.Details = @{
                CurrentMinLength = $defaultPolicy.MinPasswordLength
                RecommendedMinLength = 14
            }
            $findings += $finding
        }
        
        if ($defaultPolicy.ComplexityEnabled -eq $false) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Password Policies'
            $finding.Issue = 'Password Complexity Disabled'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.AffectedObject = 'Default Domain Policy'
            $finding.Description = "Password complexity is disabled in the default domain password policy."
            $finding.Impact = "Users can set simple, easily guessable passwords, significantly increasing risk of compromise."
            $finding.Remediation = "Enable password complexity: Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled `$true -Identity '$($domain.DistinguishedName)'"
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements"
            $finding.Details = @{
                ComplexityEnabled = $defaultPolicy.ComplexityEnabled
            }
            $findings += $finding
        }
        
        if ($defaultPolicy.LockoutThreshold -eq 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Password Policies'
            $finding.Issue = 'Account Lockout Not Configured'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = 'Default Domain Policy'
            $finding.Description = "Account lockout is not enabled (threshold is 0), allowing unlimited password attempts."
            $finding.Impact = "Domain is vulnerable to password brute-force and spray attacks with no automatic account lockout protection."
            $finding.Remediation = "Configure account lockout: Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 -LockoutDuration 00:30:00 -LockoutObservationWindow 00:30:00"
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/account-lockout-threshold"
            $finding.Details = @{
                LockoutThreshold = $defaultPolicy.LockoutThreshold
                RecommendedThreshold = 5
            }
            $findings += $finding
        }
        
        if ($defaultPolicy.MaxPasswordAge.Days -gt 90 -or $defaultPolicy.MaxPasswordAge.Days -eq 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Password Policies'
            $finding.Issue = 'Password Expiration Too Long or Disabled'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = 'Default Domain Policy'
            $finding.Description = "Maximum password age is $($defaultPolicy.MaxPasswordAge.Days) days. Recommended is 60-90 days."
            $finding.Impact = "Long-lived passwords increase the window of opportunity for compromised credentials to be exploited."
            $finding.Remediation = "Set reasonable password expiration: Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 90.00:00:00"
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/maximum-password-age"
            $finding.Details = @{
                CurrentMaxAge = $defaultPolicy.MaxPasswordAge.Days
                RecommendedMaxAge = 90
            }
            $findings += $finding
        }
        
        # Get all Fine-Grained Password Policies (PSOs)
        $psos = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction SilentlyContinue
        
        if (-not $psos -or $psos.Count -eq 0) {
            # Check if privileged accounts exist
            $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
            $hasPrivilegedUsers = $false
            
            foreach ($groupName in $privilegedGroups) {
                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
                if ($group) {
                    $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                    if ($members) {
                        $hasPrivilegedUsers = $true
                        break
                    }
                }
            }
            
            if ($hasPrivilegedUsers) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Password Policies'
                $finding.Issue = 'No Fine-Grained Password Policies for Privileged Accounts'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = 'Domain'
                $finding.Description = "No Fine-Grained Password Policies (PSOs) are configured, but privileged accounts exist in the domain."
                $finding.Impact = "Privileged accounts follow the same password policy as standard users, which may not provide adequate protection for high-value accounts."
                $finding.Remediation = "Create a stricter PSO for privileged accounts with longer passwords (20+ chars), shorter expiration, and stricter lockout policies. Use New-ADFineGrainedPasswordPolicy cmdlet."
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc770842(v=ws.10)"
                $finding.Details = @{
                    PSOCount = 0
                    DomainFunctionalLevel = $domainLevel
                }
                $findings += $finding
            }
        }
        else {
            Write-Verbose "Found $($psos.Count) Fine-Grained Password Policy Objects"
            
            foreach ($pso in $psos) {
                # Check PSO password length
                if ($pso.MinPasswordLength -lt 20) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Password Policies'
                    $finding.Issue = 'Weak PSO Password Length'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $pso.Name
                    $finding.Description = "Fine-Grained Password Policy '$($pso.Name)' requires only $($pso.MinPasswordLength) characters. For privileged accounts, 20+ characters recommended."
                    $finding.Impact = "PSOs typically apply to privileged accounts. Weak password requirements reduce protection for high-value targets."
                    $finding.Remediation = "Increase minimum password length for PSO: Set-ADFineGrainedPasswordPolicy -Identity '$($pso.Name)' -MinPasswordLength 20"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adfinegrainedpasswordpolicy"
                    $finding.Details = @{
                        PSOName = $pso.Name
                        CurrentMinLength = $pso.MinPasswordLength
                        RecommendedMinLength = 20
                        AppliesTo = $pso.AppliesTo -join '; '
                        Precedence = $pso.Precedence
                    }
                    $findings += $finding
                }
                
                # Check PSO complexity
                if ($pso.ComplexityEnabled -eq $false) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Password Policies'
                    $finding.Issue = 'PSO Password Complexity Disabled'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $pso.Name
                    $finding.Description = "Fine-Grained Password Policy '$($pso.Name)' has password complexity disabled."
                    $finding.Impact = "Accounts under this PSO can use simple passwords, increasing compromise risk for what are typically privileged accounts."
                    $finding.Remediation = "Enable complexity: Set-ADFineGrainedPasswordPolicy -Identity '$($pso.Name)' -ComplexityEnabled `$true"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adfinegrainedpasswordpolicy"
                    $finding.Details = @{
                        PSOName = $pso.Name
                        ComplexityEnabled = $pso.ComplexityEnabled
                        AppliesTo = $pso.AppliesTo -join '; '
                    }
                    $findings += $finding
                }
                
                # Check if PSO has any objects assigned
                if (-not $pso.AppliesTo -or $pso.AppliesTo.Count -eq 0) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Password Policies'
                    $finding.Issue = 'PSO Not Applied to Any Objects'
                    $finding.Severity = 'Low'
                    $finding.SeverityLevel = 1
                    $finding.AffectedObject = $pso.Name
                    $finding.Description = "Fine-Grained Password Policy '$($pso.Name)' exists but is not applied to any users or groups."
                    $finding.Impact = "The PSO has no effect and represents unused configuration that should be cleaned up."
                    $finding.Remediation = "Either apply the PSO to appropriate users/groups using Add-ADFineGrainedPasswordPolicySubject, or remove it if not needed."
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adfinegrainedpasswordpolicysubject"
                    $finding.Details = @{
                        PSOName = $pso.Name
                        Precedence = $pso.Precedence
                        MinPasswordLength = $pso.MinPasswordLength
                    }
                    $findings += $finding
                }
                
                # Check for conflicting PSos (same precedence)
                $conflictingPSOs = $psos | Where-Object { 
                    $_.Name -ne $pso.Name -and $_.Precedence -eq $pso.Precedence 
                }
                
                if ($conflictingPSOs) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Password Policies'
                    $finding.Issue = 'PSO Precedence Conflict'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $pso.Name
                    $finding.Description = "PSO '$($pso.Name)' has the same precedence ($($pso.Precedence)) as other PSO(s): $($conflictingPSOs.Name -join ', ')"
                    $finding.Impact = "When multiple PSOs apply to the same user with identical precedence, the result is unpredictable and may not enforce intended policies."
                    $finding.Remediation = "Assign unique precedence values to all PSOs. Lower numbers have higher priority. Review and adjust precedence values."
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc770394(v=ws.10)#precedence"
                    $finding.Details = @{
                        PSOName = $pso.Name
                        Precedence = $pso.Precedence
                        ConflictingPSOs = $conflictingPSOs.Name -join '; '
                    }
                    $findings += $finding
                }
            }
        }
        
        Write-Verbose "Fine-grained password policy audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during fine-grained password policy audit: $_"
        throw
    }
}

#endregion

#region DNS Security Audits

function Test-DNSSecurityConfiguration {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting DNS security configuration audit..."
    $findings = @()
    
    try {
        # Get all domain controllers (DNS servers)
        $domainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
        
        Write-Verbose "Analyzing DNS configuration on $($domainControllers.Count) domain controller(s)..."
        
        foreach ($dc in $domainControllers) {
            $dcName = $dc.HostName
            
            Write-Verbose "Checking DNS on $dcName..."
            
            # Check if DNS service is running
            try {
                $dnsService = Get-Service -Name DNS -ComputerName $dcName -ErrorAction Stop
                
                if ($dnsService.Status -ne 'Running') {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'DNS Security'
                    $finding.Issue = 'DNS Service Not Running on DC'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $dcName
                    $finding.Description = "DNS service is not running on domain controller $dcName."
                    $finding.Impact = "Clients may experience authentication and name resolution issues. Domain functionality may be degraded."
                    $finding.Remediation = "Start DNS service: Start-Service -Name DNS -ComputerName '$dcName'. Investigate why the service stopped."
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-server-not-starting"
                    $finding.Details = @{
                        ServiceStatus = $dnsService.Status
                        DomainController = $dcName
                    }
                    $findings += $finding
                }
            }
            catch {
                Write-Verbose "Could not query DNS service on $dcName : $_"
            }
            
            # Check DNS zone security using WMI/CIM
            try {
                $dnsZones = Get-CimInstance -ComputerName $dcName -Namespace root\MicrosoftDNS `
                    -ClassName MicrosoftDNS_Zone -ErrorAction Stop
                
                foreach ($zone in $dnsZones) {
                    # Check for zone transfers allowed to any server
                    if ($zone.SecureSecondaries -eq 0) {
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'DNS Security'
                        $finding.Issue = 'DNS Zone Transfers Unrestricted'
                        $finding.Severity = 'High'
                        $finding.SeverityLevel = 3
                        $finding.AffectedObject = "$dcName - $($zone.Name)"
                        $finding.Description = "DNS zone '$($zone.Name)' on $dcName allows zone transfers to any server."
                        $finding.Impact = "Attackers can enumerate all DNS records, revealing network topology, server names, and potential targets."
                        $finding.Remediation = "Restrict zone transfers to authorized DNS servers only through DNS Manager or Set-DnsServerPrimaryZone cmdlet."
                        $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/networking/dns/zone-transfers"
                        $finding.Details = @{
                            ZoneName = $zone.Name
                            SecureSecondaries = $zone.SecureSecondaries
                            DomainController = $dcName
                            ZoneType = $zone.ZoneType
                        }
                        $findings += $finding
                    }
                    
                    # Check for unsigned zones (DNSSEC)
                    if ($zone.ZoneType -eq 1 -and $zone.IsSigned -eq $false) {
                        # ZoneType 1 = Primary zone
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'DNS Security'
                        $finding.Issue = 'DNS Zone Not Signed (No DNSSEC)'
                        $finding.Severity = 'Medium'
                        $finding.SeverityLevel = 2
                        $finding.AffectedObject = "$dcName - $($zone.Name)"
                        $finding.Description = "DNS zone '$($zone.Name)' on $dcName is not signed with DNSSEC."
                        $finding.Impact = "Zone is vulnerable to DNS spoofing and cache poisoning attacks. Clients cannot verify authenticity of DNS responses."
                        $finding.Remediation = "Consider implementing DNSSEC: Use 'Sign-DnsServerZone' cmdlet or DNS Manager to sign the zone. Note: Requires proper key management."
                        $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/networking/dns/dnssec-overview"
                        $finding.Details = @{
                            ZoneName = $zone.Name
                            IsSigned = $zone.IsSigned
                            DomainController = $dcName
                        }
                        $findings += $finding
                    }
                    
                    # Check for dynamic updates set to non-secure
                    if ($zone.AllowUpdate -eq 1) {
                        # AllowUpdate: 0=None, 1=Non-secure, 2=Secure only
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'DNS Security'
                        $finding.Issue = 'Non-Secure DNS Dynamic Updates Allowed'
                        $finding.Severity = 'Critical'
                        $finding.SeverityLevel = 4
                        $finding.AffectedObject = "$dcName - $($zone.Name)"
                        $finding.Description = "DNS zone '$($zone.Name)' on $dcName allows non-secure dynamic updates."
                        $finding.Impact = "Attackers can register malicious DNS records, hijack existing hostnames, and perform man-in-the-middle attacks. This is a critical security vulnerability."
                        $finding.Remediation = "Change to secure dynamic updates only: Set-DnsServerPrimaryZone -Name '$($zone.Name)' -DynamicUpdate Secure -ComputerName '$dcName'"
                        $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-dns-dynamic-updates-windows-server-2003"
                        $finding.Details = @{
                            ZoneName = $zone.Name
                            AllowUpdate = $zone.AllowUpdate
                            DomainController = $dcName
                        }
                        $findings += $finding
                    }
                }
            }
            catch {
                Write-Verbose "Could not query DNS zones on $dcName : $_"
            }
            
            # Check for DNS scavenging configuration
            try {
                $dnsServer = Get-CimInstance -ComputerName $dcName -Namespace root\MicrosoftDNS `
                    -ClassName MicrosoftDNS_Server -ErrorAction Stop
                
                if ($dnsServer.ScavengingInterval -eq 0) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'DNS Security'
                    $finding.Issue = 'DNS Scavenging Disabled'
                    $finding.Severity = 'Low'
                    $finding.SeverityLevel = 1
                    $finding.AffectedObject = $dcName
                    $finding.Description = "DNS scavenging is disabled on $dcName. Stale DNS records will accumulate over time."
                    $finding.Impact = "Stale records can lead to connectivity issues and provide outdated information to attackers during reconnaissance."
                    $finding.Remediation = "Enable DNS scavenging: Set-DnsServerScavenging -ScavengingState `$true -ScavengingInterval 7.00:00:00 -ComputerName '$dcName'"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-scavenging-setup"
                    $finding.Details = @{
                        ScavengingInterval = $dnsServer.ScavengingInterval
                        DomainController = $dcName
                    }
                    $findings += $finding
                }
            }
            catch {
                Write-Verbose "Could not query DNS server settings on $dcName : $_"
            }
            
            # Check for DNS global query block list (protects against WPAD/ISATAP attacks)
            try {
                $queryBlockList = Invoke-Command -ComputerName $dcName -ScriptBlock {
                    try {
                        $list = Get-DnsServerGlobalQueryBlockList -ErrorAction Stop
                        return $list
                    }
                    catch {
                        return $null
                    }
                } -ErrorAction SilentlyContinue
                
                if ($queryBlockList -and $queryBlockList.Enable -eq $false) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'DNS Security'
                    $finding.Issue = 'DNS Global Query Block List Disabled'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $dcName
                    $finding.Description = "DNS Global Query Block List is disabled on $dcName, which protects against WPAD and ISATAP name hijacking."
                    $finding.Impact = "Domain is vulnerable to WPAD hijacking attacks where attackers can intercept web proxy settings and capture credentials."
                    $finding.Remediation = "Enable global query block list: Set-DnsServerGlobalQueryBlockList -Enable `$true -ComputerName '$dcName'"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverglobalqueryblocklist"
                    $finding.Details = @{
                        Enabled = $queryBlockList.Enable
                        BlockedNames = $queryBlockList.List -join '; '
                        DomainController = $dcName
                    }
                    $findings += $finding
                }
            }
            catch {
                Write-Verbose "Could not query DNS global query block list on $dcName : $_"
            }
        }
        
        # Check for LDAP signing and channel binding (prevents LDAP relay attacks)
        foreach ($dc in $domainControllers) {
            $dcName = $dc.HostName
            
            try {
                $ldapPolicy = Invoke-Command -ComputerName $dcName -ScriptBlock {
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
                    $ldapSigning = Get-ItemProperty -Path $regPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
                    $channelBinding = Get-ItemProperty -Path $regPath -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
                    
                    return @{
                        LDAPServerIntegrity = $ldapSigning.LDAPServerIntegrity
                        LdapEnforceChannelBinding = $channelBinding.LdapEnforceChannelBinding
                    }
                } -ErrorAction SilentlyContinue
                
                if ($ldapPolicy.LDAPServerIntegrity -ne 2) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'DNS Security'
                    $finding.Issue = 'LDAP Signing Not Required'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $dcName
                    $finding.Description = "LDAP signing is not required on domain controller $dcName (current value: $($ldapPolicy.LDAPServerIntegrity))."
                    $finding.Impact = "Domain is vulnerable to LDAP relay attacks where attackers can intercept and modify LDAP traffic, potentially gaining privileged access."
                    $finding.Remediation = "Require LDAP signing via registry: Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity' -Value 2. Or use Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Domain controller: LDAP server signing requirements' = 'Require signing'"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements"
                    $finding.Details = @{
                        CurrentValue = $ldapPolicy.LDAPServerIntegrity
                        RequiredValue = 2
                        DomainController = $dcName
                    }
                    $findings += $finding
                }
                
                if ($ldapPolicy.LdapEnforceChannelBinding -ne 2) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'DNS Security'
                    $finding.Issue = 'LDAP Channel Binding Not Required'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $dcName
                    $finding.Description = "LDAP channel binding is not enforced on domain controller $dcName (current value: $($ldapPolicy.LdapEnforceChannelBinding))."
                    $finding.Impact = "Vulnerable to LDAP relay attacks even over TLS. Channel binding ensures the TLS channel cannot be relayed."
                    $finding.Remediation = "Enforce LDAP channel binding: Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding' -Value 2"
                    $finding.DocumentationLink = "https://support.microsoft.com/en-us/topic/use-the-ldapenforcechannelbinding-registry-entry-to-make-ldap-authentication-over-ssl-tls-more-secure-e9ecfa27-5e57-8519-6ba3-d2c06b38d034"
                    $finding.Details = @{
                        CurrentValue = $ldapPolicy.LdapEnforceChannelBinding
                        RequiredValue = 2
                        DomainController = $dcName
                    }
                    $findings += $finding
                }
            }
            catch {
                Write-Verbose "Could not query LDAP policy on $dcName : $_"
            }
        }
        
        Write-Verbose "DNS security configuration audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during DNS security configuration audit: $_"
        throw
    }
}

#endregion

#region Replication Health Audit

function Test-ADReplicationHealth {
    <#
    .SYNOPSIS
    Audits Active Directory replication health including partners, latency, and failures.
    
    .DESCRIPTION
    Checks replication status across all domain controllers, identifies replication failures,
    measures replication latency, and validates replication partner configurations.
    
    .OUTPUTS
    Array of ADSecurityFinding objects
    #>
    [CmdletBinding()]
    param()
    
    $findings = @()
    Write-Host "Checking AD Replication Health..." -ForegroundColor Cyan
    
    try {
        # Get all domain controllers
        $allDCs = Get-ADDomainController -Filter * -ErrorAction Stop
        
        if ($allDCs.Count -eq 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = "Replication Health"
            $finding.Issue = "No Domain Controllers Found"
            $finding.Severity = "Critical"
            $finding.SeverityLevel = $Script:SeverityLevels.Critical
            $finding.Description = "Unable to enumerate domain controllers for replication health check"
            $finding.Impact = "Cannot assess replication health which is critical for AD availability"
            $finding.Remediation = "Verify domain controller availability and connectivity"
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/troubleshoot-domain-controller-issues"
            $finding.AffectedObject = "Domain Controllers"
            $finding.Details = @{
                'Message' = 'No domain controllers found in the domain.'
            }
            $findings += $finding
            return $findings
        }
        
        Write-Verbose "Found $($allDCs.Count) domain controller(s)"
        
        # Check replication status for each DC
        foreach ($dc in $allDCs) {
            Write-Verbose "Checking replication for: $($dc.HostName)"
            
            try {
                # Test connectivity first
                $pingResult = Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet -ErrorAction SilentlyContinue
                
                if (-not $pingResult) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = "Replication Health"
                    $finding.Issue = "Domain Controller Unreachable"
                    $finding.Severity = "High"
                    $finding.SeverityLevel = $Script:SeverityLevels.High
                    $finding.Description = "Domain Controller $($dc.HostName) is not responding to network requests"
                    $finding.Impact = "Replication may be failing, causing directory inconsistencies"
                    $finding.Remediation = "Verify network connectivity and DC health for $($dc.HostName)"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/troubleshoot-ad-replication-problems"
                    $finding.AffectedObject = $dc.HostName
                    $finding.Details = @{
                        'Site' = $dc.Site
                        'IsGlobalCatalog' = $dc.IsGlobalCatalog
                        'IsReadOnly' = $dc.IsReadOnly
                    }
                    $findings += $finding
                    continue
                }
                
                # Get replication metadata
                $replMetadata = Get-ADReplicationPartnerMetadata -Target $dc.HostName -Scope Domain -ErrorAction SilentlyContinue
                
                if ($replMetadata) {
                    foreach ($metadata in $replMetadata) {
                        # Check for replication failures
                        if ($metadata.LastReplicationResult -ne 0) {
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = "Replication Health"
                            $finding.Issue = "Replication Failure Detected"
                            $finding.Severity = "Critical"
                            $finding.SeverityLevel = $Script:SeverityLevels.Critical
                            $finding.Description = "Replication failure between $($dc.HostName) and $($metadata.Partner)"
                            $finding.Impact = "Directory data may be inconsistent across domain controllers, affecting authentication and authorization"
                            $finding.Remediation = "Investigate replication error code $($metadata.LastReplicationResult) using 'repadmin /showrepl' and resolve network or AD issues"
                            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/active-directory-replication-error-codes"
                            $finding.AffectedObject = "$($dc.HostName) <-> $($metadata.Partner)"
                            $finding.Details = @{
                                'SourceDC' = $dc.HostName
                                'PartnerDC' = $metadata.Partner
                                'Partition' = $metadata.Partition
                                'ErrorCode' = $metadata.LastReplicationResult
                                'LastAttempt' = $metadata.LastReplicationAttempt
                                'LastSuccess' = $metadata.LastReplicationSuccess
                                'ConsecutiveFailures' = $metadata.ConsecutiveReplicationFailures
                            }
                            $findings += $finding
                        }
                        
                        # Check for high replication latency (last success > 12 hours ago)
                        if ($metadata.LastReplicationSuccess) {
                            $timeSinceLastReplication = (Get-Date) - $metadata.LastReplicationSuccess
                            
                            if ($timeSinceLastReplication.TotalHours -gt 24) {
                                $finding = [ADSecurityFinding]::new()
                                $finding.Category = "Replication Health"
                                $finding.Issue = "High Replication Latency"
                                $finding.Severity = "High"
                                $finding.SeverityLevel = $Script:SeverityLevels.High
                                $finding.Description = "Replication between $($dc.HostName) and $($metadata.Partner) has not succeeded in $([math]::Round($timeSinceLastReplication.TotalHours, 2)) hours"
                                $finding.Impact = "Delayed replication can cause authentication failures and directory inconsistencies"
                                $finding.Remediation = "Check network connectivity, investigate replication queue, and review event logs on both domain controllers"
                                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/troubleshoot-ad-replication-problems"
                                $finding.AffectedObject = "$($dc.HostName) <-> $($metadata.Partner)"
                                $finding.Details = @{
                                    'SourceDC' = $dc.HostName
                                    'PartnerDC' = $metadata.Partner
                                    'Partition' = $metadata.Partition
                                    'HoursSinceLastReplication' = [math]::Round($timeSinceLastReplication.TotalHours, 2)
                                    'LastSuccess' = $metadata.LastReplicationSuccess
                                }
                                $findings += $finding
                            }
                            elseif ($timeSinceLastReplication.TotalHours -gt 12) {
                                $finding = [ADSecurityFinding]::new()
                                $finding.Category = "Replication Health"
                                $finding.Issue = "Moderate Replication Latency"
                                $finding.Severity = "Medium"
                                $finding.SeverityLevel = $Script:SeverityLevels.Medium
                                $finding.Description = "Replication between $($dc.HostName) and $($metadata.Partner) has not succeeded in $([math]::Round($timeSinceLastReplication.TotalHours, 2)) hours"
                                $finding.Impact = "May cause delays in directory updates propagating across domain controllers"
                                $finding.Remediation = "Monitor replication status and verify network connectivity between domain controllers"
                                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/replication/active-directory-replication-concepts"
                                $finding.AffectedObject = "$($dc.HostName) <-> $($metadata.Partner)"
                                $finding.Details = @{
                                    'SourceDC' = $dc.HostName
                                    'PartnerDC' = $metadata.Partner
                                    'Partition' = $metadata.Partition
                                    'HoursSinceLastReplication' = [math]::Round($timeSinceLastReplication.TotalHours, 2)
                                    'LastSuccess' = $metadata.LastReplicationSuccess
                                }
                                $findings += $finding
                            }
                        }
                        
                        # Check for consecutive replication failures
                        if ($metadata.ConsecutiveReplicationFailures -gt 5) {
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = "Replication Health"
                            $finding.Issue = "Multiple Consecutive Replication Failures"
                            $finding.Severity = "Critical"
                            $finding.SeverityLevel = $Script:SeverityLevels.Critical
                            $finding.Description = "Replication between $($dc.HostName) and $($metadata.Partner) has failed $($metadata.ConsecutiveReplicationFailures) consecutive times"
                            $finding.Impact = "Persistent replication failures indicate a serious configuration or connectivity issue"
                            $finding.Remediation = "Urgently investigate and resolve replication errors using 'repadmin /showrepl' and 'dcdiag /test:replications'"
                            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/troubleshoot-ad-replication-problems"
                            $finding.AffectedObject = "$($dc.HostName) <-> $($metadata.Partner)"
                            $finding.Details = @{
                                'SourceDC' = $dc.HostName
                                'PartnerDC' = $metadata.Partner
                                'Partition' = $metadata.Partition
                                'ConsecutiveFailures' = $metadata.ConsecutiveReplicationFailures
                                'LastAttempt' = $metadata.LastReplicationAttempt
                            }
                            $findings += $finding
                        }
                    }
                }
                
                # Get replication queue status
                try {
                    $replQueue = Get-ADReplicationQueueOperation -Server $dc.HostName -ErrorAction SilentlyContinue
                    
                    if ($replQueue) {
                        $queueCount = ($replQueue | Measure-Object).Count
                        
                        if ($queueCount -gt 100) {
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = "Replication Health"
                            $finding.Issue = "Large Replication Queue"
                            $finding.Severity = "High"
                            $finding.SeverityLevel = $Script:SeverityLevels.High
                            $finding.Description = "Domain Controller $($dc.HostName) has $queueCount pending replication operations"
                            $finding.Impact = "Large replication queue indicates replication delays or processing issues"
                            $finding.Remediation = "Investigate replication performance, check DC resources (CPU, memory, disk), and review for network issues"
                            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/replication/active-directory-replication-concepts"
                            $finding.AffectedObject = $dc.HostName
                            $finding.Details = @{
                                'QueueLength' = $queueCount
                                'Site' = $dc.Site
                            }
                            $findings += $finding
                        }
                        elseif ($queueCount -gt 50) {
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = "Replication Health"
                            $finding.Issue = "Elevated Replication Queue"
                            $finding.Severity = "Medium"
                            $finding.SeverityLevel = $Script:SeverityLevels.Medium
                            $finding.Description = "Domain Controller $($dc.HostName) has $queueCount pending replication operations"
                            $finding.Impact = "May indicate replication delays during peak load"
                            $finding.Remediation = "Monitor replication queue length and investigate if it continues to grow"
                            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/replication/active-directory-replication-concepts"
                            $finding.AffectedObject = $dc.HostName
                            $finding.Details = @{
                                'QueueLength' = $queueCount
                                'Site' = $dc.Site
                            }
                            $findings += $finding
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not query replication queue for $($dc.HostName): $_"
                }
                
                # Check replication partners
                try {
                    $replPartners = Get-ADReplicationConnection -Filter * -Server $dc.HostName -ErrorAction SilentlyContinue
                    
                    if ($replPartners) {
                        $disabledPartners = $replPartners | Where-Object { $_.ReplicationSchedule -eq $null -or -not $_.Enabled }
                        
                        if ($disabledPartners) {
                            foreach ($partner in $disabledPartners) {
                                $finding = [ADSecurityFinding]::new()
                                $finding.Category = "Replication Health"
                                $finding.Issue = "Disabled Replication Connection"
                                $finding.Severity = "Medium"
                                $finding.SeverityLevel = $Script:SeverityLevels.Medium
                                $finding.Description = "Replication connection '$($partner.Name)' on $($dc.HostName) is disabled"
                                $finding.Impact = "Disabled replication connections prevent directory updates from propagating"
                                $finding.Remediation = "Review why the connection is disabled and enable if appropriate, or remove if no longer needed"
                                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/reviewing-the-active-directory-logical-model"
                                $finding.AffectedObject = $partner.Name
                                $finding.Details = @{
                                    'ConnectionName' = $partner.Name
                                    'Server' = $dc.HostName
                                    'FromServer' = $partner.ReplicateFromDirectoryServer
                                }
                                $findings += $finding
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not query replication connections for $($dc.HostName): $_"
                }
                
            }
            catch {
                Write-Warning "Error checking replication for $($dc.HostName): $_"
                
                $finding = [ADSecurityFinding]::new()
                $finding.Category = "Replication Health"
                $finding.Issue = "Unable to Query Replication Status"
                $finding.Severity = "Medium"
                $finding.SeverityLevel = $Script:SeverityLevels.Medium
                $finding.Description = "Failed to retrieve replication information for $($dc.HostName)"
                $finding.Impact = "Cannot assess replication health for this domain controller"
                $finding.Remediation = "Verify permissions and connectivity to $($dc.HostName). Error: $_"
                $finding.DocumentationLink = "https://learn.microsoft.com/en-us/powershell/module/activedirectory/"
                $finding.AffectedObject = $dc.HostName
                $findings += $finding
            }
        }
        
        # Check for isolated domain controllers (no successful replication partners)
        foreach ($dc in $allDCs) {
            try {
                $replMetadata = Get-ADReplicationPartnerMetadata -Target $dc.HostName -Scope Domain -ErrorAction SilentlyContinue
                $successfulReplications = $replMetadata | Where-Object { $_.LastReplicationResult -eq 0 }
                
                if (-not $successfulReplications -and $allDCs.Count -gt 1) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = "Replication Health"
                    $finding.Issue = "Isolated Domain Controller"
                    $finding.Severity = "Critical"
                    $finding.SeverityLevel = $Script:SeverityLevels.Critical
                    $finding.Description = "Domain Controller $($dc.HostName) has no successful replication partners"
                    $finding.Impact = "DC is isolated from replication topology, causing severe directory inconsistencies"
                    $finding.Remediation = "Urgently investigate network connectivity and replication configuration for $($dc.HostName)"
                    $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/troubleshoot-ad-replication-problems"
                    $finding.AffectedObject = $dc.HostName
                    $finding.Details = @{
                        'Site' = $dc.Site
                        'IsGlobalCatalog' = $dc.IsGlobalCatalog
                    }
                    $findings += $finding
                }
            }
            catch {
                Write-Verbose "Could not check isolation status for $($dc.HostName): $_"
            }
        }
        
        # Summary finding if no issues detected
        if ($findings.Count -eq 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = "Replication Health"
            $finding.Issue = "Replication Health Check Passed"
            $finding.Severity = "Info"
            $finding.SeverityLevel = $Script:SeverityLevels.Info
            $finding.Description = "All domain controllers are replicating successfully with acceptable latency"
            $finding.Impact = "None - replication is healthy"
            $finding.Remediation = "Continue monitoring replication health regularly"
            $finding.DocumentationLink = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/replication/active-directory-replication-concepts"
            $finding.Details = @{
                'DomainControllerCount' = $allDCs.Count
                'CheckDate' = Get-Date
            }
            $findings += $finding
        }
        
        Write-Host "  Found $($findings.Count) replication health finding(s)" -ForegroundColor $(if($findings.Count -gt 1){'Yellow'}else{'Green'})
    }
    catch {
        Write-Warning "Error in replication health check: $_"
        
        $finding = [ADSecurityFinding]::new()
        $finding.Category = "Replication Health"
        $finding.Issue = "Replication Health Check Failed"
        $finding.Severity = "High"
        $finding.SeverityLevel = $Script:SeverityLevels.High
        $finding.Description = "Unable to complete replication health assessment"
        $finding.Impact = "Cannot verify critical replication status"
        $finding.Remediation = "Verify permissions and connectivity. Error: $_"
        $finding.DocumentationLink = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/troubleshoot-ad-replication-problems"
        $findings += $finding
    }
    
    return $findings
}

#endregion

#region Main Audit Function

function Start-ADSecurityAudit {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ExportPath = ".",
        
        [Parameter()]
        [int]$InactiveDaysThreshold = 90,
        
        [Parameter()]
        [int]$PasswordAgeThreshold = 180,
        
        [Parameter()]
        [string[]]$IncludeTests,
        
        [Parameter()]
        [string[]]$ExcludeTests = @(),
        
        [Parameter()]
        [switch]$IncludePrivilegedUsersReport
    )
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    
    if (-not (Test-Path $ExportPath)) {
        Write-Error "Export path does not exist: $ExportPath"
        return
    }
    
    $testFile = Join-Path $ExportPath "test_write_$(Get-Random).tmp"
    try {
        [System.IO.File]::WriteAllText($testFile, "test")
        Remove-Item $testFile -Force
    }
    catch {
        Write-Error "Export path is not writable: $ExportPath. Error: $_"
        return
    }
    
    $logPath = Join-Path $ExportPath "ADSecurityAudit_Log_$timestamp.txt"
    Start-Transcript -Path $logPath -Force
    
    try {
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
        
        Write-Verbose "Testing Domain Controller connectivity..."
        try {
            $domain = Get-ADDomain -ErrorAction Stop
            $dc = Get-ADDomainController -Discover -ErrorAction Stop
            
            if (-not (Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet)) {
                Write-Warning "Cannot reach Domain Controller: $($dc.HostName). Proceeding anyway..."
            }
            else {
                Write-Verbose "Successfully connected to Domain Controller: $($dc.HostName)"
            }
        }
        catch {
            Write-Error "Failed to connect to Active Directory Domain: $_"
            return
        }
        
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
            'CertificateServices' = { Test-ADCertificateServices }
            'KRBTGTAccount' = { Test-KRBTGTAccount -MaxPasswordAgeDays 180 }
            'DomainTrusts' = { Test-ADDomainTrusts }
            'LAPSDeployment' = { Test-LAPSDeployment }
            'AuditPolicyConfiguration' = { Test-AuditPolicyConfiguration }
            'ConstrainedDelegation' = { Test-ConstrainedDelegation }
            'ComputerAccountDelegation' = { Test-ComputerAccountDelegation -InactiveDaysThreshold $InactiveDaysThreshold }
            'FineGrainedPasswordPolicies' = { Test-FineGrainedPasswordPolicies }
            'DNSSecurityConfiguration' = { Test-DNSSecurityConfiguration }
            'ReplicationHealth' = { Test-ADReplicationHealth }
            # New tests added here
            'NTLMAndLegacyProtocols' = { Test-NTLMAndLegacyProtocols }
            'ProtectedUsersGroupCoverage' = { Test-ProtectedUsersGroupCoverage }
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
    finally {
        Stop-Transcript
    }
}

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
    
    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width
