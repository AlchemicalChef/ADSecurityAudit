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
                'UserPrincipalName', 'adminCount', 'SamAccountName', 'SID', 'Description',
                'msDS-SupportedEncryptionTypes', 'userAccountControl'
            )
        }
        
        if ($SearchBase) {
            $getUserParams['SearchBase'] = $SearchBase
        }
        
        $getUserParams['ResultPageSize'] = 500
        $users = Get-ADUser @getUserParams

        Write-Verbose "Analyzing $($users.Count) user accounts..."

        $protectedUsersGroup = $null
        try {
            $protectedUsersGroup = Get-ADGroup -Filter "Name -eq 'Protected Users'" -ErrorAction Stop
        }
        catch {
            Write-Verbose "Failed to get Protected Users group: $_"
        }
        
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
            # Improved: differentiate between service accounts and regular users, check encryption types
            if ($user.ServicePrincipalNames.Count -gt 0 -and $user.Enabled -eq $true) {
                $isPrivileged = Test-PrivilegedUser -User $user
                
                # Check password age for risk assessment
                $passwordAge = if ($user.PasswordLastSet) { (Get-Date) - $user.PasswordLastSet } else { [TimeSpan]::MaxValue }
                $hasOldPassword = $passwordAge.Days -gt 365
                
                # Check supported encryption types
                $encTypes = $user.'msDS-SupportedEncryptionTypes'
                $usesRC4Only = $false
                $usesAES = $false
                
                if ($encTypes) {
                    # Bit flags: RC4=4, AES128=8, AES256=16
                    $usesRC4Only = ($encTypes -band 4) -and -not ($encTypes -band 24)
                    $usesAES = ($encTypes -band 24) -ne 0
                }
                else {
                    # If not set, defaults to RC4
                    $usesRC4Only = $true
                }
                
                # Determine severity based on risk factors
                $severity = 'Medium'
                $severityLevel = 2
                $riskFactors = @()
                
                if ($isPrivileged) {
                    $severity = 'Critical'
                    $severityLevel = 4
                    $riskFactors += 'Privileged account'
                }
                elseif ($hasOldPassword -and $usesRC4Only) {
                    $severity = 'High'
                    $severityLevel = 3
                    $riskFactors += 'Old password (>1 year)'
                    $riskFactors += 'RC4 encryption only'
                }
                elseif ($hasOldPassword -or $usesRC4Only) {
                    $severity = 'High'
                    $severityLevel = 3
                    if ($hasOldPassword) { $riskFactors += 'Old password (>1 year)' }
                    if ($usesRC4Only) { $riskFactors += 'RC4 encryption only' }
                }
                else {
                    $riskFactors += 'Standard service account'
                }
                
                # Check if it looks like a service account (by naming convention or description)
                $isLikelyServiceAccount = $user.SamAccountName -match '^(svc|service|app|sql|iis|web|http)[-_]' -or
                                          $user.Description -match 'service|application'
                
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'User Account'
                $finding.Issue = if ($isPrivileged) { 'Privileged Account with SPN (Kerberoasting Risk)' } else { 'User Account with SPN (Kerberoasting Risk)' }
                $finding.Severity = $severity
                $finding.SeverityLevel = $severityLevel
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User account has Service Principal Names (SPNs) configured, making it vulnerable to Kerberoasting attacks. Risk factors: $($riskFactors -join ', ')."
                $finding.Impact = "Attackers can request service tickets for this account and crack the password offline. $(if ($isPrivileged) { 'As a privileged account, compromise could lead to domain-wide access.' })"
                $finding.Remediation = @"
1. $(if ($usesRC4Only) { 'Enable AES encryption: Set-ADUser -Identity ''$($user.SamAccountName)'' -KerberosEncryptionType AES256' })
2. Ensure a strong (25+ character) password is set
3. Consider migrating to a Group Managed Service Account (gMSA)
4. $(if ($hasOldPassword) { 'Rotate the password immediately' })
5. $(if ($isPrivileged) { 'Remove from privileged groups if service account does not require admin rights' })
"@
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                    ServicePrincipalNames = $user.ServicePrincipalNames -join '; '
                    PasswordLastSet = $user.PasswordLastSet
                    PasswordAgeDays = if ($passwordAge -ne [TimeSpan]::MaxValue) { $passwordAge.Days } else { 'Unknown' }
                    IsPrivileged = $isPrivileged
                    SupportsAES = $usesAES
                    UsesRC4Only = $usesRC4Only
                    RiskFactors = $riskFactors -join '; '
                    IsLikelyServiceAccount = $isLikelyServiceAccount
                }
                $findings += $finding
            }
            
            if ($protectedUsersGroup) {
                $isHighlyPrivileged = $Script:ProtectedGroups | Where-Object {
                    $user.MemberOf -match "CN=$([regex]::Escape($_)),"
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
        # Use regex escape to handle special characters in group names
        if ($User.MemberOf -match "CN=$([regex]::Escape($group)),") {
            return $true
        }
    }
    return $false
}

#endregion
