#region User Account Audits

function Test-ADUserSecurity {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$SearchBase,
        
        [Parameter()]
        [int]$InactiveDaysThreshold = 90,
        
        [Parameter()]
        [int]$PasswordAgeThreshold = 180,

        # Defense-in-depth for multi-domain forests: when this function is
        # called standalone (not via Start-ADSecurityAudit -Server, which
        # already installs a session-wide override before this ever runs),
        # there was previously no way to target a domain other than the
        # one the calling session ambiently resolves to. Passing -Server
        # here installs the same Set-ADSecurityAuditTargetServer override
        # Start-ADSecurityAudit uses, for the duration of this call only,
        # and only if one isn't ALREADY active - so calling this from
        # within a Start-ADSecurityAudit -Server run is unaffected.
        [Parameter()]
        [string]$Server
    )
    
    Write-Verbose "Starting user account security audit..."
    $findings = @()

    $__adAuditServerAlreadyActive = [bool](Get-ADSecurityAuditActiveServerOverride)
    if ($Server -and -not $__adAuditServerAlreadyActive) {
        # Resolve-ADSecurityAuditTargetServer, not the raw -Server value:
        # resolves to the domain's PDC Emulator specifically, so this
        # standalone call targets the exact same single, deterministic DC
        # Start-ADSecurityAudit itself would use for this domain, not an
        # arbitrary DC-locator pick.
        Set-ADSecurityAuditTargetServer -Server (Resolve-ADSecurityAuditTargetServer -Server $Server)
    }
    
    try {
        # Resolved once, explicitly passed to every live AD call below -
        # not relying on Set-ADSecurityAuditTargetServer's
        # $PSDefaultParameterValues injection alone. $__adServer is $null
        # when no override is active, which Get-AD*/Get-GP* cmdlets treat
        # identically to -Server being omitted entirely.
        $__adServer = Get-ADSecurityAuditActiveServerOverride
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
        if ($__adServer) { $getUserParams['Server'] = $__adServer }
        
        if ($SearchBase) {
            $getUserParams['SearchBase'] = $SearchBase
        }
        
        $getUserParams['ResultPageSize'] = 500
        $users = Get-ADUser @getUserParams

        Write-Verbose "Analyzing $($users.Count) user accounts..."

        $protectedUsersGroup = $null
        try {
            $protectedUsersGroup = if ($__adServer) {
                Get-ADGroup -Filter "Name -eq 'Protected Users'" -Server $__adServer -ErrorAction Stop
            }
            else {
                Get-ADGroup -Filter "Name -eq 'Protected Users'" -ErrorAction Stop
            }
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
                $finding.EstimatedEffort = 'Low - a single userAccountControl flag (DONT_REQ_PREAUTH) per account.'
                $finding.KnownRisks = 'Disabling pre-auth exposes the account to offline AS-REP roasting; re-enabling pre-auth has no legitimate compatibility impact unless a genuinely pre-auth-incompatible legacy Kerberos client depends on that specific account, which is rare.'
                $finding.BackupRollback = 'Easy - revert the DONT_REQ_PREAUTH flag; effective at next Kerberos authentication attempt, no data loss.'
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
                $finding.EstimatedEffort = 'Low - a single msDS-SupportedEncryptionTypes attribute per account.'
                $finding.KnownRisks = 'DES for Kerberos is only relevant to genuinely ancient clients (pre-Windows-7/Server-2008 era); removing it will break authentication only for such a legacy client if one still depends on this specific account, which is rare in a modern environment.'
                $finding.BackupRollback = 'Easy - revert msDS-SupportedEncryptionTypes to its prior value; effective at next Kerberos ticket renewal, no data loss.'
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
                $finding.EstimatedEffort = 'Low - a single userAccountControl flag (ENCRYPTED_TEXT_PWD_ALLOWED) per account.'
                $finding.KnownRisks = 'The existing reversibly-encrypted copy of the password persists until the account''s next password change, so disabling the flag alone doesn''t retroactively protect the current password.'
                $finding.BackupRollback = 'Easy - revert the flag; no data loss, though not retroactive to the already-stored reversible copy.'
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
                $finding.EstimatedEffort = 'Low - a single userAccountControl flag (DONT_EXPIRE_PASSWD) per account.'
                $finding.KnownRisks = 'Removing "password never expires" starts the account''s normal expiration clock, which for a service account can cause an unexpected outage later when the password expires unless the account is migrated to a gMSA or someone tracks the new expiration date; confirm which type of account this is first.'
                $finding.BackupRollback = 'Easy - revert the DONT_EXPIRE_PASSWD flag; effective immediately, no data loss.'
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
                $finding.EstimatedEffort = 'Medium - removing unconstrained delegation without configuring an equivalent constrained/RBCD replacement first can break the legitimate double-hop authentication scenario it was supporting, so this needs discovery of what the account/computer actually delegates to.'
                $finding.KnownRisks = 'Unconstrained delegation is one of the most consequential AD misconfigurations (a compromised host with this flag can capture and reuse TGTs of any user who authenticates to it), but removing it without a replacement delegation model will break whatever legitimate multi-hop authentication currently depends on it.'
                $finding.BackupRollback = 'Easy - revert the TRUSTED_FOR_DELEGATION flag; effective at next Kerberos ticket request, no data loss.'
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
                    $finding.EstimatedEffort = 'Low - disabling (not deleting) one account, a single attribute change.'
                    $finding.KnownRisks = 'Low risk disabling a genuinely inactive account; confirm it isn''t a seasonal or infrequently-used legitimate account (e.g. an annual-process service account) before disabling.'
                    $finding.BackupRollback = 'Easy - re-enable the account; effective immediately, no data loss.'
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
                    $finding.EstimatedEffort = 'Low - a single password reset/expiration action per account, though service accounts may need coordinated rotation everywhere the password is configured.'
                    $finding.KnownRisks = 'Forcing a password change requires the account owner to set a new password at next logon, a routine (if sometimes disruptive for service accounts) operational step; for service accounts, the manual rotation must be coordinated everywhere that account is configured.'
                    $finding.BackupRollback = 'Hard/Limited - a password can only be reset again, not restored to its previous (already known/old) value.'
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

                # BUGFIX: steps used to be hard-numbered 1-5 with the
                # conditional ones ($usesRC4Only / $hasOldPassword /
                # $isPrivileged) inlined directly after the number. When a
                # condition was false that line rendered as e.g. "1. " with
                # nothing after it - a blank recommendation line. Building
                # the list first and only numbering the steps that actually
                # apply avoids blank/gapped numbering. This also fixes the
                # AES step's account name never showing: it was wrapped in a
                # single-quoted string, and single-quoted PowerShell strings
                # don't interpolate $(...) - it printed the literal text
                # "$($user.SamAccountName)" instead of the account name.
                $remediationSteps = [System.Collections.ArrayList]::new()
                if ($usesRC4Only) {
                    [void]$remediationSteps.Add("Enable AES encryption: Set-ADUser -Identity '$($user.SamAccountName)' -KerberosEncryptionType AES256")
                }
                [void]$remediationSteps.Add('Ensure a strong (25+ character) password is set')
                [void]$remediationSteps.Add('Consider migrating to a Group Managed Service Account (gMSA)')
                if ($hasOldPassword) {
                    [void]$remediationSteps.Add('Rotate the password immediately')
                }
                if ($isPrivileged) {
                    [void]$remediationSteps.Add('Remove from privileged groups if service account does not require admin rights')
                }
                $stepNumber = 0
                $finding.Remediation = ($remediationSteps | ForEach-Object { $stepNumber++; "$stepNumber. $_" }) -join "`n"
                $finding.EstimatedEffort = if ($isPrivileged) { 'Medium - same as the non-privileged version, but the higher blast radius (a privileged account) makes coordinating the gMSA migration or password rotation with the service owner more urgent.' } else { 'Medium - the real fix (migrating to a gMSA, or ensuring a long random password) is a bigger step than removing the SPN, since the SPN is what makes the service reachable via Kerberos; needs coordination with whoever manages the service.' }
                $finding.KnownRisks = if ($isPrivileged) { 'A privileged service account with an SPN and a weak/crackable password is a high-value Kerberoasting target, since cracking it yields privileged access directly; migrating to a gMSA is the standard fix but requires the hosting application to support it.' } else { 'A service account with an SPN and a weak/crackable password is vulnerable to Kerberoasting; migrating to a gMSA (which manages its own long, automatically-rotated password) is the standard fix but requires the hosting application to support gMSA authentication.' }
                $finding.BackupRollback = if ($isPrivileged) { 'Easy - if gMSA migration isn''t viable, revert to the original account with a long/complex manually-set password; no data loss, though any ticket captured before the change remains crackable until the old password is retired.' } else { 'Easy - if gMSA migration isn''t viable for the application, revert to the original account with a manually-set long/complex password; no data loss, though any ticket captured before the change remains crackable until the old password is retired.' }
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
            
            # Computed regardless of whether the Protected Users group
            # lookup succeeded, since the new NOT_DELEGATED check below
            # doesn't depend on that group's existence.
            $isHighlyPrivileged = $Script:ProtectedGroups | Where-Object {
                $user.MemberOf -match "CN=$([regex]::Escape($_)),"
            } | Where-Object { $_ -in @('Domain Admins', 'Enterprise Admins', 'Schema Admins') }

            if ($protectedUsersGroup) {
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
                    $finding.EstimatedEffort = 'Medium - Protected Users enforces several non-configurable protections (no NTLM, no DES/RC4, no delegation, no long-lived TGT renewal) that can break dependent legitimate functionality, so Microsoft''s own guidance is to pilot it on a test group first.'
                    $finding.KnownRisks = 'Protected Users membership blocks NTLM authentication and Kerberos delegation for that account outright; any legitimate use of the account that relies on NTLM or delegation will break the moment it''s added.'
                    $finding.BackupRollback = 'Easy - remove the account from Protected Users; effective on next logon/ticket renewal, no data loss.'
                    $finding.Details = @{
                        DistinguishedName = $user.DistinguishedName
                        PrivilegedGroups = $isHighlyPrivileged -join '; '
                    }
                    $findings += $finding
                }
            }

            # 'Account is sensitive and cannot be delegated' (the
            # userAccountControl NOT_DELEGATED bit, 0x100000) - called out
            # explicitly in ASD/CISA/NSA/CCCS/NCSC-NZ/NCSC-UK's "Detecting
            # and mitigating Active Directory compromises" (Sept 2026) as
            # a top mitigation for BOTH unconstrained delegation AND the
            # built-in Administrator account specifically: a privileged
            # account with this flag set can never have its TGT cached on
            # a computer configured for unconstrained delegation, and
            # can't be used as a delegation target/source at all, closing
            # off that whole class of TGT-theft even if unconstrained
            # delegation exists elsewhere in the domain. userAccountControl
            # is already fetched above for the encryption-type checks, so
            # this is a bitmask check against data already in hand, not a
            # new query. Independent of - and in addition to - Protected
            # Users membership, which already implies this protection but
            # isn't the only way to get it.
            if ($isHighlyPrivileged) {
                $notDelegated = (($user.userAccountControl -band 0x100000) -ne 0)
                if (-not $notDelegated) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'User Account'
                    $finding.Issue = 'Privileged Account Not Configured as Sensitive and Cannot Be Delegated'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $user.SamAccountName
                    $finding.Description = "Highly privileged account '$($user.SamAccountName)' does not have the 'Account is sensitive and cannot be delegated' flag set."
                    $finding.Impact = "Without this flag, a copy of this account's TGT can be cached in memory on any computer configured for unconstrained delegation if the account authenticates to it - letting an attacker who compromises that computer extract and reuse the TGT to impersonate this privileged account."
                    $finding.Remediation = "Enable 'Account is sensitive and cannot be delegated' on the account: Set-ADAccountControl -Identity '$($user.SamAccountName)' -AccountNotDelegated `$true"
                    $finding.EstimatedEffort = 'Low - a single account flag; takes effect at next ticket request, no other configuration required.'
                    $finding.KnownRisks = 'If this account genuinely needs to be delegated for a legitimate, currently-working scenario, enabling this flag will break that delegation - confirm the account has no legitimate delegation dependency first.'
                    $finding.BackupRollback = 'Easy - clear the flag again if needed; effective at next ticket request, no data loss.'
                    $finding.Details = @{
                        DistinguishedName  = $user.DistinguishedName
                        PrivilegedGroups   = $isHighlyPrivileged -join '; '
                        UserAccountControl = $user.userAccountControl
                    }
                    $findings += $finding
                }
            }
        }
        
        # Built-in Administrator account (well-known RID 500) - called
        # out with its own dedicated section in ASD/CISA/NSA/CCCS/
        # NCSC-NZ/NCSC-UK's "Detecting and mitigating Active Directory
        # compromises" (Sept 2026): this account is EXEMPT from the
        # domain's account lockout policy (a failed-attempt lockout
        # doesn't apply to it, and even a reported "locked" state clears
        # on the next correct password), making it an especially
        # attractive password-spraying target precisely because none of
        # the lockout-threshold protection (see the new Account Lockout
        # checks in DomainSecurityAudits.ps1) applies to it. Identified
        # by SID (domain SID + "-500"), not by name, since renaming this
        # account is itself a common, legitimate hardening practice this
        # check must not penalize.
        try {
            $domainSidValue = (Get-ADDomain -Server $__adServer).DomainSID.Value
            $builtInAdminSid = "$domainSidValue-500"
            $builtInAdmin = if ($__adServer) {
                Get-ADUser -Identity $builtInAdminSid -Properties Enabled, PasswordLastSet, SamAccountName, DistinguishedName -Server $__adServer -ErrorAction Stop
            }
            else {
                Get-ADUser -Identity $builtInAdminSid -Properties Enabled, PasswordLastSet, SamAccountName, DistinguishedName -ErrorAction Stop
            }

            if ($builtInAdmin -and $builtInAdmin.Enabled) {
                $adminPasswordAge = if ($builtInAdmin.PasswordLastSet) { (Get-Date) - $builtInAdmin.PasswordLastSet } else { [TimeSpan]::MaxValue }

                if ($adminPasswordAge.Days -gt $PasswordAgeThreshold -or -not $builtInAdmin.PasswordLastSet) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'User Account'
                    $finding.Issue = 'Built-in Administrator Account Enabled and Not Recently Rotated'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $builtInAdmin.SamAccountName
                    $finding.Description = "The built-in Administrator account (RID 500, currently named '$($builtInAdmin.SamAccountName)') is enabled and its password " + $(if ($builtInAdmin.PasswordLastSet) { "was last set $($adminPasswordAge.Days) days ago, exceeding the $PasswordAgeThreshold-day threshold." } else { "has apparently never been changed since the account was created." })
                    $finding.Impact = "This account is exempt from the domain's account lockout policy, so a failed-attempt lockout never blocks password-guessing attempts against it - it can be sprayed indefinitely without the protection every other account in the domain has. Combined with an old or default-set password, this makes it an especially attractive target."
                    $finding.Remediation = "If this account is not required to be enabled, disable it and use a named, individually-attributable admin account instead: Disable-ADAccount -Identity '$($builtInAdmin.SamAccountName)'. If it must remain enabled as a break-glass account, set a long (30-character minimum), unique, unpredictable, managed password immediately and store it in a password vault, restricting its use to genuine emergencies only."
                    $finding.EstimatedEffort = 'Low - a password reset (and optionally disabling the account) on a single well-known object; confirm no automation or legacy process depends on this specific account first.'
                    $finding.KnownRisks = 'Disabling this account entirely is safe in virtually all modern environments, but confirm no legacy script or process authenticates as it directly before doing so, since it has no other owner to consult.'
                    $finding.BackupRollback = 'Easy - re-enable the account or reset the password again if needed; no data loss either way.'
                    $finding.Details = @{
                        DistinguishedName = $builtInAdmin.DistinguishedName
                        SID               = $builtInAdminSid
                        PasswordLastSet   = $builtInAdmin.PasswordLastSet
                        PasswordAgeDays   = if ($builtInAdmin.PasswordLastSet) { $adminPasswordAge.Days } else { 'Unknown' }
                    }
                    $findings += $finding
                }
            }
        }
        catch {
            Write-Verbose "Test-ADUserSecurity: failed to evaluate the built-in Administrator account (RID 500): $_"
        }

        # Built-in Guest account (well-known RID 501)
        # (files/18-account-computer-hygiene-gaps.md). Identified by SID
        # (domain SID + "-501"), same pattern as the Administrator (RID
        # 500) check above, since renaming this account is also a
        # legitimate, common hardening practice this check must not
        # penalize.
        try {
            $domainSidValueGuest = (Get-ADDomain -Server $__adServer).DomainSID.Value
            $builtInGuestSid = "$domainSidValueGuest-501"
            $builtInGuest = if ($__adServer) {
                Get-ADUser -Identity $builtInGuestSid -Properties Enabled, SamAccountName, DistinguishedName -Server $__adServer -ErrorAction Stop
            }
            else {
                Get-ADUser -Identity $builtInGuestSid -Properties Enabled, SamAccountName, DistinguishedName -ErrorAction Stop
            }

            if ($builtInGuest -and $builtInGuest.Enabled) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'User Account'
                $finding.Issue = 'Built-in Guest Account Enabled'
                $finding.Severity = 'Low'
                $finding.SeverityLevel = 1
                $finding.AffectedObject = $builtInGuest.SamAccountName
                $finding.Description = "The built-in Guest account (RID 501, currently named '$($builtInGuest.SamAccountName)') has ACCOUNTDISABLE unset in userAccountControl (i.e. it is enabled)."
                $finding.Impact = "The Guest account is intended to be disabled by default and typically has no legitimate business purpose enabled in a managed domain; an enabled Guest account is an easy, low-friction entry point (often with no password or a widely-known one) for unauthenticated or minimally-authenticated access."
                $finding.Remediation = "Disable the built-in Guest account unless there is a specific, documented business need for it: Disable-ADAccount -Identity '$($builtInGuest.SamAccountName)'."
                $finding.EstimatedEffort = 'Low - a single account disable; confirm no legacy application specifically authenticates as Guest first.'
                $finding.KnownRisks = 'Disabling Guest is safe in virtually all modern environments; confirm no legacy kiosk/anonymous-access workflow depends on it before disabling.'
                $finding.BackupRollback = 'Easy - re-enable the account if needed; no data loss either way.'
                $finding.Details = @{
                    DistinguishedName = $builtInGuest.DistinguishedName
                    SID               = $builtInGuestSid
                }
                $findings += $finding
            }
        }
        catch {
            Write-Verbose "Test-ADUserSecurity: failed to evaluate the built-in Guest account (RID 501): $_"
        }

        Write-Progress -Activity "Scanning User Accounts" -Completed
        Write-Verbose "User account audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during user account audit: $_"
        throw
    }
    finally {
        if ($Server -and -not $__adAuditServerAlreadyActive) {
            Clear-ADSecurityAuditTargetServer
        }
    }
}

function Test-PrivilegedUser {
    <#
    .SYNOPSIS
        Returns whether a user object belongs to one of the protected
        groups, based on its MemberOf list.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $User
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
