#region Domain Admin Equivalence Audit

function Test-ADDomainAdminEquivalence {
    <#
    .SYNOPSIS
        Correlates ACLs, group membership, delegation, and attribute-level
        signals to detect principals with effective Domain Admin-equivalent
        control, even without explicit group membership.
    #>
    [CmdletBinding()]
    param(
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

    $__adAuditServerAlreadyActive = [bool](Get-ADSecurityAuditActiveServerOverride)
    if ($Server -and -not $__adAuditServerAlreadyActive) {
        # Resolve-ADSecurityAuditTargetServer, not the raw -Server value:
        # resolves to the domain's PDC Emulator specifically, so this
        # standalone call targets the exact same single, deterministic DC
        # Start-ADSecurityAudit itself would use for this domain, not an
        # arbitrary DC-locator pick.
        Set-ADSecurityAuditTargetServer -Server (Resolve-ADSecurityAuditTargetServer -Server $Server)
    }

    # Resolved once, explicitly passed to every live AD call below - not
    # relying on the $PSDefaultParameterValues injection alone. $null when
    # no override is active, which Get-AD* cmdlets treat identically to
    # -Server being omitted entirely.
    $__adServer = Get-ADSecurityAuditActiveServerOverride

    try {
    Write-Verbose "Starting Admin Equivalence Audit"
    $findings = @()

    try {
        $domain = if ($__adServer) { Get-ADDomain -Server $__adServer } else { Get-ADDomain }
        $domainDN = $domain.DistinguishedName
        $domainSID = $domain.DomainSID.Value
        $netBIOSName = $domain.NetBIOSName
        $configContext = (Get-ADRootDSE -Server $__adServer).ConfigurationNamingContext
        
        # Explicitly trusted principals that normally require broad control
        $legitimatePrincipals = @(
            'NT AUTHORITY\SYSTEM',
            'BUILTIN\Administrators',
            "$netBIOSName\Administrators",
            "$netBIOSName\Domain Admins",
            "$netBIOSName\Enterprise Admins",
            "$netBIOSName\Schema Admins",
            "$netBIOSName\Domain Controllers",
            "$netBIOSName\Enterprise Domain Controllers",
            "$netBIOSName\Read-only Domain Controllers"
        )

        $broadPrincipals = @(
            'NT AUTHORITY\Authenticated Users',
            'NT AUTHORITY\INTERACTIVE',
            'NT AUTHORITY\NETWORK',
            'Everyone',
            "$netBIOSName\Domain Users"
        )

        $principalEvidence = @{}
        $computerExposure = @()

        $sensitiveGroupNames = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Backup Operators',
            'Account Operators',
            'DNSAdmins',
            'Print Operators',
            'Server Operators'
        )

        $domainControllersContainer = $domain.DomainControllersContainer
        $sensitivePrincipals = @{}

        # Property GUIDs (normalized to lowercase for consistent comparison)
        $keyCredLinkGuid = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
        # ESC14: altSecurityIdentities' own schemaIDGUID, plus the
        # "Public Information" property set that contains it - a
        # WriteProperty ACE can be scoped to either GUID and both grant
        # write access to the attribute (see the ESC14 check below for
        # why the property-set GUID matters in practice).
        $altSecurityIdentitiesGuid = '00fbf30c-91fe-11d1-aebc-0000f80367c1'
        $publicInformationPropertySetGuid = 'e48d0154-bcf8-11d1-8702-00c04fb96050'
        $spnGuid = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
        $rbcdGuid = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
        $memberAttributeGuid = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
        $passwordResetGuid = '00299570-246d-11d0-a768-00aa006e0529'
        $gpLinkGuid = 'f30e3bc2-9ff0-11d1-b603-0000f80367c1'
        $lapsGuid = 'ba19577d-37b2-4921-a637-429a1d99da82'
        $lapsPasswordGuid = '9a9a021e-4a5b-11d1-a9c3-0000f80367c1'
        $lapsPasswordExpGuid = 'e362ed86-b728-0842-b27d-2dea7a9df218'

        # Get DC computers EARLY - before any code that references it
        Write-Verbose "Enumerating Domain Controllers..."
        $dcComputers = $null
        try {
            $dcComputers = if ($__adServer) {
                Get-ADComputer -Filter "primaryGroupID -eq 516" -Server $__adServer -Properties nTSecurityDescriptor, OperatingSystem -ErrorAction Stop
            }
            else {
                Get-ADComputer -Filter "primaryGroupID -eq 516" -Properties nTSecurityDescriptor, OperatingSystem -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Failed to enumerate Domain Controllers: $_"
        }
        $dcNames = @()
        if ($dcComputers) {
            $dcNames = $dcComputers | ForEach-Object { $_.Name }
        }

        # Tier-0 lookup for the constrained-delegation-target check below:
        # generalizes "delegation to a Domain Controller" to "delegation to
        # ANY Tier-0 principal" (a Domain Admin's own workstation, a Tier-0
        # service account, or anything in a user-declared -AdditionalTier0DN
        # scope - see Get-ADTier0Principal in Common.ps1). Keyed on the
        # short hostname/SamAccountName (trailing '$' trimmed for computer
        # accounts) since msDS-AllowedToDelegateTo stores SPNs
        # (service/host), not DNs, and the delegation target is matched by
        # SPN host component, same as the existing $dcNames match just
        # below.
        $tier0SamAccountLookup = @{}
        try {
            foreach ($t0 in @(Get-ADTier0Principal)) {
                if (-not $t0.SamAccountName) { continue }
                $tier0SamAccountLookup[$t0.SamAccountName.ToLowerInvariant()] = $true
                $tier0SamAccountLookup[$t0.SamAccountName.TrimEnd('$').ToLowerInvariant()] = $true
            }
        }
        catch {
            Write-Verbose "Test-ADDomainAdminEquivalence: failed to resolve Tier-0 principal set for delegation-target check: $_"
        }

        function Add-Evidence {
            param(
                [string]$Principal,
                [string]$Reason,
                [hashtable]$Context
            )

            if (-not $principalEvidence.ContainsKey($Principal)) {
                $principalEvidence[$Principal] = [System.Collections.ArrayList]::new()
            }

            # A trustee can accumulate the exact same Reason more than once
            # (e.g. multiple ACEs on the same target matching the same
            # object-type GUID) - dedupe so the aggregated "Domain Admin
            # Equivalent Access Detected" finding lists each distinct piece
            # of evidence once, not once per contributing ACE.
            if ($principalEvidence[$Principal] | Where-Object { $_.Reason -eq $Reason }) { return }

            $entry = [PSCustomObject]@{
                Reason  = $Reason
                Context = $Context
            }

            [void]$principalEvidence[$Principal].Add($entry)
        }

        # Helper function for consistent GUID comparison
        function Test-GuidMatch {
            param(
                [string]$AceObjectType,
                [string]$TargetGuid
            )
            
            if ([string]::IsNullOrEmpty($AceObjectType)) { return $false }
            
            $aceGuid = $AceObjectType.ToString().ToLower()
            $targetLower = $TargetGuid.ToLower()
            
            # Check for empty GUID (all properties)
            if ($aceGuid -eq '00000000-0000-0000-0000-000000000000') { return $true }
            
            return $aceGuid -eq $targetLower
        }

        Write-Verbose "Collecting sensitive principals for equivalence correlation..."
        foreach ($groupName in $sensitiveGroupNames) {
            $group = $null
            try {
                $group = if ($__adServer) {
                    Get-ADGroup -Filter "Name -eq '$groupName'" -Server $__adServer -ErrorAction Stop
                }
                else {
                    Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
                }
            }
            catch {
                Write-Verbose "Failed to get group '$groupName': $_"
            }
            if (-not $group) { continue }

            $members = $null
            try {
                $members = if ($__adServer) {
                    Get-ADGroupMember -Identity $group -Recursive -Server $__adServer -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' }
                }
                else {
                    Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' }
                }
            }
            catch {
                Write-Verbose "Failed to get members of group '$groupName': $_"
            }

            foreach ($member in $members) {
                if (-not $sensitivePrincipals.ContainsKey($member.SamAccountName)) {
                    $sensitivePrincipals[$member.SamAccountName] = $member.DistinguishedName
                }
            }
        }

        Write-Verbose "Analyzing AdminSDHolder 'Ghost' accounts..."
        
        # Get all protected members recursively
        $protectedMembers = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($groupName in $sensitiveGroupNames) {
            $group = $null
            try {
                $group = if ($__adServer) {
                    Get-ADGroup -Filter "Name -eq '$groupName'" -Server $__adServer -ErrorAction Stop
                }
                else {
                    Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
                }
            }
            catch {
                Write-Verbose "Failed to get protected group '$groupName': $_"
            }
            if ($group) {
                $members = $null
                try {
                    $members = if ($__adServer) {
                        Get-ADGroupMember -Identity $group -Recursive -Server $__adServer -ErrorAction Stop
                    }
                    else {
                        Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop
                    }
                }
                catch {
                    Write-Verbose "Failed to get protected group members for '$groupName': $_"
                }
                if ($members) {
                    foreach ($m in $members) { [void]$protectedMembers.Add($m.DistinguishedName) }
                }
            }
        }

        # Find users with adminCount=1
        $adminCountUsers = $null
        try {
            $adminCountUsers = if ($__adServer) {
                Get-ADUser -LDAPFilter "(adminCount=1)" -Server $__adServer -Properties adminCount, nTSecurityDescriptor -ErrorAction Stop
            }
            else {
                Get-ADUser -LDAPFilter "(adminCount=1)" -Properties adminCount, nTSecurityDescriptor -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Failed to enumerate adminCount users: $_"
        }

        foreach ($user in $adminCountUsers) {
            if (-not $protectedMembers.Contains($user.DistinguishedName) -and $user.SamAccountName -ne "krbtgt") {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Admin Equivalence'
                $finding.Issue = 'AdminSDHolder Ghost Account'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User has 'adminCount=1' but is not a member of any protected group. This may indicate a leftover administrative account or a persistence backdoor where ACLs are frozen by SDProp."
                $finding.Impact = "The account's ACL inheritance remains disabled and its permissions frozen even though it's no longer in a protected group, which can mask a persistence mechanism or leave stale, overly-permissive rights in place unnoticed."
                $finding.Remediation = "Clear the 'adminCount' attribute (set to 0) and enable permission inheritance on the object. Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/adminsdholder-protected-accounts-and-groups"
                $finding.EstimatedEffort = 'Low - a single adminCount reset plus re-enabling inheritance on one object.'
                $finding.KnownRisks = 'Low technical risk; confirm the account isn''t intentionally protected for an undocumented but legitimate reason (e.g. a break-glass account) before clearing adminCount.'
                $finding.BackupRollback = 'Easy - reset adminCount to 1 and disable inheritance again if needed; effective immediately, no data loss.'
                $finding.Details = @{
                    UserDN = $user.DistinguishedName
                    Domain = $domain.DNSRoot
                }
                $findings += $finding
            }
        }

        Write-Verbose "Scanning for Shadow Credentials (msDS-KeyCredentialLink)..."

        $shadowCreds = $null
        try {
            $shadowCreds = if ($__adServer) {
                Get-ADObject -LDAPFilter "(msDS-KeyCredentialLink=*)" -Server $__adServer -Properties msDS-KeyCredentialLink, samAccountName, objectClass -ErrorAction Stop
            }
            else {
                Get-ADObject -LDAPFilter "(msDS-KeyCredentialLink=*)" -Properties msDS-KeyCredentialLink, samAccountName, objectClass -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Failed to scan for Shadow Credentials: $_"
        }

        foreach ($obj in $shadowCreds) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Admin Equivalence'
            $finding.Issue = 'Shadow Credentials Detected'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = $obj.Name
            $finding.Description = "Object has 'msDS-KeyCredentialLink' populated. Unless Windows Hello for Business is deployed, this indicates a potential 'Shadow Credentials' attack (Whisker/Certipy) allowing account takeover."
            $finding.Impact = "An attacker with this key credential can authenticate as the object via PKINIT without knowing (or changing) its password, giving silent, persistent account takeover that survives a password reset."
            $finding.Remediation = "Investigate the 'msDS-KeyCredentialLink' attribute. If not legitimate WHfB, clear the attribute immediately. Reference: https://posts.specterops.io/shadow-credentials-abusing-key-credential-link-translation-to-en-9d8f9fb12be8"
            $finding.EstimatedEffort = 'Low - clearing the msDS-KeyCredentialLink attribute is a single-attribute change on one object.'
            $finding.KnownRisks = 'Removing an unauthorized key credential has no legitimate compatibility impact unless it is actually a currently-enrolled Windows Hello for Business or passwordless-auth key, so confirm the key isn''t legitimate before clearing.'
            $finding.BackupRollback = 'Moderate - export the current msDS-KeyCredentialLink value before clearing so a legitimate key can be restored if the removal turns out to affect a real passwordless sign-in.'
            $finding.Details = @{
                ObjectDN    = $obj.DistinguishedName
                ObjectClass = $obj.objectClass -join ', '
                Domain      = $domain.DNSRoot
            }
            $findings += $finding
        }

        Write-Verbose "Detecting Shadow Credentials attack surface (msDS-KeyCredentialLink write access)..."

        $criticalComputers = $null
        try {
            $criticalComputers = if ($__adServer) {
                Get-ADComputer -Filter * -Server $__adServer -Properties nTSecurityDescriptor, OperatingSystem -ResultPageSize 500 -ErrorAction Stop
            }
            else {
                Get-ADComputer -Filter * -Properties nTSecurityDescriptor, OperatingSystem -ResultPageSize 500 -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Failed to enumerate computers for Shadow Credentials check: $_"
        }

        foreach ($computer in $criticalComputers) {
            if (-not $computer.nTSecurityDescriptor) { continue }
            
            foreach ($ace in $computer.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                    if (Test-GuidMatch -AceObjectType $ace.ObjectType -TargetGuid $keyCredLinkGuid) {
                        Add-Evidence -Principal $principal -Reason "Shadow Credentials write access on computer '$($computer.Name)' - allows authentication as the computer account" -Context @{
                            Target            = 'Shadow Credentials'
                            ComputerName      = $computer.Name
                            DistinguishedName = $computer.DistinguishedName
                            OperatingSystem   = $computer.OperatingSystem
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AttackPath        = 'Write msDS-KeyCredentialLink -> Request TGT as computer -> Compromise system'
                        }
                    }
                }
            }
        }

        foreach ($kvp in $sensitivePrincipals.GetEnumerator()) {
            $sam = $kvp.Key
            $dn = $kvp.Value

            $user = $null
            try {
                $user = if ($__adServer) {
                    Get-ADUser -Identity $dn -Server $__adServer -Properties nTSecurityDescriptor, altSecurityIdentities -ErrorAction Stop
                }
                else {
                    Get-ADUser -Identity $dn -Properties nTSecurityDescriptor, altSecurityIdentities -ErrorAction Stop
                }
            }
            catch {
                Write-Verbose "Failed to get user '$sam' for Shadow Credentials check: $_"
            }
            if (-not $user -or -not $user.nTSecurityDescriptor) { continue }

            foreach ($ace in $user.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                    if (Test-GuidMatch -AceObjectType $ace.ObjectType -TargetGuid $keyCredLinkGuid) {
                        Add-Evidence -Principal $principal -Reason "Shadow Credentials write access on privileged user '$sam' - direct account takeover" -Context @{
                            Target            = 'Shadow Credentials (Privileged User)'
                            Account           = $sam
                            DistinguishedName = $dn
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AttackPath        = 'Write msDS-KeyCredentialLink -> Authenticate as user -> Full compromise'
                        }
                    }
                    # ESC14: writable altSecurityIdentities on a privileged
                    # account. A WriteProperty ACE can be scoped either to
                    # this specific attribute (schemaIDGUID
                    # 00fbf30c-91fe-11d1-aebc-0000f80367c1) or to the
                    # broader "Public Information" property set that
                    # contains it (attributeSecurityGUID
                    # e48d0154-bcf8-11d1-8702-00c04fb96050) - the latter is
                    # the more common real-world exposure, per documented
                    # research on over-broad Exchange-granted rights to
                    # that property set, so both GUIDs are checked.
                    if ((Test-GuidMatch -AceObjectType $ace.ObjectType -TargetGuid $altSecurityIdentitiesGuid) -or (Test-GuidMatch -AceObjectType $ace.ObjectType -TargetGuid $publicInformationPropertySetGuid)) {
                        Add-Evidence -Principal $principal -Reason "Write access to altSecurityIdentities on privileged user '$sam' (ESC14) - allows adding an attacker-controlled certificate or Kerberos mapping" -Context @{
                            Target            = 'Weak Explicit Certificate Mapping (ESC14)'
                            Account           = $sam
                            DistinguishedName = $dn
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AttackPath        = 'Write altSecurityIdentities -> Add attacker-controlled X.509/Kerberos mapping -> Authenticate as privileged user'
                        }
                    }
                }
            }

            # Existing weak explicit mappings (ESC14), independent of
            # whether the attribute is currently writable: an
            # IssuerSubject-style mapping ("X509:<I>...<S>...", string-
            # based) is materially weaker than a key-bound mapping
            # ("X509:<SKI>..." or "X509:<SHA1-PUKEY>...", tied to a
            # specific certificate/key) - if an attacker can obtain ANY
            # certificate whose issuer and subject text happen to match,
            # they authenticate as this account, no write access to the
            # attribute required at all.
            if ($user.altSecurityIdentities) {
                $weakMappings = @($user.altSecurityIdentities | Where-Object { $_ -match '<I>' -and $_ -match '<S>' -and $_ -notmatch '<SKI>' -and $_ -notmatch '<SHA1-PUKEY>' })
                if ($weakMappings.Count -gt 0) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Certificate Services'
                    $finding.Issue = 'Weak Explicit Certificate Mapping on Privileged Account (ESC14)'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $sam
                    $finding.Description = "Privileged account '$sam' has an Issuer+Subject-style (string-based) explicit certificate mapping in altSecurityIdentities, rather than a key-bound mapping: $($weakMappings -join '; ')"
                    $finding.Impact = "An Issuer+Subject mapping authenticates based on matching text in a certificate's issuer and subject fields, not a specific key or certificate. Anyone able to obtain any certificate from a trusted CA with matching issuer/subject text - including via an unrelated AD CS misconfiguration elsewhere - can authenticate as this privileged account."
                    $finding.Remediation = "Replace the Issuer+Subject mapping with a key-bound mapping (X509:<SKI> or X509:<SHA1-PUKEY>) tied to the specific certificate this account should authenticate with."
                    $finding.EstimatedEffort = 'Medium - requires identifying the specific certificate this mapping should be bound to and updating altSecurityIdentities accordingly, coordinated with whoever manages the account''s smart card/certificate.'
                    $finding.KnownRisks = 'Replacing the mapping incorrectly (wrong SKI/key hash) will break this account''s certificate-based authentication until corrected - verify the target certificate before changing.'
                    $finding.BackupRollback = 'Easy - restore the prior altSecurityIdentities value if needed; effective immediately, no data loss.'
                    $finding.Details = @{
                        DistinguishedName = $dn
                        WeakMappings      = $weakMappings -join '; '
                        ESCType           = 'ESC14'
                    }
                    $findings += $finding
                }
            }
        }

        Write-Verbose "Checking for WriteSPN permissions (targeted Kerberoasting attack)..."

        foreach ($kvp in $sensitivePrincipals.GetEnumerator()) {
            $sam = $kvp.Key
            $dn = $kvp.Value

            $user = $null
            try {
                $user = if ($__adServer) {
                    Get-ADUser -Identity $dn -Server $__adServer -Properties nTSecurityDescriptor -ErrorAction Stop
                }
                else {
                    Get-ADUser -Identity $dn -Properties nTSecurityDescriptor -ErrorAction Stop
                }
            }
            catch {
                Write-Verbose "Failed to get user '$sam' for WriteSPN check: $_"
            }
            if (-not $user -or -not $user.nTSecurityDescriptor) { continue }

            foreach ($ace in $user.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                    if (Test-GuidMatch -AceObjectType $ace.ObjectType -TargetGuid $spnGuid) {
                        Add-Evidence -Principal $principal -Reason "WriteSPN on privileged account '$sam' - enables targeted Kerberoasting" -Context @{
                            Target            = 'WriteSPN'
                            Account           = $sam
                            DistinguishedName = $dn
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AttackPath        = 'Add fake SPN -> Request service ticket -> Offline password cracking'
                        }
                    }
                }
            }
        }

        Write-Verbose "Scanning for SID History Injection..."

        $sidHistoryUsers = $null
        try {
            $sidHistoryUsers = if ($__adServer) {
                Get-ADUser -LDAPFilter "(sIDHistory=*)" -Server $__adServer -Properties sIDHistory -ErrorAction Stop
            }
            else {
                Get-ADUser -LDAPFilter "(sIDHistory=*)" -Properties sIDHistory -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Failed to scan for SID History Injection: $_"
        }

        foreach ($user in $sidHistoryUsers) {
            foreach ($sid in $user.sIDHistory) {
                $sidStr = $sid.ToString()
                $isSameDomainSid = [bool]($sidStr -like "$domainSID*")
                $isPrivilegedRidSid = [bool]($sidStr -match '-(500|512|519)$')

                if ($isSameDomainSid) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Admin Equivalence'
                    $finding.Issue = 'SID History Injection (Same Domain)'
                    $finding.Severity = 'Critical'
                    $finding.SeverityLevel = 4
                    $finding.AffectedObject = $user.SamAccountName
                    $finding.Description = "User contains a SID from the CURRENT domain in its SID History ($sidStr). This is a definitive sign of a Golden Ticket or SID History injection attack."
                    $finding.Impact = "The account carries privileges from the injected SID in addition to its normal group memberships, effectively granting hidden, unauthorized access that standard group-membership reviews will not reveal."
                    $finding.Remediation = "Immediate Incident Response required. Reset the account and investigate origin. Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-sidhistory"
                    $finding.EstimatedEffort = 'High - this is an active-compromise indicator, not a configuration fix; it requires incident-response engagement, forensic investigation, and likely a KRBTGT password reset (twice) if a Golden Ticket is suspected, not a single change.'
                    $finding.KnownRisks = 'Resetting the account or clearing sIDHistory while an attacker may still have persistence elsewhere (forged tickets, other backdoors) can tip them off without fully evicting them, so this needs IR judgment, not just a config change.'
                    $finding.BackupRollback = 'Hard/Limited - this isn''t a reversible setting; it''s an incident-response action (reset/disable the account and investigate origin) with no rollback concept.'
                    $finding.OperationalNotes = 'Engage incident response before making changes if compromise is suspected, since a same-domain sIDHistory entry is a well-documented Golden Ticket/injection indicator rather than a misconfiguration.'
                    $finding.Details = @{
                        UserDN       = $user.DistinguishedName
                        InjectedSID  = $sidStr
                        Domain       = $domain.DNSRoot
                    }
                    $findings += $finding
                }
                
                if ($isPrivilegedRidSid) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Admin Equivalence'
                    $finding.Issue = 'Privileged SID in History'
                    $finding.Severity = 'Critical'
                    $finding.SeverityLevel = 4
                    $finding.AffectedObject = $user.SamAccountName
                    $finding.Description = "User has a highly privileged SID ($sidStr) in their SID History. They possess Domain Admin rights regardless of group membership."
                    $finding.Impact = "The account has effective Domain Admin (or equivalent) rights that won't show up in any group-membership audit, since the privilege comes from SID History rather than an actual group the account belongs to."
                    $finding.Remediation = "Clear the sIDHistory attribute immediately unless this is a verified migration account. Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-sidhistory"
                    $finding.EstimatedEffort = 'Medium - clearing sIDHistory is simple technically, but confirming the account isn''t an active cross-domain migration in progress requires checking with whoever ran the migration.'
                    $finding.KnownRisks = 'If a domain migration is still underway, clearing sIDHistory before every migrated resource''s ACL has been updated to the new SID can break the migrated user''s access to resources that still only trust the old SID.'
                    $finding.BackupRollback = 'Hard/Limited - sIDHistory can''t be restored to its prior value without re-injecting it via the same migration tooling (e.g. ADMT) that originally populated it; treat clearing it as a one-way cleanup once confirmed unauthorized.'
                    $finding.Details = @{
                        UserDN       = $user.DistinguishedName
                        PrivilegedSID = $sidStr
                        Domain       = $domain.DNSRoot
                    }
                    $findings += $finding
                }

                # Catch-all hygiene finding for any populated sIDHistory
                # entry that ISN'T already caught by the two more specific
                # checks above (same-domain injection, or a privileged
                # well-known RID). Per ASD/CISA/NSA/CCCS/NCSC-NZ/NCSC-UK's
                # "Detecting and mitigating Active Directory compromises"
                # (Sept 2026): sIDHistory "should be checked weekly" and
                # "should not be used" outside active migration, and the
                # guidance separately describes "domain hopping with
                # Golden Ticket + SID History" - injecting a FOREIGN
                # domain's security-group SID (not necessarily one of the
                # three well-known RIDs above) to move laterally across a
                # forest trust. Without this, a cross-domain sIDHistory
                # entry for a custom (non-500/512/519) group produced NO
                # finding at all, regardless of whether it was a genuine
                # leftover migration artifact or an injected foreign SID.
                # Lower severity than the two checks above since a
                # legitimate, still-in-progress domain migration is a
                # much more likely explanation here than for either of
                # those two more specific, higher-confidence indicators.
                if (-not $isSameDomainSid -and -not $isPrivilegedRidSid) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Admin Equivalence'
                    $finding.Issue = 'SID History Attribute Populated'
                    $finding.Severity = 'Low'
                    $finding.SeverityLevel = 1
                    $finding.AffectedObject = $user.SamAccountName
                    $finding.Description = "User has a SID from a different domain ($sidStr) in its SID History."
                    $finding.Impact = "sIDHistory is legitimate only during an active, in-progress domain migration. If this entry is a leftover from a completed migration, it grants the account whatever access the source-domain SID had - access that won't appear in any group-membership review of this domain. It is also the mechanism used in a 'domain hopping' attack that combines a Golden Ticket with an injected foreign-domain SID to move laterally across a forest trust."
                    $finding.Remediation = "Confirm whether this is an active, still-in-progress domain migration. If the migration is complete (all resource ACLs updated to the new SID), clear the sIDHistory attribute: Set-ADUser -Identity '$($user.SamAccountName)' -Remove @{sIDHistory=`"$sidStr`"}. If migration is still underway, leave it in place until complete."
                    $finding.EstimatedEffort = 'Low - clearing sIDHistory is a single-attribute change once a completed migration is confirmed.'
                    $finding.KnownRisks = 'Clearing sIDHistory before every migrated resource''s ACL has been updated to the new SID breaks the account''s access to resources that still only trust the old SID - confirm migration completion first.'
                    $finding.BackupRollback = 'Hard/Limited - sIDHistory can''t be restored without re-injecting it via the same migration tooling (e.g. ADMT) that originally populated it.'
                    $finding.Details = @{
                        UserDN      = $user.DistinguishedName
                        ForeignSID  = $sidStr
                        Domain      = $domain.DNSRoot
                    }
                    $findings += $finding
                }
            }
        }

        Write-Verbose "Scanning for legacy Logon Script abuse..."

        $scriptUsers = $null
        try {
            $scriptUsers = if ($__adServer) {
                Get-ADUser -LDAPFilter "(scriptPath=*)" -Server $__adServer -Properties scriptPath -ErrorAction Stop
            }
            else {
                Get-ADUser -LDAPFilter "(scriptPath=*)" -Properties scriptPath -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Failed to scan for legacy Logon Scripts: $_"
        }
        foreach ($user in $scriptUsers) {
            $path = $user.scriptPath
            
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Legacy Attack Vector'
            $finding.Issue = 'Legacy Logon Script Defined'
            $finding.Severity = 'Low'
            $finding.SeverityLevel = 1
            $finding.AffectedObject = $user.SamAccountName
            $finding.Description = "User has a legacy logon script defined: '$path'. Attackers can modify this file to achieve code execution upon user logon."
            $finding.Impact = "Anyone able to write to the referenced script file gains code execution as every user the script runs for at their next logon, a low-effort persistence and lateral-movement foothold."
            $finding.Remediation = "Migrate to Group Policy Preferences and clear the 'scriptPath' attribute. Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/logon-script-issues"
            $finding.EstimatedEffort = 'Low - a single scriptPath/userWorkstations-style attribute per account.'
            $finding.KnownRisks = 'Removing or migrating a working legacy logon script could break whatever the script does for affected users until an equivalent modern (GPO-based) replacement is validated.'
            $finding.BackupRollback = 'Easy - restore the scriptPath attribute to its prior value; effective at next logon, no data loss.'
            $finding.Details = @{
                UserDN     = $user.DistinguishedName
                ScriptPath = $path
                Domain     = $domain.DNSRoot
            }
            $findings += $finding
        }

        # Check direct control over the domain naming context and AdminSDHolder
        $controlTargets = @(
            @{ Name = 'Domain Root'; DistinguishedName = $domainDN; RiskType = 'DomainRootControl' },
            @{ Name = 'AdminSDHolder'; DistinguishedName = "CN=AdminSDHolder,CN=System,$domainDN"; RiskType = 'AdminSDHolderControl' }
        )

        if ($domainControllersContainer) {
            $controlTargets += @{ Name = 'Domain Controllers OU'; DistinguishedName = $domainControllersContainer; RiskType = 'DomainControllersContainerControl' }
        }

        foreach ($target in $controlTargets) {
            $object = $null
            try {
                $object = if ($__adServer) {
                    Get-ADObject -Identity $target.DistinguishedName -Server $__adServer -Properties nTSecurityDescriptor -ErrorAction Stop
                }
                else {
                    Get-ADObject -Identity $target.DistinguishedName -Properties nTSecurityDescriptor -ErrorAction Stop
                }
            }
            catch {
                Write-Verbose "Failed to get control target '$($target.Name)': $_"
            }
            if (-not $object -or -not $object.nTSecurityDescriptor) { continue }

            foreach ($ace in $object.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|AllExtendedRights') {
                    Add-Evidence -Principal $principal -Reason "$($target.Name) control via $($ace.ActiveDirectoryRights)" -Context @{
                        Target             = $target.Name
                        DistinguishedName  = $target.DistinguishedName
                        Rights             = $ace.ActiveDirectoryRights.ToString()
                        AccessControlType  = $ace.AccessControlType.ToString()
                        Inheritance        = if ($ace.IsInherited) { 'Inherited' } else { 'Explicit' }
                    }
                }
            }
        }

        Write-Verbose "Performing AdminSDHolder ACL Analysis..."
        $adminSdHolder = $null
        try {
            $adminSdHolder = if ($__adServer) {
                Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$domainDN" -Server $__adServer -Properties nTSecurityDescriptor -ErrorAction Stop
            }
            else {
                Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$domainDN" -Properties nTSecurityDescriptor -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Failed to get AdminSDHolder: $_"
        }
        if ($adminSdHolder -and $adminSdHolder.nTSecurityDescriptor) {
            # A trustee can hold multiple ACEs on AdminSDHolder (one per
            # property set/object type) even when ActiveDirectoryRights is
            # identical - dedupe on (principal, rights) so each is reported
            # once rather than once per ACE.
            $__seenAdminSdCompromise = @{}
            foreach ($ace in $adminSdHolder.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }
                
                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite') {
                    $__compromiseKey = "$principal|$($ace.ActiveDirectoryRights)"
                    if ($__seenAdminSdCompromise.ContainsKey($__compromiseKey)) { continue }
                    $__seenAdminSdCompromise[$__compromiseKey] = $true

                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Admin Equivalence'
                    $finding.Issue = 'AdminSDHolder ACL Compromise'
                    $finding.Severity = 'Critical'
                    $finding.SeverityLevel = 4
                    $finding.AffectedObject = 'AdminSDHolder'
                    $finding.Description = "Principal '$principal' has dangerous rights ($($ace.ActiveDirectoryRights)) on AdminSDHolder. This grants persistent Domain Admin rights via SDProp."
                    $finding.Impact = "Because SDProp periodically re-applies AdminSDHolder's ACL to every protected (Tier-0) account and group, this principal effectively controls the DACL of every Domain Admin, Enterprise Admin, and other protected object in the domain - a single ACE here compromises the entire tier."
                    $finding.Remediation = "Remove the ACE immediately and check all protected groups for 'adminCount=1' users. Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/adminsdholder-protected-accounts-and-groups"
                    $finding.EstimatedEffort = 'Low - removing a single unauthorized ACE from one object (AdminSDHolder); SDProp then reapplies the corrected ACL to every protected object automatically.'
                    $finding.KnownRisks = 'Low technical risk; an unauthorized ACE here grants no legitimate capability, so removing it has no realistic compatibility impact beyond confirming it isn''t a very recent, still-being-configured delegation.'
                    $finding.BackupRollback = 'Moderate - export the current AdminSDHolder ACL (dsacls or Get-Acl) before removing the ACE so it can be restored if needed; the correction only reaches every protected Tier-0 object once SDProp''s next propagation cycle runs, not instantly.'
                    $finding.OperationalNotes = 'SDProp runs on a periodic interval (roughly hourly by default), so previously-protected objects keep the old, compromised ACL until the next cycle completes.'
                    $finding.Details = @{
                        Principal = $principal
                        Rights    = $ace.ActiveDirectoryRights.ToString()
                        Domain    = $domain.DNSRoot
                    }
                    $findings += $finding
                }
            }
        }

        Write-Verbose "Checking Constrained Delegation to Domain Controllers..."

        $delegationRisk = $null
        try {
            $delegationRisk = if ($__adServer) {
                Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Server $__adServer -Properties msDS-AllowedToDelegateTo, samAccountName -ErrorAction Stop
            }
            else {
                Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Properties msDS-AllowedToDelegateTo, samAccountName -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Failed to check Constrained Delegation: $_"
        }

        foreach ($obj in $delegationRisk) {
            foreach ($targetSPN in $obj.'msDS-AllowedToDelegateTo') {
                $targetHost = ($targetSPN -split '/')[1]
                if ($targetHost -match ':') { $targetHost = ($targetHost -split ':')[0] }
                $targetHostShort = ($targetHost -split '\.')[0]

                if ($targetHostShort -in $dcNames) {
                    Add-Evidence -Principal $obj.Name -Reason "Admin Equivalence Edge: AllowedToDelegate (Constrained Delegation) to Domain Controller $targetHostShort" -Context @{
                        Target = $targetHostShort
                        SPN = $targetSPN
                        Attack = "Impersonate users to DC via S4U2Proxy"
                    }
                }

                # Beyond DCs specifically: constrained delegation to ANY
                # Tier-0 principal (a Domain Admin's own workstation
                # account, a Tier-0 service account, etc. - not just a DC
                # computer object) is the same S4U2Proxy impersonation
                # risk, just against a different privileged target. Uses
                # the same Tier-0 lookup ControlPaths.ps1 builds from
                # Get-ADTier0Principal (which also folds in any
                # user-declared -AdditionalTier0DN scope), matched against
                # the delegation target's short hostname/SamAccountName -
                # msDS-AllowedToDelegateTo stores SPNs (service/host), not
                # DNs, so the match has to go through the SPN's host
                # component rather than a direct DN/SID lookup.
                if ($targetHostShort -notin $dcNames -and $tier0SamAccountLookup -and $tier0SamAccountLookup.ContainsKey($targetHostShort.ToLowerInvariant())) {
                    Add-Evidence -Principal $obj.Name -Reason "Admin Equivalence Edge: AllowedToDelegate to Tier-0 Principal $targetHostShort" -Context @{
                        Target = $targetHostShort
                        SPN    = $targetSPN
                        Attack = "Impersonate users to a Tier-0 principal via S4U2Proxy"
                    }
                }
            }
        }

        Write-Verbose "Checking constrained delegation with protocol transition (S4U2Self abuse)..."
        $constrainedDelegation = $null
        try {
            $constrainedDelegation = if ($__adServer) {
                Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} -Server $__adServer -Properties msDS-AllowedToDelegateTo, servicePrincipalName, samAccountName, objectClass -ErrorAction Stop
            }
            else {
                Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo, servicePrincipalName, samAccountName, objectClass -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Failed to check constrained delegation with protocol transition: $_"
        }

        foreach ($delegator in $constrainedDelegation) {
            $allowedServices = $delegator.'msDS-AllowedToDelegateTo'
            $delegatorDetails = $null
            try {
                $delegatorDetails = if ($__adServer) {
                    Get-ADObject -Identity $delegator.DistinguishedName -Server $__adServer -Properties TrustedToAuthForDelegation -ErrorAction Stop
                }
                else {
                    Get-ADObject -Identity $delegator.DistinguishedName -Properties TrustedToAuthForDelegation -ErrorAction Stop
                }
            }
            catch {
                Write-Verbose "Failed to get delegator details for '$($delegator.samAccountName)': $_"
            }
            $hasProtocolTransition = $delegatorDetails.TrustedToAuthForDelegation

            if ($hasProtocolTransition) {
                $targets = $allowedServices | ForEach-Object {
                    $parts = $_ -split '/'
                    if ($parts.Count -ge 2) { $parts[1] } else { $_ }
                }

                Add-Evidence -Principal $delegator.samAccountName -Reason "Constrained delegation WITH protocol transition on '$($delegator.samAccountName)' - allows impersonation to sensitive services" -Context @{
                    Target               = 'Constrained Delegation + Protocol Transition'
                    Account              = $delegator.samAccountName
                    DistinguishedName    = $delegator.DistinguishedName
                    ObjectClass          = $delegator.objectClass -join ', '
                    AllowedToDelegate    = $allowedServices -join '; '
                    TargetHosts          = $targets -join '; '
                    AttackPath           = 'S4U2Self allows impersonation of ANY user to delegated services without authentication'
                }
            }
        }

        # -------------------------------------------------------------------
        # Constrained Delegation Configured to Decommissioned SPN
        # (files/18-account-computer-hygiene-gaps.md). Extends the
        # constrained-delegation enumeration already fetched above
        # ($constrainedDelegation, via msDS-AllowedToDelegateTo) with a
        # ghost-SPN cross-reference: for each listed SPN, extract the host
        # component and check it against the full computer-object list
        # already enumerated above for the Shadow Credentials check
        # ($criticalComputers) - no new msDS-AllowedToDelegateTo query.
        # -------------------------------------------------------------------
        if ($criticalComputers) {
            $knownComputerShortNames = @($criticalComputers | ForEach-Object { ($_.Name).ToLowerInvariant() })

            foreach ($delegator in $constrainedDelegation) {
                $ghostTargets = @()
                foreach ($targetSPN in @($delegator.'msDS-AllowedToDelegateTo')) {
                    $targetHostGhost = ($targetSPN -split '/')[1]
                    if (-not $targetHostGhost) { continue }
                    if ($targetHostGhost -match ':') { $targetHostGhost = ($targetHostGhost -split ':')[0] }
                    $targetHostShortGhost = (($targetHostGhost -split '\.')[0]).ToLowerInvariant()

                    if ($targetHostShortGhost -notin $knownComputerShortNames) {
                        $ghostTargets += $targetSPN
                    }
                }
                $ghostTargets = @($ghostTargets | Select-Object -Unique)

                if ($ghostTargets.Count -gt 0) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Admin Equivalence'
                    $finding.Issue = 'Constrained Delegation Configured to Decommissioned SPN'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $delegator.samAccountName
                    $finding.Description = "Account '$($delegator.samAccountName)' has msDS-AllowedToDelegateTo listing SPN(s) whose host component does not resolve to any current computer object in the domain: $($ghostTargets -join '; ')."
                    $finding.Impact = "A delegation target whose host no longer exists as a real computer object is a decommissioned target whose delegation configuration was never cleaned up. If an attacker can re-register a computer object with that same hostname (e.g. via a default, non-hardened Machine Account Quota), they could potentially receive delegated authentication traffic intended for the original, decommissioned host."
                    $finding.Remediation = "Remove the stale SPN(s) listed above from '$($delegator.samAccountName)''s msDS-AllowedToDelegateTo attribute, since the delegation target no longer exists: Set-ADObject -Identity '$($delegator.DistinguishedName)' -Remove @{'msDS-AllowedToDelegateTo'='<stale SPN>'}"
                    $finding.EstimatedEffort = 'Low - removing one or more stale SPN entries from a single account''s delegation configuration.'
                    $finding.KnownRisks = 'Low - the target host doesn''t currently exist, so removing the stale delegation entry has no legitimate functional impact today; confirm the host is genuinely decommissioned (not simply temporarily offline) before removing.'
                    $finding.BackupRollback = 'Easy - re-add the SPN to msDS-AllowedToDelegateTo if the host turns out to still be in use under a different naming scenario; no data loss either way.'
                    $finding.Details = @{
                        DistinguishedName  = $delegator.DistinguishedName
                        GhostSPNs          = ($ghostTargets -join '; ')
                        AllowedToDelegateTo = (@($delegator.'msDS-AllowedToDelegateTo') -join '; ')
                    }
                    $findings += $finding
                }
            }
        }

        Write-Verbose "Checking RBCD (AllowedToActOnBehalfOfOtherIdentity) on Domain Controllers..."
        foreach ($dc in $dcComputers) {
            $dcObj = $null
            try {
                $dcObj = if ($__adServer) {
                    Get-ADComputer -Identity $dc.DistinguishedName -Server $__adServer -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity' -ErrorAction Stop
                }
                else {
                    Get-ADComputer -Identity $dc.DistinguishedName -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity' -ErrorAction Stop
                }
            }
            catch {
                Write-Verbose "Failed to get RBCD info for DC '$($dc.Name)': $_"
            }

            if ($dcObj -and $dcObj.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
                try {
                    $sdBytes = $dcObj.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                    if ($sdBytes) {
                        $rawSD = [System.Security.AccessControl.RawSecurityDescriptor]::new($sdBytes, 0)
                        foreach ($ace in $rawSD.DiscretionaryAcl) {
                            $sid = $ace.SecurityIdentifier.Value
                            try { $principal = $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } catch { $principal = $sid }
                            
                            if ($principal -notin $legitimatePrincipals) {
                                Add-Evidence -Principal $principal -Reason "Admin Equivalence Edge: AllowedToAct (RBCD) on Domain Controller $($dc.Name)" -Context @{
                                    Target = $dc.Name
                                    Attack = "Compromise DC via RBCD impersonation"
                                }
                            }
                        }
                    }
                } catch {
                    Write-Verbose "Failed to parse RBCD SD for $($dc.Name): $_"
                }
            }
        }

        Write-Verbose "Checking for auditing high-privilege built-in groups..."
        foreach ($groupName in @('Print Operators', 'Server Operators', 'Backup Operators', 'Account Operators', 'DnsAdmins')) {
            $group = $null
            try {
                $group = if ($__adServer) {
                    Get-ADGroup -Filter "Name -eq '$groupName'" -Server $__adServer -ErrorAction Stop
                }
                else {
                    Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
                }
            }
            catch {
                Write-Verbose "Failed to get built-in group '$groupName': $_"
            }
            if (-not $group) { continue }

            $members = $null
            try {
                $members = if ($__adServer) {
                    Get-ADGroupMember -Identity $group -Server $__adServer -ErrorAction Stop
                }
                else {
                    Get-ADGroupMember -Identity $group -ErrorAction Stop
                }
            }
            catch {
                Write-Verbose "Failed to get members of built-in group '$groupName': $_"
            }

            foreach ($member in $members) {
                if ($member.objectClass -eq 'user') {
                    Add-Evidence -Principal $member.SamAccountName -Reason "Membership in dangerous built-in group '$groupName' - provides privilege escalation paths" -Context @{
                        Group      = $groupName
                        Member     = $member.SamAccountName
                        MemberDN   = $member.DistinguishedName
                        AttackPath = switch ($groupName) {
                            'Print Operators' { 'Load printer drivers on DCs -> Execute code as SYSTEM' }
                            'Server Operators' { 'Modify services on DCs -> Execute code as SYSTEM' }
                            'Backup Operators' { 'Backup SAM/SYSTEM -> Extract credentials -> Full domain compromise' }
                            'Account Operators' { 'Modify non-protected accounts -> Add to privileged groups' }
                            'DnsAdmins' { 'Load arbitrary DLL in DNS service on DC -> Execute as SYSTEM' }
                            default { 'Privilege escalation via built-in group rights' }
                        }
                    }
                }
            }
        }

        # Build findings from evidence
        foreach ($principal in $principalEvidence.Keys) {
            $evidence = $principalEvidence[$principal]
            $criticalEvidence = $evidence | Where-Object { $_.Reason -match 'Domain Root|AdminSDHolder|DCSync|Domain Controller|Privileged account|PKI|Unconstrained|AllowedToDelegate|AllowedToAct|ReadLAPSPassword|ReadGMSAPassword|WriteGPLink|Shadow Credentials|Certificate|Constrained Delegation|RBCD|LAPS password|DNS zone|Exchange|WriteSPN' }

            $severity = if ($criticalEvidence.Count -gt 0) { 'Critical' } else { 'High' }
            $severityLevel = if ($severity -eq 'Critical') { 4 } else { 3 }

            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Admin Equivalence'
            $finding.Issue = 'Domain Admin Equivalent Access Detected'
            $finding.Severity = $severity
            $finding.SeverityLevel = $severityLevel
            $finding.AffectedObject = $principal
            # BUGFIX: was a single semicolon-joined run-on sentence
            # ("reason1; reason2; reason3...") which is unreadable once a
            # principal accumulates more than a couple of pieces of
            # evidence. Rendered as one bullet per line instead - Reporting.ps1
            # and the interactive dashboard both turn embedded newlines into
            # line breaks.
            $evidenceBullets = ($evidence.Reason | ForEach-Object { "- $_" }) -join "`n"
            $finding.Description = "Principal '$principal' holds permissions that provide Domain Admin-equivalent control:`n$evidenceBullets"
            $finding.Impact = 'Compromise of this principal would allow attackers to seize control of protected groups, the domain naming context, PKI infrastructure, or perform DCSync.'
            $finding.EstimatedEffort = 'High - the underlying access is typically composed of multiple pieces of evidence (nested groups, ACEs, ownership), each of which may need a separate fix, similar to breaking a control-path chain.'
            $finding.KnownRisks = 'Removing any single contributing factor could break a legitimate, if undocumented, delegation if it was set up intentionally, so confirm with the principal''s owning team before changing each piece of evidence.'
            $finding.BackupRollback = 'Moderate - export/record each ACE or membership being changed before removing it, then re-run the audit to confirm the effective access is gone.'
            $finding.Remediation = @"
Review and remove the excessive permissions listed in the evidence:
1. Restrict Domain Naming Context and AdminSDHolder control.
2. Lock down AD CS/PKI containers in the Configuration Partition.
3. Audit and remove Unconstrained Delegation from non-DC computers.
4. Restrict control over DNSAdmins and Print Operators.
5. Remove Constrained/RBCD delegation paths to Domain Controllers.
6. Audit LAPS and GMSA password read permissions.
7. Restrict WriteGPLink permissions on Domain and OU objects.
8. Clear adminCount attribute for 'ghost' accounts.
9. Remove Shadow Credentials if not using Windows Hello for Business.
10. Clear SID History injection entries.
"@
            $finding.Details = @{
                Evidence = $evidence
                Domain   = $domain.DNSRoot
            }
            $findings += $finding
        }

        Write-Verbose "Audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during equivalence audit: $_"
        throw
    }
    }
    finally {
        if ($Server -and -not $__adAuditServerAlreadyActive) {
            Clear-ADSecurityAuditTargetServer
        }
    }
}

#endregion
