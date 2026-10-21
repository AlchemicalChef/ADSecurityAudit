#region Dangerous Permissions Audit

function Test-ADDangerousPermissions {
    <#
    .SYNOPSIS
        Audits Enterprise Key Admins scoping, dangerous rights on critical
        OUs (Domain Controllers, Users, Computers), and non-standard
        permissions on the Schema/Configuration naming context head objects.
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
        Set-ADSecurityAuditTargetServer -Server (Resolve-ADSecurityAuditTargetServer -Server $Server)
    }
    # Resolved once, explicitly passed to every live AD call below - not
    # relying on the $PSDefaultParameterValues injection alone. $null when
    # no override is active, which Get-AD* cmdlets treat identically to
    # -Server being omitted entirely.
    $__adServer = Get-ADSecurityAuditActiveServerOverride

    try {
    Write-Verbose "Starting dangerous permissions audit..."
    $findings = @()

    try {
        $domain = if ($__adServer) { Get-ADDomain -Server $__adServer } else { Get-ADDomain }
        $domainDN = $domain.DistinguishedName
        
        # Check Enterprise Key Admins for overly permissive rights (CVE misconfiguration)
        Write-Verbose "Checking Enterprise Key Admins permissions on Domain Naming Context..."
        
        $domainObject = if ($__adServer) {
            Get-ADObject -Identity $domainDN -Server $__adServer -Properties nTSecurityDescriptor
        }
        else {
            Get-ADObject -Identity $domainDN -Properties nTSecurityDescriptor
        }
        $domainAcl = $domainObject.nTSecurityDescriptor
        
        # Get Enterprise Key Admins group (if it exists - only in Windows Server 2016+)
        try {
            $ekaGroup = $null
            try {
                $ekaGroup = if ($__adServer) {
                    Get-ADGroup -Filter "Name -eq 'Enterprise Key Admins'" -Server $__adServer -ErrorAction Stop
                }
                else {
                    Get-ADGroup -Filter "Name -eq 'Enterprise Key Admins'" -ErrorAction Stop
                }
            }
            catch {
                Write-Verbose "Enterprise Key Admins group not found in the target domain: $_"
            }

            if (-not $ekaGroup) {
                # Enterprise Key Admins, like Enterprise Admins/Schema
                # Admins, exists ONLY in the forest root domain - a lookup
                # scoped to a child domain finds nothing there regardless
                # of Windows Server version, and the resulting silence was
                # previously misattributed to "pre-2016 domain" rather
                # than "wrong domain". Resolve the forest root explicitly
                # and re-query there instead, matching the same fix
                # already applied to Test-ADPrivilegedGroups.
                try {
                    $forestRootDomain = (Get-ADForest -ErrorAction Stop).RootDomain
                    if ($forestRootDomain) {
                        Write-Verbose "Test-ADDangerousPermissions: 'Enterprise Key Admins' not found in the target domain; re-querying against the forest root '$forestRootDomain' (it's forest-root-only, like Enterprise Admins/Schema Admins)."
                        $ekaGroup = Get-ADGroup -Filter "Name -eq 'Enterprise Key Admins'" -Server $forestRootDomain -ErrorAction Stop
                    }
                }
                catch {
                    Write-Verbose "Enterprise Key Admins group genuinely not found (expected on pre-2016 forests): $_"
                }
            }

            if ($ekaGroup) {
                Write-Verbose "Found Enterprise Key Admins group, checking for over-privileged ACEs..."
                
                # msDS-KeyCredentialLink attribute GUID
                $keyCredentialLinkGuid = '5b47d60f-6090-40b2-9f37-2a4de88f3063'

                # Multiple ACEs can grant the same over-broad right (one per
                # property set/object type) - dedupe per sub-check so a
                # repeated ACE doesn't produce a repeated finding.
                $__seenEkaFinding = @{}

                foreach ($ace in $domainAcl.Access) {
                    # Check if this ACE is for Enterprise Key Admins
                    if ($ace.IdentityReference.Value -match 'Enterprise Key Admins') {
                        
                        # EKA should only have ReadProperty and WriteProperty for msDS-KeyCredentialLink
                        # If it has GenericAll, WriteDacl, or other excessive rights, that's a vulnerability
                        if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite') {
                            $__ekaKey = "overprivileged|$($ace.ActiveDirectoryRights)"
                            if ($__seenEkaFinding.ContainsKey($__ekaKey)) { continue }
                            $__seenEkaFinding[$__ekaKey] = $true

                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = 'Dangerous Permissions'
                            $finding.Issue = 'Enterprise Key Admins Over-Privileged (Misconfiguration Bug)'
                            $finding.Severity = 'Critical'
                            $finding.SeverityLevel = 4
                            $finding.AffectedObject = 'Enterprise Key Admins - Domain Naming Context'
                            $finding.Description = "Enterprise Key Admins group has excessive permissions '$($ace.ActiveDirectoryRights)' on the Domain Naming Context. This is a known misconfiguration bug where EKA was granted full access instead of just ReadProperty/WriteProperty for msDS-KeyCredentialLink."
                            $finding.Impact = "This misconfiguration can unintentionally grant DCSync permissions, allowing members of Enterprise Key Admins to extract password hashes for all domain accounts. Attackers can exploit this for full domain compromise."
                            $finding.EstimatedEffort = 'Medium - a single-object ACE removal, but on a forest-wide replicated object, so it warrants confirming with the relevant application owner (e.g. Exchange, ADFS, or backup/DR tooling that sometimes provisions Configuration-NC rights during setup) before removing, plus a short post-change monitoring window.'
                            $finding.KnownRisks = 'Removing the ACE could break a directory-integrated product that legitimately extends the Configuration container (commonly Exchange setup/recipient-update accounts, or certain backup/DR tools) if the trustee is a genuine service account rather than a misconfiguration.'
                            $finding.BackupRollback = 'Moderate - export the object''s current nTSecurityDescriptor (e.g. via dsacls or Get-Acl on the AD: PowerShell drive) before making the change so the exact ACE can be re-added if needed, and allow for AD replication convergence across all DCs before the removal is fully in effect forest-wide.'
                            $finding.OperationalNotes = 'Since this ACE sits above the Public Key Services container this tool''s own AD CS checks already review separately, cross-check the trustee against any known certificate-services or Exchange install accounts before removing it, to avoid duplicating remediation effort on the wrong object.'
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
                            $__ekaKey = "notscoped|$($ace.ActiveDirectoryRights)|$($ace.ObjectType)"
                            if ($__seenEkaFinding.ContainsKey($__ekaKey)) { continue }
                            $__seenEkaFinding[$__ekaKey] = $true

                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = 'Dangerous Permissions'
                            $finding.Issue = 'Enterprise Key Admins Permissions Not Scoped to msDS-KeyCredentialLink'
                            $finding.Severity = 'High'
                            $finding.SeverityLevel = 3
                            $finding.AffectedObject = 'Enterprise Key Admins - Domain Naming Context'
                            $finding.Description = "Enterprise Key Admins has $($ace.ActiveDirectoryRights) rights scoped to ObjectType $($ace.ObjectType) instead of being scoped specifically to the msDS-KeyCredentialLink attribute (GUID: $keyCredentialLinkGuid)."
                            $finding.Impact = "Excessive property write permissions may allow unintended modifications to domain objects beyond the intended key credential management scope."
                            $finding.Remediation = "Scope Enterprise Key Admins permissions specifically to msDS-KeyCredentialLink attribute (GUID: $keyCredentialLinkGuid) only."
                            $finding.EstimatedEffort = 'Medium - a single-object ACE removal, but on a forest-wide replicated object, so it warrants confirming with the relevant application owner (e.g. Exchange, ADFS, or backup/DR tooling that sometimes provisions Configuration-NC rights during setup) before removing, plus a short post-change monitoring window.'
                            $finding.KnownRisks = 'Removing the ACE could break a directory-integrated product that legitimately extends the Configuration container (commonly Exchange setup/recipient-update accounts, or certain backup/DR tools) if the trustee is a genuine service account rather than a misconfiguration.'
                            $finding.BackupRollback = 'Moderate - export the object''s current nTSecurityDescriptor (e.g. via dsacls or Get-Acl on the AD: PowerShell drive) before making the change so the exact ACE can be re-added if needed, and allow for AD replication convergence across all DCs before the removal is fully in effect forest-wide.'
                            $finding.OperationalNotes = 'Since this ACE sits above the Public Key Services container this tool''s own AD CS checks already review separately, cross-check the trustee against any known certificate-services or Exchange install accounts before removing it, to avoid duplicating remediation effort on the wrong object.'
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
                $ou = $null
                try {
                    $ou = if ($__adServer) {
                        Get-ADObject -Identity $ouDN -Server $__adServer -Properties nTSecurityDescriptor -ErrorAction Stop
                    }
                    else {
                        Get-ADObject -Identity $ouDN -Properties nTSecurityDescriptor -ErrorAction Stop
                    }
                }
                catch {
                    Write-Verbose "Could not get OU '$ouDN': $_"
                }

                if (-not $ou) {
                    continue
                }
                
                $acl = $ou.nTSecurityDescriptor
                
                # Multiple ACEs can grant the same trustee the same
                # dangerous right (one per property set/object type) -
                # dedupe so a repeated ACE doesn't produce a repeated
                # finding.
                $__seenOuHit = @{}
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
                        $__ouHitKey = "$($ace.IdentityReference)|$($ace.ActiveDirectoryRights)"
                        if ($__seenOuHit.ContainsKey($__ouHitKey)) { continue }
                        $__seenOuHit[$__ouHitKey] = $true

                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Dangerous Permissions'
                        $finding.Issue = 'Dangerous Rights on Critical OU'
                        $finding.Severity = 'High'
                        $finding.SeverityLevel = 3
                        $finding.AffectedObject = "$ouDN - $($ace.IdentityReference)"
                        $finding.Description = "Principal '$($ace.IdentityReference)' has dangerous rights '$($ace.ActiveDirectoryRights)' on critical OU."
                        $finding.Impact = "Attackers who compromise this principal can create/modify objects in this OU, potentially adding rogue Domain Controllers or admin accounts."
                        $finding.Remediation = "Review and restrict permissions. Remove unnecessary rights using Active Directory Users and Computers > Advanced Security Settings."
                        $finding.EstimatedEffort = 'Medium - a single-object ACE removal, but on a forest-wide replicated object, so it warrants confirming with the relevant application owner (e.g. Exchange, ADFS, or backup/DR tooling that sometimes provisions Configuration-NC rights during setup) before removing, plus a short post-change monitoring window.'
                        $finding.KnownRisks = 'Removing the ACE could break a directory-integrated product that legitimately extends the Configuration container (commonly Exchange setup/recipient-update accounts, or certain backup/DR tools) if the trustee is a genuine service account rather than a misconfiguration.'
                        $finding.BackupRollback = 'Moderate - export the object''s current nTSecurityDescriptor (e.g. via dsacls or Get-Acl on the AD: PowerShell drive) before making the change so the exact ACE can be re-added if needed, and allow for AD replication convergence across all DCs before the removal is fully in effect forest-wide.'
                        $finding.OperationalNotes = 'Since this ACE sits above the Public Key Services container this tool''s own AD CS checks already review separately, cross-check the trustee against any known certificate-services or Exchange install accounts before removing it, to avoid duplicating remediation effort on the wrong object.'
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
        
        # --- Forest-level coverage backlog: Schema/Configuration NC head ACLs ---
        Write-Verbose "Checking Schema/Configuration naming context ACLs..."
        try {
            $schemaContext = if ($__adServer) { Get-ADRootDSEValue -Property schemaNamingContext -Server $__adServer } else { Get-ADRootDSEValue -Property schemaNamingContext }
            $configurationContext = if ($__adServer) { Get-ADRootDSEValue -Property configurationNamingContext -Server $__adServer } else { Get-ADRootDSEValue -Property configurationNamingContext }

            if (-not $schemaContext -or -not $configurationContext) {
                Write-Warning "Test-ADDangerousPermissions: could not resolve schema/configuration naming context, so the Schema/Configuration NC ACL checks produced no finding either way (this is NOT the same as confirming they're compliant)."
            }
            else {
            $ncAclLiveTargets = @{
                $schemaContext        = @{
                    Issue = 'Non-Standard Permissions on Schema Naming Context'
                    AcceptableTrustees = @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')
                    AcceptableGroupSuffixes = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
                }
                $configurationContext = @{
                    Issue = 'Non-Standard Permissions on Configuration Naming Context'
                    AcceptableTrustees = @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')
                    AcceptableGroupSuffixes = @('Domain Admins', 'Enterprise Admins')
                }
            }

            foreach ($ncDN in $ncAclLiveTargets.Keys) {
                if (-not $ncDN) { continue }
                $ncConfig = $ncAclLiveTargets[$ncDN]
                try {
                    $ncObject = if ($__adServer) {
                        Get-ADObject -Identity $ncDN -Server $__adServer -Properties nTSecurityDescriptor -ErrorAction Stop
                    }
                    else {
                        Get-ADObject -Identity $ncDN -Properties nTSecurityDescriptor -ErrorAction Stop
                    }
                }
                catch {
                    Write-Verbose "Could not get naming context '$ncDN': $_"
                    continue
                }

                if (-not $ncObject) { continue }
                $ncAcl = $ncObject.nTSecurityDescriptor

                # Multiple ACEs can grant the same trustee the same
                # dangerous right (one per property set/object type) -
                # dedupe so a repeated ACE doesn't produce a repeated
                # finding.
                $__seenNcHit = @{}
                foreach ($ace in @($ncAcl.Access)) {
                    if ($ace.IsInherited) { continue }

                    $identityReference = "$($ace.IdentityReference)"
                    $isAcceptable = ($identityReference -in $ncConfig.AcceptableTrustees) -or
                        ($identityReference -match 'S-1-5-32-544')
                    foreach ($suffix in $ncConfig.AcceptableGroupSuffixes) {
                        if ($identityReference -match [regex]::Escape($suffix)) { $isAcceptable = $true; break }
                    }
                    if ($isAcceptable) { continue }

                    $dangerousRights = @('GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite', 'WriteProperty')
                    $hasDangerousRight = $false
                    foreach ($right in $dangerousRights) {
                        if ($ace.ActiveDirectoryRights -match $right) {
                            $hasDangerousRight = $true
                            break
                        }
                    }

                    if ($hasDangerousRight) {
                        $__ncHitKey = "$identityReference|$($ace.ActiveDirectoryRights)"
                        if ($__seenNcHit.ContainsKey($__ncHitKey)) { continue }
                        $__seenNcHit[$__ncHitKey] = $true

                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Permissions'
                        $finding.Issue = $ncConfig.Issue
                        $finding.Severity = 'Critical'
                        $finding.SeverityLevel = 4
                        $finding.AffectedObject = "$identityReference on $ncDN"
                        $finding.Description = "A principal outside the expected administrative trustees ('$identityReference') holds '$($ace.ActiveDirectoryRights)' rights on $ncDN."
                        if ($ncDN -eq $schemaContext) {
                            $finding.Impact = "A principal able to write to the schema partition can alter object class and attribute definitions forest-wide, including the defaultSecurityDescriptor applied to newly created objects of a class - a documented forest-wide persistence and privilege-escalation vector. Schema changes replicate to every DC in the forest and cannot be cleanly reversed (attributes/classes can be marked defunct but not deleted)."
                            $finding.Remediation = "Remove the non-standard ACE from the Schema naming context head object; restrict schema write access to Schema Admins only, and keep that group empty outside planned schema-extension windows."
                            $finding.EstimatedEffort = 'Medium - a single-object ACE removal, but on a forest-wide replicated object, so it warrants confirming with the relevant application owner (e.g. Exchange, ADFS, or backup/DR tooling that sometimes provisions Configuration-NC rights during setup) before removing, plus a short post-change monitoring window.'
                            $finding.KnownRisks = 'Removing the ACE could break a directory-integrated product that legitimately extends the Configuration container (commonly Exchange setup/recipient-update accounts, or certain backup/DR tools) if the trustee is a genuine service account rather than a misconfiguration.'
                            $finding.BackupRollback = 'Moderate - export the object''s current nTSecurityDescriptor (e.g. via dsacls or Get-Acl on the AD: PowerShell drive) before making the change so the exact ACE can be re-added if needed, and allow for AD replication convergence across all DCs before the removal is fully in effect forest-wide.'
                            $finding.OperationalNotes = 'Since this ACE sits above the Public Key Services container this tool''s own AD CS checks already review separately, cross-check the trustee against any known certificate-services or Exchange install accounts before removing it, to avoid duplicating remediation effort on the wrong object.'
                        }
                        else {
                            $finding.Impact = "The Configuration NC replicates to every DC in the forest and holds the Sites/Subnets topology, the Services container (including Public Key Services, and Exchange configuration where present), Extended-Rights definitions, and the forest's WellKnown Security Principals. A principal with write/GenericAll-equivalent rights on the head object can, depending on inheritance, create or modify objects anywhere below it - a broader and more varied blast radius than the Public Key Services container alone already covered by this tool's AD CS checks."
                            $finding.Remediation = "Review and remove the non-standard ACE from the Configuration naming context head object; restrict write access to Enterprise Admins/Domain Admins only, and treat any change to this object as forest-wide until proven otherwise."
                            $finding.EstimatedEffort = 'Medium - a single-object ACE removal, but on a forest-wide replicated object, so it warrants confirming with the relevant application owner (e.g. Exchange, ADFS, or backup/DR tooling that sometimes provisions Configuration-NC rights during setup) before removing, plus a short post-change monitoring window.'
                            $finding.KnownRisks = 'Removing the ACE could break a directory-integrated product that legitimately extends the Configuration container (commonly Exchange setup/recipient-update accounts, or certain backup/DR tools) if the trustee is a genuine service account rather than a misconfiguration.'
                            $finding.BackupRollback = 'Moderate - export the object''s current nTSecurityDescriptor (e.g. via dsacls or Get-Acl on the AD: PowerShell drive) before making the change so the exact ACE can be re-added if needed, and allow for AD replication convergence across all DCs before the removal is fully in effect forest-wide.'
                            $finding.OperationalNotes = 'Since this ACE sits above the Public Key Services container this tool''s own AD CS checks already review separately, cross-check the trustee against any known certificate-services or Exchange install accounts before removing it, to avoid duplicating remediation effort on the wrong object.'
                        }
                        $finding.Details = @{
                            Identity = $identityReference
                            ActiveDirectoryRights = $ace.ActiveDirectoryRights
                            AccessControlType = $ace.AccessControlType
                            ObjectType = $ace.ObjectType
                            DistinguishedName = $ncDN
                        }
                        $findings += $finding
                    }
                }
            }
            }
        }
        catch {
            # FIXED (reported): this was Write-Verbose-only, so ANY failure
            # anywhere in the Schema/Configuration NC ACL read (permissions,
            # connectivity, an unexpected RootDSE/object shape) silently
            # skipped BOTH targets with no visible indication anything went
            # wrong - indistinguishable from "checked, and both are clean".
            # Write-Warning makes a real failure visible by default instead
            # of only appearing under -Verbose.
            Write-Warning "Test-ADDangerousPermissions: could not check Schema/Configuration naming context ACLs, so neither check produced a finding either way (this is NOT the same as confirming they're compliant): $_"
        }

        Write-Verbose "Dangerous permissions audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during dangerous permissions audit: $_"
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

