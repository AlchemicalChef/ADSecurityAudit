#region GPO Audit

function Test-ADGroupPolicies {
    <#
    .SYNOPSIS
        Audits GPO permissions, link scope, and SYSVOL file-share permissions.
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
    # Resolved once, explicitly passed to every live AD/GPO call below -
    # not relying on the $PSDefaultParameterValues injection alone. $null
    # when no override is active, which Get-AD*/Get-GP* cmdlets treat
    # identically to -Server being omitted entirely.
    $__adServer = Get-ADSecurityAuditActiveServerOverride

    try {
    Write-Verbose "Starting Group Policy audit..."
    $findings = @()

    try {
        Import-Module GroupPolicy -ErrorAction Stop
        
        $allGPOs = if ($__adServer) { Get-GPO -All -Server $__adServer } else { Get-GPO -All }
        $domain = if ($__adServer) { Get-ADDomain -Server $__adServer } else { Get-ADDomain }

        # Dynamically resolved set of OUs that actually contain a Domain
        # Controller computer object, used below instead of a hardcoded
        # 'OU=Domain Controllers' string match. FIXED (gap): the previous
        # check only matched a GPO link whose DistinguishedName contained
        # the literal text 'OU=Domain Controllers', which silently misses
        # any environment where that OU has been renamed or DCs have been
        # moved/reorganized into a differently-named or nested OU - a GPO
        # granting non-admin edit rights while linked to such an OU
        # previously produced NO finding at all. Resolved once per run
        # from the DC computer objects themselves (their DN's immediate
        # parent), which is not affected by naming.
        $dcContainerDNs = @()
        try {
            $dcComputersForOU = @(Invoke-ADQueryWithRetry -OperationName 'Get DC computer objects (GPO audit - DC OU resolution)' -Query {
                Get-ADSecurityAuditDomainController -Server $__adServer
            })
            $dcContainerDNs = @($dcComputersForOU | ForEach-Object {
                $dcDN = if ($_.ComputerObjectDN) { $_.ComputerObjectDN } elseif ($_.DistinguishedName) { $_.DistinguishedName } else { $null }
                if ($dcDN) {
                    # Parent DN = everything after the object's own
                    # leading RDN component (its first unescaped comma).
                    $parts = $dcDN -split '(?<!\\),', 2
                    if ($parts.Count -eq 2) { $parts[1] }
                }
            } | Where-Object { $_ } | Select-Object -Unique)
        }
        catch {
            Write-Verbose "Test-ADGroupPolicies: failed to resolve DC-containing OU(s) dynamically; falling back to name-based match only: $_"
        }

        # Precomputed once per run: SIDs of principals considered a
        # "standard administrative owner" for the GPO-ownership check
        # below. IMPROVED: the first version of this check compared
        # $gpo.Owner by NAME against a short hardcoded regex
        # ('Domain Admins|Enterprise Admins|SYSTEM|BUILTIN\Administrators
        # |Administrators$'), which has two real problems: (1) it's a
        # false-negative risk - any custom-named group that happens to
        # END in the word "Administrators" (e.g. a non-admin "Help Desk
        # Administrators" group) is silently treated as legitimate, and
        # (2) it's a false-positive risk - a genuinely-delegated,
        # legitimate Tier-0 owner is flagged just because its name
        # doesn't literally match one of a handful of hardcoded strings.
        # Resolving to actual SIDs - the built-in privileged groups'
        # own group objects, SYSTEM's well-known SID, and every member
        # of Get-ADTier0Principal - fixes both: membership is checked by
        # identity, not by string pattern.
        $adminOwnerSidAllowlist = @{ 'S-1-5-18' = $true }  # SYSTEM
        foreach ($groupName in $Script:ProtectedGroups) {
            try {
                $protectedGroupObj = if ($__adServer) {
                    Get-ADGroup -Filter "Name -eq '$groupName'" -Server $__adServer -ErrorAction Stop
                }
                else {
                    Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
                }
                if ($protectedGroupObj -and $protectedGroupObj.SID) {
                    $adminOwnerSidAllowlist[$protectedGroupObj.SID.Value] = $true
                }
            }
            catch {
                Write-Verbose "Test-ADGroupPolicies: failed to resolve protected group '$groupName' for GPO-owner allowlist: $_"
            }
        }
        try {
            foreach ($t0 in @(Get-ADTier0Principal)) {
                if ($t0.SID) { $adminOwnerSidAllowlist[$t0.SID] = $true }
            }
        }
        catch {
            Write-Verbose "Test-ADGroupPolicies: failed to resolve Tier-0 principal set for GPO-owner allowlist: $_"
        }

        Write-Verbose "Analyzing $($allGPOs.Count) GPOs..."
        
        $gpoCount = $allGPOs.Count
        $currentGpo = 0
        
        foreach ($gpo in $allGPOs) {
            $currentGpo++
            Write-Progress -Activity "Scanning Group Policies" -Status "Processing $($gpo.DisplayName)" `
                -PercentComplete (($currentGpo / $gpoCount) * 100)
            
            # Get GPO permissions
            $gpoPermissions = if ($__adServer) { Get-GPPermission -Guid $gpo.Id -All -Server $__adServer } else { Get-GPPermission -Guid $gpo.Id -All }
            
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
                        $finding.EstimatedEffort = 'Medium - removing a non-standard Edit/FullControl right from one GPO; confirm the trustee isn''t a legitimate delegated owner.'
                        $finding.KnownRisks = 'Procedural - confirm the trustee isn''t an active, legitimate delegated GPO administrator before removing their rights.'
                        $finding.BackupRollback = 'Easy - restore the GPO permission via GPMC; effective immediately, no data loss.'
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
            $gpoLinks = Get-ADObject -Filter "gPLink -like '*$($gpo.Id)*'" -Properties gPLink, DistinguishedName -Server $__adServer
            
            $linkedToDcContainingOU = $false

            foreach ($link in $gpoLinks) {
                # Check if linked to an OU that actually contains a DC
                # computer object (dynamically resolved above), OR the
                # legacy literal-name match as a fallback if that
                # resolution failed for some reason (e.g. DC enumeration
                # itself errored this run) - belt-and-suspenders rather
                # than silently losing coverage either way.
                $isDcOULink = ($dcContainerDNs -and ($dcContainerDNs -icontains $link.DistinguishedName)) -or ($link.DistinguishedName -match 'OU=Domain Controllers')
                if ($isDcOULink) {
                    $linkedToDcContainingOU = $true
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
                        $finding.EstimatedEffort = 'Medium - removing a non-standard Edit/Write right from the GPO object itself; confirm the trustee isn''t a legitimate delegated GPO-management account.'
                        $finding.KnownRisks = 'Procedural - confirm the trustee isn''t a legitimate delegated GPO administrator for that specific GPO before removing their rights.'
                        $finding.BackupRollback = 'Easy - restore the GPO permission via GPMC; effective immediately, though the change still needs to replicate to all DCs.'
                        $finding.Details = @{
                            GPOID = $gpo.Id
                            LinkedOU = $link.DistinguishedName
                            NonAdminTrustees = ($nonAdminEditRights.Trustee.Name -join '; ')
                        }
                        $findings += $finding
                    }
                }
            }
            
            # Check GPO ownership - even a GPO with tightly-restricted Edit
            # permissions can be re-opened at will by whoever OWNS the
            # object, since an owner can always rewrite the DACL
            # regardless of its current contents. Get-GPO already exposes
            # this directly via .Owner, so no extra ACL read is needed.
            # Escalated to Critical when the GPO is linked to an OU that
            # actually contains a DC (see $linkedToDcContainingOU above) -
            # a non-admin owner there means that principal can grant
            # itself edit rights to push arbitrary configuration/code to
            # every Domain Controller.
            if ($gpo.Owner) {
                $ownerSid = Resolve-ADPrincipalNameToSid -Name $gpo.Owner

                $isStandardOwner = $false
                if ($ownerSid) {
                    $isStandardOwner = $adminOwnerSidAllowlist.ContainsKey($ownerSid)
                }
                else {
                    # Translation failed outright (e.g. an orphaned/
                    # foreign-domain SID with no resolvable name) - fall
                    # back to the original name-based heuristic rather
                    # than treating every untranslatable owner as
                    # suspicious, which would be noisy for legitimate
                    # cross-domain/cross-forest setups this session can't
                    # resolve a SID for.
                    $isStandardOwner = [bool]($gpo.Owner -match 'Domain Admins|Enterprise Admins|SYSTEM|BUILTIN\\Administrators')
                }

                if (-not $isStandardOwner) {
                    $ownerSeverity = if ($linkedToDcContainingOU) { 'Critical' } else { 'High' }
                    $ownerSeverityLevel = if ($linkedToDcContainingOU) { 4 } else { 3 }

                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Group Policy'
                    $finding.Issue = 'Non-Standard GPO Owner'
                    $finding.Severity = $ownerSeverity
                    $finding.SeverityLevel = $ownerSeverityLevel
                    $finding.AffectedObject = $gpo.DisplayName
                    $finding.Description = "GPO '$($gpo.DisplayName)' is owned by '$($gpo.Owner)' rather than a standard administrative principal.$(if ($linkedToDcContainingOU) { ' This GPO is linked to an OU that contains a Domain Controller.' })"
                    $finding.Impact = "An object's owner can always rewrite its DACL, regardless of the object's current permissions - so a non-admin owner can grant itself Edit/FullControl on this GPO at any time, bypassing whatever permissions are visible today.$(if ($linkedToDcContainingOU) { ' Because this GPO is linked to an OU containing a Domain Controller, that ultimately means SYSTEM-level code execution on DCs.' })"
                    $finding.Remediation = "Change the GPO's owner to a standard administrative principal (typically Domain Admins), e.g. via GPMC (right-click the GPO > Properties > Security > Advanced > Owner), or with PowerShell: (Get-ADObject -Identity 'CN=$($gpo.Id),CN=Policies,CN=System,$($domain.DistinguishedName)').nTSecurityDescriptor.SetOwner([System.Security.Principal.NTAccount]'DOMAIN\Domain Admins')"
                    $finding.EstimatedEffort = 'Low - a single ownership change on one GPO object; confirm the current owner isn''t an intentional, actively-used delegated GPO-management account first.'
                    $finding.KnownRisks = 'Procedural - confirm the current owner isn''t a legitimate delegated GPO administrator for this specific GPO before changing ownership.'
                    $finding.BackupRollback = 'Easy - ownership can be changed back to the prior value at any time by an administrator; effective immediately, no data loss.'
                    $finding.Details = @{
                        GPOID              = $gpo.Id
                        Owner              = $gpo.Owner
                        OwnerSid           = $ownerSid
                        LinkedToDCOU       = $linkedToDcContainingOU
                        LinkedOUs          = ($gpoLinks.DistinguishedName -join '; ')
                    }
                    $findings += $finding
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
                $finding.EstimatedEffort = 'Low - this is a hygiene finding; typical remediation is to delete the unused GPO or formally document/retain it.'
                $finding.KnownRisks = 'Deleting an unlinked GPO is safe in the sense that it isn''t currently applied anywhere, but if it''s only temporarily unlinked (e.g. staged for a future rollout), deleting it loses that work - confirm with whoever created it first.'
                $finding.BackupRollback = 'Moderate - back up the GPO with Backup-GPO before deleting so it can be restored with Restore-GPO if needed.'
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
        # The server component of the UNC path uses the active -Server
        # override when one is set, not just the domain's DNS name - see
        # the matching comment on Get-ADGpoSecretsSysvolPolicyRoot
        # (GpoSecretsAudits.ps1) for why a bare domain name here is
        # subject to the same "closest DC" DFS-referral ambiguity Get-AD*/
        # Get-GP* cmdlets have via -Server, with no -Server parameter of
        # its own to fix it - the only fix is putting the resolved DC
        # directly in the path.
        $sysvolServer = Get-ADSecurityAuditActiveServerOverride
        if (-not $sysvolServer) { $sysvolServer = $domain.DNSRoot }
        $sysvolPath = "\\$sysvolServer\SYSVOL\$($domain.DNSRoot)"
        
        if (Test-Path $sysvolPath) {
            try {
                $sysvolAcl = Get-Acl $sysvolPath -ErrorAction Stop
                
                # The same principal can appear in more than one ACE (e.g.
                # separate "this folder only" vs "this folder, subfolders,
                # files" inheritance-flag ACEs) granting the same
                # FileSystemRights - dedupe so a repeated ACE doesn't
                # produce a repeated finding.
                $__seenSysvolHit = @{}
                foreach ($ace in $sysvolAcl.Access) {
                    # Check for write/modify rights granted to non-admin groups
                    if ($ace.FileSystemRights -match 'Write|Modify|FullControl' -and
                        $ace.AccessControlType -eq 'Allow' -and
                        $ace.IdentityReference -notmatch 'SYSTEM' -and
                        $ace.IdentityReference -notmatch 'Administrators' -and
                        $ace.IdentityReference -notmatch 'Domain Admins' -and
                        $ace.IdentityReference -notmatch 'Enterprise Admins' -and
                        $ace.IdentityReference -notmatch 'CREATOR OWNER') {
                        
                        $__sysvolKey = "$($ace.IdentityReference)|$($ace.FileSystemRights)"
                        if ($__seenSysvolHit.ContainsKey($__sysvolKey)) { continue }
                        $__seenSysvolHit[$__sysvolKey] = $true

                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Group Policy'
                        $finding.Issue = 'Insecure SYSVOL Permissions'
                        $finding.Severity = 'Critical'
                        $finding.SeverityLevel = 4
                        $finding.AffectedObject = "SYSVOL - $($ace.IdentityReference)"
                        $finding.Description = "SYSVOL has write permissions granted to '$($ace.IdentityReference)'."
                        $finding.Impact = "Attackers can tamper with GPO files, scripts, and policies that apply to all domain members, leading to widespread compromise."
                        $finding.Remediation = "Restrict SYSVOL permissions. Remove write access for non-admin principals. Only Domain Admins and SYSTEM should have write access."
                        $finding.EstimatedEffort = 'Medium - correcting ACLs on SYSVOL/NETLOGON shares (and their filesystem equivalents) on every DC, then validating legitimate scripts/GPOs still function for all clients.'
                        $finding.KnownRisks = 'Over-tightening SYSVOL permissions can break clients'' ability to read GPOs or logon scripts if a legitimate group loses access it was relying on; validate with a domain-wide policy refresh test after the change.'
                        $finding.BackupRollback = 'Moderate - export the current SYSVOL share/NTFS ACL (icacls or Get-Acl) before changing it, and allow for DFSR/FRS replication across all DCs before the change is fully in effect.'
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
    finally {
        if ($Server -and -not $__adAuditServerAlreadyActive) {
            Clear-ADSecurityAuditTargetServer
        }
    }
}

#endregion

