#region Group and Privilege Audits

function Test-ADPrivilegedGroups {
    <#
    .SYNOPSIS
        Audits privileged/protected group membership for excessive size,
        nested groups, and disabled users.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$AdditionalGroups = @(),

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

    try {
    Write-Verbose "Starting privileged group audit..."
    # Resolved once, explicitly passed to every live AD call below - not
    # relying on the $PSDefaultParameterValues injection alone. $null when
    # no override is active, which Get-AD* cmdlets treat identically to
    # -Server being omitted entirely.
    $__adServer = Get-ADSecurityAuditActiveServerOverride
    $findings = @()

    $groupsToCheck = $Script:ProtectedGroups + $AdditionalGroups

    try {
        $groupCount = $groupsToCheck.Count
        $currentGroup = 0
        $forestRootOnlyGroups = @('Enterprise Admins', 'Schema Admins')
        
        foreach ($groupName in $groupsToCheck) {
            $currentGroup++
            Write-Progress -Activity "Scanning Privileged Groups" -Status "Processing $groupName" `
                -PercentComplete (($currentGroup / $groupCount) * 100)
            
            try {
                $group = $null
                $groupServer = $__adServer
                try {
                    $group = if ($__adServer) {
                        Get-ADGroup -Filter "Name -eq '$groupName'" -Server $__adServer -Properties Members, MemberOf -ErrorAction Stop
                    }
                    else {
                        Get-ADGroup -Filter "Name -eq '$groupName'" -Properties Members, MemberOf -ErrorAction Stop
                    }
                }
                catch {
                    Write-Verbose "Failed to get group '$groupName': $_"
                }

                if (-not $group -and $groupName -in $forestRootOnlyGroups) {
                    # Enterprise Admins/Schema Admins exist ONLY in the
                    # forest root domain - a lookup scoped to a child
                    # domain (via the active -Server override) correctly
                    # finds nothing there, and previously that meant this
                    # group was silently skipped for every non-root domain
                    # audited, with no finding and no indication why.
                    # Resolve the forest root explicitly and re-query
                    # there instead.
                    try {
                        $forestRootDomain = (Get-ADForest -ErrorAction Stop).RootDomain
                        if ($forestRootDomain) {
                            Write-Verbose "Test-ADPrivilegedGroups: '$groupName' not found in the target domain (expected - it's forest-root-only); re-querying against the forest root '$forestRootDomain' instead."
                            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Server $forestRootDomain -Properties Members, MemberOf -ErrorAction Stop
                            # This group actually lives in the forest root,
                            # not $__adServer's domain - member lookups
                            # below must target the same root domain the
                            # group object itself came from, or
                            # Get-ADGroupMember -Identity $group would try
                            # to bind a root-domain object against a
                            # child-domain server and fail to find it.
                            $groupServer = $forestRootDomain
                        }
                    }
                    catch {
                        Write-Verbose "Failed to resolve '$groupName' via the forest root domain: $_"
                    }
                }

                if (-not $group) {
                    continue
                }

                # The domain the group object ITSELF actually landed in -
                # normally the audited domain, but the forest root for
                # Enterprise Admins/Schema Admins per the fallback above.
                # Get-ADGroupMember is called with -Identity $group below,
                # which binds it to this same domain regardless of the
                # ambient -Server default, so member lookups stay
                # consistent with wherever the group actually is.
                $groupDomainDN = if ($group.DistinguishedName -match '(DC=.+)$') { $matches[1] } else { $null }

                # Get recursive members for total count and user analysis
                $recursiveMembers = $null
                try {
                    $recursiveMembers = if ($groupServer) {
                        Get-ADGroupMember -Identity $group -Recursive -Server $groupServer -ErrorAction Stop
                    }
                    else {
                        Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop
                    }
                }
                catch {
                    Write-Verbose "Failed to get recursive members of '$groupName': $_"
                }

                # Get direct members separately to detect nested groups
                # (Get-ADGroupMember -Recursive only returns leaf objects, not groups)
                $directMembers = $null
                try {
                    $directMembers = if ($groupServer) {
                        Get-ADGroupMember -Identity $group -Server $groupServer -ErrorAction Stop
                    }
                    else {
                        Get-ADGroupMember -Identity $group -ErrorAction Stop
                    }
                }
                catch {
                    Write-Verbose "Failed to get direct members of '$groupName': $_"
                }

                if (-not $recursiveMembers -and -not $directMembers) {
                    continue
                }

                # --- Cross-domain membership visibility -----------------
                # Get-ADGroupMember -Recursive can return members from a
                # DIFFERENT domain than the group itself (a universal group,
                # or - in a multi-domain forest where the auditor's own
                # machine is joined to a different domain than the one
                # being audited - membership resolved via a Global Catalog
                # can legitimately include full objects from other domains
                # too). Neither case is inherently wrong, but it was
                # previously invisible: nothing recorded which domain a
                # member actually belonged to. This doesn't change the
                # membership counts/thresholds below (a cross-domain member
                # is still a real member) - it only adds visibility.
                if ($groupDomainDN -and $recursiveMembers) {
                    $membershipSplit = Split-ADObjectByTargetDomain -InputObject @($recursiveMembers) -TargetDomainDN $groupDomainDN
                    if (@($membershipSplit.Foreign).Count -gt 0) {
                        Write-Warning "Test-ADPrivilegedGroups: '$groupName' has $(@($membershipSplit.Foreign).Count) member(s) from a domain other than the group's own ($groupDomainDN). If this domain wasn't the one you intended to audit, verify -Server/DNS resolution - see the 'Cross-Domain Privileged Group Membership' finding for the affected accounts."
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Privileged Groups'
                        $finding.Issue = 'Cross-Domain Privileged Group Membership'
                        # 'Low', not a true Info bucket - Export-ADSecurityReportHTML
                        # only renders Critical/High/Medium/Low sections, so an
                        # 'Info' severity here would be counted in JSON/CSV but
                        # invisible in the HTML report itself, defeating the
                        # point of surfacing it. Low keeps its scoring impact
                        # minimal while still making it visible where an
                        # operator will actually see it.
                        $finding.Severity = 'Low'
                        $finding.SeverityLevel = 1
                        $finding.AffectedObject = $groupName
                        $finding.Description = "The '$groupName' group (domain: $groupDomainDN) has $(@($membershipSplit.Foreign).Count) member(s) whose own DistinguishedName belongs to a different domain."
                        $finding.Impact = "This can be legitimate (a universal group, or intentional cross-domain nesting in this forest) - but if this domain was not the one you intended to audit (-Server), it can also indicate the audit is unexpectedly reading data from another domain in the forest."
                        $finding.Remediation = "Review the listed accounts' domains. If this is unintentional, verify -Server was resolved to the intended domain (check the run's 'Server override:' console/verbose output) and that DNS for the target domain resolves correctly from this machine."
                        $finding.EstimatedEffort = 'Medium - removing a foreign-domain principal from a local privileged group; confirm with the other domain''s admins it isn''t an intentional, documented cross-domain admin delegation before removing.'
                        $finding.KnownRisks = 'Procedural - confirm with the other domain''s admins that the membership isn''t an intentional cross-domain delegation before removing, since doing so revokes that principal''s privileged access entirely.'
                        $finding.BackupRollback = 'Easy - re-add the principal to the group if needed; effective on next Kerberos ticket refresh, no data loss.'
                        $finding.Details = @{
                            GroupDN         = $group.DistinguishedName
                            ForeignDomains  = @($membershipSplit.Foreign | ForEach-Object { if ($_.DistinguishedName -match '(DC=.+)$') { $matches[1] } }) | Select-Object -Unique
                            ForeignMembers  = ($membershipSplit.Foreign | Select-Object -ExpandProperty SamAccountName) -join '; '
                        }
                        $findings += $finding
                    }
                }
                
                # Check for excessive membership (using recursive count)
                $memberCount = ($recursiveMembers | Measure-Object).Count
                
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
                    $finding.EstimatedEffort = 'Medium - requires reviewing each member for actual ongoing need rather than a single mechanical change, and coordinating with each member or their manager.'
                    $finding.KnownRisks = 'Removing a member who still has a legitimate ongoing need for privileged access will break their ability to perform that work until re-added, so this needs a per-member justification review, not a blanket removal.'
                    $finding.BackupRollback = 'Easy - re-add any member whose access need is confirmed; effective on next Kerberos ticket refresh, no data loss.'
                    $finding.Details = @{
                        GroupDN = $group.DistinguishedName
                        MemberCount = $memberCount
                        Members = ($recursiveMembers | Select-Object -ExpandProperty SamAccountName) -join '; '
                    }
                    $findings += $finding
                }
                
                # Check for nested groups in critical groups (using direct members)
                $nestedGroups = $directMembers | Where-Object { $_.objectClass -eq 'group' }
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
                    $finding.EstimatedEffort = 'Medium - un-nesting a group from a Tier-0 group can silently revoke access for every member of the nested group, so first enumerate who''s actually inside it.'
                    $finding.KnownRisks = 'Because nested group membership is often not obvious in a quick review, un-nesting can unexpectedly revoke privileged access from many users at once if the nested group''s full membership wasn''t understood beforehand.'
                    $finding.BackupRollback = 'Easy - re-add the nested group as a member if needed; effective on next Kerberos ticket refresh, no data loss.'
                    $finding.Details = @{
                        GroupDN = $group.DistinguishedName
                        NestedGroups = ($nestedGroups | Select-Object Name, DistinguishedName)
                    }
                    $findings += $finding
                }
                
                # Check for disabled or inactive users in privileged groups
                $userMembers = $recursiveMembers | Where-Object { $_.objectClass -eq 'user' }
                foreach ($member in $userMembers) {
                    $userDetails = $null
                    try {
                        # $groupServer, not $__adServer: a member can
                        # legitimately belong to a different domain than
                        # the group itself (see the Cross-Domain
                        # Privileged Group Membership finding above) - for
                        # the common same-domain case this is the correct
                        # server; a foreign-domain member's lookup fails
                        # gracefully into the existing catch below, same
                        # as before this change.
                        $userDetails = if ($groupServer) {
                            Get-ADUser -Identity $member -Server $groupServer -Properties Enabled, LastLogonDate -ErrorAction Stop
                        }
                        else {
                            Get-ADUser -Identity $member -Properties Enabled, LastLogonDate -ErrorAction Stop
                        }
                    }
                    catch {
                        Write-Verbose "Failed to get user details for '$($member.SamAccountName)': $_"
                    }

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
                        $finding.EstimatedEffort = 'Low - removing one already-disabled account from one group.'
                        $finding.KnownRisks = 'Essentially none - the account is already disabled and cannot authenticate, so removing its group membership has no functional impact; confirm it isn''t an intentionally disabled-but-provisioned break-glass account first.'
                        $finding.BackupRollback = 'Easy - re-add if needed; effective immediately, no functional impact either way since the account is disabled.'
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
    finally {
        if ($Server -and -not $__adAuditServerAlreadyActive) {
            Clear-ADSecurityAuditTargetServer
        }
    }
}

#endregion
