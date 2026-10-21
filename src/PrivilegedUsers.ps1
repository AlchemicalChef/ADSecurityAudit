#region Privileged Users Enumeration

function Get-ADPrivilegedUsers {
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
    
    Write-Verbose "Enumerating all privileged users..."

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
        # not relying on the $PSDefaultParameterValues injection alone.
        # $null when no override is active, which Get-AD* cmdlets treat
        # identically to -Server being omitted entirely.
        $__adServer = Get-ADSecurityAuditActiveServerOverride
        $domain = if ($__adServer) { Get-ADDomain -Server $__adServer } else { Get-ADDomain }
        $privilegedUsersList = [System.Collections.ArrayList]::new()
        $processedUsers = @{}
        
        $groupCount = $Script:ProtectedGroups.Count
        $currentGroup = 0
        
        foreach ($groupName in $Script:ProtectedGroups) {
            $currentGroup++
            Write-Progress -Activity "Enumerating Privileged Users" -Status "Processing group: $groupName" `
                -PercentComplete (($currentGroup / $groupCount) * 100)
            
            try {
                $group = $null
                try {
                    $group = if ($__adServer) {
                        Get-ADGroup -Filter "Name -eq '$groupName'" -Server $__adServer -Properties Members, Description -ErrorAction Stop
                    }
                    else {
                        Get-ADGroup -Filter "Name -eq '$groupName'" -Properties Members, Description -ErrorAction Stop
                    }
                }
                catch {
                    Write-Verbose "Failed to get group '$groupName': $_"
                }

                if (-not $group) {
                    Write-Verbose "Group '$groupName' not found, skipping..."
                    continue
                }

                Write-Verbose "Processing group: $groupName"

                # Get all members recursively
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
                    Write-Verbose "Failed to get members of group '$groupName': $_"
                }

                if (-not $members) {
                    continue
                }

                # Filter to only user objects
                $userMembers = $members | Where-Object { $_.objectClass -eq 'user' }

                foreach ($member in $userMembers) {
                    # Get full user details
                    $user = $null
                    try {
                        $user = if ($__adServer) {
                            Get-ADUser -Identity $member -Server $__adServer -Properties * -ErrorAction Stop
                        }
                        else {
                            Get-ADUser -Identity $member -Properties * -ErrorAction Stop
                        }
                    }
                    catch {
                        Write-Verbose "Failed to get user details for '$($member.SamAccountName)': $_"
                    }

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
    finally {
        if ($Server -and -not $__adAuditServerAlreadyActive) {
            Clear-ADSecurityAuditTargetServer
        }
    }
}

#endregion

