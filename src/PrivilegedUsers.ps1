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
                $group = $null
                try {
                    $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Properties Members, Description -ErrorAction Stop
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
                    $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop
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
                        $user = Get-ADUser -Identity $member -Properties * -ErrorAction Stop
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
}

#endregion

