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

