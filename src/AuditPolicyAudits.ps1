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
        
        # Critical audit subcategories that should be enabled (Success and Failure)
        $criticalAuditCategories = @{
            # Account Logon
            'Credential Validation' = @{ Category = 'Account Logon'; MinimumSetting = 'Success and Failure' }
            'Kerberos Authentication Service' = @{ Category = 'Account Logon'; MinimumSetting = 'Success and Failure' }
            'Kerberos Service Ticket Operations' = @{ Category = 'Account Logon'; MinimumSetting = 'Success and Failure' }
            
            # Account Management
            'User Account Management' = @{ Category = 'Account Management'; MinimumSetting = 'Success and Failure' }
            'Security Group Management' = @{ Category = 'Account Management'; MinimumSetting = 'Success and Failure' }
            'Computer Account Management' = @{ Category = 'Account Management'; MinimumSetting = 'Success and Failure' }
            
            # DS Access
            'Directory Service Access' = @{ Category = 'DS Access'; MinimumSetting = 'Success and Failure' }
            'Directory Service Changes' = @{ Category = 'DS Access'; MinimumSetting = 'Success and Failure' }
            
            # Logon/Logoff
            'Logon' = @{ Category = 'Logon/Logoff'; MinimumSetting = 'Success and Failure' }
            'Logoff' = @{ Category = 'Logon/Logoff'; MinimumSetting = 'Success' }
            'Account Lockout' = @{ Category = 'Logon/Logoff'; MinimumSetting = 'Failure' }
            'Special Logon' = @{ Category = 'Logon/Logoff'; MinimumSetting = 'Success' }
            
            # Policy Change
            'Audit Policy Change' = @{ Category = 'Policy Change'; MinimumSetting = 'Success and Failure' }
            'Authentication Policy Change' = @{ Category = 'Policy Change'; MinimumSetting = 'Success' }
            
            # Privilege Use
            'Sensitive Privilege Use' = @{ Category = 'Privilege Use'; MinimumSetting = 'Success and Failure' }
            
            # System
            'Security State Change' = @{ Category = 'System'; MinimumSetting = 'Success' }
            'Security System Extension' = @{ Category = 'System'; MinimumSetting = 'Success and Failure' }
        }
        
        # Try to check audit policy on DCs
        foreach ($dc in $domainControllers) {
            $dcName = $dc.HostName
            $auditPolicyChecked = $false
            $missingPolicies = @()
            
            try {
                # Try to run auditpol remotely
                Write-Verbose "Checking audit policies on $dcName..."
                
                $auditpolOutput = Invoke-Command -ComputerName $dcName -ScriptBlock {
                    $output = auditpol /get /category:* 2>&1
                    return $output
                } -ErrorAction Stop
                
                $auditPolicyChecked = $true
                
                # Parse auditpol output
                $currentSubcategory = $null
                foreach ($line in $auditpolOutput) {
                    $lineStr = $line.ToString().Trim()
                    
                    # Look for subcategory settings
                    foreach ($subcategory in $criticalAuditCategories.Keys) {
                        if ($lineStr -match "^\s*$([regex]::Escape($subcategory))\s+(.+)$") {
                            $setting = $Matches[1].Trim()
                            $required = $criticalAuditCategories[$subcategory].MinimumSetting
                            
                            # Check if the setting meets minimum requirements
                            $isCompliant = $false
                            
                            switch ($required) {
                                'Success and Failure' {
                                    $isCompliant = ($setting -match 'Success and Failure')
                                }
                                'Success' {
                                    $isCompliant = ($setting -match 'Success')
                                }
                                'Failure' {
                                    $isCompliant = ($setting -match 'Failure')
                                }
                            }
                            
                            if (-not $isCompliant -and $setting -notmatch 'Success and Failure') {
                                $missingPolicies += @{
                                    Subcategory = $subcategory
                                    Category = $criticalAuditCategories[$subcategory].Category
                                    CurrentSetting = $setting
                                    RequiredSetting = $required
                                }
                            }
                        }
                    }
                }
                
                # Create findings for missing policies
                if ($missingPolicies.Count -gt 0) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Audit Policy'
                    $finding.Issue = 'Insufficient Audit Policy Configuration'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $dcName
                    $finding.Description = "Domain Controller '$dcName' has $($missingPolicies.Count) audit subcategories not configured to recommended settings."
                    $finding.Impact = "Without proper audit policies, security incidents cannot be detected or investigated effectively. Critical events may go unlogged."
                    
                    $remediationList = $missingPolicies | ForEach-Object {
                        "- $($_.Subcategory): Current='$($_.CurrentSetting)', Required='$($_.RequiredSetting)'"
                    }
                    
                    $finding.Remediation = @"
Configure the following audit policies via Group Policy (Computer Config > Windows Settings > Security Settings > Advanced Audit Policy):

$($remediationList -join "`n")

Or use auditpol.exe:
$(($missingPolicies | ForEach-Object { "auditpol /set /subcategory:`"$($_.Subcategory)`" /success:enable /failure:enable" }) -join "`n")
"@
                    $finding.Details = @{
                        DomainController = $dcName
                        MissingPolicies = $missingPolicies
                        TotalMissing = $missingPolicies.Count
                    }
                    $findings += $finding
                }
            }
            catch {
                Write-Verbose "Could not remotely check audit policy on $dcName : $_"
                
                # Fall back to advisory finding
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Audit Policy'
                $finding.Issue = 'Advanced Audit Policy Verification Required'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $dcName
                $finding.Description = "Could not remotely verify audit policies on domain controller '$dcName'. Manual verification is required."
                $finding.Impact = "Without proper audit policies, security incidents cannot be detected or investigated effectively. Critical events may go unlogged."
                $finding.Remediation = @"
Verify and enable advanced audit policies on this DC by running:
auditpol /get /category:*

Ensure the following are enabled (Success and Failure):
- Account Logon: Credential Validation, Kerberos Authentication Service
- Account Management: User/Security Group/Computer Account Management
- DS Access: Directory Service Access/Changes
- Logon/Logoff: Logon, Special Logon, Account Lockout
- Policy Change: Audit Policy Change, Authentication Policy Change
- Privilege Use: Sensitive Privilege Use
- System: Security State Change, Security System Extension

Configure via Group Policy: Computer Config > Windows Settings > Security Settings > Advanced Audit Policy
"@
                $finding.Details = @{
                    DomainController = $dcName
                    Error = $_.Exception.Message
                    RemoteCheckFailed = $true
                }
                $findings += $finding
            }
        }
        
        # Check for SACL on sensitive AD objects
        try {
            $domain = Get-ADDomain
            $domainRoot = $domain.DistinguishedName
            
            # Check if AdminSDHolder has auditing configured
            $adminSDHolder = Get-ADObject "CN=AdminSDHolder,CN=System,$domainRoot" -Properties nTSecurityDescriptor -ErrorAction Stop
            $acl = $adminSDHolder.nTSecurityDescriptor
            
            $hasAuditRules = $false
            try {
                $auditRules = $acl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier])
                $hasAuditRules = $auditRules.Count -gt 0
            }
            catch {
                Write-Verbose "Could not get audit rules: $_"
            }
            
            if (-not $hasAuditRules) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Audit Policy'
                $finding.Issue = 'No Auditing on AdminSDHolder Object'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = 'AdminSDHolder'
                $finding.Description = "The AdminSDHolder object does not have audit rules (SACL) configured to log access attempts."
                $finding.Impact = "Changes to privileged group permissions and access attempts to critical AD objects will not be logged, hindering incident detection."
                $finding.Remediation = @"
Configure SACL on AdminSDHolder to audit modifications:
1. Open ADSI Edit
2. Navigate to CN=AdminSDHolder,CN=System,DC=domain,DC=com
3. Right-click > Properties > Security > Advanced > Auditing
4. Add: Everyone | Success/Failure | Write all properties, Modify permissions

Or use PowerShell:
`$path = "AD:CN=AdminSDHolder,CN=System,$domainRoot"
`$acl = Get-Acl `$path
`$auditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule([System.Security.Principal.SecurityIdentifier]'S-1-1-0', 'WriteProperty,WriteDacl', 'Success,Failure', [guid]::Empty)
`$acl.AddAuditRule(`$auditRule)
Set-Acl `$path `$acl
"@
                $finding.Details = @{
                    DistinguishedName = $adminSDHolder.DistinguishedName
                }
                $findings += $finding
            }
            
            # Check domain root SACL
            $domainObj = Get-ADObject $domainRoot -Properties nTSecurityDescriptor -ErrorAction Stop
            $domainAcl = $domainObj.nTSecurityDescriptor
            
            $hasDomainAuditRules = $false
            try {
                $domainAuditRules = $domainAcl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier])
                $hasDomainAuditRules = $domainAuditRules.Count -gt 0
            }
            catch {
                Write-Verbose "Could not get domain audit rules: $_"
            }
            
            if (-not $hasDomainAuditRules) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Audit Policy'
                $finding.Issue = 'No Auditing on Domain Root Object'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = 'Domain Root'
                $finding.Description = "The domain root object does not have audit rules (SACL) configured."
                $finding.Impact = "Critical changes to domain-level permissions and replication rights will not be logged."
                $finding.Remediation = "Configure SACL on the domain root to audit Write Property, Modify Permissions, and Extended Rights for Everyone."
                $finding.Details = @{
                    DistinguishedName = $domainRoot
                }
                $findings += $finding
            }
        }
        catch {
            Write-Verbose "Could not check object SACLs: $_"
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
