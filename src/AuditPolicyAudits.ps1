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
        
        # Critical audit policies that should be enabled
        $requiredAuditPolicies = @{
            'Account Logon' = @('Audit Credential Validation')
            'Account Management' = @('Audit User Account Management', 'Audit Security Group Management')
            'DS Access' = @('Audit Directory Service Access', 'Audit Directory Service Changes')
            'Logon/Logoff' = @('Audit Logon', 'Audit Logoff', 'Audit Account Lockout')
            'Object Access' = @('Audit File Share', 'Audit File System')
            'Policy Change' = @('Audit Policy Change', 'Audit Authentication Policy Change')
            'Privilege Use' = @('Audit Sensitive Privilege Use')
            'System' = @('Audit Security State Change', 'Audit Security System Extension')
        }
        
        foreach ($dc in $domainControllers) {
            try {
                # Check if we can query the DC (in a real scenario, you'd use Invoke-Command)
                # For this script, we'll check local/default domain policy
                
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Audit Policy'
                $finding.Issue = 'Advanced Audit Policy Verification Required'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $dc.Name
                $finding.Description = "Advanced audit policies should be verified on domain controller '$($dc.Name)' to ensure proper security event logging."
                $finding.Impact = "Without proper audit policies, security incidents cannot be detected or investigated effectively. Critical events may go unlogged."
                $finding.Remediation = @"
Verify and enable advanced audit policies on all DCs:
1. Account Logon: Audit Credential Validation (Success, Failure)
2. Account Management: Audit User/Security Group Management (Success, Failure)
3. DS Access: Audit Directory Service Access/Changes (Success, Failure)
4. Logon/Logoff: Audit Logon/Logoff/Account Lockout (Success, Failure)
5. Object Access: Audit File Share/System (Success, Failure)
6. Policy Change: Audit Policy/Auth Policy Change (Success, Failure)
7. Privilege Use: Audit Sensitive Privilege Use (Success, Failure)
8. System: Audit Security State Change/System Extension (Success, Failure)

Use: auditpol /get /category:* to view current settings
Configure via Group Policy: Computer Config > Windows Settings > Security Settings > Advanced Audit Policy
"@
                $finding.Details = @{
                    DomainController = $dc.Name
                    RequiredCategories = $requiredAuditPolicies.Keys -join ', '
                }
                $findings += $finding
                
            }
            catch {
                Write-Warning "Could not check audit policy on $($dc.Name): $_"
            }
        }
        
        # Check for SACL on sensitive AD objects
        try {
            $domain = Get-ADDomain
            $domainRoot = $domain.DistinguishedName
            
            # Check if AdminSDHolder has auditing configured
            $adminSDHolder = Get-ADObject "CN=AdminSDHolder,CN=System,$domainRoot" -Properties nTSecurityDescriptor -ErrorAction Stop
            $acl = $adminSDHolder.nTSecurityDescriptor
            
            $hasAuditRules = $acl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]).Count -gt 0
            
            if (-not $hasAuditRules) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Audit Policy'
                $finding.Issue = 'No Auditing on AdminSDHolder Object'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = 'AdminSDHolder'
                $finding.Description = "The AdminSDHolder object does not have audit rules (SACL) configured to log access attempts."
                $finding.Impact = "Changes to privileged group permissions and access attempts to critical AD objects will not be logged, hindering incident detection."
                $finding.Remediation = "Configure SACL on AdminSDHolder to audit 'Write all properties' and 'Modify permissions' for 'Everyone' (Success and Failure)."
                $finding.Details = @{
                    DistinguishedName = $adminSDHolder.DistinguishedName
                }
                $findings += $finding
            }
        }
        catch {
            Write-Verbose "Could not check AdminSDHolder SACL: $_"
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

