#region Domain Trust Audits

function Test-ADDomainTrusts {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting domain trust security audit..."
    $findings = @()
    
    try {
        $domain = Get-ADDomain
        $trusts = Get-ADTrust -Filter * -Properties *
        
        if (-not $trusts) {
            Write-Verbose "No domain trusts found."
            return $findings
        }
        
        Write-Verbose "Analyzing $($trusts.Count) domain trust(s)..."
        
        foreach ($trust in $trusts) {
            # Check for bidirectional trusts
            if ($trust.Direction -eq 'Bidirectional') {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Domain Trusts'
                $finding.Issue = 'Bidirectional Domain Trust'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $trust.Target
                $finding.Description = "Bidirectional trust exists with domain '$($trust.Target)', allowing authentication in both directions."
                $finding.Impact = "Increases attack surface as compromise of either domain could affect the other. Consider if bidirectional trust is necessary."
                $finding.Remediation = "Review if bidirectional trust is required. If not, convert to one-way trust or implement selective authentication."
                $finding.Details = @{
                    Target = $trust.Target
                    Direction = $trust.Direction
                    TrustType = $trust.TrustType
                    Created = $trust.Created
                }
                $findings += $finding
            }
            
            # Check if SID filtering is disabled (critical security issue)
            if ($trust.SIDFilteringQuarantined -eq $false -and $trust.TrustType -eq 'External') {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Domain Trusts'
                $finding.Issue = 'SID Filtering Disabled on External Trust'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $trust.Target
                $finding.Description = "SID filtering is disabled on external trust with '$($trust.Target)', allowing SID history injection attacks."
                $finding.Impact = "Attackers in the trusted domain could forge credentials with privileged SIDs from your domain, leading to privilege escalation."
                $finding.Remediation = "Enable SID filtering: netdom trust $($domain.DNSRoot) /domain:$($trust.Target) /quarantine:yes"
                $finding.Details = @{
                    Target = $trust.Target
                    TrustType = $trust.TrustType
                    SIDFilteringQuarantined = $trust.SIDFilteringQuarantined
                }
                $findings += $finding
            }
            
            # Check for trusts without selective authentication
            if ($trust.SelectiveAuthentication -eq $false -and $trust.TrustType -eq 'Forest') {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Domain Trusts'
                $finding.Issue = 'Forest Trust Without Selective Authentication'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $trust.Target
                $finding.Description = "Forest trust with '$($trust.Target)' does not use selective authentication, granting broad access."
                $finding.Impact = "All users in the trusted forest can authenticate to resources in this domain without explicit permission."
                $finding.Remediation = "Enable selective authentication to require explicit permission for cross-forest access."
                $finding.Details = @{
                    Target = $trust.Target
                    TrustType = $trust.TrustType
                    SelectiveAuthentication = $trust.SelectiveAuthentication
                }
                $findings += $finding
            }
            
            # Check trust password age
            if ($trust.Modified) {
                $trustAge = (Get-Date) - $trust.Modified
                if ($trustAge.Days -gt 30) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Domain Trusts'
                    $finding.Issue = 'Trust Password Not Recently Rotated'
                    $finding.Severity = 'Low'
                    $finding.SeverityLevel = 1
                    $finding.AffectedObject = $trust.Target
                    $finding.Description = "Trust with '$($trust.Target)' has not been modified in $($trustAge.Days) days. Trust passwords should rotate automatically every 30 days."
                    $finding.Impact = "May indicate trust relationship issues or lack of maintenance."
                    $finding.Remediation = "Verify trust health: netdom trust $($domain.DNSRoot) /domain:$($trust.Target) /verify"
                    $finding.Details = @{
                        Target = $trust.Target
                        LastModified = $trust.Modified
                        DaysSinceModified = $trustAge.Days
                    }
                    $findings += $finding
                }
            }
        }
        
        Write-Verbose "Domain trust audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during domain trust audit: $_"
        throw
    }
}

#endregion

