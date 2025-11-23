#region LAPS Deployment Audits

function Test-LAPSDeployment {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting LAPS deployment audit..."
    $findings = @()
    
    try {
        $domain = Get-ADDomain
        $schemaPath = "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$($domain.DistinguishedName)"
        
        # Check if LAPS schema is extended
        try {
            $lapsSchema = Get-ADObject -Identity $schemaPath -ErrorAction Stop
            $lapsInstalled = $true
            Write-Verbose "LAPS schema extension detected."
        }
        catch {
            $lapsInstalled = $false
            
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'LAPS Deployment'
            $finding.Issue = 'LAPS Not Deployed'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.AffectedObject = 'Domain'
            $finding.Description = "Local Administrator Password Solution (LAPS) is not deployed in the domain. LAPS schema extensions are missing."
            $finding.Impact = "Without LAPS, local administrator passwords across workstations and servers are likely identical or predictable, facilitating lateral movement."
            $finding.Remediation = "Deploy LAPS to randomize and manage local administrator passwords across all domain computers. Install LAPS schema: Update-AdmPwdADSchema"
            $finding.Details = @{
                Domain = $domain.DNSRoot
            }
            $findings += $finding
            
            Write-Verbose "LAPS not deployed. Skipping computer-level checks."
            return $findings
        }
        
        # If LAPS is installed, check computer coverage
        if ($lapsInstalled) {
            $computers = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime, OperatingSystem -ErrorAction Stop
            $computersWithLAPS = $computers | Where-Object { $_.'ms-Mcs-AdmPwdExpirationTime' }
            $computersWithoutLAPS = $computers | Where-Object { -not $_.'ms-Mcs-AdmPwdExpirationTime' }
            
            $totalComputers = $computers.Count
            $coveragePercent = if ($totalComputers -gt 0) { 
                [math]::Round(($computersWithLAPS.Count / $totalComputers) * 100, 2) 
            } else { 0 }
            
            Write-Verbose "LAPS coverage: $coveragePercent% ($($computersWithLAPS.Count)/$totalComputers computers)"
            
            # Alert if coverage is below 100%
            if ($coveragePercent -lt 100) {
                $severity = if ($coveragePercent -lt 50) { 'Critical' } 
                           elseif ($coveragePercent -lt 80) { 'High' } 
                           else { 'Medium' }
                           
                $severityLevel = if ($coveragePercent -lt 50) { 4 } 
                                elseif ($coveragePercent -lt 80) { 3 } 
                                else { 2 }
                
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'LAPS Deployment'
                $finding.Issue = 'Incomplete LAPS Coverage'
                $finding.Severity = $severity
                $finding.SeverityLevel = $severityLevel
                $finding.AffectedObject = "$($computersWithoutLAPS.Count) Computers"
                $finding.Description = "Only $coveragePercent% of domain computers have LAPS passwords set. $($computersWithoutLAPS.Count) computers are missing LAPS coverage."
                $finding.Impact = "Computers without LAPS retain static local administrator passwords, creating lateral movement opportunities for attackers."
                $finding.Remediation = "Deploy LAPS Group Policy to all OUs containing computers. Verify LAPS client is installed and GPO is applied. Check: gpresult /r"
                $finding.Details = @{
                    TotalComputers = $totalComputers
                    ComputersWithLAPS = $computersWithLAPS.Count
                    ComputersWithoutLAPS = $computersWithoutLAPS.Count
                    CoveragePercent = $coveragePercent
                    SampleComputersWithoutLAPS = ($computersWithoutLAPS | Select-Object -First 10 -ExpandProperty Name) -join ', '
                }
                $findings += $finding
            }
            
            # Check for expired LAPS passwords
            $now = [DateTime]::UtcNow
            $expiredLAPSComputers = $computersWithLAPS | Where-Object {
                $expirationTime = [DateTime]::FromFileTimeUtc($_.'ms-Mcs-AdmPwdExpirationTime')
                $expirationTime -lt $now
            }
            
            if ($expiredLAPSComputers.Count -gt 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'LAPS Deployment'
                $finding.Issue = 'Expired LAPS Passwords'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = "$($expiredLAPSComputers.Count) Computers"
                $finding.Description = "$($expiredLAPSComputers.Count) computers have expired LAPS passwords that have not been rotated."
                $finding.Impact = "Expired passwords may indicate computers that are offline, not receiving GPO updates, or have LAPS client issues."
                $finding.Remediation = "Investigate why LAPS passwords are not rotating. Ensure computers are online and receiving Group Policy updates."
                $finding.Details = @{
                    ExpiredCount = $expiredLAPSComputers.Count
                    SampleComputers = ($expiredLAPSComputers | Select-Object -First 10 -ExpandProperty Name) -join ', '
                }
                $findings += $finding
            }
        }
        
        Write-Verbose "LAPS deployment audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during LAPS audit: $_"
        throw
    }
}

#endregion

