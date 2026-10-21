#region LAPS Deployment Audits

function Test-LAPSDeployment {
    <#
    .SYNOPSIS
        Audits LAPS schema presence, computer coverage, and password expiration.
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Starting LAPS deployment audit..."
    $findings = @()

    try {
        $__adServer = Get-ADSecurityAuditTargetServerValue
        $domain = Get-ADDomain -Server $__adServer
        
        # Get the proper schema naming context from RootDSE
        $rootDSE = Get-ADRootDSE -Server $__adServer
        $schemaPath = "CN=ms-Mcs-AdmPwd,$($rootDSE.schemaNamingContext)"
        
        # Check if LAPS schema is extended
        try {
            $lapsSchema = Get-ADObject -Identity $schemaPath -Server $__adServer -ErrorAction Stop
            $lapsInstalled = $true
            Write-Verbose "LAPS schema extension detected."
        }
        catch {
            $lapsInstalled = $false
            
            # Also check for Windows LAPS (newer schema attribute)
            try {
                $windowsLapsSchema = "CN=ms-LAPS-Password,$($rootDSE.schemaNamingContext)"
                $windowsLaps = Get-ADObject -Identity $windowsLapsSchema -Server $__adServer -ErrorAction Stop
                $lapsInstalled = $true
                Write-Verbose "Windows LAPS schema extension detected."
            }
            catch {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'LAPS Deployment'
                $finding.Issue = 'LAPS Not Deployed'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = 'Domain'
                $finding.Description = "Local Administrator Password Solution (LAPS) is not deployed in the domain. LAPS schema extensions are missing."
                $finding.Impact = "Without LAPS, local administrator passwords across workstations and servers are likely identical or predictable, facilitating lateral movement."
                $finding.Remediation = "Deploy LAPS to randomize and manage local administrator passwords across all domain computers. For legacy LAPS: Update-AdmPwdADSchema. For Windows LAPS (Server 2019+): Update-LapsADSchema"
                $finding.EstimatedEffort = 'High - full deployment requires a one-time forest-wide schema extension, GPO creation, delegated read-rights setup, and a phased client/CSE rollout with a validation period - an environment-wide project, not a single change.'
                $finding.KnownRisks = 'Low ongoing technical risk to normal operations; the one-time schema extension step is itself an irreversible forest-wide schema change, so test/confirm it in a non-production domain first if possible.'
                $finding.BackupRollback = 'Hard/Limited - the schema extension itself can''t be undone (attributes are marked defunct, not removed, consistent with schema changes generally); the GPO/policy rollout portion, however, can be unlinked or removed cleanly at any time.'
                $finding.Details = @{
                    Domain = $domain.DNSRoot
                    LegacySchemaPath = $schemaPath
                }
                $findings += $finding
                
                Write-Verbose "LAPS not deployed. Skipping computer-level checks."
                return $findings
            }
        }
        
        # If LAPS is installed, check computer coverage
        if ($lapsInstalled) {
            # --- Legacy LAPS SearchFlags check
            # (files/17-key-material-exposure.md) ---
            # ms-Mcs-AdmPwd's schema searchFlags controls whether the
            # attribute is exposed beyond the intended restricted ACL
            # (the confidential bit). Only applicable when the legacy
            # schema attribute is actually present - Windows LAPS's newer
            # msLAPS-Password uses a different confidentiality mechanism
            # and is out of scope for this specific check. Single schema
            # read, not per-computer.
            try {
                $lapsAttributeSchema = Get-ADObject -Identity $schemaPath -Properties searchFlags -Server $__adServer -ErrorAction Stop
                if ($lapsAttributeSchema -and $null -ne $lapsAttributeSchema.searchFlags) {
                    $searchFlagsValue = [int]$lapsAttributeSchema.searchFlags
                    # fCONFIDENTIAL = 0x00000080. Microsoft's documented,
                    # correctly-locked-down default for ms-Mcs-AdmPwd sets
                    # this bit so the value is not readable via a normal
                    # attribute read even by a principal with generic read
                    # access - only via an explicit ACE granting
                    # CONTROL_ACCESS. A deployment where this bit is
                    # cleared exposes the password more broadly than the
                    # deployment's own per-computer ACLs would suggest.
                    $isConfidential = [bool]($searchFlagsValue -band 0x80)
                    if (-not $isConfidential) {
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'LAPS Deployment'
                        $finding.Issue = 'Legacy LAPS SearchFlags Exposes Password'
                        $finding.Severity = 'High'
                        $finding.SeverityLevel = 3
                        $finding.AffectedObject = 'ms-Mcs-AdmPwd (schema attribute)'
                        $finding.Description = "The ms-Mcs-AdmPwd schema attribute's searchFlags value ($searchFlagsValue) does not have the confidential (fCONFIDENTIAL, 0x80) bit set."
                        $finding.Impact = "Without the confidential bit set on this attribute's schema definition, ms-Mcs-AdmPwd can be read by any principal with generic read access to a computer object, rather than being restricted to principals holding an explicit CONTROL_ACCESS right - exposing legacy LAPS passwords more broadly than the deployment's actual per-computer ACLs would suggest."
                        $finding.Remediation = "Set the fCONFIDENTIAL bit (0x80) on ms-Mcs-AdmPwd's schema searchFlags value via ADSI Edit or PowerShell against the schema-master DC, following Microsoft's documented LAPS schema hardening guidance, then confirm read access is still correctly scoped afterward."
                        $finding.EstimatedEffort = 'Medium - a schema attribute change (Schema Admins, schema-master DC) that also changes the effective access-control model for this attribute; validate in a lab first and confirm intended readers still have explicit CONTROL_ACCESS granted before applying to production.'
                        $finding.KnownRisks = 'Setting the confidential bit changes ms-Mcs-AdmPwd from a normal-read attribute to one requiring explicit CONTROL_ACCESS - any tooling or delegated group that currently reads it via ordinary read access will need that access re-granted as CONTROL_ACCESS afterward.'
                        $finding.BackupRollback = 'Difficult - schema attribute changes are effectively permanent (schema changes are not typically reverted); test thoroughly in a lab and confirm the full set of legitimate readers before applying.'
                        $finding.Details = @{
                            DistinguishedName = $lapsAttributeSchema.DistinguishedName
                            SearchFlags       = $searchFlagsValue
                        }
                        $findings += $finding
                    }
                }
            }
            catch {
                Write-Verbose "Test-LAPSDeployment: could not read ms-Mcs-AdmPwd schema searchFlags (legacy LAPS SearchFlags check) - likely Windows-LAPS-only deployment, or schema not accessible: $_"
            }

            # Check for both legacy LAPS and Windows LAPS attributes
            $computers = Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime', OperatingSystem -ResultPageSize 500 -Server $__adServer -ErrorAction Stop
            
            $computersWithLAPS = $computers | Where-Object { 
                $_.'ms-Mcs-AdmPwdExpirationTime' -or $_.'msLAPS-PasswordExpirationTime' 
            }
            $computersWithoutLAPS = $computers | Where-Object { 
                -not $_.'ms-Mcs-AdmPwdExpirationTime' -and -not $_.'msLAPS-PasswordExpirationTime' 
            }
            
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
                $finding.EstimatedEffort = 'Medium - extending the LAPS GPO/CSE to additional OUs or computers, and validating the schema attributes and client/CSE are present on the newly covered machines.'
                $finding.KnownRisks = 'Low technical risk deploying LAPS more broadly; the main risk is procedural - confirm target computers are already schema-extended and have the LAPS client installed before expecting the GPO to take effect.'
                $finding.BackupRollback = 'Easy - remove the GPO link/scope for the newly covered OUs if needed; LAPS-managed passwords already set remain valid, no data loss.'
                $finding.Details = @{
                    TotalComputers = $totalComputers
                    ComputersWithLAPS = $computersWithLAPS.Count
                    ComputersWithoutLAPS = $computersWithoutLAPS.Count
                    CoveragePercent = $coveragePercent
                    SampleComputersWithoutLAPS = ($computersWithoutLAPS | Select-Object -First 10 -ExpandProperty Name) -join ', '
                }
                $findings += $finding
            }
            
            # Check for expired LAPS passwords (legacy LAPS)
            $now = [DateTime]::UtcNow
            $expiredLAPSComputers = $computersWithLAPS | Where-Object {
                if ($_.'ms-Mcs-AdmPwdExpirationTime') {
                    try {
                        $expirationTime = [DateTime]::FromFileTimeUtc($_.'ms-Mcs-AdmPwdExpirationTime')
                        return $expirationTime -lt $now
                    }
                    catch {
                        return $false
                    }
                }
                elseif ($_.'msLAPS-PasswordExpirationTime') {
                    try {
                        $expirationTime = [DateTime]::FromFileTimeUtc($_.'msLAPS-PasswordExpirationTime')
                        return $expirationTime -lt $now
                    }
                    catch {
                        return $false
                    }
                }
                return $false
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
                $finding.EstimatedEffort = 'Low - LAPS rotates each computer''s password on its own schedule; an expired password typically self-corrects at the next rotation unless something is blocking it.'
                $finding.KnownRisks = 'Low risk; forcing an immediate rotation on affected computers just changes the local admin password, with no compatibility impact beyond any manual process needing to fetch the new password from AD afterward.'
                $finding.BackupRollback = 'Easy - LAPS keeps rotating on its own; there is no rollback needed, since a new randomly generated password is the intended end state.'
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
