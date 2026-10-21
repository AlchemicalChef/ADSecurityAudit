#region KRBTGT Account Audits

function Test-KRBTGTAccount {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$MaxPasswordAgeDays = 180
    )
    
    Write-Verbose "Starting KRBTGT account security audit..."
    $findings = @()
    
    try {
        $krbtgtAccount = Get-ADUser -Filter "SamAccountName -eq 'krbtgt'" -Properties PasswordLastSet, Enabled, Description -Server (Get-ADSecurityAuditTargetServerValue) -ErrorAction Stop
        
        if ($krbtgtAccount.PasswordLastSet) {
            $passwordLastSet = $krbtgtAccount.PasswordLastSet
            $passwordAge = (Get-Date) - $passwordLastSet
            
            # Critical finding if KRBTGT password is too old
            if ($passwordAge.Days -gt $MaxPasswordAgeDays) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Security'
                $finding.Issue = 'KRBTGT Password Age Exceeds Recommended Threshold'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = 'krbtgt'
                $finding.Description = "The KRBTGT account password has not been changed in $($passwordAge.Days) days. Microsoft recommends changing it every 180 days."
                $finding.Impact = "An old KRBTGT password increases the window for Golden Ticket attacks. If compromised, attackers can forge Kerberos tickets with arbitrary privileges indefinitely."
                $finding.Remediation = "Reset the KRBTGT password twice (with appropriate intervals) using the official Microsoft script. WARNING: This is a sensitive operation that requires careful planning."
                $finding.EstimatedEffort = 'Medium - a KRBTGT reset needs to be done twice, roughly a replication cycle apart, to fully invalidate old tickets - this is a documented, deliberate two-step process, not a single trivial change.'
                $finding.KnownRisks = 'Resetting KRBTGT invalidates existing Kerberos tickets domain-wide once fully replicated; doing both resets in quick succession without allowing replication between them is the well-documented way to cause a temporary authentication disruption, so pace them one replication cycle apart.'
                $finding.BackupRollback = 'Hard/Limited - a password reset cannot be undone to the old value, only reset again; if issues arise, the fix is to complete the second reset and let replication converge, not to revert.'
                $finding.Details = @{
                    DistinguishedName = $krbtgtAccount.DistinguishedName
                    PasswordLastSet = $krbtgtAccount.PasswordLastSet
                    PasswordAgeDays = $passwordAge.Days
                    RecommendedMaxAgeDays = $MaxPasswordAgeDays
                }
                $findings += $finding
            }
            elseif ($passwordAge.Days -gt 90) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Security'
                $finding.Issue = 'KRBTGT Password Approaching Rotation Threshold'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = 'krbtgt'
                $finding.Description = "The KRBTGT account password is $($passwordAge.Days) days old and approaching the recommended rotation threshold."
                $finding.Impact = "Regular KRBTGT password rotation limits the window for Golden Ticket attacks."
                $finding.Remediation = "Plan to reset the KRBTGT password twice using the official Microsoft script before it exceeds 180 days."
                $finding.EstimatedEffort = 'Low - a routine, scheduled reset (or paced double reset) following Microsoft''s standard rotation cadence, timed for a low-usage window rather than reactive to an incident.'
                $finding.KnownRisks = 'Same ticket-invalidation risk as an overdue rotation, but being proactive/scheduled reduces disruption since it can be timed for a low-usage window.'
                $finding.BackupRollback = 'Hard/Limited - a password reset cannot be undone to the old value, only reset again.'
                $finding.Details = @{
                    DistinguishedName = $krbtgtAccount.DistinguishedName
                    PasswordLastSet = $krbtgtAccount.PasswordLastSet
                    PasswordAgeDays = $passwordAge.Days
                }
                $findings += $finding
            }
        }
        else {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Kerberos Security'
            $finding.Issue = 'KRBTGT Password Last Set Date Unknown'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = 'krbtgt'
            $finding.Description = "Unable to determine when the KRBTGT password was last changed."
            $finding.Impact = "Cannot assess risk of Golden Ticket attacks without knowing KRBTGT password age."
            $finding.Remediation = "Investigate why PasswordLastSet is not populated and reset the KRBTGT password."
            $finding.EstimatedEffort = 'Low - primarily an investigation into why the date is unreadable; if the password does turn out to be genuinely stale, treat it like the age-exceeded finding above.'
            $finding.KnownRisks = 'Same ticket-invalidation risk as an overdue rotation once a reset is actually performed.'
            $finding.BackupRollback = 'Hard/Limited - once reset, the password cannot be restored to a prior value.'
            $finding.OperationalNotes = 'Investigate why pwdLastSet is unreadable (a permissions or replication issue) before assuming the password is actually stale.'
            $finding.Details = @{
                DistinguishedName = $krbtgtAccount.DistinguishedName
            }
            $findings += $finding
        }
        
        Write-Verbose "KRBTGT account audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during KRBTGT audit: $_"
        throw
    }
}

#endregion

