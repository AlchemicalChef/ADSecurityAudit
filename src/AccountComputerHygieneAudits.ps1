#region Account/Computer Hygiene Gap Audits
#
# PingCastle/Semperis-comparable check(s): Semperis "Computer with no
# password set", "Distributed COM Users or Performance Log Users not
# empty". See files/18-account-computer-hygiene-gaps.md. (The other two
# checks from the same feature request - Built-in Guest Account Enabled,
# and Constrained Delegation Configured to Decommissioned SPN - live in
# UserAudits.ps1 and DomainAdminEquivalence.ps1 respectively, alongside
# the existing RID-500/delegation checks they extend.)
#
# DETECTION ONLY: both checks here are read-only attribute/membership
# reads. No AD write of any kind.

function Test-ADAccountComputerHygiene {
    <#
    .SYNOPSIS
        Audits two narrow account/computer hygiene gaps: never-joined
        computer objects with no password set, and under-audited
        built-in group membership.
    .DESCRIPTION
        Two independent, read-only checks:
          1. Computer Account Never Joined with No Password Set - a
             computer object pre-staged (e.g. via dsadd/automated
             provisioning) but never actually joined the domain, left in
             a permanently vulnerable, blank-password state. Identified
             by pwdLastSet = 0 combined with an old whenCreated (30+
             days) and no lastLogonTimestamp - the most reliable
             attribute combination available without live-network
             validation; confirm this combination against a real
             pre-staged computer object in your own environment before
             relying on it in a high-stakes context (see the doc's own
             Lab Test Notes).
          2. Broad Membership in Distributed COM Users or Performance
             Log Users - either built-in group has members beyond the
             expected, empty-by-default baseline.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param(
        # Days since creation before a zero-password, never-logged-on
        # computer object is treated as "never joined" rather than
        # possibly still mid-provisioning.
        [Parameter()]
        [int]$NeverJoinedAgeThresholdDays = 30
    )

    Write-Verbose "Starting Account/Computer Hygiene Gap audit..."
    $findings = @()
    $__adServer = Get-ADSecurityAuditTargetServerValue

    # -------------------------------------------------------------------
    # Check 1: Computer Account Never Joined with No Password Set
    # -------------------------------------------------------------------
    try {
        $allComputersHygiene = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADComputer (never-joined check)' -Query {
            Get-ADComputer -Filter '*' -Properties pwdLastSet, whenCreated, lastLogonTimestamp, DistinguishedName -ResultPageSize 500 -Server $__adServer -ErrorAction Stop
        })

        $neverJoinedComputers = @($allComputersHygiene | Where-Object {
            ($_.pwdLastSet -eq 0) -and
            (-not $_.lastLogonTimestamp) -and
            $_.whenCreated -and
            ((Get-Date) - $_.whenCreated).Days -ge $NeverJoinedAgeThresholdDays
        })

        if ($neverJoinedComputers.Count -gt 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Stale-Object & Hygiene Depth'
            $finding.Issue = 'Computer Account Never Joined with No Password Set'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = (($neverJoinedComputers | ForEach-Object { $_.Name }) -join ', ')
            $finding.Description = "$($neverJoinedComputers.Count) computer object(s) appear to have been pre-staged but never actually joined the domain (pwdLastSet=0, no lastLogonTimestamp, created $NeverJoinedAgeThresholdDays+ days ago): $(($neverJoinedComputers | ForEach-Object { $_.Name }) -join ', ')."
            $finding.Impact = "A pre-staged computer object that never joined has a blank/unset password, leaving it in a permanently vulnerable, lateral-movement-ready state - depending on domain policy, an attacker may be able to complete the join themselves and take over the computer identity, or otherwise abuse the blank-password state."
            $finding.Remediation = "For each listed object, confirm whether the intended join ever happened under a different computer name (a provisioning mismatch) or was abandoned. If abandoned, remove the stale computer object: Remove-ADComputer -Identity '<name>'. If still needed, complete the join promptly."
            $finding.EstimatedEffort = 'Low - removing or completing the join for each stale pre-staged object, but confirm with the provisioning team before removing in case the join is simply delayed rather than abandoned.'
            $finding.KnownRisks = 'Removing an object that is actually mid-provisioning (rather than genuinely abandoned) will require re-staging it - confirm current provisioning status with the responsible team first.'
            $finding.BackupRollback = 'Easy - a removed pre-staged object with no real join history can simply be re-created if needed; no real data loss.'
            $finding.Details = @{
                NeverJoinedComputers = @($neverJoinedComputers | ForEach-Object {
                    [PSCustomObject]@{
                        Name              = $_.Name
                        DistinguishedName = $_.DistinguishedName
                        WhenCreated       = $_.whenCreated
                    }
                })
                AgeThresholdDays = $NeverJoinedAgeThresholdDays
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADAccountComputerHygiene: no never-joined, blank-password computer objects found."
        }
    }
    catch {
        Write-Warning "Test-ADAccountComputerHygiene: never-joined computer check failed: $_"
    }

    # -------------------------------------------------------------------
    # Check 2: Broad Membership in Distributed COM Users or Performance
    # Log Users
    # -------------------------------------------------------------------
    $underAuditedGroups = @('Distributed COM Users', 'Performance Log Users')
    foreach ($groupName in $underAuditedGroups) {
        try {
            $group = $null
            try {
                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Server $__adServer -ErrorAction Stop
            }
            catch {
                Write-Verbose "Test-ADAccountComputerHygiene: could not resolve built-in group '$groupName' (may not exist in this domain): $_"
            }

            if (-not $group) { continue }

            $members = @()
            try {
                $members = @(Get-ADGroupMember -Identity $group -Server $__adServer -ErrorAction Stop)
            }
            catch {
                Write-Verbose "Test-ADAccountComputerHygiene: could not enumerate members of '$groupName': $_"
            }

            if ($members.Count -gt 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Privileged Groups'
                $finding.Issue = 'Broad Membership in Distributed COM Users or Performance Log Users'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $groupName
                $finding.Description = "Built-in group '$groupName' has $($members.Count) member(s), beyond the expected empty-by-default baseline: $(($members | ForEach-Object { $_.SamAccountName }) -join ', ')."
                $finding.Impact = "Distributed COM Users and Performance Log Users are both empty by default and carry non-trivial rights (launching/activating DCOM objects remotely, or remotely collecting performance-counter and event-trace data) that are rarely audited alongside the more commonly-reviewed privileged groups, making unexpected membership here an easy place for a persistence foothold to go unnoticed."
                $finding.Remediation = "Review each member's actual need for this group's rights. Remove any that lack a documented, current business justification: Remove-ADGroupMember -Identity '$groupName' -Members <member>"
                $finding.EstimatedEffort = 'Low - reviewing and removing membership from a typically-small, rarely-populated group.'
                $finding.KnownRisks = 'Removing a member who genuinely needs remote DCOM activation or remote performance-counter collection rights will break that specific workflow until re-added - confirm with the member/owning team first.'
                $finding.BackupRollback = 'Easy - re-add any member whose need is confirmed; effective on next Kerberos ticket refresh, no data loss.'
                $finding.Details = @{
                    GroupDN = $group.DistinguishedName
                    Members = ($members | Select-Object Name, SamAccountName, DistinguishedName)
                }
                $findings += $finding
            }
            else {
                Write-Verbose "Test-ADAccountComputerHygiene: '$groupName' is empty (expected default state)."
            }
        }
        catch {
            Write-Warning "Test-ADAccountComputerHygiene: error checking group '$groupName': $_"
        }
    }

    Write-Verbose "Account/Computer Hygiene Gap audit complete. Found $($findings.Count) issue(s)."
    return $findings
}

#endregion
