#region LSA Protection (RunAsPPL) Audit
#
# Checks whether LSA Protection (RunAsPPL) is enabled on each Domain
# Controller - the primary mitigation named in ASD/CISA/NSA/CCCS/NCSC-NZ/
# NCSC-UK's "Detecting and mitigating Active Directory compromises" (Sept
# 2026) for Skeleton Key and other LSASS-process-tampering techniques.
# With LSA Protection enabled, only signed, Microsoft-trusted drivers/
# plugins can load into the LSASS process, and non-protected processes
# cannot open a handle to it - both required steps for Skeleton Key,
# credential-dumping tools (e.g. Mimikatz), and similar in-memory LSASS
# tampering.
#
# DETECTION ONLY: this reads a single registry value
# (HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL) per Domain
# Controller via remote registry / Invoke-Command. It never modifies the
# value, never accesses the LSASS process itself, and performs no
# credential access, dumping, or exploitation of any kind.

function Test-ADLsaProtection {
    <#
    .SYNOPSIS
        Audits whether LSA Protection (RunAsPPL) is enabled on each
        Domain Controller.
    .DESCRIPTION
        For each Domain Controller, reads
        HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL. A value of 1
        or 2 enables LSA Protection (2 additionally requires a UEFI
        variable-backed configuration, unlockable only by a local admin
        session, but either value is treated as "enabled" here since both
        require the LSASS-tampering mitigation to be bypassed via a
        vulnerable/malicious kernel driver rather than a simple registry
        edit). Missing or 0 means LSA Protection is not enabled.

        Each DC is evaluated independently and degrades gracefully if it
        cannot be reached (a Verbose note is emitted; no terminating
        error, and that DC is simply excluded from the finding's affected
        list rather than assumed compliant or non-compliant).
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Starting LSA Protection (RunAsPPL) audit..."
    $findings = @()

    $domainControllers = @()
    try {
        # Get-ADSecurityAuditDomainController, not a bare
        # Get-ADDomainController -Filter * - the latter is forest-wide
        # regardless of -Server; see Common.ps1 for why.
        $domainControllers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADSecurityAuditDomainController (LSA Protection audit)' -Query {
            Get-ADSecurityAuditDomainController -Server (Get-ADSecurityAuditTargetServerValue)
        })
    }
    catch {
        Write-Warning "Test-ADLsaProtection: failed to enumerate Domain Controllers: $_"
    }

    if (-not $domainControllers -or $domainControllers.Count -eq 0) {
        Write-Verbose "Test-ADLsaProtection: no Domain Controllers to evaluate; no findings."
        return $findings
    }

    $perDcState = [System.Collections.ArrayList]::new()
    $lsaProtectionMissingDCs = [System.Collections.ArrayList]::new()

    foreach ($dc in $domainControllers) {
        $dcName = if ($dc.HostName) { $dc.HostName } elseif ($dc.Name) { $dc.Name } else { "$dc" }
        Write-Verbose "Test-ADLsaProtection: evaluating DC '$dcName'..."

        $dcState = [ordered]@{
            DomainController = $dcName
            Reachable        = $false
            RunAsPPL         = $null
            Error            = $null
        }

        try {
            $lsaRegistry = Invoke-ADQueryWithRetry -OperationName "Read LSA Protection (RunAsPPL) registry value on $dcName" -Query {
                Invoke-Command -ComputerName $dcName -ErrorAction Stop -ScriptBlock {
                    (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL
                }
            }

            # $lsaRegistry is $null both when the value is genuinely absent
            # (LSA Protection never configured - the common "not enabled"
            # case) and when Invoke-Command itself failed silently in a
            # way Invoke-ADQueryWithRetry's retry exhausted without
            # throwing. Reachability is tracked separately via a distinct
            # always-succeeds probe so those two cases aren't conflated
            # into "DC unreachable" for a perfectly reachable DC that
            # simply has no RunAsPPL value set.
            $reachabilityProbe = Invoke-ADQueryWithRetry -OperationName "Confirm reachability of $dcName (LSA Protection audit)" -Query {
                Invoke-Command -ComputerName $dcName -ErrorAction Stop -ScriptBlock { $true }
            }

            if ($reachabilityProbe) {
                $dcState.Reachable = $true
                $dcState.RunAsPPL = if ($null -ne $lsaRegistry) { [int]$lsaRegistry } else { $null }

                if (-not $dcState.RunAsPPL -or $dcState.RunAsPPL -eq 0) {
                    [void]$lsaProtectionMissingDCs.Add($dcName)
                }
            }
        }
        catch {
            Write-Verbose "Test-ADLsaProtection: could not read RunAsPPL registry value on '$dcName': $_"
            $dcState.Error = "$_"
        }

        if (-not $dcState.Reachable) {
            Write-Verbose "Test-ADLsaProtection: DC '$dcName' unreachable for registry read; skipping (no finding for this DC)."
        }

        [void]$perDcState.Add([PSCustomObject]$dcState)
    }

    if ($lsaProtectionMissingDCs.Count -gt 0) {
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Domain Security'
        $finding.Issue = 'LSA Protection (RunAsPPL) Not Enabled on Domain Controller'
        $finding.Severity = 'High'
        $finding.SeverityLevel = 3
        $finding.AffectedObject = ($lsaProtectionMissingDCs -join ', ')
        $finding.Description = "LSA Protection (RunAsPPL) is not enabled on $($lsaProtectionMissingDCs.Count) Domain Controller(s): $($lsaProtectionMissingDCs -join ', ')."
        $finding.Impact = "Without LSA Protection, any process with local administrator rights on the Domain Controller can open a handle to the LSASS process and load arbitrary (including unsigned) code into it. This is a required step for Skeleton Key (which overrides the NTLM/Kerberos authentication process in LSASS to authenticate as any user with a malware-set password) and for common credential-dumping tools that extract secrets directly from LSASS memory."
        $finding.Remediation = "Enable LSA Protection: set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL (REG_DWORD) to 1, then restart the Domain Controller for the change to take effect. Before enabling, audit which third-party LSA plugins/drivers (if any) are loaded, since only Microsoft-signed plugins meeting LSA Protection's signing requirements will be permitted to load once enabled."
        $finding.EstimatedEffort = 'Medium - a single registry value per DC, but requires a restart to take effect and should be preceded by auditing which LSA plugins/drivers are currently loaded (via audit mode) so none are unexpectedly blocked once enforced.'
        $finding.KnownRisks = 'A currently-loaded LSA plugin or driver that does not meet Microsoft''s signing requirements will fail to load once LSA Protection is enabled, which can break third-party smart-card, authentication-extension, or security-vendor software that hooks LSA - audit first with LSA Protection in audit-only mode if available.'
        $finding.BackupRollback = 'Easy - revert the registry value to 0 (or delete it) and restart the DC; no data loss.'
        $finding.Details = @{
            AffectedDomainControllers = @($lsaProtectionMissingDCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADLsaProtection: LSA Protection enabled on every evaluated DC."
    }

    Write-Verbose "LSA Protection audit complete. Found $($findings.Count) issues."
    return $findings
}

#endregion
