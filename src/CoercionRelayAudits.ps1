#region Coercion & NTLM Relay Exposure Audit
#
# Detects the configuration state that enables the dominant DC-compromise
# pattern of coerce-then-relay (PrinterBug / WebDAV coercion relayed to
# LDAP or AD CS). PingCastle-comparable check(s): A-DC-Coerce, A-DC-Spooler,
# A-DC-WebClient, A-DCLdapSign, A-LDAPSigningDisabled,
# A-DCLdapsChannelBinding.
#
# DETECTION ONLY: this reads Spooler/WebClient service state and the NTDS
# LDAPServerIntegrity / LdapEnforceChannelBinding registry values on each
# Domain Controller. It never sends a coercion trigger (e.g. RPC calls to
# the Print System Remote Protocol or WebDAV), never relays a credential,
# and never performs any exploitation or PoC traffic.

function Test-ADCoercionAndRelayExposure {
    <#
    .SYNOPSIS
        Audits Domain Controllers for coercion and NTLM-relay exposure:
        Print Spooler, WebClient, LDAP signing, and LDAP channel binding.
    .DESCRIPTION
        For each Domain Controller, checks:
          1. Print Spooler service state (PrinterBug coercion surface).
          2. WebClient (WebDAV) service state (WebDAV coercion surface).
          3. NTDS `LDAPServerIntegrity` registry value (LDAP signing not
             enforced).
          4. NTDS `LdapEnforceChannelBinding` registry value (LDAP channel
             binding / EPA not required).

        Each DC is evaluated independently and degrades gracefully if it
        cannot be reached (a Verbose warning is emitted; no terminating
        error, and no finding is raised for that DC on that check).

        Detection only - reads service and registry state via remote
        registry / `Invoke-Command`. No coercion request (Spooler
        RPC/WebDAV) is ever sent, and no relay or exploitation is performed.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Starting Coercion & NTLM Relay Exposure audit..."
    $findings = @()

    # -------------------------------------------------------------------
    # Enumerate Domain Controllers.
    # -------------------------------------------------------------------
    $domainControllers = @()

    try {
        # Get-ADSecurityAuditDomainController, not a bare
        # Get-ADDomainController -Filter * - the latter is forest-wide
        # regardless of -Server; see Common.ps1 for why.
        $domainControllers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADSecurityAuditDomainController (coercion/relay audit)' -Query {
            Get-ADSecurityAuditDomainController -Server (Get-ADSecurityAuditTargetServerValue)
        })
    }
    catch {
        Write-Warning "Test-ADCoercionAndRelayExposure: failed to enumerate Domain Controllers: $_"
    }

    if (-not $domainControllers -or $domainControllers.Count -eq 0) {
        Write-Verbose "Test-ADCoercionAndRelayExposure: no Domain Controllers to evaluate; no findings."
        return $findings
    }

    $perDcState = [System.Collections.ArrayList]::new()

    $spoolerRunningDCs   = [System.Collections.ArrayList]::new()
    $webClientRunningDCs = [System.Collections.ArrayList]::new()
    $ldapSignDCs         = [System.Collections.ArrayList]::new()
    $channelBindingDCs   = [System.Collections.ArrayList]::new()

    foreach ($dc in $domainControllers) {
        $dcName = if ($dc.HostName) { $dc.HostName } elseif ($dc.Name) { $dc.Name } else { "$dc" }
        Write-Verbose "Test-ADCoercionAndRelayExposure: evaluating DC '$dcName'..."

        $dcState = [ordered]@{
            DomainController          = $dcName
            Reachable                 = $false
            SpoolerStatus             = $null
            WebClientStatus           = $null
            LDAPServerIntegrity       = $null
            LdapEnforceChannelBinding = $null
            Error                     = $null
        }

        try {
            # --- Spooler service state (remote service query, retried - a
            # transient RPC failure reaching the DC is worth retrying) ---
            $spoolerSvc = Invoke-ADQueryWithRetry -OperationName "Get-Service Spooler on $dcName" -Query {
                Get-Service -ComputerName $dcName -Name 'Spooler' -ErrorAction Stop
            }

            if ($spoolerSvc) {
                $dcState.Reachable = $true
                $dcState.SpoolerStatus = "$($spoolerSvc.Status)"
                if ($spoolerSvc.Status -eq 'Running') {
                    [void]$spoolerRunningDCs.Add($dcName)
                }
            }

            # --- WebClient (WebDAV) service state ---
            # Queried separately from Spooler and WITHOUT the retry wrapper:
            # WebClient is an optional feature that's simply not installed
            # on many modern/Core builds, which is a deterministic outcome,
            # not a transient failure - retrying it with exponential backoff
            # only wastes time (and previously, requesting both service
            # names in a single Get-Service call meant a missing WebClient
            # failed the ENTIRE call, silently losing the Spooler result
            # too).
            try {
                $webClientSvc = Get-Service -ComputerName $dcName -Name 'WebClient' -ErrorAction Stop
                $dcState.Reachable = $true
                $dcState.WebClientStatus = "$($webClientSvc.Status)"
                if ($webClientSvc.Status -eq 'Running') {
                    [void]$webClientRunningDCs.Add($dcName)
                }
            }
            catch {
                # Service genuinely not installed (or host unreachable, but
                # that will already have surfaced via the Spooler check
                # above) - either way, not worth retrying.
                $dcState.WebClientStatus = 'NotInstalled'
                Write-Verbose "Test-ADCoercionAndRelayExposure: WebClient service not present on '$dcName' (or query failed): $_"
            }
        }
        catch {
            Write-Verbose "Test-ADCoercionAndRelayExposure: could not query Spooler/WebClient service state on '$dcName': $_"
            $dcState.Error = "$_"
        }

        try {
            # --- NTDS registry values (remote registry via Invoke-Command) ---
            $ntdsRegistry = Invoke-ADQueryWithRetry -OperationName "Read NTDS LDAP registry values on $dcName" -Query {
                Invoke-Command -ComputerName $dcName -ErrorAction Stop -ScriptBlock {
                    $ntdsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                    [PSCustomObject]@{
                        LDAPServerIntegrity       = (Get-ItemProperty -Path $ntdsPath -Name 'LDAPServerIntegrity' -ErrorAction SilentlyContinue).LDAPServerIntegrity
                        LdapEnforceChannelBinding = (Get-ItemProperty -Path $ntdsPath -Name 'LdapEnforceChannelBinding' -ErrorAction SilentlyContinue).LdapEnforceChannelBinding
                    }
                }
            }

            if ($ntdsRegistry) {
                $dcState.Reachable = $true

                # LDAPServerIntegrity: 2 = signing required (secure). Missing
                # or 1 = signing not required/enforced.
                $ldapIntegrityValue = $ntdsRegistry.LDAPServerIntegrity
                $dcState.LDAPServerIntegrity = if ($null -ne $ldapIntegrityValue) { [int]$ldapIntegrityValue } else { $null }
                if ($null -eq $ldapIntegrityValue -or [int]$ldapIntegrityValue -lt 2) {
                    [void]$ldapSignDCs.Add($dcName)
                }

                # LdapEnforceChannelBinding: 2 = required (secure), 1 = "when
                # supported". Missing or 0 = not enforced.
                $channelBindingValue = $ntdsRegistry.LdapEnforceChannelBinding
                $dcState.LdapEnforceChannelBinding = if ($null -ne $channelBindingValue) { [int]$channelBindingValue } else { $null }
                if ($null -eq $channelBindingValue -or [int]$channelBindingValue -lt 2) {
                    [void]$channelBindingDCs.Add($dcName)
                }
            }
        }
        catch {
            Write-Verbose "Test-ADCoercionAndRelayExposure: could not read NTDS LDAP registry values on '$dcName': $_"
            if (-not $dcState.Error) { $dcState.Error = "$_" }
        }

        if (-not $dcState.Reachable) {
            Write-Verbose "Test-ADCoercionAndRelayExposure: DC '$dcName' unreachable for service/registry reads; skipping (no finding for this DC)."
        }

        [void]$perDcState.Add([PSCustomObject]$dcState)
    }

    # -------------------------------------------------------------------
    # Finding: Print Spooler Running on Domain Controller
    # -------------------------------------------------------------------
    if ($spoolerRunningDCs.Count -gt 0) {
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Coercion & Relay Exposure'
        $finding.Issue = 'Print Spooler Running on Domain Controller'
        $finding.Severity = 'High'
        $finding.SeverityLevel = 3
        $finding.AffectedObject = ($spoolerRunningDCs -join ', ')
        $finding.Description = "The Print Spooler service is running on $($spoolerRunningDCs.Count) Domain Controller(s): $($spoolerRunningDCs -join ', ')."
        $finding.Impact = "A running Spooler service on a DC exposes the MS-RPRN/MS-PAR (PrinterBug) coercion surface: any authenticated user can coerce the DC to authenticate to an attacker-controlled host, enabling NTLM relay to LDAP/LDAPS or AD CS for domain compromise."
        $finding.Remediation = "Disable and stop the Print Spooler service on all Domain Controllers unless print serving from a DC is an explicit, documented business requirement: `Stop-Service -Name Spooler; Set-Service -Name Spooler -StartupType Disabled`."
        $finding.EstimatedEffort = 'Low - stop and disable a single service on each DC (or via GPO).'
        $finding.KnownRisks = 'Disabling the Spooler service on a DC breaks any printing initiated directly from that DC itself, which is essentially never a legitimate DC role; it has no effect on printing by domain clients, which don''t route jobs through DCs.'
        $finding.BackupRollback = 'Easy - re-enable and start the service; effective immediately, no data loss.'
        $finding.Details = @{
            AffectedDomainControllers = @($spoolerRunningDCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADCoercionAndRelayExposure: Print Spooler not running on any evaluated DC."
    }

    # -------------------------------------------------------------------
    # Finding: WebClient Service Enabled on Domain Controller
    # -------------------------------------------------------------------
    if ($webClientRunningDCs.Count -gt 0) {
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Coercion & Relay Exposure'
        $finding.Issue = 'WebClient Service Enabled on Domain Controller'
        $finding.Severity = 'High'
        $finding.SeverityLevel = 3
        $finding.AffectedObject = ($webClientRunningDCs -join ', ')
        $finding.Description = "The WebClient (WebDAV Mini-Redirector) service is running on $($webClientRunningDCs.Count) Domain Controller(s): $($webClientRunningDCs -join ', ')."
        $finding.Impact = "A running WebClient service on a DC exposes a WebDAV-based coercion surface (an alternative to PrinterBug that also works over port 80 and bypasses some Spooler-specific mitigations), allowing an attacker to coerce the DC into authenticating to a relay target."
        $finding.Remediation = "Disable and stop the WebClient service on all Domain Controllers: `Stop-Service -Name WebClient; Set-Service -Name WebClient -StartupType Disabled`."
        $finding.EstimatedEffort = 'Low - stop and disable a single service on each DC.'
        $finding.KnownRisks = 'Disabling WebClient (WebDAV) removes WebDAV redirector functionality on the DC host itself, which is essentially never a legitimate DC use case.'
        $finding.BackupRollback = 'Easy - re-enable and start the service; effective immediately, no data loss.'
        $finding.Details = @{
            AffectedDomainControllers = @($webClientRunningDCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADCoercionAndRelayExposure: WebClient not running on any evaluated DC."
    }

    # -------------------------------------------------------------------
    # Finding: LDAP Signing Not Enforced on Domain Controller
    # -------------------------------------------------------------------
    if ($ldapSignDCs.Count -gt 0) {
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Coercion & Relay Exposure'
        $finding.Issue = 'LDAP Signing Not Enforced on Domain Controller'
        $finding.Severity = 'High'
        $finding.SeverityLevel = 3
        $finding.AffectedObject = ($ldapSignDCs -join ', ')
        $finding.Description = "NTDS `LDAPServerIntegrity` is not set to require signing (value 2) on $($ldapSignDCs.Count) Domain Controller(s): $($ldapSignDCs -join ', ')."
        $finding.Impact = "Without LDAP signing required, a coerced DC authentication (or any other captured NTLM authentication) can be relayed to unsigned LDAP on a Domain Controller to read or modify directory data, including delegation and credential-adjacent attributes."
        $finding.Remediation = "Set the `Domain controller: LDAP server signing requirements` policy (or the `LDAPServerIntegrity` registry value under `HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters`) to `Require signing` (2) on every Domain Controller, then validate client compatibility before wide rollout."
        $finding.EstimatedEffort = 'Medium - a domain/DC-wide GPO or registry setting; Microsoft''s own LDAP-signing hardening guidance recommends an audit period before enforcing.'
        $finding.KnownRisks = 'Enforcing LDAP signing can break unsigned-LDAP clients, applications, or network appliances, a documented compatibility concern in Microsoft''s LDAP signing advisory.'
        $finding.BackupRollback = 'Easy - revert the GPO/registry setting; effective at next policy refresh, no data loss.'
        $finding.OperationalNotes = 'Monitor Directory Service event ID 2887 (count of unsigned LDAP binds) before enforcing, per Microsoft''s own documented rollout guidance.'
        $finding.Details = @{
            AffectedDomainControllers = @($ldapSignDCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADCoercionAndRelayExposure: LDAP signing enforced on all evaluated DCs (or no data available)."
    }

    # -------------------------------------------------------------------
    # Finding: LDAP Channel Binding Not Enforced
    # -------------------------------------------------------------------
    if ($channelBindingDCs.Count -gt 0) {
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Coercion & Relay Exposure'
        $finding.Issue = 'LDAP Channel Binding Not Enforced'
        $finding.Severity = 'High'
        $finding.SeverityLevel = 3
        $finding.AffectedObject = ($channelBindingDCs -join ', ')
        $finding.Description = "NTDS `LdapEnforceChannelBinding` is not set to require Extended Protection for Authentication (value 2) on $($channelBindingDCs.Count) Domain Controller(s): $($channelBindingDCs -join ', ')."
        $finding.Impact = "Without LDAP channel binding (EPA) required, a relayed NTLM authentication over LDAPS is not bound to the TLS channel, so it remains relayable even when LDAPS is otherwise in use, undermining coerce-then-relay-to-LDAPS defences."
        $finding.Remediation = "Set the `LdapEnforceChannelBinding` registry value under `HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters` to `2` (always) on every Domain Controller, then validate client compatibility (older clients without EPA support may need remediation first)."
        $finding.EstimatedEffort = 'Medium - a domain-wide registry/GPO setting on every DC; Microsoft''s own guidance recommends a phased "when supported" rollout before enforcing, due to legacy client compatibility.'
        $finding.KnownRisks = 'Enforcing LDAP channel binding can break LDAPS-based clients or appliances that don''t support channel binding tokens, per Microsoft''s own documented compatibility guidance.'
        $finding.BackupRollback = 'Easy - revert the registry value/GPO setting; effective after next policy refresh/service restart, no data loss.'
        $finding.Details = @{
            AffectedDomainControllers = @($channelBindingDCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADCoercionAndRelayExposure: LDAP channel binding enforced on all evaluated DCs (or no data available)."
    }

    Write-Verbose "Coercion & NTLM Relay Exposure audit complete. Found $($findings.Count) issue(s)."
    return $findings
}

#endregion
