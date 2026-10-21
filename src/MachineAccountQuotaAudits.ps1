#region Machine Account Quota Audit
#
# Checks the domain-wide ms-DS-MachineAccountQuota attribute. By default,
# every authenticated domain user may join up to 10 computer accounts to the
# domain (the classic AD default), and any value greater than 0 lets
# unprivileged users create machine accounts they own. Self-service machine
# accounts are commonly abused as a foothold for resource-based constrained
# delegation (RBCD) relay attacks and SamAccountName-spoofing techniques
# (e.g. CVE-2021-42278/42287, "noPac") that escalate a low-privilege user to
# Domain Admin equivalence.
#
# DETECTION ONLY: this is a single read-only LDAP attribute read. Nothing
# here creates, joins, or modifies any computer account.

function Test-ADMachineAccountQuota {
    <#
    .SYNOPSIS
        Audits the domain's ms-DS-MachineAccountQuota attribute.
    .DESCRIPTION
        Flags a non-zero machine account quota, distinguishing between the
        unmodified default of 10 (Critical/High risk - never reviewed) and a
        lowered-but-still-non-zero value (Medium risk - still self-service).
        A quota of 0 (hardened: computer joins must be explicitly delegated)
        produces no finding.
    .PARAMETER Server
        Optional override for which domain/DC to query, as a domain FQDN
        (e.g. 'domainb.corp.com') or a specific DC FQDN/hostname. When
        omitted, defaults to the current user's own domain
        ($env:USERDNSDOMAIN) rather than letting Get-ADDomain perform its
        default "serverless" bind, which resolves against whatever domain
        the AD module's own ambient resolution picks - not necessarily the
        target domain, which is exactly the "checks Domain A instead of
        Domain B" symptom this default exists to avoid. Pass this
        explicitly only to target a domain OTHER than your own account's.

        PDC-ONLY CHECK, NOTED ACCORDINGLY: ms-DS-MachineAccountQuota is a
        single domain-wide attribute on the domain root object, identical
        regardless of which DC answers - there is no per-DC variation to
        enumerate, unlike a true per-DC probe (e.g. Spooler/SMB-signing
        state, which genuinely differs DC to DC). This function therefore
        makes exactly one Get-ADObject call rather than using
        Get-ADSecurityAuditDomainController's per-DC enumeration. -Server
        still follows the module's normal three-mode contract via
        Resolve-ADSecurityAuditTargetServer: omitted or a domain name
        resolves to that domain's PDC Emulator specifically (the
        authoritative source for domain-wide config); an explicit,
        specific DC is honored exactly as given (never redirected to the
        PDC), since an operator naming one specific DC has often done so
        because it's the only one reachable for this engagement.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Server
    )

    Write-Verbose "Starting Machine Account Quota audit..."
    $findings = @()

    try {
        $quota = $null
        $domainDN = $null

        # Fixed: previously called Get-ADDomain/Get-ADObject with no
        # -Server, which performs a "serverless" bind that resolves
        # against the invoking account's own logon domain rather than
        # necessarily the intended target domain - in a multi-domain
        # forest this is what causes the quota check to silently read
        # the wrong domain. -Server, if supplied, is used explicitly;
        # if not, defaults to the current user's own domain
        # ($env:USERDNSDOMAIN) rather than the ambiguous default.
        #
        # CONFIRMED REGRESSION, FIXED: when called from
        # Start-ADSecurityAudit, $Server here is not the operator's
        # raw input - it's $effectiveServer, the value
        # Resolve-ADSecurityAuditTargetServer already resolved moments
        # earlier (e.g. a domain's PDC Emulator FQDN, from a plain
        # no-argument run). Re-running full resolution against an
        # already-resolved DC FQDN makes Get-ADDomainController
        # -Identity succeed and misclassifies it as "the operator
        # explicitly named this DC", corrupting the shared explicit-DC
        # scope flag other checks in the same run rely on (see
        # Resolve-ADSecurityAuditTargetServer's own idempotency guard).
        # When an override is already active for this session, reuse
        # it directly instead of re-resolving; only resolve fresh when
        # this is genuinely the first call (e.g. this function invoked
        # standalone, outside Start-ADSecurityAudit).
        if (Get-ADSecurityAuditActiveServerOverride) {
            $effectiveServer = Get-ADSecurityAuditActiveServerOverride
        }
        else {
            $effectiveServer = Resolve-ADSecurityAuditTargetServer -Server $Server
        }

        $domainParams = @{ ErrorAction = 'Stop' }
        if ($effectiveServer) { $domainParams['Server'] = $effectiveServer }
        $domain = Get-ADDomain @domainParams
        $domainDN = $domain.DistinguishedName

        $objectParams = @{ Identity = $domainDN; Properties = 'ms-DS-MachineAccountQuota'; ErrorAction = 'Stop' }
        if ($effectiveServer) { $objectParams['Server'] = $effectiveServer }
        $domainObject = Get-ADObject @objectParams
        $quota = $domainObject.'ms-DS-MachineAccountQuota'

        if ($null -eq $quota) {
            Write-Verbose "Test-ADMachineAccountQuota: could not determine ms-DS-MachineAccountQuota; skipping."
            return $findings
        }

        $quotaValue = [int]$quota

        if ($quotaValue -eq 10) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Machine Account Quota'
            $finding.Issue = 'Default Machine Account Quota Not Restricted'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = $domainDN
            $finding.Description = "ms-DS-MachineAccountQuota is set to the unmodified Active Directory default of 10, allowing every authenticated domain user to join up to 10 computer accounts to the domain."
            $finding.Impact = "Any authenticated user - including low-privilege accounts - can create and own machine accounts without any delegated permission. This is commonly abused as a foothold for resource-based constrained delegation (RBCD) relay attacks and SamAccountName-spoofing privilege escalation (e.g. CVE-2021-42278/42287, 'noPac'), letting an attacker escalate from any domain account to Domain Admin equivalence."
            $finding.Remediation = "Set ms-DS-MachineAccountQuota to 0 on the domain object (Set-ADDomain -Identity <domain> -Replace @{'ms-DS-MachineAccountQuota'=0}) and explicitly delegate computer-join rights (Create/Delete Computer Objects) on the relevant OUs to only the specific groups or provisioning accounts that need them."
            $finding.EstimatedEffort = 'Low - a single domain-wide attribute (ms-DS-MachineAccountQuota).'
            $finding.KnownRisks = 'Lowering or zeroing this quota only prevents self-service computer joins by regular users; legitimate machine joins performed by an account with delegated Create Computer Objects rights are unaffected.'
            $finding.BackupRollback = 'Easy - revert the ms-DS-MachineAccountQuota attribute to its prior value; effective immediately, no data loss.'
            $finding.Details = @{
                DistinguishedName   = $domainDN
                MachineAccountQuota = $quotaValue
                DefaultValue        = 10
            }
            $findings += $finding
        }
        elseif ($quotaValue -gt 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Machine Account Quota'
            $finding.Issue = 'Non-Zero Machine Account Quota'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = $domainDN
            $finding.Description = "ms-DS-MachineAccountQuota is set to $quotaValue, allowing every authenticated domain user to join up to $quotaValue computer account(s) to the domain."
            $finding.Impact = "Even at a reduced value, self-service computer joins remain available to any authenticated user, which still expands the attack surface for RBCD-based privilege escalation and SamAccountName-spoofing attacks."
            $finding.Remediation = "Set ms-DS-MachineAccountQuota to 0 and delegate computer-join rights explicitly to the specific groups or service accounts that require them, rather than relying on a domain-wide self-service quota."
            $finding.EstimatedEffort = 'Low - a single domain-wide attribute (ms-DS-MachineAccountQuota).'
            $finding.KnownRisks = 'Lowering the quota to zero only prevents self-service computer joins by regular users; legitimate machine joins via delegated Create Computer Objects rights are unaffected.'
            $finding.BackupRollback = 'Easy - revert the ms-DS-MachineAccountQuota attribute to its prior value; effective immediately, no data loss.'
            $finding.Details = @{
                DistinguishedName   = $domainDN
                MachineAccountQuota = $quotaValue
                DefaultValue        = 10
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADMachineAccountQuota: ms-DS-MachineAccountQuota is 0 (hardened); no finding."
        }

        Write-Verbose "Machine Account Quota audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during Machine Account Quota audit: $_"
        throw
    }
}

#endregion
