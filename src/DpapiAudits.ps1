#region Domain DPAPI Backup Key Audit
#
# PingCastle-comparable check(s): none directly. Semperis "Non-default
# access to DPAPI key". See files/17-key-material-exposure.md.
#
# The domain's DPAPI backup key lets any principal with retrieve access
# decrypt EVERY DPAPI-protected secret domain-wide (saved browser/Wi-Fi/
# credential-manager passwords, and any application relying on DPAPI for
# secret storage) for any user in the domain - a single point of
# forest-wide-per-domain compromise, sharing the same theme as this
# project's other key-material checks (gMSA KDS root key, legacy LAPS
# SearchFlags) but with no existing check anywhere in this project prior
# to this file.
#
# CORRECTED DURING SELF-REVIEW: an earlier version of this check read the
# ACL of a "CN=DPAPI,CN=System,<domain>" container, which does not exist
# - there is no distinct "DPAPI" sub-container. Per Microsoft's own
# documentation and independent research (DSInternals/SharpDPAPI), the
# actual DPAPI backup key material is stored as objects of the schema
# class 'secret' named BCKUPKEY_PREFERRED, BCKUPKEY_P, and one or more
# BCKUPKEY_<GUID>, living DIRECTLY under CN=System,<domain DN> (not a
# child container of it). The key value itself lives in each object's
# confidential currentValue attribute (schema-marked confidential, like
# ms-Mcs-AdmPwd), and real-world extraction tooling (Mimikatz
# lsadump::backupkeys, SharpDPAPI, DSInternals) reads it either via the
# LSA RetrievePrivateData RPC call (an LSA-level privilege, not an LDAP
# ACL) or via directory replication (DCSync-equivalent rights) against
# these specific objects - NOT via a distinct container ACL. This check
# now targets the correct objects: it reads the ACL on every BCKUPKEY_*
# secret object under CN=System and flags any non-default principal
# granted read/generic access to them, which is the LDAP-visible signal
# most directly analogous to the real exposure (an attacker with such
# access could replicate/read the confidential currentValue attribute
# even without a live LSA RPC call). This does not replace confirming
# DCSync-capable identities separately (see 'Unauthorized DCSync
# Permissions' and 'SPN-Holding Account Also Has DCSync Rights' above,
# which already cover forest/domain-wide replication rights generally);
# it specifically surfaces non-default ACEs on these objects themselves.
#
# DETECTION ONLY: reads ACL metadata on the domain's DPAPI backup key
# objects. No key material is ever read, decrypted, or exported.

function Test-ADDpapiBackupKeySecurity {
    <#
    .SYNOPSIS
        Audits ACL access to the domain's DPAPI backup key objects.
    .DESCRIPTION
        Enumerates the BCKUPKEY_PREFERRED / BCKUPKEY_P / BCKUPKEY_<GUID>
        secret objects under CN=System,<domain DN> (the real, documented
        location of the domain's DPAPI backup key material - see the
        correction note above) and flags any non-default principal
        granted read/generic/extended-right access on any of them.
        Compromise of this key material recovers every DPAPI-protected
        secret domain-wide.

        Detection only - reads ACL metadata, never the key material
        itself.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Starting domain DPAPI backup key ACL audit..."
    $findings = @()
    $__adServer = Get-ADSecurityAuditTargetServerValue

    $defaultDpapiPrincipals = @(
        'NT AUTHORITY\SYSTEM'
        'BUILTIN\Administrators'
        'Domain Admins'
        'Enterprise Admins'
    )

    try {
        $domain = Get-ADDomain -Server $__adServer
        $systemContainerDn = "CN=System,$($domain.DistinguishedName)"

        $bckupkeyObjects = @()
        try {
            $bckupkeyObjects = @(Invoke-ADQueryWithRetry -OperationName 'Get BCKUPKEY_* DPAPI objects (key-material audit)' -Query {
                Get-ADObject -SearchBase $systemContainerDn -SearchScope OneLevel -Filter "objectClass -eq 'secret' -and Name -like 'BCKUPKEY_*'" `
                    -Properties nTSecurityDescriptor -Server $__adServer -ErrorAction Stop
            })
        }
        catch {
            Write-Verbose "Test-ADDpapiBackupKeySecurity: could not enumerate BCKUPKEY_* objects under '$systemContainerDn': $_"
            return $findings
        }

        if ($bckupkeyObjects.Count -eq 0) {
            Write-Verbose "Test-ADDpapiBackupKeySecurity: no BCKUPKEY_* objects found under '$systemContainerDn' - unexpected for a domain that has ever had a DPAPI-protected secret created, but not itself an error condition; nothing to evaluate."
            return $findings
        }

        $nonDefaultFindingsByObject = @{}
        foreach ($bckupkeyObj in $bckupkeyObjects) {
            $aces = @($bckupkeyObj.nTSecurityDescriptor.Access)
            $nonDefaultAces = @()
            foreach ($ace in $aces) {
                if ($ace.IsInherited) { continue }
                $principal = $ace.IdentityReference.Value
                $isDefault = $false
                foreach ($default in $defaultDpapiPrincipals) {
                    if ($principal -match [regex]::Escape($default)) { $isDefault = $true; break }
                }
                if ($isDefault) { continue }

                if ($ace.ActiveDirectoryRights -match 'GenericAll|GenericRead|ReadProperty|ExtendedRight|ControlAccess') {
                    $nonDefaultAces += "$principal ($($ace.ActiveDirectoryRights))"
                }
            }
            $nonDefaultAces = @($nonDefaultAces | Select-Object -Unique)
            if ($nonDefaultAces.Count -gt 0) {
                $nonDefaultFindingsByObject[$bckupkeyObj.DistinguishedName] = $nonDefaultAces
            }
        }

        if ($nonDefaultFindingsByObject.Count -gt 0) {
            $allNonDefaultAces = @($nonDefaultFindingsByObject.Values | ForEach-Object { $_ } | Select-Object -Unique)
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Non-Default Access to Domain DPAPI Backup Key'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.AffectedObject = (($nonDefaultFindingsByObject.Keys) -join '; ')
            $finding.Description = "Non-default principal(s) have read/generic/extended-right access to one or more domain DPAPI backup key objects (BCKUPKEY_*) under '$systemContainerDn': $($allNonDefaultAces -join '; ')."
            $finding.Impact = "The domain DPAPI backup key can decrypt every DPAPI-protected secret for every user in the domain (saved credentials, browser-stored passwords, Wi-Fi keys, and any application relying on DPAPI for local secret storage) - compromise of a non-default principal with access here is a domain-wide credential-exposure event, not limited to any one account."
            $finding.Remediation = "Remove the non-default ACE(s) listed above from the affected BCKUPKEY_* object(s), restoring access to only the built-in defaults (SYSTEM, Domain/Enterprise Admins)."
            $finding.EstimatedEffort = 'Low - a targeted ACE removal on one or a small handful of domain-level objects, but confirm the principal isn''t a legitimate, currently-used backup/recovery tool before removing.'
            $finding.KnownRisks = 'No legitimate day-to-day workflow needs direct access to the domain DPAPI backup key objects themselves; removing an unexpected grant has no legitimate compatibility impact unless it turns out to be an undocumented, currently-in-use backup/recovery tool, so confirm first.'
            $finding.BackupRollback = 'Moderate - export the current ACL before removing the specific ACE(s) so they can be restored if a legitimate dependency surfaces.'
            $finding.Details = @{
                SystemContainer   = $systemContainerDn
                AffectedObjects   = @($nonDefaultFindingsByObject.Keys)
                NonDefaultAcesByObject = $nonDefaultFindingsByObject
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADDpapiBackupKeySecurity: no non-default access found on any BCKUPKEY_* object."
        }
    }
    catch {
        Write-Warning "Test-ADDpapiBackupKeySecurity: error during DPAPI backup key ACL audit: $_"
    }

    Write-Verbose "Domain DPAPI backup key ACL audit complete. Found $($findings.Count) issue(s)."
    return $findings
}

#endregion

