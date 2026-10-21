#region Domain Controller Registration Integrity Audit
#
# PingCastle-comparable check(s): S-DCRegistration. Semperis "Domain
# Controller in inconsistent state", "Evidence of Mimikatz DCShadow
# attack". T1207 (Rogue Domain Controller) is the MITRE technique this
# file's findings map to - see files/16-rogue-dc-registration-integrity.md,
# note this doc assumed T1207 was already present in
# $Script:MitreTechniqueNames (Scoring.ps1); on direct read at
# implementation time it was NOT actually present, so it was added here
# alongside the two new Issue mappings below, rather than reused.
#
# Two related checks, both answering "is every object claiming to be a
# Domain Controller actually, fully, consistently one?":
#   1. Domain Controller Registration Inconsistent - a DC's computer
#      object userAccountControl doesn't match the expected value for
#      its role, or its NTDS Settings object under
#      CN=Sites,CN=Configuration is missing.
#   2. Rogue NTDS Settings Object Detected - an nTDSDSA object exists
#      under CN=Sites,CN=Configuration whose parent server object does
#      not correspond to a real, currently-registered Domain Controller
#      - exactly the artifact a DCShadow-style attack leaves behind
#      (a temporary rogue "DC" registered just long enough to inject an
#      unlogged directory change).
#
# DETECTION ONLY: both checks are read-only Configuration-partition and
# computer-object attribute reads layered on the enumeration this module
# family (StaleObjectDepthAudits.ps1, KnownVulnAudits.ps1) already
# performs via Get-ADSecurityAuditDomainController. No live network
# probe, no replication traffic sent, no schema write, no exploitation.

# Expected userAccountControl values for a healthy, fully-registered DC.
# 0x00082000 = SERVER_TRUST_ACCOUNT (0x1000) | TRUSTED_FOR_DELEGATION
# (0x80000) | ... the standard writable-DC bit combination.
# 0x05001000 = SERVER_TRUST_ACCOUNT (0x1000) | PARTIAL_SECRETS_ACCOUNT
# (0x04000000) | TRUSTED_TO_AUTH_FOR_DELEGATION (0x01000000), the
# standard RODC bit combination.
$Script:DCIntegrityExpectedUacWritable = 0x00082000
$Script:DCIntegrityExpectedUacRodc     = 0x05001000

function Test-ADDomainControllerIntegrity {
    <#
    .SYNOPSIS
        Audits rogue-DC surface and DC registration consistency.
    .DESCRIPTION
        Two independent, read-only checks:
          1. Domain Controller Registration Inconsistent - for each
             enumerated DC, compares its computer object's
             userAccountControl against the expected bitmask for its
             role (writable vs RODC) and confirms its NTDS Settings
             object exists under the Sites/Configuration container.
          2. Rogue NTDS Settings Object Detected - enumerates every
             nTDSDSA object under CN=Sites,CN=Configuration and flags
             any whose parent server object does not correspond to a
             real DC in Get-ADSecurityAuditDomainController's output -
             the artifact left behind by a DCShadow-style attack.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Starting Domain Controller Registration Integrity audit..."
    $findings = @()
    $__adServer = Get-ADSecurityAuditTargetServerValue

    $domainControllers = @()
    try {
        $domainControllers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADSecurityAuditDomainController (DC integrity audit)' -Query {
            Get-ADSecurityAuditDomainController -Server $__adServer
        })
    }
    catch {
        Write-Warning "Test-ADDomainControllerIntegrity: failed to enumerate Domain Controllers: $_"
    }

    if (-not $domainControllers -or $domainControllers.Count -eq 0) {
        Write-Verbose "Test-ADDomainControllerIntegrity: no Domain Controllers to evaluate; no findings."
        return $findings
    }

    # -------------------------------------------------------------------
    # Check 1: Domain Controller Registration Inconsistent
    # -------------------------------------------------------------------
    $inconsistentDCs = [System.Collections.ArrayList]::new()
    $knownNtdsSettingsDns = [System.Collections.ArrayList]::new()

    foreach ($dc in $domainControllers) {
        $dcName = if ($dc.HostName) { $dc.HostName } elseif ($dc.Name) { $dc.Name } else { "$dc" }

        if ($dc.NTDSSettingsObjectDN) {
            [void]$knownNtdsSettingsDns.Add($dc.NTDSSettingsObjectDN)
        }

        $issues = @()

        # --- userAccountControl vs expected role bitmask ---
        $uac = $null
        try {
            if ($dc.ComputerObjectDN) {
                $computerObj = Get-ADObject -Identity $dc.ComputerObjectDN -Properties userAccountControl -Server $__adServer -ErrorAction Stop
                $uac = [int]$computerObj.userAccountControl
            }
            else {
                $issues += 'No ComputerObjectDN reported for this DC.'
            }
        }
        catch {
            Write-Verbose "Test-ADDomainControllerIntegrity: could not read userAccountControl for '$dcName': $_"
            $issues += "Could not read userAccountControl: $_"
        }

        if ($null -ne $uac) {
            $expectedUac = if ($dc.IsReadOnly) { $Script:DCIntegrityExpectedUacRodc } else { $Script:DCIntegrityExpectedUacWritable }
            if ($uac -ne $expectedUac) {
                $issues += "userAccountControl is $uac (0x$($uac.ToString('X'))), expected $expectedUac (0x$($expectedUac.ToString('X'))) for a $(if ($dc.IsReadOnly) { 'read-only' } else { 'writable' }) DC."
            }
        }

        # --- NTDS Settings object presence ---
        $ntdsFound = $false
        if ($dc.NTDSSettingsObjectDN) {
            try {
                $ntdsObj = Get-ADObject -Identity $dc.NTDSSettingsObjectDN -Server $__adServer -ErrorAction Stop
                if ($ntdsObj) { $ntdsFound = $true }
            }
            catch {
                Write-Verbose "Test-ADDomainControllerIntegrity: could not resolve NTDS Settings object '$($dc.NTDSSettingsObjectDN)' for '$dcName': $_"
            }
        }
        if (-not $ntdsFound) {
            $issues += 'No NTDS Settings (nTDSDSA) object found under CN=Sites,CN=Configuration for this DC - missing Configuration-partition registration.'
        }

        if ($issues.Count -gt 0) {
            [void]$inconsistentDCs.Add([PSCustomObject]@{
                DomainController = $dcName
                Issues           = $issues
            })
        }
    }

    if ($inconsistentDCs.Count -gt 0) {
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Stale-Object & Hygiene Depth'
        $finding.Issue = 'Domain Controller Registration Inconsistent'
        $finding.Severity = 'High'
        $finding.SeverityLevel = 3
        $finding.AffectedObject = (($inconsistentDCs | ForEach-Object { $_.DomainController }) -join ', ')
        $bulletLines = ($inconsistentDCs | ForEach-Object { "- $($_.DomainController): $($_.Issues -join '; ')" }) -join "`n"
        $finding.Description = "$($inconsistentDCs.Count) Domain Controller(s) have an inconsistent registration state:`n$bulletLines"
        $finding.Impact = "A DC whose computer-object userAccountControl doesn't match its expected role, or whose Configuration-partition (NTDS Settings) registration is missing or incomplete, may be the result of a manual/software misconfiguration, an incomplete promotion or demotion, or - in the userAccountControl case specifically - could mask a rogue or improperly-registered server presenting itself as a legitimate DC."
        $finding.Remediation = "Investigate each listed DC individually: confirm whether it is a genuine, currently-in-service DC. For a legitimate DC with a userAccountControl mismatch, correct the value via ADSI Edit or dsmod after confirming the expected bitmask for its role. For a DC with a missing NTDS Settings registration, this typically indicates an incomplete promotion/demotion and should be investigated with Microsoft's documented DC metadata-cleanup procedure (ntdsutil) if the DC is confirmed decommissioned, or re-promoted if it is meant to be active."
        $finding.EstimatedEffort = 'Medium - typically a single-object correction per affected DC, but requires confirming the DC''s intended current state (active, mid-promotion, or decommissioned) before deciding whether to correct or clean up metadata.'
        $finding.KnownRisks = 'Correcting userAccountControl or Configuration-partition registration on a DC that is still mid-promotion/demotion, rather than genuinely stuck, could interfere with that in-progress operation - confirm the DC''s actual current state first.'
        $finding.BackupRollback = 'Moderate - record the current attribute values before correcting them; effective on next AD replication cycle.'
        $finding.Details = @{
            AffectedDomainControllers = @($inconsistentDCs | ForEach-Object { $_.DomainController })
            PerDomainControllerIssues = @($inconsistentDCs)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADDomainControllerIntegrity: all enumerated DCs have consistent registration state."
    }

    # -------------------------------------------------------------------
    # Check 2: Rogue NTDS Settings Object Detected
    # -------------------------------------------------------------------
    try {
        $__adServer2 = Get-ADSecurityAuditTargetServerValue
        $configContext = Get-ADRootDSEValue -Property configurationNamingContext -Server $__adServer2
        $sitesContainer = "CN=Sites,$configContext"

        $ntdsDsaObjects = @(Invoke-ADQueryWithRetry -OperationName 'Get nTDSDSA objects (rogue-DC check)' -Query {
            Get-ADObject -SearchBase $sitesContainer -SearchScope Subtree -Filter "objectClass -eq 'nTDSDSA'" -Server $__adServer2 -ErrorAction Stop
        })

        $rogueNtdsObjects = @($ntdsDsaObjects | Where-Object { $_.DistinguishedName -notin $knownNtdsSettingsDns })

        if ($rogueNtdsObjects.Count -gt 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Stale-Object & Hygiene Depth'
            $finding.Issue = 'Rogue NTDS Settings Object Detected'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.AffectedObject = (($rogueNtdsObjects | ForEach-Object { $_.DistinguishedName }) -join '; ')
            $finding.Description = "$($rogueNtdsObjects.Count) NTDS Settings (nTDSDSA) object(s) exist under CN=Sites,CN=Configuration whose parent server does not correspond to any real, currently-registered Domain Controller: $(($rogueNtdsObjects | ForEach-Object { $_.DistinguishedName }) -join '; ')."
            $finding.Impact = "This is exactly the artifact a DCShadow-style attack leaves behind: a temporary rogue 'Domain Controller' registered in the Configuration partition just long enough to inject an unlogged directory change (bypassing normal Security event logging on legitimate DCs), then typically removed. A genuine, unresolved orphaned object here (rather than an active attack in progress) still indicates an incomplete or corrupted DC demotion that was never properly cleaned up."
            $finding.Remediation = "Investigate each listed object immediately as a potential active or historical DCShadow indicator: identify which computer/server object it is a child of, confirm whether that server ever legitimately existed as a DC, and check replication metadata/event logs (4742, 5137, 5141) around its creation time. If confirmed orphaned/benign, remove it using Microsoft's documented DC metadata-cleanup procedure (ntdsutil) rather than a direct object deletion."
            $finding.EstimatedEffort = 'High - this requires an incident-response-style investigation (replication metadata, event log correlation, timeline reconstruction) before any cleanup action, not a routine configuration fix.'
            $finding.KnownRisks = 'Deleting the object directly (rather than via documented DC metadata cleanup) can leave inconsistent replication metadata across the forest; treat this as a potential security incident requiring investigation before remediation, not a routine hygiene item.'
            $finding.BackupRollback = 'N/A - this is a detection/investigation finding; remediation should follow Microsoft''s documented metadata-cleanup procedure once the object is confirmed non-legitimate.'
            $finding.Details = @{
                RogueNtdsSettingsObjects = @($rogueNtdsObjects | ForEach-Object { $_.DistinguishedName })
                KnownNtdsSettingsObjects = @($knownNtdsSettingsDns)
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADDomainControllerIntegrity: no rogue NTDS Settings objects found; every nTDSDSA object corresponds to a known DC."
        }
    }
    catch {
        Write-Warning "Test-ADDomainControllerIntegrity: rogue NTDS Settings object check failed: $_"
    }

    Write-Verbose "Domain Controller Registration Integrity audit complete. Found $($findings.Count) issue(s)."
    return $findings
}

#endregion
