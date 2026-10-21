#region Remediation / Exception Tracking (accepted-risk findings persist across runs)
#
# A small, file-based exception/remediation-state store: a side file
# (conventionally AD_Remediation_State.json, one per domain, hand-maintained
# or edited via Set-ADRemediationState) that records, per finding key
# (Category+Issue+AffectedObject - the SAME matching key Get-ADRetestComparison
# already uses, via the shared Get-ADFindingMatchKey helper in Common.ps1), a
# status (Open / AcceptedRisk / InProgress / Remediated), an optional owner,
# note, and date.
#
# This module makes NO ticket-system integration calls (JIRA/ServiceNow/etc)
# and performs NO automatic expiry/review-date alerting - both are explicitly
# out of scope for this pass (see the accompanying feature doc). It does not
# infer remediation intent on its own; a human (or a script the user writes
# themselves) explicitly calls Set-ADRemediationState to record a decision.
#
# HARD DEPENDENCY: this file extends Get-ADRetestComparison (RetestComparison.ps1),
# which must already exist - it cannot be used standalone. Get-ADRetestComparison's
# optional -RemediationStatePath parameter (added alongside this file) is the
# only place this state store is consumed elsewhere in the module.
#
# SCORING IS UNAFFECTED: an AcceptedRisk finding still counts toward
# Get-ADRiskScore exactly as before. This is a display/reporting annotation
# only, never a scoring policy change - silently excluding accepted-risk
# findings from the score would misrepresent actual security posture.

function Get-ADRemediationState {
    <#
    .SYNOPSIS
        Reads a remediation-state file, returning an empty/default structure
        if it does not exist yet (first use shouldn't require pre-creating
        an empty file).
    .PARAMETER StatePath
        Path to the remediation-state JSON file (conventionally
        AD_Remediation_State.json, one per domain).
    .OUTPUTS
        PSCustomObject: DomainName, Entries (array of Key/Status/Owner/Note/SetDate).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$StatePath
    )

    if (-not (Test-Path -Path $StatePath)) {
        return [PSCustomObject]@{
            DomainName = $null
            Entries    = @()
        }
    }

    try {
        $raw = Get-Content -Path $StatePath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Failed to parse remediation state file '$StatePath': $_"
    }

    $entries = @()
    if ($raw.PSObject.Properties.Name -contains 'Entries' -and $raw.Entries) {
        $entries = @($raw.Entries)
    }

    return [PSCustomObject]@{
        DomainName = if ($raw.PSObject.Properties.Name -contains 'DomainName') { $raw.DomainName } else { $null }
        Entries    = $entries
    }
}

function Set-ADRemediationState {
    <#
    .SYNOPSIS
        Explicit read-modify-write upsert of a single remediation-state
        entry, keyed by the same Category+Issue+AffectedObject key
        Get-ADRetestComparison uses (Get-ADFindingMatchKey in Common.ps1).
    .DESCRIPTION
        Not auto-discovery - a human (or a script the user writes
        themselves) explicitly calls this to record a decision. Re-running
        this for the same -Key updates the existing entry rather than
        duplicating it.
    .PARAMETER Key
        The Category+Issue+AffectedObject key (see Get-ADFindingMatchKey).
    .PARAMETER Status
        One of Open / AcceptedRisk / InProgress / Remediated.
    .PARAMETER Owner
        Optional free-text owner (e.g. an email address).
    .PARAMETER Note
        Optional free-text note (e.g. a ticket-system reference). This
        module never calls out to any ticket system itself.
    .PARAMETER StatePath
        Path to the remediation-state JSON file. Created if it doesn't
        exist yet.
    .PARAMETER DomainName
        Optional. Recorded at the top level of the state file. Only needed
        the first time a given -StatePath is written to (or to correct it);
        subsequent calls preserve the existing DomainName if this isn't
        supplied.
    .EXAMPLE
        Set-ADRemediationState -Key 'Certificate Services|Enrollment Agent Template with Low-Privilege Enrollment (ESC3)|CN=LegacyEnroll,...' `
            -Status AcceptedRisk -Owner 'jane.doe@contoso.com' -Note 'Legacy app dependency, tracked in JIRA-1234, revisit Q3 2027.' `
            -StatePath .\AD_Remediation_State.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [ValidateSet('Open', 'AcceptedRisk', 'InProgress', 'Remediated')]
        [string]$Status,

        [Parameter()]
        [string]$Owner,

        [Parameter()]
        [string]$Note,

        [Parameter(Mandatory)]
        [string]$StatePath,

        [Parameter()]
        [string]$DomainName
    )

    $state = Get-ADRemediationState -StatePath $StatePath
    $entries = [System.Collections.ArrayList]::new(@($state.Entries))

    $existingIndex = -1
    for ($i = 0; $i -lt $entries.Count; $i++) {
        if ($entries[$i].Key -eq $Key) { $existingIndex = $i; break }
    }

    $newEntry = [PSCustomObject]@{
        Key     = $Key
        Status  = $Status
        Owner   = $Owner
        Note    = $Note
        SetDate = (Get-Date -Format 'yyyy-MM-dd')
    }

    if ($existingIndex -ge 0) {
        $entries[$existingIndex] = $newEntry
        Write-Verbose "Updated existing remediation-state entry (upsert, not append) for key: $Key"
    }
    else {
        [void]$entries.Add($newEntry)
        Write-Verbose "Added new remediation-state entry for key: $Key"
    }

    $resolvedDomainName = if ($DomainName) { $DomainName } elseif ($state.DomainName) { $state.DomainName } else { $null }

    $output = [PSCustomObject]@{
        DomainName = $resolvedDomainName
        Entries    = @($entries)
    }

    try {
        $stateDir = Split-Path -Path $StatePath -Parent
        if ($stateDir -and -not (Test-Path -Path $stateDir)) {
            New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
        }
        $output | ConvertTo-Json -Depth 6 | Out-File -FilePath $StatePath -Encoding UTF8
        Write-Verbose "Remediation state written to $StatePath"
    }
    catch {
        throw "Failed to write remediation state to '$StatePath': $_"
    }

    return $newEntry
}

#endregion
