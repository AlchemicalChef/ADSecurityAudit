# Module-level variables

# Tracks whether the CURRENTLY ACTIVE -Server override (as resolved by
# Resolve-ADSecurityAuditTargetServer) is itself an explicit, specific
# Domain Controller the operator named - as opposed to a domain name (or
# the $env:USERDNSDOMAIN default) that got resolved down to one DC (the
# PDC Emulator) purely as a deterministic pick. Both end up as "a specific
# DC FQDN" by the time downstream code sees the resolved -Server value, so
# this flag is the only way to tell the two cases apart afterwards - see
# Get-ADSecurityAuditServerIsExplicitDC / Get-ADSecurityAuditDomainController
# for why the distinction matters (whether to scope a per-DC probe to just
# that one DC, or still enumerate every DC in the domain).
$Script:ADSecurityAuditServerIsExplicitDC = $false

$Script:SeverityLevels = @{
    Critical = 4
    High = 3
    Medium = 2
    Low = 1
    Info = 0
}

# User-defined additions to the Tier-0 scope, beyond the built-in
# privileged groups/DCs/AdminSDHolder Get-ADTier0Principal already resolves
# on its own. Populated from Start-ADSecurityAudit's -AdditionalTier0DN
# parameter (Main.ps1) at the start of each run, and reset to empty there
# too, so a value from a previous Start-ADSecurityAudit call in the same
# PowerShell session never leaks into a later run that omits the
# parameter. Exists because the default Tier-0 set is necessarily generic
# (the well-known privileged groups every AD domain has) - real
# environments routinely have additional objects that are Tier-0 in
# practice (e.g. a backup service account with rights over every DC, or a
# custom-named "Tier0-Admins" group) without being nested in a built-in
# privileged group at all. See Get-ADTier0Principal below for how this is
# consumed.
$Script:AdditionalTier0DistinguishedNames = @()

$Script:ThresholdCriticalGroupSize = 5
$Script:ThresholdStandardGroupSize = 10
$Script:ThresholdInactiveDays = 90
$Script:ThresholdPasswordAgeDays = 180

$Script:ProtectedGroups = @(
    'Domain Admins'
    'Enterprise Admins'
    'Schema Admins'
    'Administrators'
    'Account Operators'
    'Server Operators'
    'Backup Operators'
    'Print Operators'
    'Domain Controllers'
    'Read-only Domain Controllers'
    'Group Policy Creator Owners'
    'Cryptographic Operators'
    'Distributed COM Users'
)

# Extended Rights GUIDs - these are for checking ACEs with ExtendedRight permissions
# Note: WriteOwner, WriteDacl, GenericAll, GenericWrite are standard AD rights checked via 
# ActiveDirectoryRights property, NOT via GUIDs
$Script:DangerousExtendedRights = @{
    'DS-Replication-Get-Changes' = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes-All' = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes-In-Filtered-Set' = '89e95b76-444d-4c62-991a-0facbeda640c'
    'User-Force-Change-Password' = '00299570-246d-11d0-a768-00aa006e0529'
    'DS-Replication-Manage-Topology' = '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Synchronize' = '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
}

# Property GUIDs for checking WriteProperty permissions
$Script:DangerousPropertyGuids = @{
    'Member' = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
    'msDS-KeyCredentialLink' = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
    'ServicePrincipalName' = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
    'msDS-AllowedToActOnBehalfOfOtherIdentity' = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
    'GPLink' = 'f30e3bc2-9ff0-11d1-b603-0000f80367c1'
    'ms-Mcs-AdmPwd' = 'ba19577d-37b2-4921-a637-429a1d99da82'
    'ms-LAPS-Password' = 'd95f499a-f5dd-4796-a2d5-6a3fba6a8e34'
    'ms-LAPS-EncryptedPassword' = 'f3531ec6-6330-4f8e-8d39-7c7867f0e4a4'
}

# Standard AD rights that indicate dangerous permissions (checked via -match on ActiveDirectoryRights)
$Script:DangerousStandardRights = @(
    'GenericAll'
    'GenericWrite'
    'WriteDacl'
    'WriteOwner'
    'AllExtendedRights'
)

# Keep legacy variable name for backward compatibility
$Script:DangerousRights = $Script:DangerousExtendedRights

class ADSecurityFinding {
    [string]$Category
    [string]$Issue
    [string]$Severity
    [int]$SeverityLevel
    [string]$Description
    [string]$Impact
    [string]$Remediation
    [string]$AffectedObject
    [hashtable]$Details
    [datetime]$DetectedDate

    # --- Additive metadata fields (introduced in v1.2.0) ---
    # These are appended to the finding/output contract and are OPTIONAL.
    # They are populated centrally from the mapping table in src/Scoring.ps1
    # via Set-ADFindingMetadata. Existing consumers that ignore them are
    # unaffected. Per the contract: finding fields are additive only.
    [string]$MitreTechnique   # MITRE ATT&CK technique id, e.g. 'T1558.001'
    [string]$AnssiControl     # ANSSI-style control id, e.g. 'vuln1_krbtgt_age'
    [int]$Weight              # Risk-score contribution (default 0)

    # --- Additive enrichment fields (introduced in v1.24.0) ---
    # Change-management-ready guidance appended per the process in
    # Finding-Enrichment-Prompt.md. These are OPTIONAL and set directly in
    # each check (src/*.ps1) immediately after Description/Impact/
    # Remediation, the same way those three fields already work - no
    # separate lookup table or tagging pass to cross-reference. Existing
    # consumers that ignore them are unaffected. Per the contract: finding
    # fields are additive only.
    [string]$EstimatedEffort  # Low/Medium/High + one-sentence reason
    [string]$KnownRisks       # 1-2 sentences on plausible compatibility/technical risk
    [string]$BackupRollback   # Easy/Moderate/Hard-Limited + one-sentence undo summary
    [string]$OperationalNotes # Optional; omitted when there's nothing additive to say

    # --- Additive coverage-linkage field (introduced in v1.24.0, alongside
    #     Test Coverage tracking) ---
    # The $allTests key (Main.ps1) of the check that produced this finding,
    # e.g. 'DomainSecurity', 'DangerousPermissions'. Set by Main.ps1's test
    # loop, NOT by individual check functions (a check has no way to know
    # its own registered name in $allTests - Main.ps1 is the one place that
    # already has both the finding and the key it came from in hand).
    #
    # Exists so a finding can be cross-referenced against a Test Coverage
    # sidecar (AD_Security_TestCoverage_<timestamp>.json) after the fact -
    # critically, so Get-ADRetestComparison can tell "this finding is
    # absent from the retest because the underlying issue was fixed" apart
    # from "this finding is absent from the retest because the check that
    # would have found it failed or was excluded this time" (see that
    # function's own docs for the false-negative this closes). A finding
    # from an export that predates this field is simply blank here -
    # treated the same as "unknown/can't cross-reference", never assumed
    # to mean any particular test.
    [string]$TestName

    ADSecurityFinding() {
        $this.DetectedDate = Get-Date
        $this.Details = @{}
        $this.MitreTechnique = ''
        $this.AnssiControl = ''
        $this.Weight = 0
        $this.EstimatedEffort = ''
        $this.KnownRisks = ''
        $this.BackupRollback = ''
        $this.OperationalNotes = ''
        $this.TestName = ''
    }
}

# Retry helper function for AD queries with exponential backoff
function Resolve-ADPrincipalNameToSid {
    <#
    .SYNOPSIS
        Best-effort translation of a 'DOMAIN\Name'-style principal name to
        its SID string.
    .DESCRIPTION
        Wraps the raw .NET NTAccount.Translate(SecurityIdentifier) call.
        Extracted as its own function - rather than inlined at each call
        site - for two reasons: (1) it's the one piece of several
        SID/name-translation call sites in this module (GpoAudits.ps1,
        GpoSecretsAudits.ps1, DomainAdminEquivalence.ps1, ReplicationAudits.ps1
        each do their own inline Translate() calls) that specifically goes
        NAME -> SID, used where a caller needs to compare against a
        SID-keyed allowlist rather than just display a resolved name; and
        (2) a raw .NET method call can't be shadowed/mocked the way a
        PowerShell function can, so testing any code that calls
        NTAccount.Translate() directly is entirely at the mercy of the live
        security-provider context (LSA/domain availability) - which varies
        by OS and by whether the test run has any real AD context at all,
        making the SUCCESS path effectively untestable inline. Wrapping it
        in a named function lets tests substitute a deterministic result
        instead.

        Returns $null - never throws - when translation fails for any
        reason (an orphaned SID, a foreign/cross-forest principal this
        session can't resolve, or simply no security-provider context
        available at all), so callers get a clean success/failure signal
        to build their own fallback behavior on.
    .PARAMETER Name
        The principal name to translate, e.g. 'CONTOSO\Domain Admins' or
        'BUILTIN\Administrators'.
    .OUTPUTS
        [string] the SID, or $null if translation failed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    try {
        return (New-Object System.Security.Principal.NTAccount($Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        Write-Verbose "Resolve-ADPrincipalNameToSid: failed to translate '$Name' to a SID: $_"
        return $null
    }
}

function Invoke-ADQueryWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Query,

        [int]$MaxAttempts = 2,
        [int]$DelaySeconds = 1,
        [string]$OperationName = "AD Query"
    )

    $attempt = 0
    $lastError = $null

    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            return (& $Query)
        }
        catch {
            $lastError = $_
            Write-Verbose "$OperationName failed (attempt $attempt/$MaxAttempts): $_"

            if ($attempt -lt $MaxAttempts) {
                $wait = $DelaySeconds * [math]::Pow(2, $attempt - 1)
                Start-Sleep -Seconds $wait
            }
        }
    }

    Write-Warning "$OperationName failed after $MaxAttempts attempts: $lastError"
    return $null
}

# Fixed: -ExportPath (and any other user-supplied path in this module) was
# being handed, while still possibly relative, to raw .NET file APIs
# ([System.IO.File]::WriteAllText, etc.) elsewhere. PowerShell cmdlets like
# Join-Path/Test-Path/New-Item are provider-aware and correctly resolve a
# relative path against $PWD (the shell's own current location) - but raw
# .NET APIs resolve relative paths against [Environment]::CurrentDirectory
# instead, and the two are frequently out of sync (many hosts - IDE
# integrated terminals, scheduled tasks, some launch shortcuts - leave
# [Environment]::CurrentDirectory pointing at the user's profile folder
# rather than keeping it synced to $PWD). The reported symptom: passing
# -ExportPath ".\foldername" resolved fine for the Join-Path/Test-Path
# calls, but the raw .NET write-test a few lines later in Main.ps1 silently
# resolved against the profile directory instead and threw "Export path is
# not writable" for a perfectly valid, writable relative path.
function Resolve-ADSecurityAuditPath {
    <#
    .SYNOPSIS
        Resolves a possibly-relative, possibly-nonexistent path to a
        fully-qualified absolute path, using PowerShell's own current
        location ($PWD) rather than .NET's [Environment]::CurrentDirectory.
    .DESCRIPTION
        Uses the PowerShell engine's own path resolution
        (GetUnresolvedProviderPathFromPSPath), which always honors $PWD.
        Works whether the path exists yet or not (string computation only -
        no filesystem access) and whether it was already absolute or not
        (a no-op in that case, aside from normalization).
    .PARAMETER Path
        The (possibly relative) path to resolve.
    .OUTPUTS
        [string] the fully-qualified absolute path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

# --- Multi-domain / multi-forest target override ---
#
# PROBLEM: none of the Get-AD*/Set-AD* calls anywhere in this module pass
# -Server. Without it, the AD PowerShell module uses a "serverless" bind
# that resolves against the invoking account's own logon domain (or
# whatever DC AD's client-side locator happens to pick), NOT necessarily
# the domain the operator actually intends to audit. In a multi-domain
# forest this produces exactly the reported symptom: an account from
# Domain A running the audit against/on a Domain B machine ends up reading
# Domain A's domain object, DCs, users, etc. instead of Domain B's.
#
# FIX: rather than patch every Get-AD*/Set-AD* call site individually
# (fragile - a single missed call silently reintroduces the bug),
# Set-ADSecurityAuditTargetServer installs a $PSDefaultParameterValues
# entry that auto-supplies -Server on every Get-AD*/Set-AD* cmdlet call for
# the rest of the session, until Clear-ADSecurityAuditTargetServer removes
# it. Start-ADSecurityAudit calls these around the live audit run when its
# own -Server parameter is supplied; see src/Main.ps1.
#
# $PSDefaultParameterValues is looked up by the engine at parameter-binding
# time in whatever scope is active when the cmdlet is invoked, so setting
# it at Global scope here means it applies inside every dot-sourced audit
# function in src/*.ps1, not just code in this file.
function Set-ADSecurityAuditTargetServer {
    <#
    .SYNOPSIS
        Forces every Get-AD*/Set-AD* AND Get-GP*/Set-GP* cmdlet call for
        the rest of the session to explicitly target one domain/DC,
        instead of the default serverless bind that can silently resolve
        to the wrong domain in a multi-domain forest.
    .DESCRIPTION
        Covers two SEPARATE PowerShell modules, not one: the
        ActiveDirectory module's Get-AD*/Set-AD*/New-AD*/Remove-AD*
        cmdlets, and the GroupPolicy module's Get-GP*/Set-GP*/New-GP*/
        Remove-GP* cmdlets (Get-GPO, Get-GPInheritance, Get-GPPermission,
        Get-GPRegistryValue, etc. - all used by this module's GPO-related
        checks: Test-ADGroupPolicies, Test-ADLegacyAuthSurface,
        Test-ADDomainHardeningFlags, Test-ADKerberosHardening).

        Prior to this fix, only the ActiveDirectory-module wildcard was
        installed. Cmdlet names in the GroupPolicy module start with
        "Get-GP", not "Get-AD" - the 'Get-AD*:Server' wildcard NEVER
        matched them, so every GPO-related check was completely unscoped
        by -Server the entire time, regardless of whether an override was
        active for AD cmdlets. Get-GPO/Get-GPInheritance/Get-GPPermission/
        Get-GPRegistryValue all accept the same -Server parameter (and
        derive the target domain from whichever server you point them at,
        without also needing -Domain), so this is exactly the same fix,
        just for a second module the original wildcard silently missed.
    .PARAMETER Server
        A domain FQDN (e.g. 'domainb.corp.com') or a specific DC FQDN/
        hostname (e.g. 'dc01.domainb.corp.com'). Either is accepted by
        -Server on both the AD and GroupPolicy cmdlets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Server
    )
    if (-not $Global:PSDefaultParameterValues) {
        $Global:PSDefaultParameterValues = @{}
    }
    $Global:PSDefaultParameterValues['Get-AD*:Server'] = $Server
    $Global:PSDefaultParameterValues['Set-AD*:Server'] = $Server
    $Global:PSDefaultParameterValues['New-AD*:Server'] = $Server
    $Global:PSDefaultParameterValues['Remove-AD*:Server'] = $Server
    $Global:PSDefaultParameterValues['Get-GP*:Server'] = $Server
    $Global:PSDefaultParameterValues['Set-GP*:Server'] = $Server
    $Global:PSDefaultParameterValues['New-GP*:Server'] = $Server
    $Global:PSDefaultParameterValues['Remove-GP*:Server'] = $Server
    Write-Verbose "Set-ADSecurityAuditTargetServer: Get-AD*/Set-AD*/New-AD*/Remove-AD* AND Get-GP*/Set-GP*/New-GP*/Remove-GP* cmdlets will now explicitly target '$Server' for the rest of this session."
}

function Clear-ADSecurityAuditTargetServer {
    <#
    .SYNOPSIS
        Removes the -Server override installed by
        Set-ADSecurityAuditTargetServer. Safe to call even if it was never
        set (no-op).
    #>
    [CmdletBinding()]
    param()
    if ($Global:PSDefaultParameterValues) {
        $Global:PSDefaultParameterValues.Remove('Get-AD*:Server')
        $Global:PSDefaultParameterValues.Remove('Set-AD*:Server')
        $Global:PSDefaultParameterValues.Remove('New-AD*:Server')
        $Global:PSDefaultParameterValues.Remove('Remove-AD*:Server')
        $Global:PSDefaultParameterValues.Remove('Get-GP*:Server')
        $Global:PSDefaultParameterValues.Remove('Set-GP*:Server')
        $Global:PSDefaultParameterValues.Remove('New-GP*:Server')
        $Global:PSDefaultParameterValues.Remove('Remove-GP*:Server')
    }
    # Reset alongside the override itself so a leftover $true from a
    # previous run/call never survives into one where no -Server has been
    # resolved yet - see the flag's declaration comment for what it means.
    $Script:ADSecurityAuditServerIsExplicitDC = $false
}

# When -Server isn't supplied at all, this resolves a sensible, DETERMINISTIC
# default instead of leaving it to whatever the AD module/Windows LDAP
# client's own ambient resolution happens to pick (which is the whole class
# of bug the rest of this file exists to work around). Defaults to the
# CURRENT USER's own domain - $env:USERDNSDOMAIN, the DNS domain of the
# account whose credentials are running this session, set by the LSA at
# logon - rather than the machine's joined domain, matching the most common
# operator intent ("audit the domain my account belongs to") without
# requiring -Server to be typed for that case at all.
function Resolve-ADSecurityAuditTargetServer {
    <#
    .SYNOPSIS
        Resolves the effective -Server value to a SPECIFIC DC - the
        domain's PDC Emulator, when a DOMAIN NAME was given or defaulted
        to; but honors an explicit, specific DC identity AS GIVEN, without
        substituting a different DC for it.
    .DESCRIPTION
        $env:USERDNSDOMAIN is set by the LSA at logon from the DOMAIN
        ACCOUNT's own domain - not $env:USERDOMAIN (NetBIOS form, can be
        the computer name for a local logon) and not the machine's own
        joined domain (Get-CimInstance Win32_ComputerSystem / Get-ADDomain
        with no override). This means the default now correctly follows
        the operator's account even when the machine itself is joined to a
        different domain in the forest - the scenario this module's
        -Server parameter was originally added to fix.

        Whatever value that gives (an explicit -Server, or the
        $env:USERDNSDOMAIN default) is then checked to see whether it is
        ALREADY a specific Domain Controller's own identity - via
        Get-ADDomainController -Identity, which only succeeds for a real
        DC's own GUID/Name/IPv4Address/DNS host name, not a bare domain
        FQDN. If so, that exact value is returned unchanged: an operator
        who names a specific DC has very often done so deliberately (a
        segmented network, explicit rules of engagement, or simply the
        only DC reachable for this engagement) and may not have access to,
        or want traffic directed at, that domain's PDC Emulator at all -
        silently redirecting to a different DC than the one asked for
        defeats the entire purpose of passing a specific -Server value.
        This was a real bug (reported): a specific-DC -Server value was
        previously always promoted to the PDC Emulator regardless, which
        broke the "only this one DC is reachable for the engagement" case
        even though it worked correctly for the "target this domain"
        case.

        Only when the value is NOT itself a resolvable DC identity (the
        normal case: a domain FQDN, or the $env:USERDNSDOMAIN default) is
        it resolved ONE MORE STEP: to that domain's PDC Emulator FSMO role
        holder specifically, via Get-ADDomain's own .PDCEmulator property.
        This removes an entire category of ambiguity that a domain name or
        "just pick a DC" left open:
          - A bare domain FQDN is not a valid Get-ADDomainController
            -Identity value (only a real DC's own GUID/Name/IPv4Address/
            DNS host name is) - every live-network-probe call that used
            to receive the raw domain name here had to work around that
            separately (see Get-ADSecurityAuditDomainController /
            Get-ADTargetDomainController).
          - Resolving a domain name to "a" DC via the normal DC-locator
            (DNS SRV records + site/subnet mapping) is exactly the
            non-deterministic, "closest DC" resolution this module's
            -Server override exists to bypass in the first place - it can
            depend on the calling MACHINE's own site membership rather
            than the domain actually being audited.
          - Every AD query in a single run now targets the exact same DC
            throughout, rather than potentially different DCs picked
            independently by different cmdlet calls - important on a
            domain with any inter-DC replication lag, since the PDC
            Emulator is also where Windows itself directs urgent/
            authoritative reads (e.g. password/lockout state) by
            convention.
        Falls back to the plain domain/DC name as given if the PDC
        Emulator can't be resolved (e.g. an unreachable or inaccessible
        domain) rather than turning a working (if less precise)
        resolution into a hard failure.

        KNOWN LIMITATION: if the caller used `runas /netonly` (or an
        equivalent alternate-credential technique) to run this session
        under a DIFFERENT domain's credentials than the one they're
        locally logged into, $env:USERDNSDOMAIN still reflects the
        original interactive logon's domain, not the alternate
        credential's domain, since /netonly does not change the process's
        inherited environment block. Pass -Server explicitly in that case.
    .PARAMETER Server
        The explicit -Server value the caller passed, if any. Empty/$null
        means "not specified". Accepts a domain FQDN, a specific DC name,
        or is omitted entirely.
    .OUTPUTS
        [string] the specific DC as given (if it was already one), the
        resolved PDC Emulator FQDN for the target domain (if a domain name
        was given or defaulted to), the plain value passed/defaulted to if
        PDC resolution failed, or $null if neither an explicit value nor
        $env:USERDNSDOMAIN is available (e.g. a local, non-domain logon
        session) - callers treat a $null return the same way they
        previously treated "no -Server given at all".
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Server
    )

    # IDEMPOTENCY GUARD (fixes a real, confirmed regression): ten check
    # functions (AdminSDAudits, DomainAdminEquivalence, DomainHardening-
    # Audits, GpoAudits, GroupAudits, KerberosHardeningAudits,
    # PermissionsAudits, PrivilegedUsers, RodcSecurityAudits, UserAudits)
    # each independently call
    # `Set-ADSecurityAuditTargetServer -Server (Resolve-ADSecurityAuditTargetServer -Server $Server)`
    # so they're self-sufficient when invoked standalone, outside Main.ps1's
    # pipeline. But when invoked FROM Main.ps1, $Server here is not the
    # operator's raw input - it's $effectiveServer, the ALREADY-RESOLVED
    # value this same function produced moments earlier (e.g. a domain's
    # PDC Emulator FQDN, resolved from "no -Server given" or a domain
    # name). That resolved FQDN is, by definition, itself a valid DC
    # identity - so re-running full resolution against it made
    # Get-ADDomainController -Identity succeed and misclassified it as
    # "the operator explicitly named this one DC", flipping
    # $Script:ADSecurityAuditServerIsExplicitDC from false to true even
    # though no -Server was ever given at the top level. Since that flag
    # is script-scoped (not reset between checks), this also silently
    # corrupted every LATER check in the same run that reads the flag
    # without calling Resolve again itself (e.g. AuditPolicyAudits.ps1) -
    # explaining reports of audit-policy-style checks narrowing to a
    # single DC even on a plain, no-argument run.
    #
    # Once $Server already matches the currently active override (i.e.
    # this exact value already went through resolution earlier THIS
    # session - always true for the ten call sites above when running
    # under Main.ps1), there is nothing new to resolve: return it
    # unchanged and leave the explicit-DC flag exactly as it already is,
    # rather than re-deriving (and potentially corrupting) it. This does
    # not change standalone-invocation behavior at all - the first call
    # in a session (or a call with a genuinely different $Server) still
    # runs the full resolution logic below.
    if ($Server -and $Server -eq (Get-ADSecurityAuditActiveServerOverride)) {
        Write-Verbose "Resolve-ADSecurityAuditTargetServer: '$Server' already matches the active override for this session; returning it unchanged without re-deriving the explicit-DC scope flag."
        return $Server
    }

    $requested = $null
    if ($Server) {
        $requested = $Server
    }
    elseif ($env:USERDNSDOMAIN) {
        Write-Verbose "Resolve-ADSecurityAuditTargetServer: -Server not specified; defaulting to the current user's domain (`$env:USERDNSDOMAIN): $env:USERDNSDOMAIN"
        $requested = $env:USERDNSDOMAIN
    }
    else {
        Write-Verbose "Resolve-ADSecurityAuditTargetServer: -Server not specified and `$env:USERDNSDOMAIN is empty (e.g. a local, non-domain logon session); falling back to the AD module's own default resolution."
        $Script:ADSecurityAuditServerIsExplicitDC = $false
        return $null
    }

    # Fixed: don't promote an ALREADY-specific Domain Controller to the
    # domain's PDC Emulator instead. -Identity only succeeds for a real
    # DC's own GUID/Name/IPv4Address/DNS host name (it throws for a bare
    # domain FQDN - the same distinction Get-ADTargetDomainController's
    # own fix relies on), so success here is an unambiguous signal that
    # $requested already names one specific DC, which is returned as-is.
    # No -Server is passed on this call: -Identity and -Server are not
    # meaningfully combinable here (there is no "different DC to ask" once
    # -Identity already names the DC itself), and no override is active
    # yet at the point this function runs, so nothing would auto-inject
    # one anyway.
    try {
        $specificDC = Get-ADDomainController -Identity $requested -ErrorAction Stop
        if ($specificDC) {
            $Script:ADSecurityAuditServerIsExplicitDC = $true

            # Determine BEFORE logging whether this explicitly-named DC
            # happens to also be the domain's PDC Emulator, so the verbose
            # message (and the run-scope note below) can say so either way
            # instead of always phrasing this as "avoided substituting the
            # PDC" - which reads as if the PDC was somehow at risk of being
            # used, even on the (common) occasion the operator's explicit
            # DC IS the PDC. $requested is asked about its OWN domain here
            # (Get-ADDomain -Server $requested) - always reachable, since
            # $requested is the one DC we already know this run can talk
            # to - so this adds no new reachability dependency beyond what
            # -Server already requires.
            $pdcEmulator = $null
            $pdcLookupFailed = $false
            try {
                $pdcEmulator = (Get-ADDomain -Server $requested -ErrorAction Stop).PDCEmulator
            }
            catch {
                $pdcLookupFailed = $true
                Write-Verbose "Resolve-ADSecurityAuditTargetServer: could not determine whether '$requested' is the domain's PDC Emulator: $_"
            }

            $isPdc = $pdcEmulator -and $specificDC.HostName -and
                $pdcEmulator.ToString().ToLowerInvariant() -eq $specificDC.HostName.ToString().ToLowerInvariant()

            if ($isPdc) {
                Write-Verbose "Resolve-ADSecurityAuditTargetServer: '$requested' is itself a specific Domain Controller (and happens to be the domain's PDC Emulator); using it directly. NOTE: because -Server named a specific DC rather than a domain name, every per-DC check in this run is scoped to ONLY '$requested' - other Domain Controllers in the domain will NOT be evaluated (see Get-ADSecurityAuditDomainController)."
            }
            elseif ($pdcLookupFailed) {
                Write-Verbose "Resolve-ADSecurityAuditTargetServer: '$requested' is itself a specific Domain Controller; using it directly rather than substituting the domain's PDC Emulator for it (could not confirm whether it is also the PDC Emulator - see prior warning). NOTE: because -Server named a specific DC rather than a domain name, every per-DC check in this run is scoped to ONLY '$requested' - other Domain Controllers in the domain will NOT be evaluated."
            }
            else {
                Write-Verbose "Resolve-ADSecurityAuditTargetServer: '$requested' is itself a specific Domain Controller (NOT the domain's PDC Emulator, which is '$pdcEmulator'); using it directly rather than substituting the PDC Emulator for it. NOTE: because -Server named a specific DC rather than a domain name, every per-DC check in this run is scoped to ONLY '$requested' - other Domain Controllers in the domain will NOT be evaluated."
            }

            # Surface a run-scope note whenever -Server names one explicit,
            # specific DC, since this narrows every per-DC probe in the
            # module (Get-ADSecurityAuditDomainController) to ONLY that DC
            # for the rest of the run - a real coverage gap the report
            # reader should know about regardless of whether the named DC
            # happens to also be the PDC. The wording differs because the
            # PDC-only-check implication (Test-ADMachineAccountQuota,
            # Test-ADDomainSecurity - see their own docs) only applies when
            # the named DC is NOT the PDC; when it IS the PDC, those
            # specific checks are unaffected and the note says so.
            if ($isPdc) {
                Add-ADRunScopeNote -Category 'PDC Scope' -Message "This run was scoped to a single, explicitly-named Domain Controller ('$($specificDC.HostName)'), which also happens to be the domain's PDC Emulator. This module's 'PDC-only' checks (e.g. Machine Account Quota, password policy, domain/forest functional level, tombstone lifetime) are unaffected by this. However, every OTHER per-DC check (e.g. audit policy, LDAP signing/channel binding, Kerberos hardening, legacy-auth surface, RODC posture) was scoped to this one DC only and did NOT evaluate any other Domain Controller in the domain - if the environment has other DCs with different configuration or patch levels, this run will not have surfaced that."
            }
            elseif (-not $pdcLookupFailed) {
                Add-ADRunScopeNote -Category 'PDC Scope' -Message "This run was scoped to Domain Controller '$($specificDC.HostName)', which is NOT the domain's PDC Emulator ('$pdcEmulator'). This module's 'PDC-only' checks (e.g. Machine Account Quota, password policy, domain/forest functional level, tombstone lifetime) read a single domain/forest-wide attribute and queried '$($specificDC.HostName)' directly rather than the PDC - the value should be identical to the PDC's own barring replication lag, but confirm '$($specificDC.HostName)' is fully replicated if these findings are load-bearing for this engagement. Every other per-DC check was also scoped to this one DC only and did NOT evaluate any other Domain Controller in the domain."
            }
            else {
                Add-ADRunScopeNote -Category 'PDC Scope' -Message "This run was scoped to a single, explicitly-named Domain Controller ('$($specificDC.HostName)'). Whether this is also the domain's PDC Emulator could not be confirmed (see Verbose log), so this module's 'PDC-only' checks (e.g. Machine Account Quota, password policy, domain/forest functional level, tombstone lifetime) may have queried a non-PDC DC. Every per-DC check was scoped to this one DC only and did NOT evaluate any other Domain Controller in the domain."
            }

            return $requested
        }
    }
    catch {
        Write-Verbose "Resolve-ADSecurityAuditTargetServer: '$requested' is not itself a resolvable Domain Controller identity ($_); treating it as a domain name and resolving to its PDC Emulator."
    }

    # Past this point, $requested is a domain name (or the
    # $env:USERDNSDOMAIN default), not an operator-named specific DC -
    # every remaining return path below resolves to "a" DC only as an
    # implementation detail (a deterministic single-DC pick, or a bare
    # fallback), not something the operator asked to be scoped to
    # exclusively. Get-ADSecurityAuditDomainController and other
    # per-DC-probe consumers rely on this flag to decide whether to still
    # enumerate every DC in the domain (yes, in this branch) or narrow to
    # just one DC (only when the flag above was set true).
    $Script:ADSecurityAuditServerIsExplicitDC = $false

    try {
        $pdcEmulator = (Get-ADDomain -Server $requested -ErrorAction Stop).PDCEmulator
        if ($pdcEmulator) {
            Write-Verbose "Resolve-ADSecurityAuditTargetServer: resolved '$requested' to its PDC Emulator '$pdcEmulator' - this DC is the default/domain-wide query target for the rest of this run/call (e.g. single-attribute 'PDC-only' checks). This is NOT a single-DC scope: per-DC checks (audit policy, Kerberos hardening, RODC posture, etc.) still enumerate and evaluate EVERY Domain Controller in the domain, exactly as when -Server is omitted entirely."
            return $pdcEmulator
        }
    }
    catch {
        Write-Verbose "Resolve-ADSecurityAuditTargetServer: could not resolve the PDC Emulator for '$requested' ($_); falling back to '$requested' as given."
    }

    return $requested
}

# Several files previously read the Configuration/Schema naming context via
# a RAW ADSI bind - ([ADSI]"LDAP://RootDSE").configurationNamingContext -
# instead of the AD module's own Get-ADRootDSE cmdlet. [ADSI]"LDAP://..."
# is a System.DirectoryServices/COM object construction, NOT a PowerShell
# cmdlet call, so it is invisible to $PSDefaultParameterValues entirely -
# Set-ADSecurityAuditTargetServer's -Server override has no effect on it
# whatsoever. Left alone, it performs its own independent "serverless" LDAP
# bind that resolves via the Windows LDAP client's locator, which
# typically binds to a DC of the CALLING MACHINE's own joined domain -
# so even with -Server correctly set to a different target, every one of
# these calls would silently keep talking to the wrong domain regardless.
# This was the actual remaining root cause behind "the -Server override is
# still talking to the wrong domain" even when the operator's own account
# and machine agree with each other.
#
# Fix: go through Get-ADRootDSE instead, which IS a Get-AD* cmdlet and
# therefore honors the -Server override automatically (via the global
# default) or explicitly (via its own -Server parameter, for callers that
# have one in scope).
function Get-ADRootDSEValue {
    <#
    .SYNOPSIS
        Returns configurationNamingContext or schemaNamingContext from
        RootDSE, honoring the -Server override - unlike a raw
        [ADSI]"LDAP://RootDSE" bind, which does not.
    .PARAMETER Property
        'configurationNamingContext' or 'schemaNamingContext'.
    .PARAMETER Server
        Optional explicit override, for callers that already have -Server
        in their own parameter list. When omitted, relies on whatever
        Set-ADSecurityAuditTargetServer has installed globally, if anything.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('configurationNamingContext', 'schemaNamingContext')]
        [string]$Property,

        [Parameter()]
        [string]$Server
    )
    $rootDSEParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $rootDSEParams['Server'] = $Server }
    $rootDSE = Get-ADRootDSE @rootDSEParams
    return $rootDSE.$Property
}

# Get-ADDomainController's -Discover and -Server are mutually exclusive
# parameter sets - if Set-ADSecurityAuditTargetServer's global -Server
# default is active and a call site still uses -Discover directly (as
# several live-network-probe checks do, independent of Main.ps1's own DC
# discovery), PowerShell throws a parameter-binding error rather than
# honoring the override, and the probe is silently skipped by the
# surrounding try/catch instead of correctly targeting the requested
# domain. This centralizes the same "if an override is active, resolve
# directly against it; otherwise fall back to -Discover" logic Main.ps1
# already applies to its own DC connectivity check, so every other
# live-probe call site gets the same correctness for free.
function Get-ADSecurityAuditActiveServerOverride {
    <#
    .SYNOPSIS
        Returns the -Server value currently installed by
        Set-ADSecurityAuditTargetServer, or $null if no override is active.
    .DESCRIPTION
        A few call sites (forest-root-only group lookups, anonymous-bind/
        zone-transfer probes) need to know and explicitly reuse the ACTUAL
        override value - not just rely on $PSDefaultParameterValues to
        auto-supply it - because they either can't use a plain Get-AD*
        cmdlet call (raw network probes) or need to deliberately query a
        DIFFERENT server for one specific lookup (e.g. the forest root
        instead of the audited child domain) without losing track of what
        the "normal" override value was. Centralized here instead of each
        caller re-reading $Global:PSDefaultParameterValues directly.

        LESSON LEARNED / MANDATORY PATTERN GOING FORWARD - READ THIS
        BEFORE ADDING ANY NEW Get-AD*/Set-AD*/Get-GP*/Set-GP* CALL:
        Set-ADSecurityAuditTargetServer installs
        $Global:PSDefaultParameterValues['Get-AD*:Server'] (and the
        Get-GP*/Set-GP*/etc. equivalents), which SHOULD auto-supply
        -Server to every matching cmdlet call with no per-call-site
        change needed - that was the whole point of the mechanism, and
        the wildcard matching logic is textbook-correct PowerShell.
        Despite that, in practice the global default was observed NOT to
        be picked up for at least some -Server-critical Get-AD* calls in
        production use, and explicitly hardcoding -Server on the
        affected calls resolved it. The exact cause has not been root-
        caused (candidates include host/profile-specific
        $PSDefaultParameterValues quirks, or some Get-AD* calls running
        in a context/scope where the global default did not apply as
        expected) - but the practical, binding consequence is:

        DO NOT rely on the global $PSDefaultParameterValues default alone
        for any new Get-AD*/Set-AD*/New-AD*/Remove-AD*/Get-GP*/Set-GP*/
        New-GP*/Remove-GP* call added to this codebase. Every new call
        MUST explicitly pass -Server (Get-ADSecurityAuditTargetServerValue)
        (or the equivalent already-resolved local variable, e.g.
        $__adServer/$targetServer, where a function has already captured
        one) - even though the global default is ALSO installed as a
        second layer of defense. Passing an explicit -Server value that
        happens to be $null (no override active) is safe and behaves
        identically to omitting -Server entirely; it is NOT safe to skip
        the explicit -Server and assume the global default will cover it.
    .OUTPUTS
        [string] the active -Server override, or $null.
    #>
    [CmdletBinding()]
    param()

    if ($Global:PSDefaultParameterValues -and $Global:PSDefaultParameterValues.ContainsKey('Get-AD*:Server')) {
        return $Global:PSDefaultParameterValues['Get-AD*:Server']
    }
    return $null
}

function Get-ADSecurityAuditTargetServerValue {
    <#
    .SYNOPSIS
        Alias for Get-ADSecurityAuditActiveServerOverride - same function,
        second name. Prefer calling this one in new code; both resolve to
        the identical value and either name is safe to use interchangeably
        in existing code.
    .DESCRIPTION
        Two names exist for the same underlying value because a later fix
        (this function) was written independently of
        Get-ADSecurityAuditActiveServerOverride (the original, still used
        by several existing call sites - forest-root group resolution,
        Get-ADTargetDomainController, the anonymous-bind/zone-transfer
        probes) before the two were reconciled. Rather than rename every
        existing call site to consolidate on one name (needless churn,
        highest-risk step for zero behavioral benefit), this function is
        kept as a thin, permanent alias so code written against EITHER
        name keeps working. See the MANDATORY PATTERN note on
        Get-ADSecurityAuditActiveServerOverride - it applies identically
        to this name.
    .OUTPUTS
        [string] the active -Server override, or $null.
    #>
    [CmdletBinding()]
    param()
    return Get-ADSecurityAuditActiveServerOverride
}

function Get-ADSecurityAuditServerIsExplicitDC {
    <#
    .SYNOPSIS
        Returns whether the CURRENTLY ACTIVE -Server override is itself an
        explicit, specific Domain Controller the operator named - as
        opposed to a domain name (or the $env:USERDNSDOMAIN default) that
        Resolve-ADSecurityAuditTargetServer resolved down to one DC (the
        PDC Emulator) purely as a deterministic pick.
    .DESCRIPTION
        Both cases end up as "a specific DC FQDN" by the time downstream
        code sees the resolved -Server value, so the string alone can't
        distinguish them - this flag is set by
        Resolve-ADSecurityAuditTargetServer at the point where that
        distinction is still knowable, and read back here by any consumer
        that needs to decide between two genuinely different behaviors:

          - $true (operator named one specific DC): a per-DC probe should
            scope to ONLY that DC - the operator very often named it
            because it's the only one reachable/in-scope for this
            engagement (a segmented network, explicit rules of
            engagement), and enumerating/attempting every other DC in the
            domain anyway would generate noise or failures against DCs
            that were never meant to be touched. See
            Get-ADSecurityAuditDomainController.
          - $false (a domain name, or no override at all): the existing
            "enumerate every DC in the domain" behavior is correct and
            should NOT be narrowed to one DC - several checks (e.g. the
            anonymous-bind/null-session probes in
            DomainHardeningAudits.ps1) specifically enumerate every DC to
            avoid missing a partially-hardened fleet.

        Always $false until Resolve-ADSecurityAuditTargetServer has run at
        least once in this session, and reset to $false by
        Clear-ADSecurityAuditTargetServer, so a bare -Server value nobody
        ran through that resolution function is never mistakenly treated
        as an explicit single-DC scope.
    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    param()
    return [bool]$Script:ADSecurityAuditServerIsExplicitDC
}

function Split-ADObjectByTargetDomain {
    <#
    .SYNOPSIS
        Splits a set of AD objects into those that belong to the domain
        currently being audited and those that don't, instead of silently
        mixing cross-domain objects into a single-domain audit's results.
    .DESCRIPTION
        -Server pins a Get-AD* cmdlet CALL to one domain, but doesn't
        guarantee every OBJECT that call returns actually belongs to that
        domain. The clearest case in this module: Get-ADGroupMember
        -Recursive walks nested group membership, and in a multi-domain
        forest a privileged group can legitimately contain members from
        OTHER domains (a universal group, or a child domain's Domain Admins
        nested into the forest root's Enterprise Admins). Get-ADGroupMember
        does not filter these out or flag them - they come back as
        ordinary member objects, indistinguishable from same-domain members
        unless something checks their own DistinguishedName.

        This is exactly the shape of the "wrong domain" failure mode this
        module's -Server override exists to prevent: an operator scoped to
        Domain B can still end up with Domain A objects quietly folded into
        Domain B's findings/report if nothing validates membership at this
        level - particularly plausible if Domain A happens to be the
        forest root (Enterprise Admins/Schema Admins live there) or the
        machine's own joined domain. Call sites that walk group membership
        should use this to make any cross-domain leakage visible (a
        Write-Warning and/or a dedicated finding) rather than silent.
    .PARAMETER InputObject
        AD objects to check (anything with a DistinguishedName property -
        users, computers, groups).
    .PARAMETER TargetDomainDN
        The DistinguishedName of the domain being audited (e.g.
        $domain.DistinguishedName). An object is considered in-scope only
        if its own DistinguishedName ends with this.
    .OUTPUTS
        PSCustomObject: InScope (array), Foreign (array).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [array]$InputObject = @(),

        [Parameter(Mandatory)]
        [string]$TargetDomainDN
    )

    $inScope = @()
    $foreign = @()
    foreach ($obj in @($InputObject)) {
        if (-not $obj -or -not $obj.DistinguishedName) {
            # Can't determine domain membership without a DN. Treated as
            # in-scope rather than silently dropped - this guard is a
            # safety net for detecting cross-domain contamination, not a
            # general-purpose filter, and a DN-less object is a different
            # (pre-existing) problem it isn't meant to paper over.
            $inScope += $obj
            continue
        }
        # Suffix match on the DN, not an exact/case-sensitive comparison -
        # DNs are case-insensitive in AD and TargetDomainDN is itself a
        # suffix of every in-domain object's own DN (e.g. an object DN of
        # "CN=user1,OU=Users,DC=domainb,DC=corp,DC=com" against a
        # TargetDomainDN of "DC=domainb,DC=corp,DC=com").
        if ($obj.DistinguishedName.ToString().ToLowerInvariant().EndsWith($TargetDomainDN.ToLowerInvariant())) {
            $inScope += $obj
        }
        else {
            $foreign += $obj
        }
    }

    return [PSCustomObject]@{
        InScope = @($inScope)
        Foreign = @($foreign)
    }
}

function Get-ADSecurityAuditDomainController {
    <#
    .SYNOPSIS
        Enumerates Domain Controllers for ONE specific domain, correctly
        scoped - unlike a bare `Get-ADDomainController -Filter`, which
        queries the forest-wide Sites/Configuration container and returns
        DCs from EVERY domain in the forest regardless of which -Server
        you bind to. When -Server is itself an explicit, specific DC
        (rather than a domain name), scopes to ONLY that one DC instead.
    .DESCRIPTION
        Get-ADDomainController's -Filter/-LDAPFilter parameter set searches
        the Configuration naming context (CN=Sites,CN=Configuration,...),
        which is forest-wide and replicated to every DC in the forest - so
        -Server only controls WHICH DC answers the query, not the query's
        SCOPE. Every one of this module's per-DC probes (anonymous bind,
        null session, Kerberos hardening, legacy auth, audit policy,
        known-DC-vulnerability checks, stale-object depth, RODC security,
        control-path graph, coercion/relay exposure, and the main run's own
        DC connectivity check) previously used a bare
        `Get-ADDomainController -Filter *` to enumerate DCs to probe. In a
        multi-domain forest this silently returns - and every one of those
        checks then iterates over - Domain Controllers from OTHER domains
        too, regardless of an active -Server override. This is a concrete,
        confirmed explanation for "wrong domain" symptoms reported
        specifically against DCs: -Server WAS being honored for BINDING
        the query, but the query's own RESULT SET was never actually
        domain-scoped to begin with - a completely different failure mode
        than the -Server plumbing itself being broken.

        This function performs the same -Filter enumeration, then filters
        the result to DCs whose own .Domain property matches the domain
        actually resolved via Get-ADDomain against the same -Server.
        Get-ADDomain does NOT have this problem - it uses a different,
        -Identity/-Server-scoped code path, not the forest-wide
        Configuration container -Filter search does.

        FIXED (reported regression): the domain-wide enumeration above is
        correct when -Server is a domain name (or defaulted), but was
        ALSO being applied when -Server was itself an explicit, specific
        DC the operator named - e.g. the only DC reachable/in-scope for an
        engagement (a segmented network, explicit rules of engagement).
        Every per-DC probe would then still attempt every OTHER DC in the
        domain too, generating failures/noise against DCs that were never
        meant to be touched and defeating the entire purpose of naming one
        specific DC. Since the resolved -Server string alone can't
        distinguish "operator named this DC" from "a domain name got
        resolved down to one DC (the PDC Emulator) as a deterministic
        pick" (see Resolve-ADSecurityAuditTargetServer), this function now
        checks Get-ADSecurityAuditServerIsExplicitDC, which carries that
        distinction forward explicitly. When it's true, this function
        resolves and returns ONLY the named DC (still honoring -Filter,
        by checking that DC's own membership in the filtered result set,
        since -Filter and -Identity are mutually exclusive parameter
        sets on Get-ADDomainController) instead of enumerating the domain.
    .PARAMETER Server
        Optional. Passed through to both the Get-ADDomain and
        Get-ADDomainController calls - typically the active -Server
        override, when the caller wants to be explicit about it. When
        omitted, no -Server is passed to either call, so an active
        Set-ADSecurityAuditTargetServer override (if any) is still applied
        via the normal $PSDefaultParameterValues auto-injection - this
        matches every call site's pre-fix behavior exactly, so the ONLY
        behavioral change from this fix is the domain-scoping filter
        below, not how -Server itself gets resolved.
    .PARAMETER Filter
        Optional. Passed through to Get-ADDomainController's -Filter.
        Defaults to '*'. Accepts the same string or script-block filter
        syntax Get-ADDomainController itself does (e.g. a RODC-only
        filter), while still getting correct domain scoping (or, when
        -Server is an explicit specific DC, correct single-DC scoping).
    .PARAMETER IgnoreExplicitDCScope
        When set, ALWAYS enumerates every DC belonging to the resolved
        target domain, even if -Server is itself an explicit, specific DC
        that would otherwise narrow the result to just that one DC.

        Added for callers that need the domain's TRUE total DC inventory
        for a purpose OTHER than deciding which DCs to probe/query live -
        e.g. the "Insufficient Domain Controller Count" redundancy finding
        (Test-ADStaleObjectDepth), and the primaryGroupID=516 legitimacy
        check in that same function (a real DC's computer object is only
        recognized as legitimately holding primaryGroupID 516 if its DN
        appears in the enumerated DC set - narrowing that set to one
        explicitly-named DC would misclassify every OTHER real DC in the
        domain as suspicious). Both are properties of the DOMAIN, not of
        which DC(s) the operator happened to scope live probing to, so
        narrowing them to match -Server's probe-scoping intent would
        produce an actively wrong answer (an under-count, or a false-
        positive "rogue DC-like object" finding) rather than a merely
        incomplete one.

        $Server is still used as the QUERY TARGET when this switch is
        set (the one DC we ask has to be reachable - typically the same
        explicitly-named DC that's reachable for everything else in this
        run) - only the RESULT-SET NARROWING is bypassed. This is safe:
        Get-ADDomainController's -Filter search reads the forest-wide
        Configuration container, which every DC (including the one
        explicitly named) replicates in full, so asking dc07 "list every
        DC in this domain" returns a complete, accurate answer even
        though dc07 itself is the only DC this run has been told to
        contact.
    .OUTPUTS
        Array of Get-ADDomainController result objects: every DC belonging
        to the resolved target domain (the normal case, or always when
        -IgnoreExplicitDCScope is set), or exactly the one DC named by
        -Server when it is an explicit specific DC and
        -IgnoreExplicitDCScope is NOT set (empty if that DC doesn't match
        a non-default -Filter). Throws if the Get-ADDomain call, or
        resolving an explicit -Server to its DC, fails - mirroring the
        -ErrorAction Stop every existing call site already used on its own
        bare Get-ADDomainController call.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        $Filter = '*',

        [Parameter()]
        [switch]$IgnoreExplicitDCScope
    )

    $domainParams = @{ ErrorAction = 'Stop' }
    if ($Server) { $domainParams['Server'] = $Server }
    $targetDomainDNSRoot = (Get-ADDomain @domainParams).DNSRoot

    if ($Server -and (Get-ADSecurityAuditServerIsExplicitDC) -and -not $IgnoreExplicitDCScope) {
        Write-Verbose "Get-ADSecurityAuditDomainController: '$Server' is an explicit, specific Domain Controller (not a domain name); scoping to ONLY this DC instead of enumerating every DC in '$targetDomainDNSRoot'."
        try {
            $singleDC = Get-ADDomainController -Identity $Server -ErrorAction Stop
        }
        catch {
            throw "Get-ADSecurityAuditDomainController: could not resolve the explicitly-named Domain Controller '$Server': $_"
        }

        if ($Filter -and $Filter -ne '*') {
            # -Filter and -Identity are mutually exclusive parameter sets
            # on Get-ADDomainController, so the single DC's match against
            # a non-default filter (e.g. an RODC-only filter) can't be
            # checked in the same -Identity call above. Run the same
            # broad -Filter query the non-explicit-DC path below would
            # use, purely to confirm whether our one DC is a member of
            # that result set - not to enumerate DCs to probe.
            $filterParams = @{ Filter = $Filter; ErrorAction = 'Stop' }
            if ($Server) { $filterParams['Server'] = $Server }
            $filterMatches = @(Get-ADDomainController @filterParams | Where-Object { $_.Domain -eq $targetDomainDNSRoot })
            $isMatch = [bool]@($filterMatches | Where-Object { $_.HostName -eq $singleDC.HostName })
            if (-not $isMatch) {
                Write-Verbose "Get-ADSecurityAuditDomainController: '$Server' does not match -Filter '$Filter'; returning no Domain Controllers."
                return @()
            }
        }

        return @($singleDC)
    }

    $dcParams = @{ Filter = $Filter; ErrorAction = 'Stop' }
    if ($Server) { $dcParams['Server'] = $Server }
    $allDCs = @(Get-ADDomainController @dcParams)

    $scoped = @($allDCs | Where-Object { $_.Domain -eq $targetDomainDNSRoot })

    $foreignCount = $allDCs.Count - $scoped.Count
    if ($foreignCount -gt 0) {
        Write-Warning "Get-ADSecurityAuditDomainController: excluded $foreignCount Domain Controller(s) belonging to a domain other than '$targetDomainDNSRoot' - Get-ADDomainController's -Filter searches the forest-wide Configuration container and returns every domain's DCs regardless of -Server."
    }

    return $scoped
}

function Get-ADTargetDomainController {
    <#
    .SYNOPSIS
        Resolves one Domain Controller for a live network probe (e.g. an
        anonymous-bind check, a zone-transfer SOA query, an AD-integrated
        DNS zone read), honoring the Set-ADSecurityAuditTargetServer
        -Server override when active instead of unconditionally calling
        -Discover.
    .DESCRIPTION
        These callers only ever talk to ONE DC (the underlying operation -
        a single LDAP bind, a single DNS query - has no per-DC variation to
        probe, unlike the true per-DC probes that use
        Get-ADSecurityAuditDomainController's full enumeration instead).
        Per the module's "PDC-only" convention for exactly this kind of
        single-server, domain-wide-state check: when the target is a
        DOMAIN (an explicit domain name, or the default), this resolves
        to that domain's actual PDC Emulator specifically - not an
        arbitrary DC picked by enumeration order, which
        Get-ADDomainController's -Filter does not guarantee to be
        deterministic or PDC-first. When the target is instead an
        explicit, specific DC the operator named, that DC is honored
        exactly as given (never substituted for the PDC), per
        Resolve-ADSecurityAuditTargetServer's own established principle:
        an operator who names one specific DC has often done so because
        it's the only one reachable for this engagement, and redirecting
        elsewhere would defeat the purpose of naming it.

        FIXED (reported): previously took the first entry
        (Get-ADSecurityAuditDomainController -Server $overrideServer)[0]
        of the enumerated DC list without regard to which DC that
        actually was - functionally fine for these checks (any DC in the
        domain has consistent AD-integrated DNS/LDAP state), but
        inconsistent with the "PDC-only checks use the PDC of the domain
        in scope" convention documented and followed elsewhere in this
        module (e.g. Test-ADMachineAccountQuota, Test-ADDomainSecurity),
        and non-deterministic across runs/domains since enumeration order
        is not guaranteed to put the PDC first.
    .OUTPUTS
        A Get-ADDomainController result object (has .HostName, etc.), or
        $null if resolution failed.
    #>
    [CmdletBinding()]
    param()

    $overrideServer = Get-ADSecurityAuditActiveServerOverride

    try {
        if ($overrideServer) {
            if (Get-ADSecurityAuditServerIsExplicitDC) {
                # Operator named this exact DC - honor it as given, same
                # principle as Resolve-ADSecurityAuditTargetServer itself.
                # Get-ADSecurityAuditDomainController with the explicit-DC
                # scope active returns exactly this one DC.
                $dcs = @(Get-ADSecurityAuditDomainController -Server $overrideServer)
                if ($dcs.Count -gt 0) {
                    return $dcs[0]
                }
                throw "No Domain Controllers found for '$overrideServer'."
            }

            # $overrideServer is a domain name (or the $env:USERDNSDOMAIN
            # default) resolved down to a DC purely as an implementation
            # detail - for a single-server, domain-wide-state check like
            # this one, prefer that domain's actual PDC Emulator
            # specifically, not an arbitrary member of the enumerated set.
            try {
                $pdcEmulator = (Get-ADDomain -Server $overrideServer -ErrorAction Stop).PDCEmulator
            }
            catch {
                $pdcEmulator = $null
                Write-Verbose "Get-ADTargetDomainController: could not resolve the PDC Emulator for '$overrideServer' ($_); falling back to the first enumerated DC."
            }

            $dcs = @(Get-ADSecurityAuditDomainController -Server $overrideServer)
            if ($dcs.Count -eq 0) {
                throw "No Domain Controllers found for '$overrideServer'."
            }

            if ($pdcEmulator) {
                $pdcMatch = $dcs | Where-Object { $_.HostName -eq $pdcEmulator } | Select-Object -First 1
                if ($pdcMatch) {
                    return $pdcMatch
                }
                Write-Verbose "Get-ADTargetDomainController: resolved PDC Emulator '$pdcEmulator' was not present in the enumerated DC set for '$overrideServer'; falling back to the first enumerated DC."
            }

            return $dcs[0]
        }
        else {
            return (Get-ADDomainController -Discover -ErrorAction Stop)
        }
    }
    catch {
        Write-Verbose "Get-ADTargetDomainController: could not resolve a target DC: $_"
        return $null
    }
}

# Live per-DC registry fallback helper, used by any check that follows the
# "GPO-linked policy first, then a direct per-DC registry read if no linked
# GPO defines the value" pattern (SMBv1/signing/LmCompatibilityLevel/LLMNR/
# WSUS in LegacyAuthAudits.ps1, and the null-session check in
# DomainHardeningAudits.ps1). Promoted here in v1.20.5 from a function that
# used to be nested (and therefore private) inside
# Test-ADLegacyAuthSurface, so a second module can reuse the exact same
# read-only remote-registry logic instead of carrying its own copy.
#
# Read-only: this only ever reads a registry value via remote registry /
# Invoke-Command; it never sets, clears, or otherwise modifies one.
function Get-ADLiveRegistryValuePerDc {
    <#
    .SYNOPSIS
        Reads a single registry value directly from each of a list of
        Domain Controllers (remote registry / Invoke-Command).
    .DESCRIPTION
        Intended as the live fallback for a registry value that no linked
        GPO defines, so a locally configured (non-policy) value is still
        detected rather than silently missed. Never sets or clears a value.
    .PARAMETER DomainControllers
        Domain controller objects (as returned by Get-ADDomainController),
        each expected to expose HostName and/or Name.
    .PARAMETER Key
        Registry key path, e.g. 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'.
    .PARAMETER ValueName
        The value name to read under Key.
    .OUTPUTS
        PSCustomObject[] with DomainController, Value, and Error - one
        record per DC, Error populated (and Value $null) on read failure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$DomainControllers,

        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [string]$ValueName
    )
    $results = [System.Collections.ArrayList]::new()
    $regPath = "Registry::$Key"
    foreach ($dc in $DomainControllers) {
        $dcName = if ($dc.HostName) { $dc.HostName } else { $dc.Name }
        try {
            $value = Invoke-ADQueryWithRetry -OperationName "Read '$Key\$ValueName' on $dcName" -Query {
                Invoke-Command -ComputerName $dcName -ErrorAction Stop -ScriptBlock {
                    param($p, $vn)
                    (Get-ItemProperty -Path $p -Name $vn -ErrorAction SilentlyContinue).$vn
                } -ArgumentList $regPath, $ValueName
            }
            [void]$results.Add([PSCustomObject]@{ DomainController = $dcName; Value = $value; Error = $null })
        }
        catch {
            Write-Verbose "Get-ADLiveRegistryValuePerDc: could not read '$Key\$ValueName' on '$dcName': $_"
            [void]$results.Add([PSCustomObject]@{ DomainController = $dcName; Value = $null; Error = "$_" })
        }
    }
    return $results
}

# Retrieve the domain's privileged / Tier-0 principal set (users + groups).
#
# This is the single shared definition of "Tier-0" used across detection
# modules (introduced in v1.3.0 alongside Get-ADSnapshot). Later features
# (Exchange, RODC, graph-based analysis, etc.) should call this instead of
# re-deriving their own privileged-principal list, so the definition stays
# consistent everywhere it's used.
#
# Detection only: this performs read-only group-membership enumeration
# (recursive) against $Script:ProtectedGroups. It does not touch or modify
# any object.
function Get-ADTier0Principal {
    <#
    .SYNOPSIS
        Returns the set of Tier-0 (privileged) principals for the domain.
    .DESCRIPTION
        Recursively expands $Script:ProtectedGroups (Domain Admins, Enterprise
        Admins, Schema Admins, built-in Administrators, DCs, RODCs, and the
        other groups the module already treats as privileged) and returns one
        record per unique principal (user, computer, or group) along with the
        list of protected groups that grant it privileged status.
        Also includes any DNs from $Script:AdditionalTier0DistinguishedNames
        (set via Start-ADSecurityAudit's -AdditionalTier0DN, or passed
        directly via -AdditionalTier0DN below) - user-declared Tier-0 scope
        beyond the built-in privileged groups, e.g. a backup service
        account or custom-named admin group that isn't nested in any of
        $Script:ProtectedGroups. Each is tagged with PrivilegedGroups =
        'Additional Tier-0 Scope (user-defined)' so callers/reports can
        still tell it apart from a built-in-group-derived Tier-0 member.
    .OUTPUTS
        PSCustomObject[] with SID, SamAccountName, ObjectClass, DistinguishedName,
        and PrivilegedGroups (the protected groups this principal belongs to).
    .PARAMETER AdditionalTier0DN
        Extra distinguished names to fold into the Tier-0 set for this call,
        in addition to whatever is already in
        $Script:AdditionalTier0DistinguishedNames. Mainly for direct/test
        use; a normal run populates the script-scoped list instead (see
        Start-ADSecurityAudit -AdditionalTier0DN).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$AdditionalTier0DN = @()
    )

    Write-Verbose "Resolving Tier-0 principal set..."
    $tier0 = [System.Collections.ArrayList]::new()
    $seen = @{}

    # Resolved once, explicitly passed to every live AD call below - not
    # relying on the $PSDefaultParameterValues injection alone (see the
    # MANDATORY PATTERN note on Get-ADSecurityAuditActiveServerOverride).
    $__adServer = Get-ADSecurityAuditActiveServerOverride

    foreach ($groupName in $Script:ProtectedGroups) {
        $group = $null
        $groupServer = $__adServer
        try {
            $group = if ($__adServer) {
                Get-ADGroup -Filter "Name -eq '$groupName'" -Server $__adServer -ErrorAction Stop
            }
            else {
                Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Get-ADTier0Principal: failed to get group '$groupName': $_"
        }

        if (-not $group -and $groupName -in @('Enterprise Admins', 'Schema Admins')) {
            # Same forest-root-only fix as Test-ADPrivilegedGroups
            # (GroupAudits.ps1): these two groups exist ONLY in the
            # forest root domain, so a lookup scoped to a child domain
            # always finds nothing there and would otherwise silently
            # exclude them from the Tier-0 set for every non-root domain
            # audited - a real detection gap for the RC4/FAST checks that
            # consume this function's output.
            try {
                $forestRootDomain = (Get-ADForest -ErrorAction Stop).RootDomain
                if ($forestRootDomain) {
                    Write-Verbose "Get-ADTier0Principal: '$groupName' not found in the target domain (expected - it's forest-root-only); re-querying against the forest root '$forestRootDomain' instead."
                    $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Server $forestRootDomain -ErrorAction Stop
                    $groupServer = $forestRootDomain
                }
            }
            catch {
                Write-Verbose "Get-ADTier0Principal: failed to resolve '$groupName' via the forest root domain: $_"
            }
        }

        if (-not $group) { continue }

        $members = $null
        try {
            $members = if ($groupServer) {
                Get-ADGroupMember -Identity $group -Recursive -Server $groupServer -ErrorAction Stop
            }
            else {
                Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Get-ADTier0Principal: failed to get members of '$groupName': $_"
            continue
        }

        foreach ($member in @($members)) {
            $key = $member.SID.Value
            if (-not $key) { $key = $member.DistinguishedName }

            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = [System.Collections.ArrayList]::new()
                [void]$tier0.Add([PSCustomObject]@{
                    DistinguishedName      = $member.DistinguishedName
                    SID                    = $member.SID.Value
                    SamAccountName         = $member.SamAccountName
                    ObjectClass            = $member.objectClass
                    PrivilegedGroups       = $seen[$key]
                    PrivilegedGroupsString = ''
                })
            }
            [void]$seen[$key].Add($groupName)
        }
    }

    # --- User-declared additional Tier-0 scope (e.g. a backup service
    #     account or custom admin group that isn't nested in any built-in
    #     privileged group). Each DN is resolved directly via Get-ADObject
    #     rather than via group membership - it's added to the Tier-0 SET
    #     itself, not assumed to be a group whose members should be
    #     expanded. Best-effort: a DN that no longer resolves (typo,
    #     deleted object, wrong domain) is skipped with a verbose warning
    #     rather than failing the whole run. ---
    $additionalDNs = @($Script:AdditionalTier0DistinguishedNames) + @($AdditionalTier0DN) | Where-Object { $_ } | Select-Object -Unique
    foreach ($dn in $additionalDNs) {
        $obj = $null
        try {
            $obj = if ($__adServer) {
                Get-ADObject -Identity $dn -Properties objectSID, sAMAccountName -Server $__adServer -ErrorAction Stop
            }
            else {
                Get-ADObject -Identity $dn -Properties objectSID, sAMAccountName -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Get-ADTier0Principal: failed to resolve additional Tier-0 DN '$dn': $_"
            continue
        }

        $sid = if ($obj.objectSID) { $obj.objectSID.Value } else { $null }
        $key = if ($sid) { $sid } else { $obj.DistinguishedName }

        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = [System.Collections.ArrayList]::new()
            [void]$tier0.Add([PSCustomObject]@{
                DistinguishedName      = $obj.DistinguishedName
                SID                    = $sid
                SamAccountName         = $obj.sAMAccountName
                ObjectClass            = $obj.objectClass
                PrivilegedGroups       = $seen[$key]
                PrivilegedGroupsString = ''
            })
        }
        [void]$seen[$key].Add('Additional Tier-0 Scope (user-defined)')
    }

    Write-Verbose "Get-ADTier0Principal: resolved $($tier0.Count) unique Tier-0 principals ($($additionalDNs.Count) from user-defined additional scope)."
    return @($tier0 | ForEach-Object { $_.PrivilegedGroupsString = ($_.PrivilegedGroups -join '; '); $_ })
}

# --- Run-scope notes: "this check ran, but against a narrower/different
# target than its normal assumption" ---
#
# This is for LIVE-mode scoping conditions
# that don't stop a check from running, and don't change what it queries
# incorrectly - but are still worth surfacing, because the reader might
# reasonably assume something different happened. The first (and so far
# only) case: a "PDC-only" check (Test-ADMachineAccountQuota,
# Test-ADDomainSecurity - see their own docs for why they're PDC-only)
# queried an explicitly-named Domain Controller that is NOT the domain's
# actual PDC Emulator, because the operator named that specific DC via
# -Server. The check still ran and still returned a real answer - domain-
# wide attributes are readable from any DC - but a reader who assumes
# "PDC-only checks always hit the PDC" should be told that didn't happen
# this run, in case replication lag to that specific DC is a live concern
# for their engagement.
#
# Reset once per Start-ADSecurityAudit run, so notes never leak between
# runs in the same PowerShell session.
$Script:ADRunScopeNotes = [System.Collections.ArrayList]::new()

function Reset-ADRunScopeNotes {
    <#
    .SYNOPSIS
        Clears the run-scope-note list. Called once at the start of every
        Start-ADSecurityAudit run.
    #>
    [CmdletBinding()]
    param()
    $Script:ADRunScopeNotes = [System.Collections.ArrayList]::new()
}

function Add-ADRunScopeNote {
    <#
    .SYNOPSIS
        Records one run-scope note for the HTML report's "Run Scope
        Information" section.
    .PARAMETER Category
        Short label grouping the note (e.g. 'PDC Scope').
    .PARAMETER Message
        Full, reader-facing explanation - shown verbatim in the report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Message
    )
    [void]$Script:ADRunScopeNotes.Add([PSCustomObject]@{
        Category = $Category
        Message  = $Message
    })
}

function Get-ADRunScopeNotes {
    <#
    .SYNOPSIS
        Returns the run-scope notes recorded so far in this run/collection.
    #>
    [CmdletBinding()]
    param()
    return @($Script:ADRunScopeNotes)
}

function ConvertTo-ADFlatFindingsArray {
    <#
    .SYNOPSIS
        Recursively flattens a findings collection that may contain nested
        arrays, so downstream code always sees one finding-like object per
        element rather than a sub-array of several.
    .DESCRIPTION
        Defensive guard against a jagged/nested input array - e.g. a
        findings JSON export that (for reasons not fully understood -
        Main.ps1's own $allFindings += $result assembly loop flattens
        correctly, so the nesting has been observed only after a JSON
        round-trip through Get-ADRetestComparison's offline file read, not
        during a live audit run) ends up containing an element that is
        itself a sub-array of several finding objects instead of one.

        When that happens, PowerShell's member-enumeration silently turns
        every property read on that element into an array (e.g.
        $finding.Weight returns System.Object[] instead of an int), which
        then throws deep inside Get-ADRiskScore's arithmetic with a
        confusing "cannot convert System.Object[] to Int32" error rather
        than a clear message about the actual shape problem. Flattening
        immediately after the file is read means every consumer (scoring,
        finding-key matching) only ever sees real, individual finding
        objects.

        A "finding" is anything that is NOT itself an array/enumerable
        collection. Strings and dictionaries/hashtables are treated as leaf
        values (never recursed into), since a finding's own Details
        hashtable is legitimate finding-level content, not a nested
        collection of findings.
    .PARAMETER Findings
        The findings array to flatten (may already be flat - flattening an
        already-flat array is a safe no-op).
    .OUTPUTS
        A flat array where every element is a single finding-like object.

        CALLERS MUST WRAP THIS CALL IN @(...): "$x = ConvertTo-ADFlatFindingsArray -Findings $y"
        silently sets $x to a real $null (not an empty array) whenever the
        result is empty - a fundamental PowerShell behavior (a function
        that outputs zero objects produces "nothing" on the pipeline,
        which a plain variable assignment sees as $null), not something
        fixable inside this function itself. That real $null can then
        fail a DOWNSTREAM Mandatory+[AllowEmptyCollection()] parameter
        (e.g. Get-ADRiskScore's -Findings) with "Cannot bind argument...
        because it is null" - confirmed the hard way: a genuinely-empty
        (all findings resolved) retest export reliably hit this in
        Get-ADRetestComparison. "$x = @(ConvertTo-ADFlatFindingsArray -Findings $y)"
        avoids it - @() around the whole call forces a real (possibly
        empty) array through the assignment regardless of how many
        objects the function actually output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Findings
    )

    $flat = [System.Collections.ArrayList]::new()

    function Add-ADFlatFindingItem {
        param($Item)
        if ($null -eq $Item) { return }
        $isNestedCollection = ($Item -is [System.Collections.IEnumerable]) -and
                              ($Item -isnot [string]) -and
                              ($Item -isnot [System.Collections.IDictionary])
        if ($isNestedCollection) {
            foreach ($sub in $Item) { Add-ADFlatFindingItem -Item $sub }
        }
        else {
            [void]$flat.Add($Item)
        }
    }

    foreach ($item in $Findings) { Add-ADFlatFindingItem -Item $item }

    return @($flat)
}

function Set-ADFindingProperty {
    <#
    .SYNOPSIS
        Sets a named property on a finding, regardless of whether it's a
        live [ADSecurityFinding] (every property already exists - plain
        assignment works) or a PSCustomObject from an older JSON export
        whose schema predates that property (plain assignment throws
        "the property ... cannot be found on this object").
    .DESCRIPTION
        Used by Set-ADFindingMetadata (see its own docs for the bug this
        fixes) so that MITRE/ANSSI/Weight backfill works uniformly
        whether -Finding came from a live run or ConvertFrom-Json.
    .PARAMETER Object
        The finding to mutate, in place. Any shape.
    .PARAMETER Name
        Property name to set.
    .PARAMETER Value
        Value to assign.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Object,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        $Value
    )
    if ($Object.PSObject.Properties.Name -contains $Name) {
        $Object.$Name = $Value
    }
    else {
        # Property doesn't exist on this object at all (a JSON export from
        # before this property existed in the schema) - plain assignment
        # would throw. Add it as a new note property instead.
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
    }
}

function Resolve-ADRebuiltReportOutputPath {
    <#
    .SYNOPSIS
        Resolves an -OutputPath argument for the offline "rebuild from
        JSON" functions (Export-ADSecurityReportHTMLFromJson,
        Export-ADSecurityReportCSVFromJson) to a concrete file path,
        accepting either an exact file path OR a folder.
    .DESCRIPTION
        Reported gap: -OutputPath required an exact file path - callers
        who just wanted to point at "the reports folder" and get a
        sensibly-named file had to construct the filename themselves,
        duplicating this module's own naming convention. Mirrors
        -FindingsPath/-BaselinePath/-RetestPath already accepting either
        a file or a folder (Resolve-ADRetestReportFile) - this closes the
        same file-or-folder flexibility on the output side.

        Treated as a FOLDER (auto-named file created inside it) when
        EITHER:
          - -OutputPath already exists on disk as a directory, or
          - -OutputPath has no file extension at all (a not-yet-created
            path is ambiguous between "a folder to create" and "a file
            path with no extension"; this module's own outputs always
            have an extension, so "no extension" is treated as "this is
            a folder path").
        Otherwise treated as an exact file path, unchanged from prior
        behavior - including when it has a DIFFERENT extension than
        -Extension (the caller's explicit choice is respected, not
        second-guessed).

        The auto-generated filename is "AD_Security_Audit_<timestamp>-recreated.<ext>"
        - deliberately NOT the same name Start-ADSecurityAudit's live
        export would use for the same timestamp (which would silently
        overwrite the original report if the rebuild is pointed at the
        same folder the original JSON/HTML/CSV already lives in - a real
        risk since "point it at the folder your reports are already in"
        is exactly the convenient use case this is meant to support).
    .PARAMETER OutputPath
        The caller's -OutputPath argument - a file or a folder.
    .PARAMETER FindingsFile
        The resolved findings JSON FileInfo (from Resolve-ADRetestReportFile),
        used to derive the auto-generated filename's timestamp so it's
        traceable back to the export it was rebuilt from.
    .PARAMETER Extension
        File extension (without a dot) to use when auto-generating a
        filename, e.g. 'html' or 'csv'.
    .OUTPUTS
        [string] the resolved, concrete file path to write to. The
        containing directory is created if it doesn't exist yet (for
        both the folder case and an exact file path in a new directory).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [System.IO.FileInfo]$FindingsFile,

        [Parameter(Mandatory)]
        [string]$Extension
    )

    $isFolder = (Test-Path -Path $OutputPath -PathType Container) -or
        (-not (Test-Path -Path $OutputPath) -and [string]::IsNullOrEmpty([System.IO.Path]::GetExtension($OutputPath)))

    if ($isFolder) {
        $timestamp = $FindingsFile.Name -replace '^AD_Security_Audit_', '' -replace '\.json$', ''
        $fileName = "AD_Security_Audit_$timestamp-recreated.$Extension"
        $resolved = Join-Path -Path $OutputPath -ChildPath $fileName
        Write-Verbose "Resolve-ADRebuiltReportOutputPath: -OutputPath '$OutputPath' is a folder; writing '$resolved'."
    }
    else {
        $resolved = $OutputPath
    }

    $targetDir = Split-Path -Path $resolved -Parent
    if ($targetDir -and -not (Test-Path -Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }

    return $resolved
}

function ConvertTo-ADNormalizedTestCoverage {
    <#
    .SYNOPSIS
        Defensively repairs test-coverage data found in a "columnar"
        shape (one object whose TestName/Status/FindingCount/ErrorMessage
        properties are each an array of N values) back into the intended
        shape (N separate objects, each with scalar properties).
    .DESCRIPTION
        Reported bug: a real AD_Security_TestCoverage_<timestamp>.json,
        round-tripped through Get-ADTestCoverageSidecar, came back as a
        SINGLE entry whose 4 properties were each N-element arrays
        instead of N separate entries - visible as "1 check(s) tracked"
        in the summary line while the per-check table showed every test
        name/finding-count crammed into one row, and the CSV rebuild
        wrote literal "System.Object[]" into every column.

        Confirmed mechanism for the visual symptom (regardless of how the
        columnar shape itself arises - not reproducible from a clean
        Main.ps1-style construction + ConvertTo-Json/ConvertFrom-Json
        round-trip in this module's tested PowerShell version, so it may
        be specific to Windows PowerShell 5.1's JSON handling or another
        environment difference): with $entry.TestName/.FindingCount as
        arrays, string interpolation ("$($entry.TestName)") space-joins
        every element into one string - explaining "all N test names/
        finding counts crammed into one cell". With $entry.Status as an
        array, PowerShell's `switch` statement - given a COLLECTION
        rather than a scalar as its test value - evaluates every element
        independently and accumulates every match's output, so a
        27-element array of "Completed" made the 'Completed' case body
        run 27 times, producing 27 separately-styled badge <span>
        elements all crammed into that same one cell. Export-Csv calling
        .ToString() on each still-array-valued property explains the
        literal "System.Object[]" in the CSV rebuild.

        This function detects that columnar shape (any entry whose
        TestName is a collection rather than a scalar string) and
        un-transposes it back into one object per check, index-aligned
        across all four properties. A no-op (returns the input unchanged)
        for the normal, correctly-shaped case.
    .PARAMETER Coverage
        Array of coverage entries, in either shape.
    .OUTPUTS
        [array] of coverage entries, guaranteed one object per check with
        scalar properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [array]$Coverage
    )

    if (-not $Coverage -or $Coverage.Count -eq 0) { return @() }

    $isColumnar = $false
    foreach ($item in $Coverage) {
        # Check all four properties, not just TestName - broadens the
        # safety net in case a future/different malformation only affects
        # some of them (e.g. TestName stayed scalar but Status/FindingCount
        # came back as arrays).
        foreach ($propName in @('TestName', 'Status', 'FindingCount', 'ErrorMessage')) {
            $propValue = $item.$propName
            if ($null -ne $propValue -and $propValue -isnot [string] -and $propValue -is [System.Collections.IEnumerable]) {
                $isColumnar = $true
                break
            }
        }
        if ($isColumnar) { break }
    }
    if (-not $isColumnar) {
        return @($Coverage)
    }

    Write-Warning "ConvertTo-ADNormalizedTestCoverage: this run's test-coverage data was in an unexpected (columnar) shape - repaired it into one entry per check for display. If this recurs, please keep the raw AD_Security_TestCoverage_*.json so the cause can be tracked down (this has not been reproduced from a normal write/read round-trip in this module's tested PowerShell version)."

    $normalized = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($item in $Coverage) {
        $names     = @($item.TestName)
        $statuses  = @($item.Status)
        $counts    = @($item.FindingCount)
        $errors    = @($item.ErrorMessage)
        # Row count from the LONGEST of the four, not just TestName's -
        # the broadened detection above can now catch a malformation where
        # some OTHER property is the array while TestName stayed scalar;
        # keying off TestName alone would silently drop every row past
        # its own (shorter) length in that case.
        $rowCount = ($names.Count, $statuses.Count, $counts.Count, $errors.Count | Measure-Object -Maximum).Maximum
        for ($i = 0; $i -lt $rowCount; $i++) {
            $normalized.Add([PSCustomObject]@{
                TestName     = if ($i -lt $names.Count) { $names[$i] } else { "(unknown check $i)" }
                Status       = if ($i -lt $statuses.Count) { $statuses[$i] } else { $null }
                FindingCount = if ($i -lt $counts.Count) { $counts[$i] } else { 0 }
                ErrorMessage = if ($i -lt $errors.Count) { $errors[$i] } else { $null }
            })
        }
    }
    return @($normalized)
}

function Get-ADTestCoverageSidecar {
    <#
    .SYNOPSIS
        Reads a sibling AD_Security_TestCoverage_*.json sidecar, if
        present, given ANY of this module's other same-run sidecar files
        (the findings JSON or the score JSON) that shares its timestamp.
    .DESCRIPTION
        Same sibling-file idiom as Get-ADRetestSidecarMeta
        (RetestComparison.ps1) for the Score sidecar: derives the expected
        coverage sidecar name from the given file's own name (swapping
        its "AD_Security_Audit_"/"AD_Security_Score_" prefix for
        "AD_Security_TestCoverage_", preserving the shared "<timestamp>.json"
        suffix) and looks for it next to it. Returns an empty array (not
        $null, not a throw) when the sidecar doesn't exist - an export
        from before test-coverage tracking was added, or one where the
        sidecar was deleted/not copied alongside the other file, simply
        has no coverage section to show. The caller is expected to handle
        "no coverage data available" as a normal, unremarkable case, not
        an error.

        Accepting either sidecar kind (not just the findings JSON) means
        Get-ADMaturityTrend - which only ever has the SCORE sidecar in
        hand, having discovered runs by scanning for
        AD_Security_Score_*.json rather than the findings JSON - can use
        this same lookup instead of duplicating the naming-convention
        substitution itself.
    .PARAMETER FindingsFile
        A resolved AD_Security_Audit_<timestamp>.json OR
        AD_Security_Score_<timestamp>.json FileInfo for the same run
        (from Resolve-ADRetestReportFile / Resolve-ADMaturityTrendScoreFiles).
    .OUTPUTS
        [array] of coverage entries (TestName/Status/FindingCount/
        ErrorMessage), or an empty array if no sidecar was found or it
        could not be parsed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$FindingsFile
    )

    $coverageName = $FindingsFile.Name -replace '^AD_Security_(Audit|Score)_', 'AD_Security_TestCoverage_'
    $coveragePath = Join-Path -Path $FindingsFile.DirectoryName -ChildPath $coverageName

    if (-not (Test-Path -Path $coveragePath)) {
        Write-Verbose "Get-ADTestCoverageSidecar: no coverage sidecar '$coveragePath' next to '$($FindingsFile.Name)' - this export predates test-coverage tracking, or the sidecar wasn't kept alongside it. Proceeding with no Test Coverage section."
        return @()
    }

    try {
        $coverage = @(Get-Content -Path $coveragePath -Raw | ConvertFrom-Json)
        $coverage = ConvertTo-ADNormalizedTestCoverage -Coverage $coverage
        Write-Verbose "Get-ADTestCoverageSidecar: loaded $($coverage.Count) coverage entry(ies) from '$coveragePath'."
        return $coverage
    }
    catch {

        Write-Warning "Could not parse test coverage sidecar '$coveragePath' (this does not block report recreation, it just means no Test Coverage section): $_"
        return @()
    }
}

function Merge-ADFindingNarrativeGaps {
    <#
    .SYNOPSIS
        Backfills EstimatedEffort/KnownRisks/BackupRollback/OperationalNotes
        on findings loaded from an older JSON export that predates those
        fields (or predates a given Issue's current wording), using
        $Script:ADFindingNarrativeLibrary (src/FindingNarrativeLibrary.ps1,
        mechanically extracted from the current source - see
        tools/Build-ADFindingNarrativeLibrary.ps1).
    .DESCRIPTION
        Reported gap: recreating an HTML report from an old
        AD_Security_Audit_*.json export (Export-ADSecurityReportHTMLFromJson)
        silently OMITS the "Estimated Effort" / "Known Risks" /
        "Backup / Rollback" / "Operational Notes" sections entirely for any
        finding whose export predates those fields (added v1.24.0) - not a
        crash, just missing sections, which reads as the recreated report
        being incomplete/"stale" next to a fresh run's report.

        This is a best-effort, clearly-labeled backfill, not a
        reconstruction of "what the original run actually showed":
          * A field is ONLY backfilled if the loaded finding's own value
            for it is blank/missing. A finding that already has its own
            text (from a reasonably recent export) is never touched -
            this never overwrites real, originally-captured data.
          * The backfilled text is CURRENT guidance for that Issue name,
            not necessarily what an older module version would have
            written at the time - the library has no version history,
            only "whatever the source says today".
          * Only applies when a library entry exists for the finding's
            Issue name at all - most findings (the ones without
            EstimatedEffort/KnownRisks/BackupRollback in the source to
            begin with) have no entry and are left exactly as loaded, so
            this never invents guidance that doesn't exist anywhere in
            the codebase.
          * Also (re)tags MITRE/ANSSI/Weight via Set-ADFindingMetadata for
            any finding missing that metadata - seeSet-ADFindingMetadata's
            own docs for the related bug this depends on being fixed
            (PSCustomObject mutation not persisting through a typed
            parameter).
    .PARAMETER Findings
        Array of findings (from ConvertFrom-Json - PSCustomObject - or a
        live run). Mutated in place.
    .OUTPUTS
        [int] the number of findings that had at least one field backfilled,
        so a caller can surface it in the report (e.g. a run-scope note).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Findings
    )

    if (-not $Script:ADFindingNarrativeLibrary) {
        Write-Verbose "Merge-ADFindingNarrativeGaps: `$Script:ADFindingNarrativeLibrary is not loaded (FindingNarrativeLibrary.ps1 not dot-sourced); skipping narrative backfill."
        return 0
    }

    $backfilledCount = 0
    foreach ($finding in $Findings) {
        [void](Set-ADFindingMetadata -Finding $finding)

        $libEntry = $Script:ADFindingNarrativeLibrary[$finding.Issue]
        if (-not $libEntry) { continue }

        $touchedThisFinding = $false
        foreach ($field in @('EstimatedEffort', 'KnownRisks', 'BackupRollback', 'OperationalNotes')) {
            $current = $finding.$field
            if ([string]::IsNullOrWhiteSpace($current) -and -not [string]::IsNullOrWhiteSpace($libEntry.$field)) {
                Set-ADFindingProperty -Object $finding -Name $field -Value $libEntry.$field
                $touchedThisFinding = $true
            }
        }
        if ($touchedThisFinding) { $backfilledCount++ }
    }

    return $backfilledCount
}

function Test-ADFindingDetailsKey {
    <#
    .SYNOPSIS
        Checks whether a finding's Details bag has a given key, regardless
        of whether Details is a real Hashtable (a live/in-memory run) or a
        PSCustomObject (a finding that came from ConvertFrom-Json - the
        default, non--AsHashtable parse turns every JSON object, including
        a finding's Details, into a PSCustomObject instead of a
        Hashtable).
    .DESCRIPTION
        FIXED (reported): Export-ADSecurityReportHTML's control-path
        section called $finding.Details.ContainsKey(...) directly, which
        only exists on IDictionary (Hashtable). That's correct for a live
        Start-ADSecurityAudit run - Details is always built as a
        Hashtable there - but Export-ADSecurityReportHTMLFromJson feeds it
        findings read back from a JSON export instead, where Details has
        already round-tripped through ConvertFrom-Json into a
        PSCustomObject. PSCustomObject has no ContainsKey method at all,
        so every one of those calls threw "Method invocation failed
        because [...PSCustomObject] does not contain a method named
        'ContainsKey'" - reliably, for every control-path finding, any
        time a report was recreated from JSON.

        This is the general-purpose fix, not a one-off patch of the
        JSON-recreate code path specifically: any current or future
        caller that might receive JSON-sourced findings (directly, or via
        a snapshot/retest/consolidation file that itself embeds findings)
        can use this instead of assuming Details is a Hashtable.
    .PARAMETER Details
        The finding's .Details value. $null-safe - returns $false.
    .PARAMETER Key
        The key/property name to look for.
    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        $Details,

        [Parameter(Mandatory)]
        [string]$Key
    )
    if ($null -eq $Details) { return $false }
    if ($Details -is [System.Collections.IDictionary]) {
        return $Details.ContainsKey($Key)
    }
    # PSCustomObject (or anything else exposing PSObject.Properties, e.g.
    # a deserialized JSON object) - check by property name instead.
    return [bool]($Details.PSObject.Properties.Name -contains $Key)
}

function Get-ADFindingMatchKey {
    <#
    .SYNOPSIS
        Builds the Category+Issue+AffectedObject key used to match the same
        finding across two different runs (e.g. a baseline and a retest).
    .DESCRIPTION
        Coarser keys (Category+Issue only) would hide partial remediation -
        e.g. 5 stale accounts down to 2 should show 3 resolved and 2 still
        open, not just "still present". This is the SINGLE SOURCE OF TRUTH
        for that key construction - Get-ADRetestComparison (RetestComparison.ps1)
        and the remediation-state store (RemediationState.ps1) both call this
        function rather than building the "$Category|$Issue|$AffectedObject"
        string independently, so the two can never disagree on what a "key" is.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Category,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Issue,
        [Parameter(Mandatory)][AllowEmptyString()][string]$AffectedObject
    )
    return "$Category|$Issue|$AffectedObject"
}

# Sanitize values for CSV export to prevent formula injection
function ConvertTo-SafeCsvValue {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    process {
        if ([string]::IsNullOrEmpty($Value)) {
            return $Value
        }

        # Prefix with single quote if value starts with characters that could be interpreted as formulas
        if ($Value -match '^[=+\-@\t\r]') {
            return "'" + $Value
        }

        return $Value
    }
}

function ConvertTo-ADFindingsCsvRows {
    <#
    .SYNOPSIS
        Converts an array of findings into the flat, CSV-safe row shape
        used for the AD_Security_Audit_<timestamp>.csv export.
    .DESCRIPTION
        SINGLE SOURCE OF TRUTH for the findings CSV column list. Both
        Start-ADSecurityAudit's live export (Main.ps1) and
        Export-ADSecurityReportCSVFromJson (Reporting.ps1 - the "rebuild
        the CSV from an old JSON export" recovery path) call this instead
        of each maintaining their own Select-Object/column list, so the
        two can never drift out of sync with each other the way the CSV
        and JSON exports previously drifted from EACH OTHER before this
        function existed (SeverityLevel/Details, then later
        EstimatedEffort/KnownRisks/BackupRollback/OperationalNotes, were
        each added to the ADSecurityFinding class and the JSON export
        long before anyone remembered to add them to the CSV's
        hand-maintained column list - see the comment above the CSV
        export call in Main.ps1 for that history). Adding a new column
        now only means editing it here, and both export paths pick it up
        automatically.
    .PARAMETER Findings
        Array of findings (live [ADSecurityFinding] objects, or
        PSCustomObject from ConvertFrom-Json - either works, since this
        only reads properties, never calls a typed method on them).
    .OUTPUTS
        Array of [PSCustomObject] rows, formula-injection-sanitized,
        ready for Export-Csv.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Findings
    )

    $Findings | Select-Object Category, Issue, Severity, AffectedObject, Description, Impact, Remediation, DetectedDate, MitreTechnique, AnssiControl, Weight, SeverityLevel, Details, EstimatedEffort, KnownRisks, BackupRollback, OperationalNotes, TestName |
        ForEach-Object {
            [PSCustomObject]@{
                Category = $_.Category | ConvertTo-SafeCsvValue
                Issue = $_.Issue | ConvertTo-SafeCsvValue
                Severity = $_.Severity | ConvertTo-SafeCsvValue
                AffectedObject = $_.AffectedObject | ConvertTo-SafeCsvValue
                Description = $_.Description | ConvertTo-SafeCsvValue
                Impact = $_.Impact | ConvertTo-SafeCsvValue
                Remediation = $_.Remediation | ConvertTo-SafeCsvValue
                DetectedDate = $_.DetectedDate
                MitreTechnique = $_.MitreTechnique | ConvertTo-SafeCsvValue
                AnssiControl = $_.AnssiControl | ConvertTo-SafeCsvValue
                Weight = $_.Weight
                SeverityLevel = $_.SeverityLevel
                # Compact JSON string, not a native CSV column-per-key -
                # Details is an open-ended per-check hashtable (different
                # keys per Issue), so there's no fixed column set to
                # flatten it into without the schema changing per-check.
                # Still sanitized against formula injection like every
                # other free-text column.
                Details = ($_.Details | ConvertTo-Json -Compress -Depth 5) | ConvertTo-SafeCsvValue
                EstimatedEffort = $_.EstimatedEffort | ConvertTo-SafeCsvValue
                KnownRisks = $_.KnownRisks | ConvertTo-SafeCsvValue
                BackupRollback = $_.BackupRollback | ConvertTo-SafeCsvValue
                OperationalNotes = $_.OperationalNotes | ConvertTo-SafeCsvValue
                TestName = $_.TestName | ConvertTo-SafeCsvValue
            }
        }
}

function ConvertTo-ADFriendlyDateText {
    <#
    .SYNOPSIS
        Normalizes a GeneratedDate-style value read back from a
        ConvertFrom-Json'd sidecar/report into a clean, human-readable date
        string.
    .DESCRIPTION
        Every "GeneratedDate = Get-Date" in this module is meant to end up as
        a plain, re-parseable date string once ConvertTo-Json/Out-File has
        written it to disk. Prior to this fix, several of those assignments
        stored the raw [datetime] object instead of a string. PowerShell's
        JSON serializer expands a raw [datetime] using its own ETS note
        properties (DisplayHint/DateTime/value) rather than a plain string,
        so ConvertFrom-Json hands back a PSCustomObject that renders as
        "@{value=...; DisplayHint=2; DateTime=...}" wherever it's dropped
        directly into a report - never a real error, just useless text.

        This helper is defensive on BOTH sides of that fix: it recovers a
        clean date from the old corrupted shape (so already-generated
        sidecars/exports don't need to be regenerated), and it's a no-op
        pass-through for the plain ISO-8601 strings the fixed code now
        writes.
    .PARAMETER Value
        The raw value as read from a ConvertFrom-Json'd object. Any of:
        $null/empty, a [datetime], a plain (parseable) string, or the
        corrupted PSCustomObject shape described above.
    .OUTPUTS
        A "yyyy-MM-dd HH:mm:ss" string, or $null if $Value was empty. If the
        value can't be parsed as a date at all, its best-effort string form
        is returned rather than throwing, so a report can still show
        *something* instead of failing to render.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if (-not $Value) { return $null }

    if ($Value -is [datetime]) {
        return $Value.ToString('yyyy-MM-dd HH:mm:ss')
    }

    # The corrupted legacy shape: ConvertTo-Json expanded a raw [datetime]
    # into its own DisplayHint/DateTime/value note properties instead of a
    # plain string. Recover the actual date from 'value' (the underlying
    # DateTime's own value, most reliable) or fall back to 'DateTime' (the
    # pre-formatted display string).
    if ($Value.PSObject -and ($Value.PSObject.Properties.Name -contains 'DisplayHint') -and
        (($Value.PSObject.Properties.Name -contains 'value') -or ($Value.PSObject.Properties.Name -contains 'DateTime'))) {
        $raw = if ($Value.PSObject.Properties.Name -contains 'value') { $Value.value } else { $Value.DateTime }
        try { return ([datetime]$raw).ToString('yyyy-MM-dd HH:mm:ss') }
        catch { return "$raw" }
    }

    # Plain string (the fixed, current format) or anything else stringy.
    try { return ([datetime]$Value).ToString('yyyy-MM-dd HH:mm:ss') }
    catch { return "$Value" }
}

function ConvertTo-ADFlatAce {
    <#
    .SYNOPSIS
        Flattens an AuthorizationRuleCollection (nTSecurityDescriptor.Access)
        into plain, JSON-serialisable records.
    .DESCRIPTION
        ActiveDirectoryAccessRule objects don't round-trip through
        ConvertTo-Json/ConvertFrom-Json cleanly (SID/GUID typed members,
        circular refs). This captures just the fields the detection modules
        actually evaluate.

        Relocated here from src/Snapshot.ps1 (removed in the offline/
        -Snapshot mode removal) since it's a general-purpose ACE-flattening
        helper consumed by live detection code (ControlPaths.ps1), not
        something specific to the removed snapshot mechanism.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Access
    )

    foreach ($ace in $Access) {
        [PSCustomObject]@{
            IdentityReference     = "$($ace.IdentityReference.Value)"
            ActiveDirectoryRights = "$($ace.ActiveDirectoryRights)"
            AccessControlType     = "$($ace.AccessControlType)"
            IsInherited           = [bool]$ace.IsInherited
            InheritanceType       = "$($ace.InheritanceType)"
            ObjectType            = "$($ace.ObjectType)"
            InheritedObjectType   = "$($ace.InheritedObjectType)"
        }
    }
}
