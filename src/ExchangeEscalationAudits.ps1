#region Exchange-in-AD Privilege Escalation Audit
#
# Detects Exchange-related security principals holding dangerous rights on
# the domain head object and/or the AdminSDHolder object (PrivExchange-style
# escalation path: Exchange Windows Permissions / Exchange Trusted
# Subsystem -> WriteDacl on the domain -> DCSync). Also flags the same
# exposure when it is a RESIDUAL ACE left behind after Exchange has been
# decommissioned from the forest, since the ACE itself does not get cleaned
# up automatically. PingCastle-comparable check(s): P-ExchangePrivEsc, P-ExchangeAdminSDHolder.
#
# DETECTION ONLY: every determination here is a read of nTSecurityDescriptor
# on the domain head and CN=AdminSDHolder,CN=System,<domain>, evaluated
# against a fixed list of well-known Exchange principal names. This module
# never sends a PrivExchange push-subscription request, an NTLM relay, or
# any other exploitation/coercion traffic to any host; it purely inspects
# ACLs that are already present.

# Well-known Exchange security principals that historically receive (or
# have received) elevated rights on the domain object as part of Exchange
# setup/RBAC (Exchange Windows Permissions, Exchange Trusted Subsystem) or
# that indicate an Exchange RBAC role group with domain-level reach
# (Organization Management). Matched case-insensitively against the ACE's
# resolved identity name, independent of Exchange still being installed.
$Script:ExchangePrincipalNames = @(
    'Exchange Windows Permissions'
    'Exchange Trusted Subsystem'
    'Exchange Servers'
    'Exchange Enterprise Servers'
    'Organization Management'
)

# Rights that, if held by an Exchange principal on the domain head, allow an
# attacker who compromises that principal (or any member of it) to modify
# the domain object's ACL and grant themselves DCSync (WriteDacl/WriteOwner),
# or to directly replicate secrets (GenericAll implies both).
$Script:ExchangeDangerousRights = @(
    'GenericAll'
    'WriteDacl'
    'WriteOwner'
)

function Test-ADExchangeEscalation {
    <#
    .SYNOPSIS
        Audits for Exchange-in-AD privilege escalation via WriteDACL on the
        domain object and Exchange-related ACEs on AdminSDHolder.
    .DESCRIPTION
        Reads the nTSecurityDescriptor of the domain head object and of
        CN=AdminSDHolder,CN=System,<domain DN> and flags any ACE granting
        GenericAll, WriteDacl, or WriteOwner to a well-known Exchange
        security principal (Exchange Windows Permissions, Exchange Trusted
        Subsystem, Exchange Servers, Exchange Enterprise Servers,
        Organization Management).

        This fires whether or not Exchange is currently installed in the
        forest: residual ACEs left behind after an Exchange decommission
        are just as exploitable as ACEs on a live Exchange deployment, so
        the presence of the ACE - not the presence of Exchange servers - is
        what is evaluated.

        Reuses Get-ADTier0Principal purely for descriptive context in
        Details (whether the affected principal is also a resolvable
        Tier-0 group); it does not gate detection.

        Detection only: reads nTSecurityDescriptor.Access. Performs no
        exploitation, PrivExchange push-subscription, NTLM relay, or any
        other coercion/PoC traffic to any host.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Starting Exchange-in-AD privilege escalation audit..."
    $findings = @()

    # -------------------------------------------------------------------
    # Resolve the two ACLs to inspect.
    # -------------------------------------------------------------------
    $domainDN = $null
    $adminSDHolderDN = $null
    $domainAces = @()
    $adminSDHolderAces = @()

    $__adServer = Get-ADSecurityAuditTargetServerValue
    try {
        $domain = Invoke-ADQueryWithRetry -OperationName 'Get-ADDomain (exchange-escalation audit)' -Query {
            Get-ADDomain -Server $__adServer -ErrorAction Stop
        }
    }
    catch {
        Write-Error "Test-ADExchangeEscalation: failed to resolve domain: $_"
        return $findings
    }

    if (-not $domain) {
        Write-Warning "Test-ADExchangeEscalation: could not resolve domain; skipping."
        return $findings
    }

    $domainDN = $domain.DistinguishedName
    $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"

    try {
        $domainObject = Invoke-ADQueryWithRetry -OperationName "Get-ADObject nTSecurityDescriptor on $domainDN" -Query {
            Get-ADObject -Identity $domainDN -Properties nTSecurityDescriptor -Server $__adServer -ErrorAction Stop
        }
        if ($domainObject -and $domainObject.nTSecurityDescriptor) {
            $domainAces = @($domainObject.nTSecurityDescriptor.Access)
        }
    }
    catch {
        Write-Verbose "Test-ADExchangeEscalation: could not read ACL on domain head '$domainDN': $_"
    }

    try {
        $adminSDHolderObject = Invoke-ADQueryWithRetry -OperationName "Get-ADObject nTSecurityDescriptor on $adminSDHolderDN" -Query {
            Get-ADObject -Identity $adminSDHolderDN -Properties nTSecurityDescriptor -Server $__adServer -ErrorAction Stop
        }
        if ($adminSDHolderObject -and $adminSDHolderObject.nTSecurityDescriptor) {
            $adminSDHolderAces = @($adminSDHolderObject.nTSecurityDescriptor.Access)
        }
    }
    catch {
        Write-Verbose "Test-ADExchangeEscalation: could not read ACL on AdminSDHolder '$adminSDHolderDN': $_"
    }

    if ((-not $domainAces -or $domainAces.Count -eq 0) -and (-not $adminSDHolderAces -or $adminSDHolderAces.Count -eq 0)) {
        Write-Verbose "Test-ADExchangeEscalation: no ACEs available to evaluate; no findings."
        return $findings
    }

    # For descriptive context only (not a detection gate): resolve Tier-0
    # so Details can note whether the affected principal is also part of
    # the domain's privileged set.
    $tier0Names = @{}
    try {
        foreach ($p in @(Get-ADTier0Principal)) {
            if ($p.SamAccountName) { $tier0Names[$p.SamAccountName] = $true }
        }
    }
    catch {
        Write-Verbose "Test-ADExchangeEscalation: Get-ADTier0Principal unavailable for context: $_"
    }

    # -------------------------------------------------------------------
    # Helper: does this ACE's identity match one of the Exchange principal
    # names, and does it grant a dangerous right?
    # -------------------------------------------------------------------
    function Test-ExchangeDangerousAce {
        param($Ace)

        $identity = "$($Ace.IdentityReference)"
        $matchedPrincipal = $null
        foreach ($name in $Script:ExchangePrincipalNames) {
            if ($identity -match [regex]::Escape($name)) {
                $matchedPrincipal = $name
                break
            }
        }
        if (-not $matchedPrincipal) { return $null }

        $rights = "$($Ace.ActiveDirectoryRights)"
        $accessType = "$($Ace.AccessControlType)"
        if ($accessType -ne 'Allow') { return $null }

        $hasDangerousRight = $false
        foreach ($right in $Script:ExchangeDangerousRights) {
            if ($rights -match $right) { $hasDangerousRight = $true; break }
        }
        if (-not $hasDangerousRight) { return $null }

        return [PSCustomObject]@{
            Identity          = $identity
            MatchedPrincipal  = $matchedPrincipal
            Rights            = $rights
            IsInherited       = [bool]$Ace.IsInherited
            InheritanceType   = "$($Ace.InheritanceType)"
            ObjectType        = "$($Ace.ObjectType)"
            InheritedObjectType = "$($Ace.InheritedObjectType)"
        }
    }

    # -------------------------------------------------------------------
    # Finding: Exchange Group Holds WriteDACL on Domain Object
    # -------------------------------------------------------------------
    # A trustee can hold multiple ACEs on the same object (one per property
    # set/object type) even when Identity+Rights are identical - dedupe so
    # each combination is reported once rather than once per raw ACE.
    $domainHits = [System.Collections.ArrayList]::new()
    $__seenDomainHit = @{}
    foreach ($ace in $domainAces) {
        $hit = Test-ExchangeDangerousAce -Ace $ace
        if ($hit) {
            $__hitKey = "$($hit.Identity)|$($hit.Rights)"
            if (-not $__seenDomainHit.ContainsKey($__hitKey)) {
                $__seenDomainHit[$__hitKey] = $true
                [void]$domainHits.Add($hit)
            }
        }
    }

    if ($domainHits.Count -gt 0) {
        foreach ($hit in $domainHits) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Exchange-in-AD Privilege Escalation'
            $finding.Issue = 'Exchange Group Holds WriteDACL on Domain Object'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.AffectedObject = "$domainDN - $($hit.Identity)"
            $finding.Description = "'$($hit.Identity)' (matched Exchange principal '$($hit.MatchedPrincipal)') holds '$($hit.Rights)' on the domain head object '$domainDN'. This is the classic PrivExchange-style escalation path: Exchange Windows Permissions / Exchange Trusted Subsystem is granted WriteDacl on the domain during Exchange setup, and any principal that can add itself (or a controlled identity) to that group inherits the ability to rewrite the domain's ACL and grant itself replication (DCSync) rights."
            $finding.Impact = "Any account that can control or is a member of '$($hit.Identity)' can modify the domain object's ACL to grant DS-Replication-Get-Changes / DS-Replication-Get-Changes-All to an attacker-controlled principal, enabling a full DCSync credential dump and complete domain compromise - with no need for elevated Exchange server access itself."
            $finding.Remediation = "Remove the '$($hit.Rights)' ACE for '$($hit.Identity)' from the domain head object's ACL (e.g. via ADSIEdit/dsacls.exe against '$domainDN'). If Exchange is still in use, apply Microsoft's post-PrivExchange guidance to scope Exchange's domain permissions down instead of relying on broad WriteDacl. If Exchange has been decommissioned, this ACE is residual and should be removed entirely."
            $finding.EstimatedEffort = 'Medium - removing this legacy right requires confirming the current Exchange version/CU no longer needs it and coordinating with the Exchange admin team.'
            $finding.KnownRisks = 'Some Exchange functionality - particularly on older CUs that still expect this legacy permission model - can break if the right is removed while an in-place Exchange server still depends on it; confirm current CU-level guidance before removing.'
            $finding.BackupRollback = 'Moderate - export the domain object''s ACL before removing the ACE so it can be restored if Exchange functionality is affected; changes follow normal AD replication.'
            $finding.Details = @{
                DomainDN            = $domainDN
                Identity            = $hit.Identity
                MatchedPrincipal    = $hit.MatchedPrincipal
                ActiveDirectoryRights = $hit.Rights
                IsInherited         = $hit.IsInherited
                InheritanceType     = $hit.InheritanceType
                ObjectType          = $hit.ObjectType
                InheritedObjectType = $hit.InheritedObjectType
                IsTier0Principal    = [bool]$tier0Names.ContainsKey($hit.Identity)
            }
            $findings += $finding
        }
    }
    else {
        Write-Verbose "Test-ADExchangeEscalation: no Exchange principal holds WriteDacl/WriteOwner/GenericAll on the domain object."
    }

    # -------------------------------------------------------------------
    # Finding: Exchange-Related AdminSDHolder ACE
    # -------------------------------------------------------------------
    $adminSDHolderHits = [System.Collections.ArrayList]::new()
    $__seenAdminSDHolderHit = @{}
    foreach ($ace in $adminSDHolderAces) {
        $hit = Test-ExchangeDangerousAce -Ace $ace
        if ($hit) {
            $__hitKey = "$($hit.Identity)|$($hit.Rights)"
            if (-not $__seenAdminSDHolderHit.ContainsKey($__hitKey)) {
                $__seenAdminSDHolderHit[$__hitKey] = $true
                [void]$adminSDHolderHits.Add($hit)
            }
        }
    }

    if ($adminSDHolderHits.Count -gt 0) {
        foreach ($hit in $adminSDHolderHits) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Exchange-in-AD Privilege Escalation'
            $finding.Issue = 'Exchange-Related AdminSDHolder ACE'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = "$adminSDHolderDN - $($hit.Identity)"
            $finding.Description = "'$($hit.Identity)' (matched Exchange principal '$($hit.MatchedPrincipal)') holds '$($hit.Rights)' on AdminSDHolder ($adminSDHolderDN). SDProp propagates this ACE to every protected (Tier-0) account and group every 60 minutes, extending Exchange's reach into every AdminCount=1 object regardless of whether Exchange is still installed."
            $finding.Impact = "Any account that can control or is a member of '$($hit.Identity)' effectively holds '$($hit.Rights)' on every protected account/group in the domain (Domain Admins members, Enterprise Admins members, etc.), since SDProp re-applies the AdminSDHolder template ACL to them on its normal cycle."
            $finding.Remediation = "Remove the '$($hit.Rights)' ACE for '$($hit.Identity)' from AdminSDHolder ($adminSDHolderDN). After removal, allow SDProp to re-propagate (or force it with a directory-service restart / repadmin) and re-verify no protected object retains the inherited rights."
            $finding.EstimatedEffort = 'Medium - a single-object ACE removal, but coordinate with the Exchange admin team to confirm the current Exchange version doesn''t still rely on it.'
            $finding.KnownRisks = 'Removing an Exchange-related AdminSDHolder ACE that a currently-installed Exchange version still expects could break Exchange''s ability to manage protected mail-enabled accounts.'
            $finding.BackupRollback = 'Moderate - export the AdminSDHolder ACL before removing the ACE; the correction only reaches every protected object after SDProp''s next propagation cycle.'
            $finding.Details = @{
                AdminSDHolderDN     = $adminSDHolderDN
                Identity            = $hit.Identity
                MatchedPrincipal    = $hit.MatchedPrincipal
                ActiveDirectoryRights = $hit.Rights
                IsInherited         = $hit.IsInherited
                InheritanceType     = $hit.InheritanceType
                ObjectType          = $hit.ObjectType
                InheritedObjectType = $hit.InheritedObjectType
                IsTier0Principal    = [bool]$tier0Names.ContainsKey($hit.Identity)
            }
            $findings += $finding
        }
    }
    else {
        Write-Verbose "Test-ADExchangeEscalation: no Exchange principal holds dangerous rights on AdminSDHolder."
    }

    Write-Verbose "Completed Exchange-in-AD privilege escalation audit. Findings: $($findings.Count)"
    return $findings
}

#endregion
