#region Stale-Object & Hygiene Depth Audit (PASSWD_NOTREQD, primaryGroupID, duplicate SPNs, DC registration)
#
# Audits the long-tail account/object hygiene gaps that individually look
# minor but collectively make up a large share of PingCastle-like findings:
# accounts flagged PASSWD_NOTREQD, primaryGroupID tampering used to hide
# privileged membership, duplicate Service Principal Names, Domain
# Controllers missing subnet/site registration, and an environment with
# insufficient Domain Controller redundancy. PingCastle-comparable check(s):
# S-PwdNotRequired, S-PrimaryGroup, S-C-PrimaryGroup, S-Duplicate,
# S-DC-SubnetMissing, A-NotEnoughDC, S-DCRegistration.
#
# DETECTION ONLY: every check here is a read of userAccountControl,
# primaryGroupID, servicePrincipalName, DC inventory (Get-ADDomainController)
# and AD Sites & Services subnet objects (Get-ADReplicationSubnet). Nothing
# here creates, deletes, or modifies any account, attribute, SPN, subnet, or
# site object, and no exploitation, coercion, relay, or PoC traffic is ever
# sent.

# Well-known default primaryGroupID RIDs. Any value other than these (for the
# object type in question) can indicate an attempt to hide true privileged
# group membership, since primaryGroupID membership does not appear in the
# forward-linked memberOf attribute and is easy to overlook in a manual
# review.
$Script:StaleDepthDefaultPrimaryGroupIds = @{
    DomainUsers      = 513
    DomainComputers  = 515
    DomainControllers = 516
    ReadOnlyDomainControllers = 521
}

# userAccountControl bit flag for PASSWD_NOTREQD (0x0020). Matches the
# convention already used for UAC bit checks elsewhere in the module (e.g.
# TrustedForDelegation / DONT_REQ_PREAUTH handling in UserAudits.ps1).
$Script:StaleDepthPasswdNotReqdFlag = 0x0020

function Test-ADIpInCidrRange {
    <#
    .SYNOPSIS
        Returns $true if an IPv4 address falls within a CIDR range.
    .DESCRIPTION
        Pure read-only arithmetic helper used to match a Domain Controller's
        IPv4 address against an AD Sites & Services subnet (e.g.
        '10.0.1.0/24'). No network traffic is generated.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IpAddress,

        [Parameter(Mandatory)]
        [string]$CidrRange
    )

    try {
        $parts = $CidrRange -split '/'
        if ($parts.Count -ne 2) { return $false }

        $networkAddress = $parts[0]
        $prefixLength = [int]$parts[1]

        if ($prefixLength -lt 0 -or $prefixLength -gt 32) { return $false }

        $ipBytes = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()
        $netBytes = [System.Net.IPAddress]::Parse($networkAddress).GetAddressBytes()

        # IPv6 or malformed input - not something this check reasons about.
        if ($ipBytes.Length -ne 4 -or $netBytes.Length -ne 4) { return $false }

        # BitConverter on a little-endian host reverses byte order; build the
        # UInt32 manually (network byte order / big-endian) so the mask
        # arithmetic below is correct regardless of host endianness.
        $ipInt = ([uint32]$ipBytes[0] -shl 24) -bor ([uint32]$ipBytes[1] -shl 16) -bor ([uint32]$ipBytes[2] -shl 8) -bor [uint32]$ipBytes[3]
        $netInt = ([uint32]$netBytes[0] -shl 24) -bor ([uint32]$netBytes[1] -shl 16) -bor ([uint32]$netBytes[2] -shl 8) -bor [uint32]$netBytes[3]

        if ($prefixLength -eq 0) {
            $mask = 0
        }
        else {
            $mask = [uint32]([uint64]0xFFFFFFFF -shl (32 - $prefixLength))
        }

        return (($ipInt -band $mask) -eq ($netInt -band $mask))
    }
    catch {
        Write-Verbose "Test-ADIpInCidrRange: could not evaluate '$IpAddress' against '$CidrRange': $_"
        return $false
    }
}

function Test-ADStaleObjectDepth {
    <#
    .SYNOPSIS
        Audits long-tail stale-object and account/object hygiene gaps.
    .DESCRIPTION
        Five independent, read-only checks:
          1. PASSWD_NOTREQD - accounts with userAccountControl bit 0x0020
             set, which lets the account authenticate with an empty
             password or a password that never satisfies policy length
             requirements.
          2. primaryGroupID tampering - flags user/computer objects whose
             primaryGroupID does not match the expected default for their
             object type (513 for users, 515 for computers, 516 legitimate
             only for actual Domain Controllers), a known technique for
             hiding privileged group membership from a memberOf-based
             review.
          3. Duplicate Service Principal Names - builds a case-insensitive
             SPN index across users and computers and reports every SPN
             registered on more than one account, listing all holders (a
             duplicate SPN breaks Kerberos authentication and can indicate
             a rogue or leftover service account).
          4. DC Subnet/Site Registration Gap - cross-checks each Domain
             Controller's IPv4 address against AD Sites & Services subnet
             objects (Get-ADReplicationSubnet) and flags DCs whose address
             is not covered by any defined subnet.
          5. Insufficient Domain Controller Count - flags a domain with
             fewer than two Domain Controllers (no redundancy).
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Starting Stale-Object & Hygiene Depth audit..."
    $findings = @()
    $__adServer = Get-ADSecurityAuditTargetServerValue

    # -------------------------------------------------------------------
    # Gather users/computers/DCs.
    # -------------------------------------------------------------------
    $users = @()
    $computers = @()
    $domainControllers = @()

    try {
        $users = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADUser (stale-object depth)' -Query {
            Get-ADUser -Filter '*' -ResultPageSize 500 -Server $__adServer -ErrorAction Stop -Properties `
                SamAccountName, DistinguishedName, Enabled, userAccountControl, `
                PrimaryGroupID, ServicePrincipalNames
        })
    }
    catch {
        Write-Warning "Test-ADStaleObjectDepth: failed to collect users: $_"
    }

    try {
        $computers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADComputer (stale-object depth)' -Query {
            Get-ADComputer -Filter '*' -ResultPageSize 500 -Server $__adServer -ErrorAction Stop -Properties `
                SamAccountName, DistinguishedName, Enabled, userAccountControl, `
                PrimaryGroupID, ServicePrincipalNames
        })
    }
    catch {
        Write-Warning "Test-ADStaleObjectDepth: failed to collect computers: $_"
    }

    try {
        # Get-ADSecurityAuditDomainController, not a bare
        # Get-ADDomainController -Filter * - the latter is forest-wide
        # regardless of -Server; see Common.ps1 for why.
        $domainControllers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADSecurityAuditDomainController (stale-object depth)' -Query {
            Get-ADSecurityAuditDomainController -Server $__adServer
        })
    }
    catch {
        Write-Warning "Test-ADStaleObjectDepth: failed to collect domain controllers: $_"
    }

    # --- True, unscoped domain-wide DC inventory (independent of a
    # -Server-narrowed $domainControllers above) ---
    #
    # $domainControllers above is deliberately -Server-scoped: when the
    # operator names one specific DC, it correctly narrows to just that DC
    # for the subnet/site-registration check below (Check 4), which is a
    # live per-DC probe that should only touch the DC(s) the operator
    # scoped this run to.
    #
    # But TWO other things in this function need the domain's TRUE total
    # DC inventory regardless of that scoping, because they're properties
    # of the DOMAIN, not of which DC(s) probing was scoped to:
    #   1. $dcComputerDNs below (which computer objects are legitimately
    #      recognized as Domain Controllers, for the primaryGroupID=516
    #      check) - narrowing this to one explicitly-named DC would
    #      misclassify every OTHER real DC's computer object as a
    #      non-DC holding a suspicious primaryGroupID, a false positive.
    #   2. Check 5 (Insufficient Domain Controller Count) below - a
    #      redundancy assessment of the whole domain, which must reflect
    #      the true total regardless of -Server scoping. Reusing the
    #      possibly-narrowed $domainControllers here previously caused
    #      this check to report "only 1 DC" whenever -Server named one
    #      specific DC, even in a domain with several DCs (reported bug).
    #
    # -IgnoreExplicitDCScope (Get-ADSecurityAuditDomainController,
    # Common.ps1) exists specifically for this: it still USES $__adServer
    # as the query target (so it works even when only one DC is reachable
    # for this engagement), but always returns every DC belonging to the
    # resolved domain rather than narrowing to just the named DC.
    $allDomainControllersInDomain = @()
    try {
        $allDomainControllersInDomain = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADSecurityAuditDomainController -IgnoreExplicitDCScope (stale-object depth, true count)' -Query {
            Get-ADSecurityAuditDomainController -Server $__adServer -IgnoreExplicitDCScope
        })
    }
    catch {
        Write-Warning "Test-ADStaleObjectDepth: failed to collect the true (unscoped) domain-wide DC inventory; falling back to the -Server-scoped list for the count/legitimacy checks (may undercount or misclassify a real DC if -Server was narrowed to one specific DC): $_"
        $allDomainControllersInDomain = $domainControllers
    }

    # DNs of computer objects that are actual Domain Controllers, so a
    # primaryGroupID of 516 (Domain Controllers) is recognised as legitimate
    # only for those objects and suspicious for anything else. Built from
    # $allDomainControllersInDomain (the TRUE, unscoped domain-wide
    # inventory), not the possibly -Server-narrowed $domainControllers -
    # see the comment above for why.
    $dcComputerDNs = @{}
    foreach ($dc in $allDomainControllersInDomain) {
        $dcDN = $null
        if ($dc.PSObject.Properties['ComputerObjectDN']) { $dcDN = $dc.ComputerObjectDN }
        elseif ($dc -is [hashtable] -and $dc.ContainsKey('ComputerObjectDN')) { $dcDN = $dc.ComputerObjectDN }
        if ($dcDN) { $dcComputerDNs[$dcDN] = $true }
    }

    # -------------------------------------------------------------------
    # Check 1: PASSWD_NOTREQD (userAccountControl bit 0x0020)
    # -------------------------------------------------------------------
    try {
        Write-Verbose "Test-ADStaleObjectDepth: checking for PASSWD_NOTREQD accounts..."
        foreach ($user in $users) {
            $uac = $user.userAccountControl
            if ($null -eq $uac) { continue }
            $uacValue = [int]$uac

            if (($uacValue -band $Script:StaleDepthPasswdNotReqdFlag) -ne 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Stale-Object & Hygiene Depth'
                $finding.Issue = 'Accounts with PASSWD_NOTREQD Set'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "The account '$($user.SamAccountName)' has the PASSWD_NOTREQD flag set on userAccountControl (0x$('{0:X}' -f $uacValue)), which removes the requirement that the account's password satisfy the domain password policy - including allowing a blank password."
                $finding.Impact = "An account with PASSWD_NOTREQD can be assigned an empty or trivially weak password without any policy enforcement, making it a low-effort credential-guessing or password-spraying target."
                $finding.Remediation = "Clear the PASSWD_NOTREQD flag (Set-ADUser -Identity <account> -PasswordNotRequired `$false) and ensure the account has a password that meets the domain password policy."
                $finding.EstimatedEffort = 'Low - clearing a single userAccountControl flag on one account, though note the account still keeps its current (possibly blank/weak) password until it''s actually changed.'
                $finding.KnownRisks = 'Clearing the flag alone has no immediate compatibility impact, since the account keeps its current password until it''s next changed - this is a two-step fix (clear the flag, then force a password reset), not an instant risk elimination.'
                $finding.BackupRollback = 'Easy - re-set the PASSWD_NOTREQD flag if needed; effective immediately, no data loss.'
                $finding.Details = @{
                    SamAccountName    = $user.SamAccountName
                    DistinguishedName = $user.DistinguishedName
                    UserAccountControl = $uacValue
                    Enabled           = $user.Enabled
                }
                $findings += $finding
            }
        }
    }
    catch {
        Write-Warning "Test-ADStaleObjectDepth: PASSWD_NOTREQD check failed: $_"
    }

    # -------------------------------------------------------------------
    # Check 2: Non-default primaryGroupID (membership hiding)
    # -------------------------------------------------------------------
    try {
        Write-Verbose "Test-ADStaleObjectDepth: checking primaryGroupID values..."

        foreach ($user in $users) {
            $pgid = $user.PrimaryGroupID
            if ($null -eq $pgid) {
                Write-Verbose "Test-ADStaleObjectDepth: no primaryGroupID available for '$($user.SamAccountName)'; skipping."
                continue
            }
            $pgidValue = [int]$pgid

            if ($pgidValue -ne $Script:StaleDepthDefaultPrimaryGroupIds.DomainUsers) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Stale-Object & Hygiene Depth'
                $finding.Issue = 'Non-Default primaryGroupID (Membership Hiding)'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User account '$($user.SamAccountName)' has a primaryGroupID of $pgidValue instead of the expected default of $($Script:StaleDepthDefaultPrimaryGroupIds.DomainUsers) (Domain Users)."
                $finding.Impact = "primaryGroupID membership is not reflected in the group's forward-linked 'member' attribute, so tools and reviewers that enumerate privileged group membership via memberOf/member alone can miss it entirely. Setting primaryGroupID to a privileged RID (e.g. 512 - Domain Admins) is a known technique for hiding effectively-privileged accounts from casual review."
                $finding.Remediation = "Verify the business justification for the non-default primaryGroupID. If unintended, reset it to $($Script:StaleDepthDefaultPrimaryGroupIds.DomainUsers) (Set-ADUser -Identity <account> -Replace @{primaryGroupID=$($Script:StaleDepthDefaultPrimaryGroupIds.DomainUsers)}) after confirming the account is already an explicit member of any group it legitimately needs."
                $finding.EstimatedEffort = 'Medium - resetting primaryGroupID to the standard value requires first confirming the object genuinely isn''t a legitimate DC or service account with a documented reason for a non-default primary group, since this is also a known persistence/membership-hiding technique.'
                $finding.KnownRisks = 'Legitimate reasons for a non-default primaryGroupID are rare, but confirm the object isn''t a genuinely misconfigured-but-legitimate service account before treating it purely as malicious persistence and resetting it.'
                $finding.BackupRollback = 'Easy - revert the primaryGroupID attribute to its prior value; effective immediately, no data loss.'
                $finding.Details = @{
                    SamAccountName    = $user.SamAccountName
                    DistinguishedName = $user.DistinguishedName
                    PrimaryGroupID    = $pgidValue
                    ExpectedDefault   = $Script:StaleDepthDefaultPrimaryGroupIds.DomainUsers
                    ObjectType        = 'User'
                }
                $findings += $finding
            }
        }

        foreach ($computer in $computers) {
            $pgid = $computer.PrimaryGroupID
            if ($null -eq $pgid) {
                Write-Verbose "Test-ADStaleObjectDepth: no primaryGroupID available for '$($computer.SamAccountName)'; skipping."
                continue
            }
            $pgidValue = [int]$pgid

            $isDcObject = $dcComputerDNs.ContainsKey($computer.DistinguishedName)
            $expectedDefault = if ($isDcObject) { $Script:StaleDepthDefaultPrimaryGroupIds.DomainControllers } else { $Script:StaleDepthDefaultPrimaryGroupIds.DomainComputers }

            # 516 (Domain Controllers) is legitimate ONLY for objects that are
            # actually registered as Domain Controllers; 515 (Domain
            # Computers) is the expected default for everything else.
            $isLegitimate = ($pgidValue -eq $expectedDefault) -or
                            (-not $isDcObject -and $pgidValue -eq $Script:StaleDepthDefaultPrimaryGroupIds.DomainComputers) -or
                            ($isDcObject -and $pgidValue -eq $Script:StaleDepthDefaultPrimaryGroupIds.DomainControllers)

            if (-not $isLegitimate) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Stale-Object & Hygiene Depth'
                $finding.Issue = 'Non-Default primaryGroupID (Membership Hiding)'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $computer.SamAccountName
                $finding.Description = "Computer account '$($computer.SamAccountName)' has a primaryGroupID of $pgidValue, which does not match the expected default ($($Script:StaleDepthDefaultPrimaryGroupIds.DomainComputers) for a member computer, or $($Script:StaleDepthDefaultPrimaryGroupIds.DomainControllers) only if it is a genuine Domain Controller)."
                $finding.Impact = "As with user objects, primaryGroupID membership is invisible to memberOf-based reviews. A non-DC computer object with primaryGroupID 516 (Domain Controllers) or another privileged RID can gain effective privileges that are not visible through normal group-membership auditing."
                $finding.Remediation = "Verify the business justification for the non-default primaryGroupID. If unintended, reset it to $($Script:StaleDepthDefaultPrimaryGroupIds.DomainComputers) (Domain Computers) unless the object is a genuine, currently-registered Domain Controller."
                $finding.EstimatedEffort = 'Medium - resetting primaryGroupID to the standard value requires first confirming the object genuinely isn''t a legitimate DC or service account with a documented reason for a non-default primary group, since this is also a known persistence/membership-hiding technique.'
                $finding.KnownRisks = 'Legitimate reasons for a non-default primaryGroupID are rare, but confirm the object isn''t a genuinely misconfigured-but-legitimate service account before treating it purely as malicious persistence and resetting it.'
                $finding.BackupRollback = 'Easy - revert the primaryGroupID attribute to its prior value; effective immediately, no data loss.'
                $finding.Details = @{
                    SamAccountName    = $computer.SamAccountName
                    DistinguishedName = $computer.DistinguishedName
                    PrimaryGroupID    = $pgidValue
                    ExpectedDefault   = $expectedDefault
                    IsRegisteredDC    = $isDcObject
                    ObjectType        = 'Computer'
                }
                $findings += $finding
            }
        }
    }
    catch {
        Write-Warning "Test-ADStaleObjectDepth: primaryGroupID check failed: $_"
    }

    # -------------------------------------------------------------------
    # Check 3: Duplicate Service Principal Names
    # -------------------------------------------------------------------
    try {
        Write-Verbose "Test-ADStaleObjectDepth: checking for duplicate SPNs..."

        # Case-insensitive index: SPN -> list of holder identifiers.
        $spnIndex = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[string]]]::new([System.StringComparer]::OrdinalIgnoreCase)

        $allPrincipals = @()
        $allPrincipals += $users
        $allPrincipals += $computers

        foreach ($principal in $allPrincipals) {
            $spns = $principal.ServicePrincipalNames
            if (-not $spns) { continue }

            foreach ($spn in @($spns)) {
                if ([string]::IsNullOrWhiteSpace($spn)) { continue }

                if (-not $spnIndex.ContainsKey($spn)) {
                    $spnIndex[$spn] = [System.Collections.Generic.List[string]]::new()
                }
                $spnIndex[$spn].Add($principal.SamAccountName)
            }
        }

        foreach ($spn in $spnIndex.Keys) {
            $holders = $spnIndex[$spn]
            if ($holders.Count -gt 1) {
                $uniqueHolders = @($holders | Select-Object -Unique)
                if ($uniqueHolders.Count -le 1) { continue }

                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Stale-Object & Hygiene Depth'
                $finding.Issue = 'Duplicate Service Principal Names'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $spn
                $finding.Description = "The Service Principal Name '$spn' is registered on $($uniqueHolders.Count) accounts: $($uniqueHolders -join ', ')."
                $finding.Impact = "A duplicate SPN breaks Kerberos authentication for the affected service (clients may authenticate against the wrong account or fail entirely), and can also indicate a stale, decommissioned, or rogue account still holding a legitimate service's identity."
                $finding.Remediation = "Determine which account is the correct current holder of this SPN and remove it from all others (setspn -X to find domain-wide duplicates; Set-ADUser/-Computer -Remove @{ServicePrincipalNames='$spn'} on the incorrect holder(s))."
                $finding.EstimatedEffort = 'Medium - Kerberos treats a duplicate SPN as ambiguous, and identifying which account should legitimately hold the SPN (versus the stale/incorrect one) requires investigation before removing it.'
                $finding.KnownRisks = 'Removing the SPN from the wrong account (rather than the stale one) can break the legitimate service instead of fixing the conflict.'
                $finding.BackupRollback = 'Easy - re-add the SPN to the account it was removed from via setspn; effective immediately, no data loss.'
                $finding.Details = @{
                    ServicePrincipalName = $spn
                    Holders               = $uniqueHolders
                    HolderCount           = $uniqueHolders.Count
                }
                $findings += $finding
            }
        }
    }
    catch {
        Write-Warning "Test-ADStaleObjectDepth: duplicate SPN check failed: $_"
    }

    # -------------------------------------------------------------------
    # Check 4: DC Subnet/Site Registration Gap
    # -------------------------------------------------------------------
    try {
        Write-Verbose "Test-ADStaleObjectDepth: checking DC subnet/site registration..."

        $subnets = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADReplicationSubnet (stale-object depth)' -Query {
            Get-ADReplicationSubnet -Filter * -Properties Name, Site -Server $__adServer -ErrorAction Stop
        })

        foreach ($dc in $domainControllers) {
            $dcIp = $null
            if ($dc.PSObject.Properties['IPv4Address']) { $dcIp = $dc.IPv4Address }
            elseif ($dc -is [hashtable] -and $dc.ContainsKey('IPv4Address')) { $dcIp = $dc.IPv4Address }

            if ([string]::IsNullOrWhiteSpace($dcIp)) {
                Write-Verbose "Test-ADStaleObjectDepth: no IPv4Address available for a DC; skipping subnet check for that DC."
                continue
            }

            $dcName = $dc.Name
            $covered = $false
            foreach ($subnet in $subnets) {
                if (Test-ADIpInCidrRange -IpAddress $dcIp -CidrRange $subnet.Name) {
                    $covered = $true
                    break
                }
            }

            if (-not $covered) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Stale-Object & Hygiene Depth'
                $finding.Issue = 'DC Subnet/Site Registration Gap'
                $finding.Severity = 'Low'
                $finding.SeverityLevel = 1
                $finding.AffectedObject = $dcName
                $finding.Description = "Domain Controller '$dcName' ($dcIp) is not covered by any AD Sites & Services subnet object, so it cannot be mapped to a site."
                $finding.Impact = "Clients and other Domain Controllers that fall outside a defined subnet fall back to slower, less predictable site-selection and replication behaviour, which can cause clients to authenticate against a distant DC and can mask real network-topology issues."
                $finding.Remediation = "Create or extend an AD Sites & Services subnet object covering $dcIp and associate it with the correct site (Get-ADReplicationSite / New-ADReplicationSubnet)."
                $finding.EstimatedEffort = 'Medium - creating the missing AD Sites and Services subnet object touches the forest-wide sites topology (Configuration NC), so validate the site boundary is correct before publishing it.'
                $finding.KnownRisks = 'An incorrect subnet-to-site mapping can send clients or DCs to authenticate across a slow WAN link instead of a local DC, so getting the subnet/site boundary right matters more than simply filling the gap.'
                $finding.BackupRollback = 'Easy - remove or correct the subnet object; effective as clients next look up their site, no data loss.'
                $finding.Details = @{
                    DomainController = $dcName
                    IPv4Address      = $dcIp
                    KnownSubnets     = @($subnets | ForEach-Object { $_.Name })
                }
                $findings += $finding
            }
        }
    }
    catch {
        Write-Warning "Test-ADStaleObjectDepth: DC subnet/site registration check failed: $_"
    }

    # -------------------------------------------------------------------
    # Check 5: Insufficient Domain Controller Count
    # -------------------------------------------------------------------
    try {
        Write-Verbose "Test-ADStaleObjectDepth: checking Domain Controller count..."

        # FIXED (reported bug): this used to read @($domainControllers).Count
        # - the -Server-SCOPED list - so a run with -Server narrowed to one
        # specific DC always reported "the domain has only 1 Domain
        # Controller" regardless of how many DCs the domain actually has.
        # This is a redundancy assessment of the whole domain, so it must
        # always use the TRUE, unscoped count: $allDomainControllersInDomain
        # (the live -IgnoreExplicitDCScope enumeration), not the possibly
        # -Server-narrowed $domainControllers.
        $dcCount = @($allDomainControllersInDomain).Count

        if ($dcCount -lt 2) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Stale-Object & Hygiene Depth'
            $finding.Issue = 'Insufficient Domain Controller Count'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = 'Domain'
            $finding.Description = "The domain has only $dcCount Domain Controller(s)."
            $finding.Impact = "With no redundant Domain Controller, the domain has a single point of failure - loss of that DC (hardware failure, ransomware, or maintenance error) can cause a full authentication and directory outage until it is recovered."
            $finding.Remediation = "Deploy at least one additional Domain Controller, ideally in a separate physical/virtual failure domain, to provide redundancy for authentication and directory services."
            $finding.EstimatedEffort = 'High - adding DCs is an infrastructure project (server/VM provisioning, licensing, capacity planning, possibly a new site), not a configuration change, and needs coordination with infrastructure/capacity-planning teams.'
            $finding.KnownRisks = 'No risk from adding a DC itself beyond the normal operational load of any new DC promotion (replication during initial sync); the risk this finding actually describes is the opposite - insufficient redundancy leaves directory availability exposed if the remaining DC(s) fail.'
            $finding.BackupRollback = 'Easy - a newly added DC can be demoted/removed later if genuinely not needed, with no impact on existing DCs.'
            $finding.Details = @{
                DomainControllerCount = $dcCount
                DomainControllers     = @($allDomainControllersInDomain | Where-Object { $_.PSObject.Properties['Name'] } | ForEach-Object { $_.Name })
            }
            $findings += $finding
        }
    }
    catch {
        Write-Warning "Test-ADStaleObjectDepth: DC count check failed: $_"
    }

    # -------------------------------------------------------------------
    # Check 6: Legacy FRS-Based SYSVOL Replication In Use
    # (files/20-legacy-protocol-replication-hygiene.md)
    # -------------------------------------------------------------------
    # SYSVOL replication migrates from the legacy File Replication
    # Service (FRS) to DFS Replication (DFSR) through four states (Start/
    # Prepared/Redirected/Eliminated) that Microsoft's own dfsrmig.exe
    # tool tracks and reports via `dfsrmig /GetGlobalState`. Only the
    # Eliminated state means FRS is no longer involved in SYSVOL
    # replication at all.
    #
    # NOTE ON DETECTION MECHANISM: an earlier version of this check read
    # a raw AD attribute (msDFSR-Options on DFSR-GlobalSettings) directly
    # and assumed a simple 0-3 integer value. On closer verification
    # against Microsoft's own documentation, that was wrong on two
    # counts: (1) msDFSR-Options is a generic DFSR object-options bit
    # field used by several DFSR-related object classes, not the SYSVOL
    # migration state tracker; the actual state is carried by msDFSR-Flags
    # (a bit-flag combination, not a simple integer, and one that
    # legitimately differs slightly in the presence of RODCs); and (2)
    # decoding that bit-flag combination correctly from documentation
    # alone (rather than a live-verified lab) risked introducing a
    # confidently-wrong result. Following this project's own "verify,
    # don't assume" principle, this check instead shells out to
    # `dfsrmig.exe /GetGlobalState` on the domain's PDC Emulator (the
    # same DC dfsrmig itself always contacts for this operation) and
    # parses its own human-readable state name from the output - the
    # same authoritative source an administrator would consult manually,
    # rather than re-deriving the state from a raw, easy-to-misread
    # attribute. Read-only: /GetGlobalState only reports state, it does
    # not change it.
    try {
        Write-Verbose "Test-ADStaleObjectDepth: checking SYSVOL FRS/DFSR migration state via dfsrmig.exe..."
        $domainForDfsr = Get-ADDomain -Server $__adServer
        $dfsrTargetDc = Get-ADTargetDomainController
        $dfsrTargetDcName = if ($dfsrTargetDc) { $dfsrTargetDc.HostName } else { $null }

        $migrationStateLabel = $null
        if ($dfsrTargetDcName) {
            try {
                # Bounded connection timeout (10s) on the remoting attempt
                # itself: unlike an AD/LDAP query, a WinRM connection to an
                # unreachable/nonexistent host can otherwise take
                # significantly longer than this project's other
                # Invoke-Command-based checks to fail closed, depending on
                # the environment's own network/DNS timeout behavior - this
                # check should never be the slow one in a run (or, in a
                # fully-mocked/offline unit-test context where no real DC
                # is reachable at all, drag out test execution far longer
                # than a query that's supposed to be effectively
                # instantaneous once caught).
                $dfsrSessionOption = New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 15000
                $dfsrmigOutput = Invoke-ADQueryWithRetry -MaxAttempts 1 -OperationName "Run dfsrmig /GetGlobalState on $dfsrTargetDcName" -Query {
                    Invoke-Command -ComputerName $dfsrTargetDcName -SessionOption $dfsrSessionOption -ErrorAction Stop -ScriptBlock {
                        & dfsrmig.exe /GetGlobalState 2>&1 | Out-String
                    }
                }
                if ($dfsrmigOutput) {
                    # dfsrmig's own output names the state explicitly, e.g.
                    # "Current DFSR global state: 'Eliminated'" - match the
                    # state name directly rather than parsing a numeric
                    # code, so this doesn't depend on assumptions about
                    # dfsrmig's internal numbering.
                    if ($dfsrmigOutput -match "(?i)\b(Eliminated|Redirected|Prepared|Start)\b") {
                        $migrationStateLabel = $Matches[1]
                    }
                    else {
                        Write-Verbose "Test-ADStaleObjectDepth: dfsrmig /GetGlobalState output did not contain a recognized state name on '$dfsrTargetDcName': $dfsrmigOutput"
                    }
                }
            }
            catch {
                Write-Verbose "Test-ADStaleObjectDepth: could not run dfsrmig.exe /GetGlobalState on '$dfsrTargetDcName' (e.g. WinRM/PowerShell remoting unavailable, or the domain predates DFSR migration tooling); skipping this check rather than guessing at the migration state: $_"
            }
        }
        else {
            Write-Verbose "Test-ADStaleObjectDepth: could not resolve a target DC for the dfsrmig check; skipping."
        }

        if ($migrationStateLabel -and $migrationStateLabel -ine 'Eliminated') {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Stale-Object & Hygiene Depth'
            $finding.Issue = 'Legacy FRS-Based SYSVOL Replication In Use'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = $domainForDfsr.DNSRoot
            $finding.Description = "Domain '$($domainForDfsr.DNSRoot)' has not completed the FRS-to-DFSR SYSVOL migration (dfsrmig /GetGlobalState reports: $migrationStateLabel, confirmed against '$dfsrTargetDcName')."
            $finding.Impact = "The File Replication Service (FRS) has been deprecated since Windows Server 2008 in favor of DFS Replication (DFSR) and receives no further security fixes. A domain still using FRS (or mid-migration, with FRS still present) for SYSVOL replication carries an unsupported, unpatched replication component for a critical directory-wide share (Group Policy templates, logon scripts)."
            $finding.Remediation = "Complete the FRS-to-DFSR SYSVOL migration using ``Dfsrmig.exe`` (``/SetGlobalState 3`` progressing through Prepared -> Redirected -> Eliminated, verifying domain-wide replication health at each step with ``Dfsrmig.exe /GetMigrationState``) following Microsoft's documented migration procedure."
            $finding.EstimatedEffort = 'High - a domain-wide replication-mechanism migration affecting every DC''s SYSVOL share; Microsoft''s own procedure requires progressing through and verifying each state (Prepared/Redirected/Eliminated) before advancing, and should be scheduled and tested rather than rushed.'
            $finding.KnownRisks = 'A migration attempted without verifying full replication health at each intermediate state can leave some DCs serving a stale or incomplete SYSVOL, which can affect Group Policy application and logon scripts domain-wide - follow Microsoft''s documented state-by-state verification before advancing.'
            $finding.BackupRollback = 'Difficult - FRS-to-DFSR migration state advances are one-directional by design (Microsoft does not support reverting from Eliminated back to FRS); back up SYSVOL content before starting and verify each intermediate state thoroughly rather than planning to roll back.'
            $finding.Details = @{
                Domain              = $domainForDfsr.DNSRoot
                CheckedAgainstDC    = $dfsrTargetDcName
                MigrationStateLabel = $migrationStateLabel
                DetectionMethod     = 'dfsrmig.exe /GetGlobalState (remote execution via PowerShell remoting), not a raw AD attribute read.'
            }
            $findings += $finding
        }
        elseif ($migrationStateLabel) {
            Write-Verbose "Test-ADStaleObjectDepth: SYSVOL FRS-to-DFSR migration is complete (state: Eliminated)."
        }
        else {
            Write-Verbose "Test-ADStaleObjectDepth: could not confirm SYSVOL FRS/DFSR migration state; no finding emitted (avoiding a guess in either direction)."
        }
    }
    catch {
        Write-Warning "Test-ADStaleObjectDepth: SYSVOL FRS/DFSR migration state check failed: $_"
    }

    Write-Verbose "Stale-Object & Hygiene Depth audit complete. Found $($findings.Count) issues."
    return $findings
}

#endregion
