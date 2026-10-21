#region AD-Integrated DNS Security Audit
#
# Audits AD-integrated DNS for the DNS-specific attack surface that most
# generic AD reviews miss: DnsAdmins group membership (a well-known
# Domain-Controller code-execution path via the DNS server's
# ServerLevelPluginDll mechanism), zone transfer exposure, insecure dynamic
# updates, overly broad child-object creation rights on zone objects
# (the "ADIDNS" spoofing/MITM surface), and stale/dangling DNS zone
# delegations. PingCastle-comparable check(s): P-DNSAdmin, P-DNSDelegation,
# A-DnsZoneTransfert, A-DnsZoneUpdate1, A-DnsZoneUpdate2,
# A-DnsZoneAUCreateChild.
#
# DETECTION ONLY: this module reads group membership, AD-integrated zone
# object attributes/ACLs, and (optionally) the read-only DNS Server
# PowerShell cmdlets `Get-DnsServerZone` (transfer settings are read from its
# SecureSecondaries/SecondaryServers properties - there is no separate
# "Get-DnsServerZoneTransfer" cmdlet) and `Get-DnsServerZoneDelegation`
# (delegation NS/glue enumeration). The delegation-staleness check also
# issues ordinary DNS SOA queries against already-published glue IP
# addresses, and optionally reads AD Sites & Services subnet objects
# (`Get-ADReplicationSubnet`) for an informational-only signal. It never
# creates, deletes, or modifies a DNS record or zone, never registers a
# plugin DLL or hostname, never claims an IP address, and performs no
# exploitation, coercion, relay, takeover, or PoC traffic.

# Well-known/service SIDs that legitimately end up referenced from DnsAdmins
# in some environments and should not be flagged as "non-default" human/
# service membership. DnsAdmins itself has NO members by default, so
# anything outside this short, well-known list is reported.
$Script:DnsAdminsExpectedSids = @{
    'S-1-5-9'  = 'Enterprise Domain Controllers'
    'S-1-5-18' = 'NT AUTHORITY\SYSTEM'
    'S-1-5-20' = 'NT AUTHORITY\NETWORK SERVICE'
}

# Principals whose presence in a zone's CreateChild (or equivalent broad)
# ACE indicates the classic ADIDNS spoofing/MITM exposure: any authenticated
# user (or broader) can create arbitrary child DNS node objects in the zone.
$Script:DnsAdidnsBroadPrincipalSids = @{
    'S-1-5-11' = 'Authenticated Users'
    'S-1-1-0'  = 'Everyone'
    'S-1-5-7'  = 'ANONYMOUS LOGON'
}

# Pseudo-zone names that live alongside real zones under the
# DomainDnsZones/ForestDnsZones MicrosoftDNS container but are not
# attacker-relevant DNS zones themselves.
$Script:DnsPseudoZoneNames = @('RootDNSServers', '..TrustAnchors')

# Best-effort parser for the AD-integrated DNS zone 'dNSProperty' attribute
# (a multivalued binary attribute; each value is one DNS_PROPERTY record as
# used by the DNS Server RPC/AD storage format: a 20-byte header - 4-byte
# data length, 4 reserved bytes, 4-byte property Id, 4-byte data type, 4-byte
# flag - followed by the property's data). Only used to recover DWORD-typed
# zone properties (ALLOW_UPDATE, SECURE_SECONDARIES) when the DnsServer
# PowerShell module is not available. Returns $null (rather than a possibly
# wrong value) for anything it cannot confidently parse, so a parsing gap
# degrades to "skip this check" instead of an incorrect finding.
function Get-ADDnsZonePropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$DnsPropertyValues,

        [Parameter(Mandatory)]
        [uint32]$PropertyId
    )

    foreach ($propBytes in $DnsPropertyValues) {
        try {
            if (-not $propBytes -or $propBytes.Length -lt 24) { continue }

            $id = [BitConverter]::ToUInt32($propBytes, 8)
            if ($id -ne $PropertyId) { continue }

            # DWORD-typed property value immediately follows the 20-byte header.
            return [BitConverter]::ToUInt32($propBytes, 20)
        }
        catch {
            Write-Verbose "Get-ADDnsZonePropertyValue: failed to parse a dNSProperty value: $_"
            continue
        }
    }

    return $null
}

# Best-effort classifier for whether an IPv4 address falls in a private/
# reserved range (RFC1918, loopback, link-local). Used only as a severity
# signal for stale DNS delegations: a delegation whose unresponsive glue
# server sits on a public address is externally re-claimable by anyone (a
# classic subdomain-takeover setup) and is treated as higher severity than
# one whose glue address is simply unreachable on internal infrastructure.
# Returns $null (rather than guessing) for anything it cannot parse as an
# IPv4 address, consistent with Get-ADDnsZonePropertyValue's "degrade to
# skip, don't guess" convention in this file.
function Test-ADIsPrivateIpAddress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IpAddress
    )

    try {
        $parsed = [System.Net.IPAddress]::Parse($IpAddress)
        if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            # IPv6 or otherwise not something this best-effort check reasons about.
            return $null
        }

        $b = $parsed.GetAddressBytes()

        if ($b[0] -eq 10) { return $true }                                   # 10.0.0.0/8
        if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $true } # 172.16.0.0/12
        if ($b[0] -eq 192 -and $b[1] -eq 168) { return $true }               # 192.168.0.0/16
        if ($b[0] -eq 127) { return $true }                                  # 127.0.0.0/8 (loopback)
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return $true }               # 169.254.0.0/16 (link-local)

        return $false
    }
    catch {
        Write-Verbose "Test-ADIsPrivateIpAddress: could not parse '$IpAddress' as an IPv4 address: $_"
        return $null
    }
}

function Test-ADDnsSecurity {
    <#
    .SYNOPSIS
        Audits AD-integrated DNS security: DnsAdmins membership, zone
        transfer exposure, insecure dynamic updates, ADIDNS
        (broad child-object creation), and stale/dangling zone delegations
        on AD-integrated zones.
    .DESCRIPTION
        Five checks:
          1. DnsAdmins group membership - any member outside a short list of
             well-known service SIDs is flagged (DnsAdmins is empty by
             default; membership grants a well-known DC code-execution path
             via the DNS server's ServerLevelPluginDll mechanism).
          2. DNS Zone Transfer Allowed - flags AD-integrated zones configured
             to transfer to any server or to any server listed as an NS
             record for the zone (i.e. not restricted to an explicit
             secondary-server list).
          3. Insecure Dynamic DNS Updates Enabled - flags zones allowing
             nonsecure (unauthenticated) dynamic updates.
          4. Authenticated Users Can Create Child Objects in DNS Zone
             (ADIDNS) - flags zones whose AD object ACL grants CreateChild
             (or an equivalently broad right) to Authenticated Users,
             Everyone, or ANONYMOUS LOGON, enabling arbitrary DNS record
             registration/spoofing.
          5. Stale/Dangling DNS Zone Delegation - for each AD-integrated
             zone's delegated child zones (`Get-DnsServerZoneDelegation`),
             confirms each delegation NS's glue IP still answers an
             authoritative SOA query for the child zone. A glue IP that no
             longer responds is the stale/dangling signal (per PingCastle's
             P-DNSDelegation): whoever can now claim that hostname or
             reclaim that IP can serve authoritative-looking answers for the
             sub-zone. Delegations that simply point outside this module's
             known AD Sites & Services subnets, but still answer correctly,
             are NOT flagged - that is common for legitimate delegations to
             non-AD infrastructure (e.g. a cloud DNS provider) and is
             recorded only as weak, informational context, never as the
             basis for a finding.

        Checks 2-4 prefer the read-only `Get-DnsServerZone` cmdlet (DnsServer
        RSAT module, reading its DynamicUpdate/SecureSecondaries properties)
        when available, and fall back to a best-effort read of the zone AD
        object's `dNSProperty` attribute when that module is not installed.
        If neither source yields a confident answer for a zone, that check
        is skipped for that zone (Verbose only) rather than guessing. Check
        5 has no `dNSProperty`-based fallback (delegation/NS records have no
        such representation) and is skipped entirely when the DnsServer
        module is unavailable.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Starting AD-integrated DNS security audit..."
    $findings = @()
    $__adServer = Get-ADSecurityAuditTargetServerValue

    # -------------------------------------------------------------------
    # Check 1: Non-Default Members in DnsAdmins
    # -------------------------------------------------------------------
    try {
        $nonDefaultMembers = [System.Collections.ArrayList]::new()
        $dnsAdminsDN = $null

        $dnsAdminsGroup = $null
        try {
            $dnsAdminsGroup = Invoke-ADQueryWithRetry -OperationName 'Get-ADGroup DnsAdmins' -Query {
                Get-ADGroup -Filter "Name -eq 'DnsAdmins'" -Server $__adServer -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Test-ADDnsSecurity: error looking up 'DnsAdmins' group: $_"
        }

        if ($dnsAdminsGroup) {
            $dnsAdminsDN = $dnsAdminsGroup.DistinguishedName
            $members = Invoke-ADQueryWithRetry -OperationName 'Get-ADGroupMember DnsAdmins' -Query {
                Get-ADGroupMember -Identity $dnsAdminsGroup -Server $__adServer -ErrorAction Stop
            }

            foreach ($member in @($members)) {
                $sidValue = if ($member.SID) { $member.SID.Value } else { $null }
                if ($sidValue -and $Script:DnsAdminsExpectedSids.ContainsKey($sidValue)) { continue }
                [void]$nonDefaultMembers.Add("$($member.SamAccountName) ($($member.objectClass))")
            }
        }
        else {
            Write-Verbose "Test-ADDnsSecurity: 'DnsAdmins' group not found (DNS role may not be installed on any DC)."
        }

        if ($nonDefaultMembers.Count -gt 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'DNS Security'
            $finding.Issue = 'Non-Default Members in DnsAdmins'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = if ($dnsAdminsDN) { $dnsAdminsDN } else { 'DnsAdmins' }
            $finding.Description = "The 'DnsAdmins' group, which has no members by default, contains $($nonDefaultMembers.Count) member(s): $($nonDefaultMembers -join ', ')."
            $finding.Impact = "Members of DnsAdmins can configure the DNS server's `ServerLevelPluginDll` registry value, causing the DNS service (which runs as SYSTEM on the Domain Controller) to load an attacker-supplied DLL on next restart. This is a well-known path from DnsAdmins membership directly to SYSTEM-level code execution on a Domain Controller."
            $finding.Remediation = "Remove non-essential members from DnsAdmins and treat it as a Tier-0-equivalent group. Restrict `ServerLevelPluginDll` configuration rights, and where possible manage DNS via a dedicated, closely audited administrative workflow rather than broad DnsAdmins membership."
            $finding.EstimatedEffort = 'Low - removing an unexpected member from one group.'
            $finding.KnownRisks = 'DnsAdmins membership is a well-documented privilege-escalation vector (historical DNS-server-service DLL abuse); removing an unexpected member has no legitimate compatibility risk beyond that person losing DNS management rights, so confirm with them first.'
            $finding.BackupRollback = 'Easy - re-add the member if needed; effective on next Kerberos ticket refresh, no data loss.'
            $finding.Details = @{
                DistinguishedName = $dnsAdminsDN
                Members           = @($nonDefaultMembers)
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADDnsSecurity: no non-default DnsAdmins members found."
        }
    }
    catch {
        Write-Warning "Test-ADDnsSecurity: error auditing DnsAdmins membership: $_"
    }

    # -------------------------------------------------------------------
    # Checks 2-5: per-zone transfer / dynamic update / ADIDNS CreateChild /
    # delegation staleness.
    # -------------------------------------------------------------------
    try {
        $domain = Get-ADDomain -Server $__adServer -ErrorAction Stop
        $forest = Get-ADForest -Server $__adServer -ErrorAction SilentlyContinue

        $dnsPartitions = @("DC=DomainDnsZones,$($domain.DistinguishedName)")
        if ($forest) {
            $forestRootDN = ($forest.RootDomain | ForEach-Object { "DC=$($_ -replace '\.', ',DC=')" })
            $dnsPartitions += "DC=ForestDnsZones,$forestRootDN"
        }

        $zoneObjects = [System.Collections.ArrayList]::new()
        foreach ($partition in $dnsPartitions) {
            try {
                $zonesInPartition = Get-ADObject -SearchBase "CN=MicrosoftDNS,$partition" -Filter "objectClass -eq 'dnsZone'" `
                    -Properties dNSProperty, nTSecurityDescriptor -Server $__adServer -ErrorAction Stop
                foreach ($z in @($zonesInPartition)) {
                    if ($z.Name -in $Script:DnsPseudoZoneNames) { continue }
                    [void]$zoneObjects.Add($z)
                }
            }
            catch {
                Write-Verbose "Test-ADDnsSecurity: no DNS zones found under '$partition': $_"
            }
        }

        if ($zoneObjects.Count -eq 0) {
            Write-Verbose "Test-ADDnsSecurity: no AD-integrated DNS zones found; skipping zone-level checks."
            Write-Verbose "AD-integrated DNS security audit complete. Found $($findings.Count) issue(s)."
            return $findings
        }

        # Determine whether the read-only DnsServer module is available for
        # the more precise cmdlet-based path; otherwise fall back to the
        # dNSProperty attribute read on each zone object.
        $useDnsCmdlets = $false
        $dnsCmdletTargetDC = $null
        if (Get-Module -ListAvailable -Name DnsServer -ErrorAction SilentlyContinue) {
            try {
                # Fixed: previously called Get-ADDomainController -Discover
                # directly - mutually exclusive with -Server as a parameter
                # set, so an active -Server override elsewhere in the run
                # would throw here and silently fall back to the
                # attribute-read path against the wrong domain instead of
                # honoring the override. Get-ADTargetDomainController
                # resolves directly against the override when one is active.
                $dnsCmdletTargetDC = (Get-ADTargetDomainController).HostName
                if ($dnsCmdletTargetDC) {
                    Import-Module DnsServer -ErrorAction Stop
                    $useDnsCmdlets = $true
                }
            }
            catch {
                Write-Verbose "Test-ADDnsSecurity: DnsServer module present but could not be used ($_); falling back to AD attribute reads."
                $useDnsCmdlets = $false
            }
        }
        else {
            Write-Verbose "Test-ADDnsSecurity: DnsServer RSAT module not available; falling back to AD attribute (dNSProperty) reads for zone transfer/dynamic update."
        }

        # Best-effort, informational-only context for the delegation-
        # staleness check: known AD Sites & Services subnet ranges. A glue
        # IP falling outside all of these is NOT itself a finding (a
        # legitimate delegation to non-AD infrastructure, e.g. a cloud DNS
        # provider, is common) - it is only ever recorded as weak supporting
        # context alongside the actual (glue-unresponsive) stale-delegation
        # signal. Read-only; absence of this data does not block the check.
        $knownSubnetRanges = @()
        if ($useDnsCmdlets) {
            try {
                $knownSubnetRanges = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADReplicationSubnet (DNS delegation staleness)' -Query {
                    Get-ADReplicationSubnet -Filter * -Properties Name -Server $__adServer -ErrorAction Stop
                } | ForEach-Object { $_.Name })
            }
            catch {
                Write-Verbose "Test-ADDnsSecurity: could not read AD Sites & Services subnets for the delegation-staleness informational signal (non-fatal): $_"
                $knownSubnetRanges = @()
            }
        }

        $broadTransferZones  = [System.Collections.ArrayList]::new()
        $insecureUpdateZones = [System.Collections.ArrayList]::new()
        $adidnsZones         = [System.Collections.ArrayList]::new()
        $staleDelegations    = [System.Collections.ArrayList]::new()
        $zoneDetailLookup    = @{}

        foreach ($zone in $zoneObjects) {
            $zoneName = $zone.Name
            $zoneDN   = $zone.DistinguishedName
            $transferSetting = $null
            $updateSetting   = $null

            if ($useDnsCmdlets) {
                try {
                    $dnsZoneInfo = Invoke-ADQueryWithRetry -OperationName "Get-DnsServerZone '$zoneName'" -Query {
                        Get-DnsServerZone -Name $zoneName -ComputerName $dnsCmdletTargetDC -ErrorAction Stop
                    }
                    if ($dnsZoneInfo) {
                        if ($dnsZoneInfo.DynamicUpdate) {
                            $updateSetting = "$($dnsZoneInfo.DynamicUpdate)"
                        }
                        # Zone-transfer configuration is a property of the zone
                        # object itself (SecureSecondaries/SecondaryServers) -
                        # there is no separate "Get-DnsServerZoneTransfer"
                        # cmdlet in the DnsServer module, so it's read here
                        # rather than via a second (nonexistent) cmdlet call.
                        if ($dnsZoneInfo.SecureSecondaries) {
                            $transferSetting = switch ("$($dnsZoneInfo.SecureSecondaries)") {
                                'TransferAnyServer'        { 'Any' }
                                'TransferToZoneNameServer' { 'Named' }
                                'TransferToSecureServers'  { 'Specific' }
                                'NoTransfer'               { 'None' }
                                default                    { $null }
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Test-ADDnsSecurity: Get-DnsServerZone failed for '$zoneName': $_"
                }
            }
            else {
                $dnsPropertyValues = @($zone.dNSProperty)
                if ($dnsPropertyValues.Count -gt 0) {
                    # DSPROPERTY_ZONE_ALLOW_UPDATE = 2 (0 = None, 1 = Nonsecure and secure, 2 = Secure only)
                    $allowUpdateRaw = Get-ADDnsZonePropertyValue -DnsPropertyValues $dnsPropertyValues -PropertyId 2
                    if ($null -ne $allowUpdateRaw) {
                        $updateSetting = switch ([int]$allowUpdateRaw) {
                            0 { 'None' }
                            1 { 'NonsecureAndSecure' }
                            2 { 'Secure' }
                            default { $null }
                        }
                    }

                    # DSPROPERTY_ZONE_SECURE_SECONDARIES = 9 (0 = any server, 1 = servers listed on Name Servers tab,
                    # 2 = explicit secondary-server list only, 3 = no transfers)
                    $secureSecondariesRaw = Get-ADDnsZonePropertyValue -DnsPropertyValues $dnsPropertyValues -PropertyId 9
                    if ($null -ne $secureSecondariesRaw) {
                        $transferSetting = switch ([int]$secureSecondariesRaw) {
                            0 { 'Any' }
                            1 { 'Named' }
                            2 { 'Specific' }
                            3 { 'None' }
                            default { $null }
                        }
                    }
                }
                else {
                    Write-Verbose "Test-ADDnsSecurity: zone '$zoneName' has no dNSProperty values to parse; skipping transfer/update checks for this zone."
                }
            }

            $zoneDetailLookup[$zoneName] = @{
                DistinguishedName = $zoneDN
                DynamicUpdate     = $updateSetting
                ZoneTransferType  = $transferSetting
            }

            if ($transferSetting -in @('Any', 'Named')) {
                [void]$broadTransferZones.Add(@{ Zone = $zoneName; Setting = $transferSetting })
            }

            if ($updateSetting -eq 'NonsecureAndSecure') {
                [void]$insecureUpdateZones.Add(@{ Zone = $zoneName; Setting = $updateSetting })
            }

            # --- ADIDNS: broad CreateChild (or equivalently broad) rights on the zone object ---
            try {
                $acl = $zone.nTSecurityDescriptor
                if ($acl -and $acl.Access) {
                    $broadPrincipalsForZone = [System.Collections.ArrayList]::new()

                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -ne 'Allow') { continue }
                        if ($ace.ActiveDirectoryRights -notmatch 'CreateChild|GenericAll') { continue }

                        $identity = "$($ace.IdentityReference)"
                        foreach ($sid in $Script:DnsAdidnsBroadPrincipalSids.Keys) {
                            $wellKnownName = $Script:DnsAdidnsBroadPrincipalSids[$sid]
                            if ($identity -match [regex]::Escape($wellKnownName) -or $identity -match [regex]::Escape($sid)) {
                                [void]$broadPrincipalsForZone.Add(@{
                                    Principal = $wellKnownName
                                    Rights    = "$($ace.ActiveDirectoryRights)"
                                })
                            }
                        }
                    }

                    if ($broadPrincipalsForZone.Count -gt 0) {
                        [void]$adidnsZones.Add(@{
                            Zone              = $zoneName
                            DistinguishedName = $zoneDN
                            BroadPrincipals   = @($broadPrincipalsForZone)
                        })
                    }
                }
            }
            catch {
                Write-Verbose "Test-ADDnsSecurity: could not evaluate ACL for zone '$zoneName': $_"
            }

            # --- Stale/Dangling DNS Zone Delegation ---
            # Only possible via the DnsServer cmdlet path: delegation/NS
            # records have no dNSProperty-based fallback representation.
            if ($useDnsCmdlets) {
                $delegations = @()
                try {
                    $delegations = @(Invoke-ADQueryWithRetry -OperationName "Get-DnsServerZoneDelegation '$zoneName'" -Query {
                        Get-DnsServerZoneDelegation -ZoneName $zoneName -ComputerName $dnsCmdletTargetDC -ErrorAction Stop
                    })
                }
                catch {
                    Write-Verbose "Test-ADDnsSecurity: Get-DnsServerZoneDelegation failed for '$zoneName' (zone may have no delegations): $_"
                    $delegations = @()
                }

                foreach ($delegation in @($delegations)) {
                    # Cmdlet output shape can vary slightly by Windows Server
                    # version; read defensively and skip (Verbose only)
                    # rather than guess at a property that isn't there.
                    $childZoneName = $null
                    if ($delegation.PSObject.Properties['ChildZoneName'] -and $delegation.ChildZoneName) {
                        $childZoneName = "$($delegation.ChildZoneName)"
                    }
                    elseif ($delegation.PSObject.Properties['Name'] -and $delegation.Name) {
                        $childZoneName = "$($delegation.Name)"
                    }

                    if ([string]::IsNullOrWhiteSpace($childZoneName)) {
                        Write-Verbose "Test-ADDnsSecurity: could not determine the delegated child zone name for a delegation under '$zoneName'; skipping."
                        continue
                    }

                    # DNS cmdlet output can return an FQDN with a trailing
                    # root dot (e.g. '_msdcs.ad.local.'). Left unstripped,
                    # that trailing dot breaks the "already fully-qualified"
                    # regex match below (it no longer ends in exactly
                    # ".$zoneName") and the code falls through to appending
                    # $zoneName again, producing a malformed doubled name
                    # like '_msdcs.ad.local..ad.local'. Trim it first so
                    # both the match and the fallback concatenation operate
                    # on a normalized name.
                    $childZoneName = $childZoneName.TrimEnd('.')

                    $fullChildZoneName = if ($childZoneName -match ('\.' + [regex]::Escape($zoneName) + '$') -or $childZoneName -eq $zoneName) {
                        $childZoneName
                    }
                    else {
                        "$childZoneName.$zoneName"
                    }

                    $nameServers = @()
                    if ($delegation.PSObject.Properties['NameServer'] -and $delegation.NameServer) {
                        $nameServers = @($delegation.NameServer)
                    }

                    foreach ($ns in $nameServers) {
                        $nsHost = $null
                        if ($ns.PSObject.Properties['Name'] -and $ns.Name) { $nsHost = "$($ns.Name)" }
                        elseif ($ns.PSObject.Properties['NameServer'] -and $ns.NameServer) { $nsHost = "$($ns.NameServer)" }

                        $glueIps = @()
                        if ($ns.PSObject.Properties['IPAddress'] -and $ns.IPAddress) {
                            $glueIps = @($ns.IPAddress | ForEach-Object { "$_" } | Where-Object { $_ })
                        }

                        if ($glueIps.Count -eq 0) {
                            Write-Verbose "Test-ADDnsSecurity: delegation NS '$nsHost' under '$zoneName' -> '$fullChildZoneName' has no glue IP recorded; cannot test responsiveness, skipping."
                            continue
                        }

                        foreach ($glueIp in $glueIps) {
                            # Primary signal: does this glue IP still answer
                            # an authoritative SOA query for the delegated
                            # child zone? A delegation that doesn't actually
                            # answer is unambiguously stale.
                            $responds = $false
                            try {
                                $soaAnswer = Resolve-DnsName -Name $fullChildZoneName -Server $glueIp -Type SOA -DnsOnly -ErrorAction Stop
                                if ($soaAnswer) { $responds = $true }
                            }
                            catch {
                                Write-Verbose "Test-ADDnsSecurity: glue IP '$glueIp' for delegated zone '$fullChildZoneName' (NS '$nsHost') did not answer an SOA query: $_"
                                $responds = $false
                            }

                            if ($responds) { continue }

                            # Secondary, informational-only signal: is this
                            # glue IP outside every known AD Sites & Services
                            # subnet? This does NOT gate the finding - a
                            # legitimate delegation to non-AD infrastructure
                            # is common - it is only ever extra context.
                            $outsideKnownSubnets = $null
                            if ($knownSubnetRanges.Count -gt 0) {
                                $withinKnownSubnet = $false
                                foreach ($subnetRange in $knownSubnetRanges) {
                                    if (Test-ADIpInCidrRange -IpAddress $glueIp -CidrRange $subnetRange) {
                                        $withinKnownSubnet = $true
                                        break
                                    }
                                }
                                $outsideKnownSubnets = -not $withinKnownSubnet
                            }

                            [void]$staleDelegations.Add(@{
                                ParentZone          = $zoneName
                                ChildZone           = $fullChildZoneName
                                NameServer          = $nsHost
                                GlueIpAddress       = $glueIp
                                IsPublicIpAddress   = ((Test-ADIsPrivateIpAddress -IpAddress $glueIp) -eq $false)
                                OutsideKnownSubnets = $outsideKnownSubnets
                            })
                        }
                    }
                }
            }
        }

        # -------------------------------------------------------------------
        # Finding: DNS Zone Transfer Allowed
        # -------------------------------------------------------------------
        if ($broadTransferZones.Count -gt 0) {
            $zoneNames = @($broadTransferZones | ForEach-Object { $_.Zone })
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'DNS Security'
            $finding.Issue = 'DNS Zone Transfer Allowed'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = ($zoneNames -join ', ')
            $finding.Description = "$($broadTransferZones.Count) AD-integrated zone(s) allow zone transfers to any server or to any server listed as a name server for the zone, rather than an explicit secondary-server list: $($zoneNames -join ', ')."
            $finding.Impact = "Zone transfers expose the complete contents of a DNS zone - hostnames, IP addresses, and often internal naming conventions for servers, workstations, and services - to any host that can request an AXFR, aiding network reconnaissance ahead of further attacks."
            $finding.Remediation = "Restrict zone transfers to an explicit list of authorized secondary server IP addresses (`Set-DnsServerPrimaryZone -Name <Zone> -SecureSecondaries TransferToSecureServers -SecondaryServers <IP1>,<IP2>`), or disable transfers entirely if no secondaries are in use."
            $finding.EstimatedEffort = 'Low - restricting zone transfer to specific secondary server IPs is a single zone property.'
            $finding.KnownRisks = 'Restricting zone transfer will break any legitimate secondary DNS server that currently relies on unrestricted transfer, so confirm the authorized secondary list first.'
            $finding.BackupRollback = 'Easy - revert to the prior zone-transfer setting; effective immediately, no data loss.'
            $finding.Details = @{
                Zones       = @($broadTransferZones)
                DetailByZone = $zoneDetailLookup
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADDnsSecurity: no zones with broad zone-transfer settings found."
        }

        # -------------------------------------------------------------------
        # Finding: Insecure Dynamic DNS Updates Enabled
        # -------------------------------------------------------------------
        if ($insecureUpdateZones.Count -gt 0) {
            $zoneNames = @($insecureUpdateZones | ForEach-Object { $_.Zone })
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'DNS Security'
            $finding.Issue = 'Insecure Dynamic DNS Updates Enabled'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = ($zoneNames -join ', ')
            $finding.Description = "$($insecureUpdateZones.Count) AD-integrated zone(s) permit nonsecure (unauthenticated) dynamic updates: $($zoneNames -join ', ')."
            $finding.Impact = "Nonsecure dynamic updates let any client on the network - authenticated or not - create or modify DNS records in the zone without proof of identity, enabling record spoofing/hijacking that can redirect traffic or facilitate downstream relay/MITM attacks."
            $finding.Remediation = "Set the zone to accept secure dynamic updates only (`Set-DnsServerPrimaryZone -Name <Zone> -DynamicUpdate Secure`), which restricts updates to Kerberos-authenticated domain-joined clients."
            $finding.EstimatedEffort = 'Medium - switching to secure-only dynamic updates requires the zone to already be AD-integrated, and breaks self-registration for any non-domain-joined device currently updating its own record.'
            $finding.KnownRisks = 'Switching to secure-only updates will break dynamic registration from any non-Windows or non-domain-joined device that currently self-registers (some Linux/IoT/appliance DHCP-DNS integrations), a documented Microsoft behavior.'
            $finding.BackupRollback = 'Easy - revert the zone''s dynamic-update setting; effective immediately, no data loss to existing records.'
            $finding.Details = @{
                Zones        = @($insecureUpdateZones)
                DetailByZone = $zoneDetailLookup
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADDnsSecurity: no zones with insecure dynamic updates found."
        }

        # -------------------------------------------------------------------
        # Finding: Authenticated Users Can Create Child Objects in DNS Zone (ADIDNS)
        # -------------------------------------------------------------------
        if ($adidnsZones.Count -gt 0) {
            $zoneNames = @($adidnsZones | ForEach-Object { $_.Zone })
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'DNS Security'
            $finding.Issue = 'Authenticated Users Can Create Child Objects in DNS Zone'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = ($zoneNames -join ', ')
            $finding.Description = "$($adidnsZones.Count) AD-integrated zone object(s) grant broad principals (Authenticated Users, Everyone, or ANONYMOUS LOGON) the right to create child objects: $($zoneNames -join ', ')."
            $finding.Impact = "Any authenticated (or, in the worst case, unauthenticated) principal can register arbitrary new DNS node objects in the zone (ADIDNS), enabling record spoofing for names not already present - commonly used to impersonate wildcard/service names, poison WPAD-style discovery, or stage NTLM-relay/MITM attacks."
            $finding.Remediation = "Review and tighten the zone object's ACL to remove CreateChild (or broader) rights from Authenticated Users/Everyone/ANONYMOUS LOGON, restricting DNS record creation to the intended administrative or provisioning principals."
            $finding.EstimatedEffort = 'Medium - removing the broad create-child ACE and confirming no legitimate dynamic-update workflow depends on it, since this is actually the AD-integrated DNS zone''s default ACL for supporting computer self-registration.'
            $finding.KnownRisks = 'This permission is the default AD-integrated DNS zone ACL that lets domain-joined computers dynamically register their own DNS records; removing it broadly can break legitimate machine self-registration unless replaced with a Secure-only dynamic update model plus targeted exceptions.'
            $finding.BackupRollback = 'Moderate - export the zone''s current ACL first (dnscmd or Get-Acl on the zone''s AD object) and reapply if self-registration breaks; changes follow normal AD/DNS replication.'
            $finding.Details = @{
                Zones = @($adidnsZones)
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADDnsSecurity: no zones with broad ADIDNS CreateChild rights found."
        }

        # -------------------------------------------------------------------
        # Finding: Stale/Dangling DNS Zone Delegation
        # -------------------------------------------------------------------
        if ($staleDelegations.Count -gt 0) {
            $affectedChildZones = @($staleDelegations | ForEach-Object { $_.ChildZone } | Select-Object -Unique)
            $anyPublicGlue = @($staleDelegations | Where-Object { $_.IsPublicIpAddress }).Count -gt 0

            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'DNS Security'
            $finding.Issue = 'Stale/Dangling DNS Zone Delegation'
            # Conditional severity: an unresponsive glue server on a public
            # IP address is externally re-claimable by anyone (classic
            # subdomain-takeover setup) and is rated higher than a glue
            # server that is simply unreachable on internal infrastructure.
            $finding.Severity = if ($anyPublicGlue) { 'High' } else { 'Medium' }
            $finding.SeverityLevel = if ($anyPublicGlue) { 3 } else { 2 }
            $finding.AffectedObject = ($affectedChildZones -join ', ')
            # BUGFIX (v1.24.0): the per-delegation detail (which specific
            # NameServer/glue IP is actually stale - the thing someone
            # needs to go act on) previously lived ONLY in
            # Details.StaleDelegations, which the HTML report never
            # renders (Details is otherwise JSON/CSV-only). A reader of
            # the HTML report saw a zone-name list and a count with no way
            # to find the actual stale record without opening the JSON.
            # Enumerated as bullets here, same convention already used for
            # Domain Admin Equivalence's evidence list and the ESC4
            # weak-ACL finding.
            $delegationBullets = ($staleDelegations | ForEach-Object {
                $glueLabel = if ($_.IsPublicIpAddress) { "$($_.GlueIpAddress) (public IP)" } else { "$($_.GlueIpAddress)" }
                "- $($_.ChildZone): NS '$($_.NameServer)' at $glueLabel did not answer"
            }) -join "`n"
            $finding.Description = "$($staleDelegations.Count) DNS delegation name-server record(s) across $($affectedChildZones.Count) delegated child zone(s) point at glue IP addresses that no longer answer authoritatively for the delegated zone:`n$delegationBullets"
            $finding.Impact = "A delegation whose glue nameservers no longer respond is stale/dangling: the parent zone's NS/glue records still hand authority for the sub-zone to infrastructure that appears retired or reassigned. Whoever can now claim that hostname or reclaim that IP address can serve authoritative-looking answers for the sub-zone - a well-documented DNS delegation/subdomain-takeover risk."
            $finding.Remediation = "Confirm whether each delegated child zone is still in use. If it is not, remove the stale NS/glue records from the parent zone (`Remove-DnsServerZoneDelegation`). If the child zone is still needed, repoint the delegation at the nameservers actually serving it today."
            $finding.EstimatedEffort = 'Low - removing a delegation (NS/glue) record pointing at a decommissioned name server.'
            $finding.KnownRisks = 'A dangling delegation is itself a documented subdomain-takeover risk (an attacker registering the abandoned target can serve authoritative answers for that subdomain), so removing it eliminates a real exposure rather than introducing one.'
            $finding.BackupRollback = 'Easy - re-create the delegation record if the name server is later reinstated; effective immediately, no data loss.'
            $finding.Details = @{
                StaleDelegations = @($staleDelegations)
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADDnsSecurity: no stale/dangling DNS zone delegations found."
        }
    }
    catch {
        Write-Warning "Test-ADDnsSecurity: error auditing DNS zone security: $_"
    }

    Write-Verbose "AD-integrated DNS security audit complete. Found $($findings.Count) issue(s)."
    return $findings
}

#endregion
