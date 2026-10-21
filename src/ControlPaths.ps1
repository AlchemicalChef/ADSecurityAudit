#region Attack-Path Graph & Indirect-Privilege (Control-Path) Findings
#
# Step 15 (v1.16.0) - builds a directed control-edge graph from dangerous
# ACEs, group membership, and object ownership, then computes reachability
# from non-Tier-0 principals to the Tier-0 set (Get-ADTier0Principal + DCs +
# AdminSDHolder + the domain head object). Chaining the module's existing
# per-object primitives this way surfaces INDIRECT privilege-escalation
# paths that flat per-object checks (e.g. Test-ADDangerousPermissions)
# cannot express on their own - the few paths that actually lead to Domain
# Admins/Domain Controllers, rather than a pile of individually-scored ACEs.
#
#   1. Get-ADControlPathGraph - one read-only pass that builds the directed
#      edge set (MemberOf / ACE / Owner) plus the Tier-0 target list.
#   2. Test-ADControlPaths    - BFS from every non-Tier-0 principal that
#      appears as an edge source to the Tier-0 set, emitting one finding per
#      reachable path with the full hop chain in Details.
#   3. Export-ADControlPathGraphBloodHound - optional BloodHound-compatible
#      generic-edge JSON export of the same graph, for cross-checking
#      against a BloodHound collection of the same environment.
#
# DETECTION ONLY: every edge is derived from a read of nTSecurityDescriptor,
# group membership, or object ownership - all attribute/ACL reads already
# performed elsewhere in this module. No exploitation, coercion, relay,
# ticket forging, or PoC traffic is ever sent to any host.
#
# Scope note: to keep this bounded on large domains, ACL/ownership edges are
# collected for the Tier-0 target set itself plus every group that is a
# (recursive) member of another protected group - i.e. every object that
# actually sits on a chain toward Tier-0 - rather than sweeping
# nTSecurityDescriptor across every object in the domain. A dangerous ACE on
# an object that is NOT itself on a path to Tier-0 cannot contribute to an
# indirect Tier-0 path, and is already covered by Test-ADDangerousPermissions
# and the other flat per-object checks.

# Broad/well-known principals that make any path they sit on Critical,
# regardless of how many hops separate them from the Tier-0 target.
# Domain Computers added per ASD/CISA/NSA/CCCS/NCSC-NZ/NCSC-UK's "Detecting
# and mitigating Active Directory compromises" (Sept 2026), which
# specifically calls out this group in TWO separate techniques
# (MachineAccountQuota compromise and Silver Ticket): every computer
# object in the domain - including one a low-privileged user creates via
# the default MachineAccountQuota=10 - is a member of Domain Computers, so
# a dangerous ACE or Tier-0-group membership held by Domain Computers is
# functionally as broad a path as one held by Domain Users, and was
# previously NOT treated as broad here despite the module's other checks
# (Test-ADMachineAccountQuota) already flagging the underlying quota issue.
$Script:ControlPathBroadPrincipalPattern = '(^|\\)(Everyone|Authenticated Users|Domain Users|Domain Computers|ANONYMOUS LOGON)$'

function Add-ADControlPathEdge {
    <#
    .SYNOPSIS
        Internal helper: appends one directed edge to a control-path graph.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]$EdgeList,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$From,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$To,

        [Parameter(Mandatory)]
        [ValidateSet('MemberOf', 'ACE', 'Owner')]
        [string]$EdgeType,

        [Parameter()]
        [string]$Detail = ''
    )

    if ([string]::IsNullOrWhiteSpace($From) -or [string]::IsNullOrWhiteSpace($To)) { return }
    if ($From -ieq $To) { return }

    [void]$EdgeList.Add([PSCustomObject]@{
        From     = $From
        To       = $To
        EdgeType = $EdgeType
        Detail   = $Detail
    })
}

function Get-ADControlPathGraph {
    <#
    .SYNOPSIS
        Builds a directed control-edge graph (dangerous ACEs + group
        membership + ownership) and the Tier-0 target set to reach.
    .DESCRIPTION
        One read-only pass that produces:
          - MemberOf edges  : member DN -> group DN, from group membership.
          - ACE edges       : ACE principal -> target DN, for dangerous
                               standard rights (GenericAll/WriteDacl/
                               WriteOwner/GenericWrite/AllExtendedRights),
                               dangerous extended rights (incl. the
                               DS-Replication set), and dangerous property
                               writes (Member, msDS-KeyCredentialLink, etc.),
                               reusing the tables in src/Common.ps1.
          - Owner edges     : object owner -> target DN, when the owner is
                               not already a Tier-0/system/built-in
                               administrative principal.

        ACL/ownership edges are collected only for the Tier-0 target set and
        any group that is itself a (recursive) member of another protected
        group (see the module-level scope note above); MemberOf edges are
        collected for every group in the domain since that walk is cheap and
        is needed to discover which groups feed into Tier-0 in the first
        place.
    .OUTPUTS
        [hashtable] with keys: Edges (PSCustomObject[] From/To/EdgeType/
        Detail), Tier0Targets (PSCustomObject[] DistinguishedName/Label),
        Tier0Lookup (case-insensitive DN/SID/SamAccountName lookup table),
        GeneratedDate.
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Get-ADControlPathGraph: building control-edge graph..."
    $__adServer = Get-ADSecurityAuditTargetServerValue

    $edges = [System.Collections.ArrayList]::new()
    $tier0Targets = [System.Collections.ArrayList]::new()
    $tier0Lookup = @{}

    # --- Resolve domain ---
    $domain = $null
    try {
        $domain = Get-ADDomain -Server $__adServer -ErrorAction Stop
    }
    catch {
        Write-Verbose "Get-ADControlPathGraph: failed to resolve domain: $_"
    }

    # --- Tier-0 principals (reuses the shared step-02 helper) ---
    $tier0Principals = @(Get-ADTier0Principal)
    foreach ($p in $tier0Principals) {
        foreach ($key in @($p.DistinguishedName, $p.SID, $p.SamAccountName)) {
            if ($key) { $tier0Lookup["$key".ToLowerInvariant()] = $true }
        }
        if ($p.DistinguishedName) {
            $label = if ($p.SamAccountName) { "Tier-0 principal ($($p.SamAccountName))" } else { 'Tier-0 principal' }
            [void]$tier0Targets.Add([PSCustomObject]@{ DistinguishedName = $p.DistinguishedName; Label = $label })
        }
    }

    # --- Domain Controllers ---
    $dcList = @()
    try {
        # Get-ADSecurityAuditDomainController, not a bare
        # Get-ADDomainController -Filter * - the latter is forest-wide
        # regardless of -Server; see Common.ps1 for why.
        $dcList = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADSecurityAuditDomainController (control-path graph)' -Query {
            Get-ADSecurityAuditDomainController -Server $__adServer
        })
    }
    catch {
        Write-Verbose "Get-ADControlPathGraph: failed to enumerate domain controllers: $_"
    }
    foreach ($dc in @($dcList)) {
        if (-not $dc) { continue }
        $dcDN = if ($dc.ComputerObjectDN) { $dc.ComputerObjectDN } elseif ($dc.DistinguishedName) { $dc.DistinguishedName } else { $null }
        if ($dcDN) {
            $tier0Lookup["$dcDN".ToLowerInvariant()] = $true
            [void]$tier0Targets.Add([PSCustomObject]@{ DistinguishedName = $dcDN; Label = "Domain Controller ($($dc.Name))" })
        }
    }

    # --- AdminSDHolder + domain head ---
    $domainHeadDN = if ($domain) { $domain.DistinguishedName } else { $null }
    $adminSDHolderDN = if ($domainHeadDN) { "CN=AdminSDHolder,CN=System,$domainHeadDN" } else { $null }

    if ($adminSDHolderDN) {
        $tier0Lookup["$adminSDHolderDN".ToLowerInvariant()] = $true
        [void]$tier0Targets.Add([PSCustomObject]@{ DistinguishedName = $adminSDHolderDN; Label = 'AdminSDHolder' })
    }
    if ($domainHeadDN) {
        $tier0Lookup["$domainHeadDN".ToLowerInvariant()] = $true
        [void]$tier0Targets.Add([PSCustomObject]@{ DistinguishedName = $domainHeadDN; Label = 'Domain Head' })
    }

    # --- Protected groups themselves (Domain Admins, Enterprise Admins, ...)
    #     Get-ADTier0Principal returns their MEMBERS, not the group objects;
    #     controlling one of these groups directly (via ACE or nested
    #     membership) is just as much "reaching Tier-0" as controlling a
    #     member of it, so they are added as targets in their own right. ---
    foreach ($groupName in $Script:ProtectedGroups) {
        $groupDN = $null
        try {
            $g = Invoke-ADQueryWithRetry -OperationName "Get-ADGroup '$groupName' (control-path graph)" -Query {
                Get-ADGroup -Filter "Name -eq '$groupName'" -Server $__adServer -ErrorAction Stop
            }
            if ($g) { $groupDN = $g.DistinguishedName }
        }
        catch {
            Write-Verbose "Get-ADControlPathGraph: failed to resolve protected group '$groupName': $_"
        }
        if ($groupDN) {
            $tier0Lookup["$groupDN".ToLowerInvariant()] = $true
            [void]$tier0Targets.Add([PSCustomObject]@{ DistinguishedName = $groupDN; Label = "Protected group ($groupName)" })
        }
    }

    # --- Group membership edges (member DN -> group DN) ---
    $groups = @()
    try {
        $rawGroups = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADGroup (control-path graph)' -Query {
            Get-ADGroup -Filter '*' -ResultPageSize 500 -Properties Members -Server $__adServer -ErrorAction Stop
        })
        $groups = @($rawGroups | ForEach-Object {
            [PSCustomObject]@{
                Name              = $_.Name
                DistinguishedName = $_.DistinguishedName
                Members           = @($_.Members)
            }
        })
    }
    catch {
        Write-Verbose "Get-ADControlPathGraph: failed to enumerate groups: $_"
    }

    $groupIndex = @{}
    foreach ($group in $groups) {
        if (-not $group.DistinguishedName) { continue }
        $groupIndex[$group.DistinguishedName.ToLowerInvariant()] = $group
        foreach ($memberDN in @($group.Members)) {
            Add-ADControlPathEdge -EdgeList $edges -From $memberDN -To $group.DistinguishedName -EdgeType 'MemberOf' -Detail $group.Name
        }
    }

    # --- Backward walk: find every group that is itself a (recursive)
    #     member of another protected/Tier-0-target group, so ACL/ownership
    #     edges get collected for the whole chain, not just the leaf. ---
    $controlRelevant = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($t in $tier0Targets) { [void]$controlRelevant.Add($t.DistinguishedName) }

    $memberOfByTarget = @{}
    foreach ($edge in $edges) {
        if ($edge.EdgeType -ne 'MemberOf') { continue }
        $key = $edge.To.ToLowerInvariant()
        if (-not $memberOfByTarget.ContainsKey($key)) {
            $memberOfByTarget[$key] = [System.Collections.ArrayList]::new()
        }
        [void]$memberOfByTarget[$key].Add($edge.From)
    }

    $frontier = [System.Collections.ArrayList]::new()
    foreach ($t in $tier0Targets) { [void]$frontier.Add($t.DistinguishedName) }
    $visitedBackward = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    while ($frontier.Count -gt 0) {
        $current = $frontier[0]
        $frontier.RemoveAt(0)
        if (-not $visitedBackward.Add($current)) { continue }

        $key = $current.ToLowerInvariant()
        if (-not $memberOfByTarget.ContainsKey($key)) { continue }

        foreach ($memberDN in $memberOfByTarget[$key]) {
            [void]$controlRelevant.Add($memberDN)
            if ($groupIndex.ContainsKey($memberDN.ToLowerInvariant())) {
                [void]$frontier.Add($memberDN)
            }
        }
    }

    # --- ACL + ownership edges over the control-relevant object set ---
    foreach ($targetDN in $controlRelevant) {
        $aclInfo = $null

        try {
            $obj = Invoke-ADQueryWithRetry -OperationName "Get-ADObject nTSecurityDescriptor ($targetDN)" -Query {
                Get-ADObject -Identity $targetDN -Properties nTSecurityDescriptor -Server $__adServer -ErrorAction Stop
            }
            if ($obj -and $obj.nTSecurityDescriptor) {
                $aclInfo = @{
                    Owner  = "$($obj.nTSecurityDescriptor.Owner)"
                    Access = @(ConvertTo-ADFlatAce -Access @($obj.nTSecurityDescriptor.Access))
                }
            }
        }
        catch {
            Write-Verbose "Get-ADControlPathGraph: could not read ACL for '$targetDN': $_"
        }

        if (-not $aclInfo) { continue }

        # Ownership edge - an owner can always rewrite the DACL, regardless
        # of what the current ACL says, so this is a control edge in its
        # own right even with zero dangerous ACEs present.
        if ($aclInfo.Owner -and
            -not $tier0Lookup.ContainsKey("$($aclInfo.Owner)".ToLowerInvariant()) -and
            $aclInfo.Owner -notmatch '\\SYSTEM$' -and
            $aclInfo.Owner -notmatch '\\Administrators$' -and
            $aclInfo.Owner -notmatch '\\Domain Admins$' -and
            $aclInfo.Owner -notmatch '\\Enterprise Admins$') {
            Add-ADControlPathEdge -EdgeList $edges -From $aclInfo.Owner -To $targetDN -EdgeType 'Owner' -Detail 'Owner'
        }

        foreach ($ace in @($aclInfo.Access)) {
            if ($ace.IsInherited) { continue }
            $principal = $ace.IdentityReference
            if (-not $principal) { continue }
            if ($principal -match '\\SYSTEM$' -or
                $principal -match '\\Domain Admins$' -or
                $principal -match '\\Enterprise Admins$' -or
                $principal -match '\\Administrators$' -or
                $principal -eq 'CREATOR OWNER') {
                continue
            }

            $isDangerous = $false

            foreach ($right in $Script:DangerousStandardRights) {
                if ("$($ace.ActiveDirectoryRights)" -match $right) { $isDangerous = $true; break }
            }

            if (-not $isDangerous -and "$($ace.ActiveDirectoryRights)" -match 'ExtendedRight') {
                foreach ($extGuid in $Script:DangerousExtendedRights.Values) {
                    if ("$($ace.ObjectType)".ToLowerInvariant() -eq $extGuid.ToLowerInvariant()) { $isDangerous = $true; break }
                }
            }

            if (-not $isDangerous -and "$($ace.ActiveDirectoryRights)" -match 'WriteProperty') {
                foreach ($propGuid in $Script:DangerousPropertyGuids.Values) {
                    if ("$($ace.ObjectType)".ToLowerInvariant() -eq $propGuid.ToLowerInvariant()) { $isDangerous = $true; break }
                }
            }

            if ($isDangerous) {
                Add-ADControlPathEdge -EdgeList $edges -From $principal -To $targetDN -EdgeType 'ACE' -Detail "$($ace.ActiveDirectoryRights)"
            }
        }
    }

    Write-Verbose "Get-ADControlPathGraph: built $($edges.Count) edge(s) across $($controlRelevant.Count) control-relevant object(s) and $($tier0Targets.Count) Tier-0 target(s)."

    return @{
        Edges         = @($edges)
        Tier0Targets  = @($tier0Targets)
        Tier0Lookup   = $tier0Lookup
        GeneratedDate = Get-Date
    }
}

function Test-ADControlPaths {
    <#
    .SYNOPSIS
        Computes reachability from non-Tier-0 principals to the Tier-0 set
        over the control-edge graph, emitting indirect-privilege findings.
    .DESCRIPTION
        Calls Get-ADControlPathGraph, then runs a breadth-first search from
        every principal that appears as the source of an ACE or ownership
        edge (group-membership-only sources are not evaluated as starting
        points - being a plain member of a non-Tier-0 group is not itself a
        privilege escalation) to the nearest reachable Tier-0 target. Each
        reachable path becomes one finding with the full principal-> ... ->
        target hop chain recorded in Details.HopChain. A broad principal
        (Everyone/Authenticated Users/Domain Users/ANONYMOUS LOGON) on any
        path is always Critical, regardless of hop count.

        Also flags Tier-0 objects owned by a non-Tier-0 principal
        (implicit control via DACL rewrite) as a standalone finding.

        Detection only - read-only graph traversal over data already
        collected by Get-ADControlPathGraph. No exploitation, coercion,
        relay, ticket forging, or PoC traffic is ever sent to any host.
    .PARAMETER BloodHoundExportPath
        Optional path. When supplied, the underlying graph is also exported
        as a BloodHound-compatible generic-edge JSON file via
        Export-ADControlPathGraphBloodHound, as a separate artifact from the
        findings returned by this function.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$BloodHoundExportPath
    )

    Write-Verbose "Starting control-path (indirect privilege) audit..."
    $findings = @()

    try {
        $graph = Get-ADControlPathGraph

        if ($BloodHoundExportPath) {
            try {
                Export-ADControlPathGraphBloodHound -Graph $graph -Path $BloodHoundExportPath
            }
            catch {
                Write-Warning "Test-ADControlPaths: BloodHound export failed: $_"
            }
        }

        if (-not $graph.Edges -or $graph.Edges.Count -eq 0 -or -not $graph.Tier0Targets -or $graph.Tier0Targets.Count -eq 0) {
            Write-Verbose "Test-ADControlPaths: empty graph or no Tier-0 targets resolved; nothing to analyse."
            return $findings
        }

        # Forward adjacency: From (lowercased) -> list of outgoing edges.
        $adjacency = @{}
        foreach ($edge in $graph.Edges) {
            $key = $edge.From.ToLowerInvariant()
            if (-not $adjacency.ContainsKey($key)) { $adjacency[$key] = [System.Collections.ArrayList]::new() }
            [void]$adjacency[$key].Add($edge)
        }

        # Only ACE/Owner edges are worth starting a path from - a principal
        # that only ever appears as a plain group member (MemberOf) has no
        # control relationship to chain from; if it is itself Tier-0 that
        # is already the direct membership case, not an indirect path.
        $sources = @($graph.Edges | Where-Object { $_.EdgeType -ne 'MemberOf' } | ForEach-Object { $_.From } | Select-Object -Unique)

        foreach ($source in $sources) {
            $sourceKey = $source.ToLowerInvariant()
            if ($graph.Tier0Lookup.ContainsKey($sourceKey)) { continue }

            $queue = [System.Collections.ArrayList]::new()
            [void]$queue.Add([PSCustomObject]@{
                Node = $source
                Path = @([PSCustomObject]@{ Node = $source; EdgeType = $null; Detail = $null })
            })
            $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            [void]$visited.Add($source)
            $foundPath = $null

            while ($queue.Count -gt 0 -and -not $foundPath) {
                $current = $queue[0]
                $queue.RemoveAt(0)
                $currentKey = $current.Node.ToLowerInvariant()

                if ($current.Path.Count -gt 1 -and $graph.Tier0Lookup.ContainsKey($currentKey)) {
                    $foundPath = $current.Path
                    break
                }

                if (-not $adjacency.ContainsKey($currentKey)) { continue }

                foreach ($edge in $adjacency[$currentKey]) {
                    if ($visited.Contains($edge.To)) { continue }
                    [void]$visited.Add($edge.To)
                    $newPath = $current.Path + @([PSCustomObject]@{ Node = $edge.To; EdgeType = $edge.EdgeType; Detail = $edge.Detail })
                    [void]$queue.Add([PSCustomObject]@{ Node = $edge.To; Path = $newPath })
                }
            }

            if (-not $foundPath) { continue }

            $hopChain = ($foundPath | ForEach-Object {
                if ($_.EdgeType) { "-[$($_.EdgeType):$($_.Detail)]-> $($_.Node)" } else { "$($_.Node)" }
            }) -join ' '

            $isBroad = $source -match $Script:ControlPathBroadPrincipalPattern
            $finalNode = $foundPath[$foundPath.Count - 1].Node
            $targetLabel = ($graph.Tier0Targets | Where-Object { $_.DistinguishedName -ieq $finalNode } | Select-Object -First 1).Label
            if (-not $targetLabel) { $targetLabel = $finalNode }

            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Attack Paths'

            if ($isBroad) {
                $finding.Issue = 'Everyone/Authenticated Users on a Control Path to Tier-0'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
            }
            else {
                $finding.Issue = 'Indirect Control Path to Tier-0 Object'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
            }

            $hopCount = $foundPath.Count - 1
            $finding.AffectedObject = "$source -> $targetLabel"
            $finding.Description = "Principal '$source' can reach the Tier-0 object '$targetLabel' through a chain of $hopCount control hop(s) (group membership, dangerous ACEs, and/or ownership), even though it holds no direct privileged group membership of its own."
            $finding.Impact = "Chained, non-obvious control relationships like this are the paths real intrusions use to reach Domain Admins/Domain Controllers; a flat, per-object permissions review would not surface this because no single hop looks critical in isolation."
            $finding.Remediation = "Break the chain by removing the unnecessary/unexpected control relationship closest to '$source' (see Details.HopChain for the full path), then re-run this audit and confirm the path no longer resolves. Prefer removing the group nesting or ACE outright over adding compensating controls."
            $finding.EstimatedEffort = 'Medium - breaking one specific hop (a group nesting or ACE) in the chain; effort scales with how many hops and objects are involved for a given path.'
            $finding.KnownRisks = 'Removing the identified hop could break a legitimate, if poorly documented, delegation model if the chain was set up intentionally rather than accidentally, so confirm with the object owner before removing.'
            $finding.BackupRollback = 'Moderate - export the specific ACE or group membership being removed so it can be restored, then re-run this audit to confirm the path no longer resolves.'
            $finding.Details = @{
                Source               = $source
                Target               = $targetLabel
                TargetDN             = $finalNode
                HopCount             = $hopCount
                HopChain             = $hopChain
                BroadPrincipalOnPath = [bool]$isBroad
            }
            $findings += $finding
        }

        # --- Owner of Tier-0 Object is Non-Privileged ---
        foreach ($edge in @($graph.Edges | Where-Object { $_.EdgeType -eq 'Owner' })) {
            if (-not $graph.Tier0Lookup.ContainsKey($edge.To.ToLowerInvariant())) { continue }
            if ($graph.Tier0Lookup.ContainsKey($edge.From.ToLowerInvariant())) { continue }

            $targetLabel = ($graph.Tier0Targets | Where-Object { $_.DistinguishedName -ieq $edge.To } | Select-Object -First 1).Label
            if (-not $targetLabel) { $targetLabel = $edge.To }

            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Attack Paths'
            $finding.Issue = 'Owner of Tier-0 Object is Non-Privileged'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = "$($edge.From) owns $targetLabel"
            $finding.Description = "The Tier-0 object '$targetLabel' is owned by '$($edge.From)', which is not itself a Tier-0 principal. Object ownership grants implicit WriteDacl-equivalent control - an owner can always rewrite the DACL - regardless of the current ACL contents."
            $finding.Impact = "An attacker who compromises the owning principal can grant themselves any right on this object, including full control, without needing an existing dangerous ACE."
            $finding.Remediation = "Change ownership of '$targetLabel' to a Tier-0 principal (e.g. Domain Admins) and investigate how the current owner was set."
            $finding.EstimatedEffort = 'Low - a single ownership change on one object.'
            $finding.KnownRisks = 'Low technical risk; object ownership implicitly carries WriteDacl-equivalent rights, so confirm no automation currently depends on the existing owner''s implicit rights before changing it.'
            $finding.BackupRollback = 'Easy - reassign ownership back to the prior principal if needed; effective immediately.'
            $finding.Details = @{
                Owner    = $edge.From
                Target   = $targetLabel
                TargetDN = $edge.To
            }
            $findings += $finding
        }

        Write-Verbose "Control-path audit complete. Found $($findings.Count) issue(s)."
        return $findings
    }
    catch {
        Write-Error "Error during control-path audit: $_"
        throw
    }
}

function Export-ADControlPathGraphBloodHound {
    <#
    .SYNOPSIS
        Exports a control-path graph as a BloodHound-compatible generic-edge
        JSON file.
    .DESCRIPTION
        Writes a minimal subset of BloodHound's "Generic Edges" custom
        ingest schema (start/end name-matched nodes + an edge kind) so the
        graph produced by Get-ADControlPathGraph can be cross-checked
        against a BloodHound collection of the same lab/environment. This is
        a separate artifact from the module's JSON/HTML/CSV findings export
        and does not change that output contract.
    .PARAMETER Graph
        The graph hashtable returned by Get-ADControlPathGraph.
    .PARAMETER Path
        Output file path for the JSON edge export.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Graph,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $edgeKindMap = @{
        MemberOf = 'MemberOf'
        ACE      = 'GenericAll'
        Owner    = 'Owns'
    }

    $bhEdges = @(foreach ($edge in @($Graph.Edges)) {
        $kind = if ($edgeKindMap.ContainsKey($edge.EdgeType)) { $edgeKindMap[$edge.EdgeType] } else { $edge.EdgeType }
        [PSCustomObject]@{
            start      = @{ value = $edge.From; match_by = 'name' }
            end        = @{ value = $edge.To; match_by = 'name' }
            kind       = $kind
            properties = @{ detail = $edge.Detail; sourceModule = 'ADSecurityAudit-ControlPaths' }
        }
    })

    $payload = @{
        graph = @{
            nodes = @()
            edges = $bhEdges
        }
    }

    $payload | ConvertTo-Json -Depth 8 | Out-File -FilePath $Path -Encoding UTF8
    Write-Verbose "Export-ADControlPathGraphBloodHound: wrote $($bhEdges.Count) edge(s) to '$Path'."
}

#endregion
