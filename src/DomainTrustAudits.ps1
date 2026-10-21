#region Domain Trust Audits
#
# PingCastle-comparable check(s): S-DomainTrust-Bidirectional (informal -
# PingCastle does not expose a single stable rule id for the equivalent
# "review bidirectional trusts" behavior; comparable in effect, not a
# literal rule-id match).
#
# Fixed 2026-09-20: 'Bidirectional Domain Trust' previously had no
# TrustType scoping and fired on every bidirectional trust, including
# ordinary intra-forest ParentChild/TreeRoot/CrossLink/Shortcut trusts,
# which are bidirectional and transitive by design in any multi-domain
# forest and are not a security concern the same way a bidirectional
# External or Forest (inter-forest) trust is. Found while investigating a
# PingCastle-comparable bug-fix candidate (3.5.x: "New CrossRef-based
# filtering logic correctly identifies within-forest trusts and no longer
# flags them as insecure") - the exact mechanism differs, but the
# practical effect (over-flagging benign within-forest trust structure)
# is the same class of issue. The other two checks in this file already
# scoped correctly by TrustType; only this one didn't.

function Test-ADDomainTrusts {
    <#
    .SYNOPSIS
        Audits domain trust configuration: direction, SID filtering,
        selective authentication, and trust password rotation.
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Starting domain trust security audit..."
    $findings = @()

    try {
        $__adServer = Get-ADSecurityAuditTargetServerValue
        $domain = Get-ADDomain -Server $__adServer
        $trusts = Get-ADTrust -Filter * -Properties * -Server $__adServer
        
        if (-not $trusts) {
            Write-Verbose "No domain trusts found."
            return $findings
        }
        
        Write-Verbose "Analyzing $($trusts.Count) domain trust(s)..."
        
        foreach ($trust in $trusts) {
            # Check for bidirectional trusts - excluding intra-forest trust
            # types (ParentChild, TreeRoot, CrossLink, Shortcut), which are
            # bidirectional and transitive by design in every multi-domain
            # forest and are not a security concern the way a bidirectional
            # External or Forest (inter-forest) trust is. Without this
            # exclusion, this check fired on every normal parent-child
            # domain relationship in a multi-domain forest - a false-
            # positive class analogous to one PingCastle fixed in its own
            # trust-classification logic (3.5.x: "New CrossRef-based
            # filtering logic correctly identifies within-forest trusts and
            # no longer flags them as insecure"). The other two checks in
            # this function (SID filtering, selective authentication)
            # already correctly scope by TrustType; this one didn't.
            if ($trust.Direction -eq 'Bidirectional' -and $trust.TrustType -notin @('ParentChild', 'TreeRoot', 'CrossLink', 'Shortcut')) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Domain Trusts'
                $finding.Issue = 'Bidirectional Domain Trust'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $trust.Target
                $finding.Description = "Bidirectional trust exists with domain '$($trust.Target)', allowing authentication in both directions."
                $finding.Impact = "Increases attack surface as compromise of either domain could affect the other. Consider if bidirectional trust is necessary."
                $finding.Remediation = "Review if bidirectional trust is required. If not, convert to one-way trust or implement selective authentication."
                $finding.EstimatedEffort = 'High - narrowing a bidirectional trust to one-way is a structural, cross-forest/cross-domain decision requiring sign-off from the other domain''s owners and a dependency discovery of which direction of access is actually used.'
                $finding.KnownRisks = 'Narrowing to one-way removes the ability for principals on the now-untrusted side to authenticate to resources on the other side, so a dependency check with the other domain''s owners is required before narrowing, not just a local change.'
                $finding.BackupRollback = 'Moderate - trust direction can be reconfigured back to bidirectional via Active Directory Domains and Trusts (or netdom) at any time, effective quickly with no data loss, but requires the same cross-domain admin coordination to make the change again.'
                $finding.Details = @{
                    Target = $trust.Target
                    Direction = $trust.Direction
                    TrustType = $trust.TrustType
                    Created = $trust.Created
                }
                $findings += $finding
            }
            
            # Check if SID filtering is disabled (critical security issue)
            if ($trust.SIDFilteringQuarantined -eq $false -and $trust.TrustType -eq 'External') {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Domain Trusts'
                $finding.Issue = 'SID Filtering Disabled on External Trust'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $trust.Target
                $finding.Description = "SID filtering is disabled on external trust with '$($trust.Target)', allowing SID history injection attacks."
                $finding.Impact = "Attackers in the trusted domain could forge credentials with privileged SIDs from your domain, leading to privilege escalation."
                $finding.Remediation = "Enable SID filtering: netdom trust $($domain.DNSRoot) /domain:$($trust.Target) /quarantine:yes"
                $finding.EstimatedEffort = 'Low - a single trust property toggle.'
                $finding.KnownRisks = 'SID filtering blocks SID-history-based authorization across the trust, so if the other domain legitimately relies on SID history for migrated accounts to retain access, enabling filtering can break that access; confirm no active migration depends on it.'
                $finding.BackupRollback = 'Easy - toggle SID filtering back off; effective immediately, no data loss.'
                $finding.Details = @{
                    Target = $trust.Target
                    TrustType = $trust.TrustType
                    SIDFilteringQuarantined = $trust.SIDFilteringQuarantined
                }
                $findings += $finding
            }
            
            # Check for trusts without selective authentication
            if ($trust.SelectiveAuthentication -eq $false -and $trust.TrustType -eq 'Forest') {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Domain Trusts'
                $finding.Issue = 'Forest Trust Without Selective Authentication'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $trust.Target
                $finding.Description = "Forest trust with '$($trust.Target)' does not use selective authentication, granting broad access."
                $finding.Impact = "All users in the trusted forest can authenticate to resources in this domain without explicit permission."
                $finding.Remediation = "Enable selective authentication to require explicit permission for cross-forest access."
                $finding.EstimatedEffort = 'Medium - enabling selective authentication requires then explicitly granting "Allowed to Authenticate" rights to every resource/group that legitimately needs cross-forest access, so plan a discovery pass of existing cross-forest access first.'
                $finding.KnownRisks = 'Enabling selective authentication immediately blocks all cross-forest authentication except where an explicit Allowed-to-Authenticate ACE has been granted, so existing legitimate cross-forest access will break until those ACEs are added.'
                $finding.BackupRollback = 'Easy - toggle selective authentication back off via Domains and Trusts; effective immediately, no data loss.'
                $finding.Details = @{
                    Target = $trust.Target
                    TrustType = $trust.TrustType
                    SelectiveAuthentication = $trust.SelectiveAuthentication
                }
                $findings += $finding
            }
            
            # Check for the PIM_TRUST attribute (files/19-trust-pim-attribute.md).
            # Sibling check to KerberosHardeningAudits.ps1's Cross-Trust TGT
            # Delegation check - same trustAttributes property (already
            # fetched above via -Properties *), a different bit
            # (TRUST_ATTRIBUTE_PIM_TRUST = 0x00000400). No new AD query.
            if ($null -ne $trust.trustAttributes) {
                $pimTrustAttrs = [int]$trust.trustAttributes
                if (($pimTrustAttrs -band 0x00000400) -ne 0) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Domain Trusts'
                    $finding.Issue = 'Trust Configured for Privileged Identity Management (PIM_TRUST)'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $trust.Target
                    $finding.Description = "Trust with '$($trust.Target)' has the TRUST_ATTRIBUTE_PIM_TRUST bit set in trustAttributes."
                    $finding.Impact = "PIM_TRUST reduces the SID-filtering protection normally applied across the trust boundary, widening the set of SIDs/claims that can cross the trust and be honored on this side."
                    $finding.Remediation = "Confirm this trust is a deliberate, currently-used Privileged Identity Management (PIM) trust relationship. If not, clear the TRUST_ATTRIBUTE_PIM_TRUST attribute using the appropriate trust-management tooling so normal SID filtering is restored."
                    $finding.EstimatedEffort = 'Low - a single trust-attribute bit toggle, but confirm with the trust''s owning teams before clearing it, since PIM trusts are typically deliberate cross-forest identity-management configurations.'
                    $finding.KnownRisks = 'Clearing PIM_TRUST restores standard SID filtering across the trust, which will break any legitimate Privileged Identity Management workflow that currently depends on the relaxed filtering - confirm the trust''s purpose with its owning teams before changing it.'
                    $finding.BackupRollback = 'Easy - the attribute can be re-set if a legitimate dependency surfaces; effective immediately, no data loss.'
                    $finding.Details = @{
                        Target          = $trust.Target
                        TrustType       = $trust.TrustType
                        TrustAttributes = $pimTrustAttrs
                    }
                    $findings += $finding
                }
            }

            # Check trust password age
            if ($trust.Modified) {
                $trustAge = (Get-Date) - $trust.Modified
                if ($trustAge.Days -gt 30) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Domain Trusts'
                    $finding.Issue = 'Trust Password Not Recently Rotated'
                    $finding.Severity = 'Low'
                    $finding.SeverityLevel = 1
                    $finding.AffectedObject = $trust.Target
                    $finding.Description = "Trust with '$($trust.Target)' has not been modified in $($trustAge.Days) days. Trust passwords should rotate automatically every 30 days."
                    $finding.Impact = "May indicate trust relationship issues or lack of maintenance."
                    $finding.Remediation = "Verify trust health: netdom trust $($domain.DNSRoot) /domain:$($trust.Target) /verify"
                    $finding.EstimatedEffort = 'Low - a single reset command per trust.'
                    $finding.KnownRisks = 'Resetting the trust password briefly interrupts the secure channel until both sides sync, so schedule it during a low-authentication-volume window; a mismatched reset (only one side updated) can break the trust until corrected, a documented Netlogon secure-channel behavior.'
                    $finding.BackupRollback = 'Easy - the secure channel can be re-reset on both sides if an issue arises; no data loss beyond a brief authentication interruption.'
                    $finding.Details = @{
                        Target = $trust.Target
                        LastModified = $trust.Modified
                        DaysSinceModified = $trustAge.Days
                    }
                    $findings += $finding
                }
            }
        }
        
        Write-Verbose "Domain trust audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during domain trust audit: $_"
        throw
    }
}

#endregion

