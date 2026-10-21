#region GPO-Deployed Secrets & Insecure Settings Audit (GPP cpassword, script credentials)
#
# Scans SYSVOL/GPO content for secrets and settings that GPOs push out to
# every affected computer/user: leftover Group Policy Preferences (GPP)
# `cpassword` values (MS14-025), plaintext-looking credentials referenced in
# logon/startup scripts, and insecure settings deployed via GPO (firewall
# disabled, weak folder options, insecure RDP), and GPO-deployed User Rights
# Assignments that grant a sensitive logon right to an overly broad
# principal (Everyone/ANONYMOUS LOGON/Authenticated Users).
# PingCastle-comparable check(s): P-DelegationGPOData, P-DelegationFileDeployed,
# P-DelegationLoginScript, S-FirewallScript, S-FolderOptions,
# S-TerminalServicesGPO, A-AnonymousAuthorizedGPO.
#
# DETECTION ONLY: this module reads SYSVOL policy files (GPP XML, referenced
# scripts) and GPO-linked registry policy values. A `cpassword` value found
# in GPP XML is reported by PRESENCE and FILE PATH ONLY - it is never
# decrypted, decoded, or printed. A credential pattern found in a script is
# reported by LOCATION (file/line) only - the matched line's sensitive
# content is never echoed verbatim into a finding. Nothing here decrypts,
# reuses, exfiltrates, or acts on any discovered secret, and no exploitation,
# coercion, relay, or PoC traffic is ever sent.

# GPP preference files known to carry a `cpassword` attribute when a
# password is set via Group Policy Preferences (MS14-025).
$Script:GpoSecretsGppFiles = @(
    'Groups.xml',
    'Services.xml',
    'ScheduledTasks.xml',
    'Drives.xml',
    'DataSources.xml',
    'Printers.xml'
)

# Script extensions considered when scanning SYSVOL logon/startup/shutdown
# script folders for embedded credentials.
$Script:GpoSecretsScriptExtensions = @('*.bat', '*.cmd', '*.ps1', '*.vbs', '*.kix')

# Well-known SIDs treated as "broad principals" when found granted a
# sensitive User Rights Assignment via GPO (GptTmpl.inf lists principals as
# SIDs, not resolved names). Scoped locally to this file rather than added
# to a module-wide table, since no shared SID->name map exists elsewhere in
# the module for this purpose.
$Script:GpoSecretsBroadPrincipalSids = @{
    'S-1-1-0'  = 'Everyone'
    'S-1-5-7'  = 'ANONYMOUS LOGON'
    'S-1-5-11' = 'Authenticated Users'
}

# Sensitive logon rights checked for grants to a broad principal above.
# Maps the GptTmpl.inf [Privilege Rights] key to its friendly display name.
$Script:GpoSecretsSensitiveLogonRights = @{
    'SeNetworkLogonRight'          = 'Access this computer from the network'
    'SeRemoteInteractiveLogonRight' = 'Allow log on through Remote Desktop Services'
}

# Well-known LOCAL built-in group SIDs (constant across every computer,
# unlike domain-relative RIDs) that GptTmpl.inf's [Group Membership]
# ("Restricted Groups") section can push membership into. Only the
# security-sensitive ones are checked - granting/replacing membership in
# any of these via GPO is a direct, GPO-wide privilege-escalation
# mechanism (every computer the GPO applies to gets the same membership
# pushed to it), and it is a common, straightforward BloodHound-style
# "AdminTo via GPO" edge that is otherwise easy to miss since it lives in
# a security template, not a conventional ACE.
$Script:GpoSecretsRestrictedGroupSids = @{
    'S-1-5-32-544' = 'Administrators'
    'S-1-5-32-555' = 'Remote Desktop Users'
    'S-1-5-32-551' = 'Backup Operators'
    'S-1-5-32-547' = 'Power Users'
}

# Lightweight, conservative patterns for spotting a credential embedded in a
# script. These intentionally match on structure (a credential-flavoured
# keyword next to an assignment/parameter), not on any specific secret
# value, and are used only to flag a LOCATION for follow-up - the matched
# line's content is never included in a finding's Details.
$Script:GpoSecretsScriptCredentialPatterns = @(
    '(?i)\bnet\s+use\b.*\s/user:',
    '(?i)\bpassword\s*[:=]',
    '(?i)-AsPlainText\b',
    '(?i)ConvertTo-SecureString\b',
    '(?i)\bpwd\s*[:=]',
    '(?i)runas\s+/user:.*\s/savecred'
)

function Get-ADGpoSecretsSysvolPolicyRoot {
    <#
    .SYNOPSIS
        Resolves the SYSVOL \Policies path for the current domain.
    .DESCRIPTION
        Read-only path resolution helper, consistent with the SYSVOL path
        already used for permission checks in Test-ADGroupPolicies.

        The server component of the UNC path uses the active
        Set-ADSecurityAuditTargetServer -Server override when one is set,
        rather than always using the domain's DNS name. A bare domain name
        in a UNC path (\\domain.tld\SYSVOL\...) is resolved via DFS
        Namespace referral, which - like DC-locator for AD queries - picks
        a DC based on the CALLING MACHINE's own site/subnet proximity, not
        necessarily the domain actually being audited. This is the same
        "closest DC" ambiguity Get-AD*/Get-GP* cmdlets have via -Server;
        Get-Acl on a UNC path has no -Server parameter at all, so the only
        way to pin it to a specific DC is to put that DC directly in the
        path itself.
    #>
    [CmdletBinding()]
    param()

    $__adServer = Get-ADSecurityAuditTargetServerValue
    $domain = Get-ADDomain -Server $__adServer
    $sysvolServer = Get-ADSecurityAuditActiveServerOverride
    if (-not $sysvolServer) { $sysvolServer = $domain.DNSRoot }
    return "\\$sysvolServer\SYSVOL\$($domain.DNSRoot)\Policies"
}

function Test-ADGpoDeployedSecrets {
    <#
    .SYNOPSIS
        Audits SYSVOL/GPO content for deployed secrets and insecure settings.
    .DESCRIPTION
        Four independent, read-only checks against each GPO's SYSVOL policy
        folder:
          1. GPP cpassword Found in SYSVOL - parses the standard GPP XML
             files (Groups.xml, Services.xml, ScheduledTasks.xml, Drives.xml,
             DataSources.xml, Printers.xml) for a `cpassword` attribute.
             Flagged by PRESENCE and FILE PATH ONLY; the value is never
             decrypted or included in the finding.
          2. Credentials Referenced in Logon/Startup Script - pattern-scans
             scripts under each GPO's \Machine\Scripts and \User\Scripts
             folders (and any script referenced by a linked logon/startup
             script GPO setting) for common credential-embedding patterns
             (net use /user:, ConvertTo-SecureString, runas /savecred,
             etc.). Reports the file and line number only, never the
             matched line's content.
          3. Insecure Setting Deployed via GPO - reads each GPO's
             GptTmpl.inf / registry.pol for a Windows Firewall profile
             explicitly disabled, weak Folder Options settings (hidden
             files/extensions forced visible off, i.e. hiding), and
             insecure Terminal Services/RDP settings (Network Level
             Authentication disabled, unencrypted RDP security layer
             allowed).
          4. GPO Grants Sensitive Logon Right to Broad Principal
             (PingCastle A-AnonymousAuthorizedGPO-comparable) - parses the
             same GptTmpl.inf's [Privilege Rights] section for
             SeNetworkLogonRight ("Access this computer from the network")
             or SeRemoteInteractiveLogonRight ("Allow log on through Remote
             Desktop Services") grants that include the SID for Everyone
             (S-1-1-0), ANONYMOUS LOGON (S-1-5-7), or Authenticated Users
             (S-1-5-11). Matched on SID, since GptTmpl.inf stores principals
             as SIDs, not resolved names. Reported as its own always-Critical
             finding, consistent with this module's convention that a broad
             principal (Everyone/Authenticated Users/Domain Users/ANONYMOUS
             LOGON) on any sensitive path is always Critical.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Starting GPO-Deployed Secrets & Insecure Settings audit..."
    $findings = @()
    $__adServer = Get-ADSecurityAuditTargetServerValue

    # -------------------------------------------------------------------
    # Resolve the list of GPOs (id + display name) to enumerate.
    # -------------------------------------------------------------------
    $gpoList = @()
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $gpoList = @(Invoke-ADQueryWithRetry -OperationName "Enumerate GPOs" -Query {
            Get-GPO -All -Server $__adServer | Select-Object Id, DisplayName
        })
    }
    catch {
        Write-Warning "Test-ADGpoDeployedSecrets: failed to enumerate GPOs: $_"
        return $findings
    }

    if (-not $gpoList -or $gpoList.Count -eq 0) {
        Write-Verbose "Test-ADGpoDeployedSecrets: no GPOs found; nothing to scan."
        return $findings
    }

    $policyRoot = $null
    try {
        $policyRoot = Get-ADGpoSecretsSysvolPolicyRoot
    }
    catch {
        Write-Warning "Test-ADGpoDeployedSecrets: failed to resolve SYSVOL policy root: $_"
        return $findings
    }

    if (-not (Test-Path -LiteralPath $policyRoot)) {
        Write-Warning "Test-ADGpoDeployedSecrets: SYSVOL policy root not accessible at expected location: $policyRoot"
        return $findings
    }

    $gpoCount = $gpoList.Count
    $currentGpo = 0

    foreach ($gpo in $gpoList) {
        $currentGpo++
        Write-Progress -Activity "Scanning SYSVOL GPO content" -Status "Processing $($gpo.DisplayName)" `
            -PercentComplete (($currentGpo / $gpoCount) * 100)

        $gpoFolder = Join-Path -Path $policyRoot -ChildPath "{$($gpo.Id)}"
        if (-not (Test-Path -LiteralPath $gpoFolder)) {
            Write-Verbose "Test-ADGpoDeployedSecrets: no SYSVOL folder for GPO '$($gpo.DisplayName)' ($gpoFolder); skipping."
            continue
        }

        # ---------------------------------------------------------------
        # Check 1 - GPP cpassword presence in the standard preference XMLs.
        # Stream: enumerate matching filenames anywhere under the GPO
        # folder rather than loading the whole tree, so large SYSVOL trees
        # don't need to be held in memory at once.
        # ---------------------------------------------------------------
        try {
            $gppFiles = Get-ChildItem -LiteralPath $gpoFolder -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $Script:GpoSecretsGppFiles -contains $_.Name }

            foreach ($gppFile in $gppFiles) {
                try {
                    # Read as text and check for the attribute name only;
                    # avoids parsing/holding the decrypted value at all.
                    $rawContent = Get-Content -LiteralPath $gppFile.FullName -Raw -ErrorAction Stop
                    if ($rawContent -match 'cpassword\s*=\s*"[^"]+"') {
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Group Policy'
                        $finding.Issue = 'GPP cpassword Found in SYSVOL'
                        $finding.Severity = 'Critical'
                        $finding.SeverityLevel = 4
                        $finding.AffectedObject = $gpo.DisplayName
                        $finding.Description = "GPO '$($gpo.DisplayName)' contains a Group Policy Preferences file with a 'cpassword' attribute set, a known-broken (MS14-025) reversible encryption scheme for which the AES key is public."
                        $finding.Impact = "Any authenticated user can read the file from SYSVOL and trivially recover the plaintext password, typically for a local administrator, service, or mapped-drive account."
                        $finding.Remediation = "Remove the affected GPP setting (Group Policy Management Console), delete the leftover XML file if the GPO no longer references it, and rotate the exposed credential immediately. Do not deploy passwords via GPP; use LAPS or a managed service account instead."
                        $finding.EstimatedEffort = 'Medium - the embedded account''s password must be rotated everywhere it''s used (it''s already fully compromised) and the GPP item removed or recreated without cpassword.'
                        $finding.KnownRisks = 'The embedded password is trivially decryptable by any authenticated user, since Microsoft publicly released the AES key used for GPP cpassword encryption after MS14-025 - treat it as already fully compromised and rotate the account''s password before or immediately after removing the GPP item.'
                        $finding.BackupRollback = 'Hard/Limited - like the logon-script credential finding, this isn''t a reversible setting; the exposure already happened and the credential must be rotated, not restored.'
                        $finding.Details = @{
                            GpoId    = $gpo.Id
                            FilePath = $gppFile.FullName
                            FileName = $gppFile.Name
                        }
                        $findings += $finding
                    }
                }
                catch {
                    Write-Verbose "Test-ADGpoDeployedSecrets: failed to read '$($gppFile.FullName)': $_"
                }
            }
        }
        catch {
            Write-Verbose "Test-ADGpoDeployedSecrets: failed to enumerate GPP files under '$gpoFolder': $_"
        }

        # ---------------------------------------------------------------
        # Check 2 - credential patterns in logon/startup/shutdown scripts.
        # ---------------------------------------------------------------
        try {
            $scriptRoots = @(
                (Join-Path $gpoFolder 'Machine\Scripts'),
                (Join-Path $gpoFolder 'User\Scripts')
            ) | Where-Object { Test-Path -LiteralPath $_ }

            foreach ($scriptRoot in $scriptRoots) {
                $scriptFiles = Get-ChildItem -LiteralPath $scriptRoot -Recurse -File -Include $Script:GpoSecretsScriptExtensions -ErrorAction SilentlyContinue

                foreach ($scriptFile in $scriptFiles) {
                    try {
                        $lineNumber = 0
                        $matchedLines = @()

                        # Stream line-by-line rather than loading the whole
                        # file, so large scripts don't need to be held in
                        # memory at once.
                        foreach ($line in [System.IO.File]::ReadLines($scriptFile.FullName)) {
                            $lineNumber++
                            foreach ($pattern in $Script:GpoSecretsScriptCredentialPatterns) {
                                if ($line -match $pattern) {
                                    $matchedLines += $lineNumber
                                    break
                                }
                            }
                        }

                        if ($matchedLines.Count -gt 0) {
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = 'Group Policy'
                            $finding.Issue = 'Credentials Referenced in Logon/Startup Script'
                            $finding.Severity = 'High'
                            $finding.SeverityLevel = 3
                            $finding.AffectedObject = $gpo.DisplayName
                            $finding.Description = "GPO '$($gpo.DisplayName)' deploys a script that appears to reference a credential inline (e.g. a 'net use /user:', 'runas /savecred', or ConvertTo-SecureString-style pattern)."
                            $finding.Impact = "A credential embedded in a script deployed to every targeted computer/user is readable by any authenticated principal with SYSVOL read access, without needing to decrypt anything."
                            $finding.Remediation = "Remove hard-coded credentials from logon/startup/shutdown scripts. Use a managed identity (gMSA), LAPS, or a secrets vault retrieved at runtime instead of embedding credentials in a script deployed via GPO."
                            $finding.EstimatedEffort = 'High - the exposed credential must be rotated everywhere it''s used, and the script reworked to avoid embedding credentials (e.g. migrating to a gMSA), which may involve other teams if the account is shared.'
                            $finding.KnownRisks = 'The credential must be treated as already compromised, since any authenticated user can read SYSVOL; rotating it needs to be coordinated with everything else that uses the same account/password.'
                            $finding.BackupRollback = 'Hard/Limited - this isn''t a reversible setting; once a credential has been exposed via SYSVOL it must be rotated, not restored, and the exposure history can''t be undone.'
                            $finding.Details = @{
                                GpoId       = $gpo.Id
                                FilePath    = $scriptFile.FullName
                                FileName    = $scriptFile.Name
                                LineNumbers = $matchedLines
                            }
                            $findings += $finding
                        }
                    }
                    catch {
                        Write-Verbose "Test-ADGpoDeployedSecrets: failed to scan script '$($scriptFile.FullName)': $_"
                    }
                }
            }
        }
        catch {
            Write-Verbose "Test-ADGpoDeployedSecrets: failed to enumerate scripts under '$gpoFolder': $_"
        }

        # ---------------------------------------------------------------
        # Check 3 - insecure settings deployed via GPO (GptTmpl.inf).
        # Firewall-off, weak folder options, insecure RDP/Terminal
        # Services. Best-effort text parse of the security template; a
        # missing/unparseable file simply yields no finding for that GPO.
        # ---------------------------------------------------------------
        try {
            $gptTmplPath = Join-Path $gpoFolder 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
            if (Test-Path -LiteralPath $gptTmplPath) {
                $tmplContent = Get-Content -LiteralPath $gptTmplPath -Raw -ErrorAction Stop

                $insecureSettings = @()

                # Windows Firewall disabled for a profile (0 = off).
                if ($tmplContent -match '(?im)^\s*EnableFirewall\s*=\s*0\s*$') {
                    $insecureSettings += 'Windows Firewall disabled for at least one profile'
                }

                # Folder Options: hidden files forced to be shown as
                # normal / extensions hidden (helps mask malicious
                # double-extension files). Hidden=2 shows hidden files.
                if ($tmplContent -match '(?im)^\s*HideFileExt\s*=\s*1\s*$') {
                    $insecureSettings += 'File extensions hidden by policy (HideFileExt=1)'
                }

                # Terminal Services / RDP: NLA disabled or security layer
                # allows unencrypted/RDP-native negotiation.
                if ($tmplContent -match '(?im)^\s*UserAuthentication\s*=\s*0\s*$') {
                    $insecureSettings += 'Network Level Authentication (NLA) disabled for RDP'
                }
                if ($tmplContent -match '(?im)^\s*SecurityLayer\s*=\s*0\s*$') {
                    $insecureSettings += 'RDP Security Layer set to the insecure native RDP protocol'
                }

                if ($insecureSettings.Count -gt 0) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Group Policy'
                    $finding.Issue = 'Insecure Setting Deployed via GPO'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $gpo.DisplayName
                    # BUGFIX: was a single semicolon-joined run-on sentence;
                    # rendered as one bullet per setting instead for readability.
                    $insecureSettingBullets = ($insecureSettings | ForEach-Object { "- $_" }) -join "`n"
                    $finding.Description = "GPO '$($gpo.DisplayName)' deploys one or more weakening settings:`n$insecureSettingBullets"
                    $finding.Impact = "Disabling the host firewall, hiding file extensions, or weakening RDP authentication/encryption each independently lowers the bar for initial access, lateral movement, or social-engineering-based execution on every computer the GPO applies to."
                    $finding.Remediation = "Review the GPO's Security Options and re-enable the Windows Firewall for all profiles, restore default Folder Options (show known file extensions), and require Network Level Authentication with a secure (SSL/TLS) RDP security layer."
                    $finding.EstimatedEffort = 'Medium - a single GPO setting change; confirm no application depends on the weaker current setting before tightening it.'
                    $finding.KnownRisks = 'Depends on the specific setting; generically, confirm no application or workflow relies on the current, weaker behavior before changing it.'
                    $finding.BackupRollback = 'Easy - revert the specific GPO setting; effective at next Group Policy refresh, no data loss.'
                    $finding.Details = @{
                        GpoId            = $gpo.Id
                        FilePath         = $gptTmplPath
                        InsecureSettings = $insecureSettings
                    }
                    $findings += $finding
                }

                # -----------------------------------------------------------
                # Check 4 - GPO grants a sensitive logon right (SeNetworkLogonRight,
                # SeRemoteInteractiveLogonRight) to a broad principal
                # (Everyone / ANONYMOUS LOGON / Authenticated Users).
                # GptTmpl.inf's [Privilege Rights] section lists granted
                # principals as a comma-separated list of SIDs prefixed with
                # '*' (e.g. "*S-1-1-0,*S-1-5-32-544"), so this matches on SID,
                # not principal name. Reported as its own always-Critical
                # finding, per this module's broad-principal convention (see
                # 'Everyone/Authenticated Users on a Control Path to Tier-0').
                # -----------------------------------------------------------
                $broadRightGrants = @()

                foreach ($rightKey in $Script:GpoSecretsSensitiveLogonRights.Keys) {
                    $rightMatch = [regex]::Match($tmplContent, "(?im)^\s*$rightKey\s*=\s*(.+)\s*$")
                    if (-not $rightMatch.Success) {
                        continue
                    }

                    $grantedSids = $rightMatch.Groups[1].Value -split ',' | ForEach-Object { $_.Trim().TrimStart('*') }
                    $broadSidsGranted = $grantedSids | Where-Object { $Script:GpoSecretsBroadPrincipalSids.ContainsKey($_) }

                    if ($broadSidsGranted.Count -gt 0) {
                        $broadPrincipalNames = $broadSidsGranted | ForEach-Object { $Script:GpoSecretsBroadPrincipalSids[$_] }
                        $rightDisplayName = $Script:GpoSecretsSensitiveLogonRights[$rightKey]
                        $broadRightGrants += [PSCustomObject]@{
                            Right            = $rightKey
                            RightDisplayName = $rightDisplayName
                            BroadPrincipals  = $broadPrincipalNames
                        }
                    }
                }

                if ($broadRightGrants.Count -gt 0) {
                    $grantBullets = ($broadRightGrants | ForEach-Object {
                        "- $($_.Right) ('$($_.RightDisplayName)') grants this right to $(($_.BroadPrincipals) -join ', ')"
                    }) -join "`n"

                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Group Policy'
                    $finding.Issue = 'GPO Grants Sensitive Logon Right to Broad Principal'
                    $finding.Severity = 'Critical'
                    $finding.SeverityLevel = 4
                    $finding.AffectedObject = $gpo.DisplayName
                    $finding.Description = "GPO '$($gpo.DisplayName)' deploys a User Rights Assignment granting a sensitive logon right to an overly broad principal:`n$grantBullets"
                    $finding.Impact = "Granting network or RDP logon rights to Everyone, ANONYMOUS LOGON, or Authenticated Users can silently re-open anonymous or unauthenticated-adjacent access to every computer the GPO applies to, independent of any domain-wide anonymous-access setting."
                    $finding.Remediation = "Edit the GPO's User Rights Assignment (Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment) and remove Everyone/ANONYMOUS LOGON/Authenticated Users from the affected right(s), granting access only to specific, intended security groups."
                    $finding.EstimatedEffort = 'Medium - removing a broad principal from a User Rights Assignment in one GPO; confirm no legitimate broad-access scenario (e.g. an intentional kiosk deployment) depends on it.'
                    $finding.KnownRisks = 'Removing a broad principal from a sensitive logon right can lock out any system or service that currently relies on that broad grant, so confirm intent before narrowing.'
                    $finding.BackupRollback = 'Easy - revert the User Rights Assignment setting in the GPO; effective at next Group Policy refresh, no data loss.'
                    $finding.Details = @{
                        GpoId       = $gpo.Id
                        FilePath    = $gptTmplPath
                        BroadGrants = $broadRightGrants
                    }
                    $findings += $finding
                }

                # -----------------------------------------------------------
                # Check 5 - GPO pushes local group membership via
                # "Restricted Groups" (GptTmpl.inf's [Group Membership]
                # section). This is a direct, GPO-wide privilege grant -
                # every computer the GPO applies to gets the listed
                # membership pushed to it - and is a common, otherwise
                # easy-to-miss "AdminTo via GPO" style edge, since it lives
                # in a security template file rather than a conventional
                # ACE any of the ACL-based checks elsewhere in this module
                # would catch. Entries look like
                # "*S-1-5-32-544__Members = *S-1-5-21-...-1104,CORP\jdoe" -
                # matched on the well-known LOCAL group SID (constant
                # across every computer), same convention as the broad-
                # principal check above.
                # -----------------------------------------------------------
                $restrictedGroupHits = @()
                $groupMembershipSection = [regex]::Match($tmplContent, '(?ims)^\[Group Membership\]\s*(.*?)(^\[|\z)')
                if ($groupMembershipSection.Success) {
                    $groupMembershipBody = $groupMembershipSection.Groups[1].Value

                    foreach ($sid in $Script:GpoSecretsRestrictedGroupSids.Keys) {
                        $membersMatch = [regex]::Match($groupMembershipBody, "(?im)^\*?$([regex]::Escape($sid))__Members\s*=\s*(.*)\s*$")
                        if (-not $membersMatch.Success) { continue }

                        $rawMembers = $membersMatch.Groups[1].Value.Trim()
                        if ([string]::IsNullOrWhiteSpace($rawMembers)) { continue }

                        # Each entry is either '*<SID>' or a plain
                        # 'DOMAIN\name'. Resolve SIDs to a display name on
                        # a best-effort basis (translation can fail for a
                        # SID from a domain/forest this session can't
                        # resolve); fall back to the raw SID string.
                        $memberNames = @($rawMembers -split ',' | ForEach-Object {
                            $entry = $_.Trim()
                            if ($entry.StartsWith('*')) {
                                $rawSid = $entry.TrimStart('*')
                                try {
                                    (New-Object System.Security.Principal.SecurityIdentifier($rawSid)).Translate([System.Security.Principal.NTAccount]).Value
                                }
                                catch {
                                    $rawSid
                                }
                            }
                            else {
                                $entry
                            }
                        } | Where-Object { $_ })

                        if ($memberNames.Count -eq 0) { continue }

                        $restrictedGroupHits += [PSCustomObject]@{
                            GroupSid   = $sid
                            GroupName  = $Script:GpoSecretsRestrictedGroupSids[$sid]
                            Members    = $memberNames
                        }
                    }
                }

                if ($restrictedGroupHits.Count -gt 0) {
                    $restrictedGroupBullets = ($restrictedGroupHits | ForEach-Object {
                        "- $($_.GroupName) membership set to: $(($_.Members) -join ', ')"
                    }) -join "`n"

                    $sensitiveGroupNames = @($restrictedGroupHits.GroupName)
                    $severity = if ($sensitiveGroupNames -contains 'Administrators' -or $sensitiveGroupNames -contains 'Backup Operators') { 'Critical' } else { 'High' }
                    $severityLevel = if ($severity -eq 'Critical') { 4 } else { 3 }

                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Group Policy'
                    $finding.Issue = 'GPO Deploys Restricted Groups Membership'
                    $finding.Severity = $severity
                    $finding.SeverityLevel = $severityLevel
                    $finding.AffectedObject = $gpo.DisplayName
                    $finding.Description = "GPO '$($gpo.DisplayName)' uses Restricted Groups to set local group membership on every computer it applies to:`n$restrictedGroupBullets"
                    $finding.Impact = "Restricted Groups REPLACES the target local group's membership on every computer the GPO applies to (it does not just add to it), so this GPO is a direct, GPO-wide grant of local privilege - equivalent to a BloodHound 'AdminTo' edge from a GPO. Anyone who can edit or is granted membership by this GPO gains that local privilege on every affected computer at the next Group Policy refresh."
                    $finding.Remediation = "Review the Restricted Groups membership pushed by this GPO (Computer Configuration > Windows Settings > Security Settings > Restricted Groups) and confirm every listed member is intended and still needed. Remove any unexpected principal, and consider scoping the GPO link more narrowly if the membership isn't appropriate for every computer it currently applies to."
                    $finding.EstimatedEffort = 'Medium - editing the Restricted Groups membership list in one GPO; confirm with the owning team which members are actually still needed before removing any.'
                    $finding.KnownRisks = 'Removing a member that legitimately needs local admin/RDP/backup rights on the affected computers will revoke that access at the next Group Policy refresh - confirm current legitimate use before narrowing.'
                    $finding.BackupRollback = 'Easy - restore the prior Restricted Groups membership list in the GPO; effective at next Group Policy refresh, no data loss.'
                    $finding.Details = @{
                        GpoId            = $gpo.Id
                        FilePath         = $gptTmplPath
                        RestrictedGroups = $restrictedGroupHits
                    }
                    $findings += $finding
                }
            }
        }
        catch {
            Write-Verbose "Test-ADGpoDeployedSecrets: failed to read GptTmpl.inf for GPO '$($gpo.DisplayName)': $_"
        }
    }

    Write-Progress -Activity "Scanning SYSVOL GPO content" -Completed
    Write-Verbose "Test-ADGpoDeployedSecrets: completed with $($findings.Count) finding(s)."
    return $findings
}

#endregion
