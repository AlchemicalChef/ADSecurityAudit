#region Domain Admin Equivalence Audit

function Test-ADDomainAdminEquivalence {
    [CmdletBinding()]
    param()

    Write-Verbose "Starting Admin Equivalence Audit"
    $findings = @()

    try {
        $domain = Get-ADDomain
        $domainDN = $domain.DistinguishedName
        $domainSID = $domain.DomainSID.Value
        $netBIOSName = $domain.NetBIOSName
        $configContext = (Get-ADRootDSE).ConfigurationNamingContext
        
        # Explicitly trusted principals that normally require broad control
        $legitimatePrincipals = @(
            'NT AUTHORITY\SYSTEM',
            'BUILTIN\Administrators',
            "$netBIOSName\Administrators",
            "$netBIOSName\Domain Admins",
            "$netBIOSName\Enterprise Admins",
            "$netBIOSName\Schema Admins",
            "$netBIOSName\Domain Controllers",
            "$netBIOSName\Enterprise Domain Controllers",
            "$netBIOSName\Read-only Domain Controllers"
        )

        $broadPrincipals = @(
            'NT AUTHORITY\Authenticated Users',
            'NT AUTHORITY\INTERACTIVE',
            'NT AUTHORITY\NETWORK',
            'Everyone',
            "$netBIOSName\Domain Users"
        )

        $principalEvidence = @{}
        $computerExposure = @()

        $sensitiveGroupNames = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Backup Operators',
            'Account Operators',
            'DNSAdmins',
            'Print Operators',
            'Server Operators'
        )

        $domainControllersContainer = $domain.DomainControllersContainer
        $sensitivePrincipals = @{}

        # Property GUIDs (normalized to lowercase for consistent comparison)
        $keyCredLinkGuid = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
        $spnGuid = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
        $rbcdGuid = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
        $memberAttributeGuid = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
        $passwordResetGuid = '00299570-246d-11d0-a768-00aa006e0529'
        $gpLinkGuid = 'f30e3bc2-9ff0-11d1-b603-0000f80367c1'
        $lapsGuid = 'ba19577d-37b2-4921-a637-429a1d99da82'
        $lapsPasswordGuid = '9a9a021e-4a5b-11d1-a9c3-0000f80367c1'
        $lapsPasswordExpGuid = 'e362ed86-b728-0842-b27d-2dea7a9df218'

        # Get DC computers EARLY - before any code that references it
        Write-Verbose "Enumerating Domain Controllers..."
        $dcComputers = Get-ADComputer -Filter "primaryGroupID -eq 516" -Properties nTSecurityDescriptor, OperatingSystem -ErrorAction SilentlyContinue
        $dcNames = @()
        if ($dcComputers) {
            $dcNames = $dcComputers | ForEach-Object { $_.Name }
        }

        function Add-Evidence {
            param(
                [string]$Principal,
                [string]$Reason,
                [hashtable]$Context
            )

            if (-not $principalEvidence.ContainsKey($Principal)) {
                $principalEvidence[$Principal] = [System.Collections.ArrayList]::new()
            }

            $entry = [PSCustomObject]@{
                Reason  = $Reason
                Context = $Context
            }

            [void]$principalEvidence[$Principal].Add($entry)
        }

        # Helper function for consistent GUID comparison
        function Test-GuidMatch {
            param(
                [string]$AceObjectType,
                [string]$TargetGuid
            )
            
            if ([string]::IsNullOrEmpty($AceObjectType)) { return $false }
            
            $aceGuid = $AceObjectType.ToString().ToLower()
            $targetLower = $TargetGuid.ToLower()
            
            # Check for empty GUID (all properties)
            if ($aceGuid -eq '00000000-0000-0000-0000-000000000000') { return $true }
            
            return $aceGuid -eq $targetLower
        }

        Write-Verbose "Collecting sensitive principals for equivalence correlation..."
        foreach ($groupName in $sensitiveGroupNames) {
            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
            if (-not $group) { continue }

            $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue | Where-Object { $_.objectClass -eq 'user' }

            foreach ($member in $members) {
                if (-not $sensitivePrincipals.ContainsKey($member.SamAccountName)) {
                    $sensitivePrincipals[$member.SamAccountName] = $member.DistinguishedName
                }
            }
        }

        Write-Verbose "Analyzing AdminSDHolder 'Ghost' accounts..."
        
        # Get all protected members recursively
        $protectedMembers = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($groupName in $sensitiveGroupNames) {
            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
            if ($group) {
                $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
                foreach ($m in $members) { [void]$protectedMembers.Add($m.DistinguishedName) }
            }
        }

        # Find users with adminCount=1
        $adminCountUsers = Get-ADUser -LDAPFilter "(adminCount=1)" -Properties adminCount, nTSecurityDescriptor -ErrorAction SilentlyContinue
        
        foreach ($user in $adminCountUsers) {
            if (-not $protectedMembers.Contains($user.DistinguishedName) -and $user.SamAccountName -ne "krbtgt") {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Admin Equivalence'
                $finding.Issue = 'AdminSDHolder Ghost Account'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User has 'adminCount=1' but is not a member of any protected group. This may indicate a leftover administrative account or a persistence backdoor where ACLs are frozen by SDProp."
                $finding.Remediation = "Clear the 'adminCount' attribute (set to 0) and enable permission inheritance on the object. Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/adminsdholder-protected-accounts-and-groups"
                $finding.Details = @{
                    UserDN = $user.DistinguishedName
                    Domain = $domain.DNSRoot
                }
                $findings += $finding
            }
        }

        Write-Verbose "Scanning for Shadow Credentials (msDS-KeyCredentialLink)..."

        $shadowCreds = Get-ADObject -LDAPFilter "(msDS-KeyCredentialLink=*)" -Properties msDS-KeyCredentialLink, samAccountName, objectClass -ErrorAction SilentlyContinue

        foreach ($obj in $shadowCreds) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Admin Equivalence'
            $finding.Issue = 'Shadow Credentials Detected'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = $obj.Name
            $finding.Description = "Object has 'msDS-KeyCredentialLink' populated. Unless Windows Hello for Business is deployed, this indicates a potential 'Shadow Credentials' attack (Whisker/Certipy) allowing account takeover."
            $finding.Remediation = "Investigate the 'msDS-KeyCredentialLink' attribute. If not legitimate WHfB, clear the attribute immediately. Reference: https://posts.specterops.io/shadow-credentials-abusing-key-credential-link-translation-to-en-9d8f9fb12be8"
            $finding.Details = @{
                ObjectDN    = $obj.DistinguishedName
                ObjectClass = $obj.objectClass -join ', '
                Domain      = $domain.DNSRoot
            }
            $findings += $finding
        }

        Write-Verbose "Detecting Shadow Credentials attack surface (msDS-KeyCredentialLink write access)..."

        $criticalComputers = Get-ADComputer -Filter * -Properties nTSecurityDescriptor, OperatingSystem -ErrorAction SilentlyContinue

        foreach ($computer in $criticalComputers) {
            if (-not $computer.nTSecurityDescriptor) { continue }
            
            foreach ($ace in $computer.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                    if (Test-GuidMatch -AceObjectType $ace.ObjectType -TargetGuid $keyCredLinkGuid) {
                        Add-Evidence -Principal $principal -Reason "Shadow Credentials write access on computer '$($computer.Name)' - allows authentication as the computer account" -Context @{
                            Target            = 'Shadow Credentials'
                            ComputerName      = $computer.Name
                            DistinguishedName = $computer.DistinguishedName
                            OperatingSystem   = $computer.OperatingSystem
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AttackPath        = 'Write msDS-KeyCredentialLink -> Request TGT as computer -> Compromise system'
                        }
                    }
                }
            }
        }

        foreach ($kvp in $sensitivePrincipals.GetEnumerator()) {
            $sam = $kvp.Key
            $dn = $kvp.Value

            $user = Get-ADUser -Identity $dn -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $user -or -not $user.nTSecurityDescriptor) { continue }

            foreach ($ace in $user.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                    if (Test-GuidMatch -AceObjectType $ace.ObjectType -TargetGuid $keyCredLinkGuid) {
                        Add-Evidence -Principal $principal -Reason "Shadow Credentials write access on privileged user '$sam' - direct account takeover" -Context @{
                            Target            = 'Shadow Credentials (Privileged User)'
                            Account           = $sam
                            DistinguishedName = $dn
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AttackPath        = 'Write msDS-KeyCredentialLink -> Authenticate as user -> Full compromise'
                        }
                    }
                }
            }
        }

        Write-Verbose "Checking for WriteSPN permissions (targeted Kerberoasting attack)..."

        foreach ($kvp in $sensitivePrincipals.GetEnumerator()) {
            $sam = $kvp.Key
            $dn = $kvp.Value

            $user = Get-ADUser -Identity $dn -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $user -or -not $user.nTSecurityDescriptor) { continue }

            foreach ($ace in $user.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                    if (Test-GuidMatch -AceObjectType $ace.ObjectType -TargetGuid $spnGuid) {
                        Add-Evidence -Principal $principal -Reason "WriteSPN on privileged account '$sam' - enables targeted Kerberoasting" -Context @{
                            Target            = 'WriteSPN'
                            Account           = $sam
                            DistinguishedName = $dn
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AttackPath        = 'Add fake SPN -> Request service ticket -> Offline password cracking'
                        }
                    }
                }
            }
        }

        Write-Verbose "Scanning for SID History Injection..."
        
        $sidHistoryUsers = Get-ADUser -LDAPFilter "(sIDHistory=*)" -Properties sIDHistory -ErrorAction SilentlyContinue
        
        foreach ($user in $sidHistoryUsers) {
            foreach ($sid in $user.sIDHistory) {
                $sidStr = $sid.ToString()
                
                if ($sidStr -like "$domainSID*") {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Admin Equivalence'
                    $finding.Issue = 'SID History Injection (Same Domain)'
                    $finding.Severity = 'Critical'
                    $finding.SeverityLevel = 4
                    $finding.AffectedObject = $user.SamAccountName
                    $finding.Description = "User contains a SID from the CURRENT domain in its SID History ($sidStr). This is a definitive sign of a Golden Ticket or SID History injection attack."
                    $finding.Remediation = "Immediate Incident Response required. Reset the account and investigate origin. Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-sidhistory"
                    $finding.Details = @{
                        UserDN       = $user.DistinguishedName
                        InjectedSID  = $sidStr
                        Domain       = $domain.DNSRoot
                    }
                    $findings += $finding
                }
                
                if ($sidStr -match '-(500|512|519)$') {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Admin Equivalence'
                    $finding.Issue = 'Privileged SID in History'
                    $finding.Severity = 'Critical'
                    $finding.SeverityLevel = 4
                    $finding.AffectedObject = $user.SamAccountName
                    $finding.Description = "User has a highly privileged SID ($sidStr) in their SID History. They possess Domain Admin rights regardless of group membership."
                    $finding.Remediation = "Clear the sIDHistory attribute immediately unless this is a verified migration account. Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-sidhistory"
                    $finding.Details = @{
                        UserDN       = $user.DistinguishedName
                        PrivilegedSID = $sidStr
                        Domain       = $domain.DNSRoot
                    }
                    $findings += $finding
                }
            }
        }

        Write-Verbose "Scanning for legacy Logon Script abuse..."
        
        $scriptUsers = Get-ADUser -LDAPFilter "(scriptPath=*)" -Properties scriptPath -ErrorAction SilentlyContinue
        foreach ($user in $scriptUsers) {
            $path = $user.scriptPath
            
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Legacy Attack Vector'
            $finding.Issue = 'Legacy Logon Script Defined'
            $finding.Severity = 'Low'
            $finding.SeverityLevel = 1
            $finding.AffectedObject = $user.SamAccountName
            $finding.Description = "User has a legacy logon script defined: '$path'. Attackers can modify this file to achieve code execution upon user logon."
            $finding.Remediation = "Migrate to Group Policy Preferences and clear the 'scriptPath' attribute. Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/logon-script-issues"
            $finding.Details = @{
                UserDN     = $user.DistinguishedName
                ScriptPath = $path
                Domain     = $domain.DNSRoot
            }
            $findings += $finding
        }

        # Check direct control over the domain naming context and AdminSDHolder
        $controlTargets = @(
            @{ Name = 'Domain Root'; DistinguishedName = $domainDN; RiskType = 'DomainRootControl' },
            @{ Name = 'AdminSDHolder'; DistinguishedName = "CN=AdminSDHolder,CN=System,$domainDN"; RiskType = 'AdminSDHolderControl' }
        )

        if ($domainControllersContainer) {
            $controlTargets += @{ Name = 'Domain Controllers OU'; DistinguishedName = $domainControllersContainer; RiskType = 'DomainControllersContainerControl' }
        }

        foreach ($target in $controlTargets) {
            $object = Get-ADObject -Identity $target.DistinguishedName -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $object -or -not $object.nTSecurityDescriptor) { continue }

            foreach ($ace in $object.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|AllExtendedRights') {
                    Add-Evidence -Principal $principal -Reason "$($target.Name) control via $($ace.ActiveDirectoryRights)" -Context @{
                        Target             = $target.Name
                        DistinguishedName  = $target.DistinguishedName
                        Rights             = $ace.ActiveDirectoryRights.ToString()
                        AccessControlType  = $ace.AccessControlType.ToString()
                        Inheritance        = if ($ace.IsInherited) { 'Inherited' } else { 'Explicit' }
                    }
                }
            }
        }

        Write-Verbose "Performing AdminSDHolder ACL Analysis..."
        $adminSdHolder = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$domainDN" -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
        if ($adminSdHolder -and $adminSdHolder.nTSecurityDescriptor) {
            foreach ($ace in $adminSdHolder.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }
                
                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite') {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Admin Equivalence'
                    $finding.Issue = 'AdminSDHolder ACL Compromise'
                    $finding.Severity = 'Critical'
                    $finding.SeverityLevel = 4
                    $finding.AffectedObject = 'AdminSDHolder'
                    $finding.Description = "Principal '$principal' has dangerous rights ($($ace.ActiveDirectoryRights)) on AdminSDHolder. This grants persistent Domain Admin rights via SDProp."
                    $finding.Remediation = "Remove the ACE immediately and check all protected groups for 'adminCount=1' users. Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/adminsdholder-protected-accounts-and-groups"
                    $finding.Details = @{
                        Principal = $principal
                        Rights    = $ace.ActiveDirectoryRights.ToString()
                        Domain    = $domain.DNSRoot
                    }
                    $findings += $finding
                }
            }
        }

        Write-Verbose "Checking Constrained Delegation to Domain Controllers..."
        
        $delegationRisk = Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Properties msDS-AllowedToDelegateTo, samAccountName -ErrorAction SilentlyContinue
        
        foreach ($obj in $delegationRisk) {
            foreach ($targetSPN in $obj.'msDS-AllowedToDelegateTo') {
                $targetHost = ($targetSPN -split '/')[1]
                if ($targetHost -match ':') { $targetHost = ($targetHost -split ':')[0] }
                $targetHostShort = ($targetHost -split '\.')[0]

                if ($targetHostShort -in $dcNames) {
                    Add-Evidence -Principal $obj.Name -Reason "Admin Equivalence Edge: AllowedToDelegate (Constrained Delegation) to Domain Controller $targetHostShort" -Context @{
                        Target = $targetHostShort
                        SPN = $targetSPN
                        Attack = "Impersonate users to DC via S4U2Proxy"
                    }
                }
            }
        }

        Write-Verbose "Checking constrained delegation with protocol transition (S4U2Self abuse)..."
        $constrainedDelegation = Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo, servicePrincipalName, samAccountName, objectClass -ErrorAction SilentlyContinue

        foreach ($delegator in $constrainedDelegation) {
            $allowedServices = $delegator.'msDS-AllowedToDelegateTo'
            $delegatorDetails = Get-ADObject -Identity $delegator.DistinguishedName -Properties TrustedToAuthForDelegation -ErrorAction SilentlyContinue
            $hasProtocolTransition = $delegatorDetails.TrustedToAuthForDelegation

            if ($hasProtocolTransition) {
                $targets = $allowedServices | ForEach-Object {
                    $parts = $_ -split '/'
                    if ($parts.Count -ge 2) { $parts[1] } else { $_ }
                }

                Add-Evidence -Principal $delegator.samAccountName -Reason "Constrained delegation WITH protocol transition on '$($delegator.samAccountName)' - allows impersonation to sensitive services" -Context @{
                    Target               = 'Constrained Delegation + Protocol Transition'
                    Account              = $delegator.samAccountName
                    DistinguishedName    = $delegator.DistinguishedName
                    ObjectClass          = $delegator.objectClass -join ', '
                    AllowedToDelegate    = $allowedServices -join '; '
                    TargetHosts          = $targets -join '; '
                    AttackPath           = 'S4U2Self allows impersonation of ANY user to delegated services without authentication'
                }
            }
        }

        Write-Verbose "Checking RBCD (AllowedToActOnBehalfOfOtherIdentity) on Domain Controllers..."
        foreach ($dc in $dcComputers) {
            $dcObj = Get-ADComputer -Identity $dc.DistinguishedName -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity' -ErrorAction SilentlyContinue

            if ($dcObj.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
                try {
                    $sdBytes = $dcObj.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                    if ($sdBytes) {
                        $rawSD = [System.Security.AccessControl.RawSecurityDescriptor]::new($sdBytes, 0)
                        foreach ($ace in $rawSD.DiscretionaryAcl) {
                            $sid = $ace.SecurityIdentifier.Value
                            try { $principal = $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } catch { $principal = $sid }
                            
                            if ($principal -notin $legitimatePrincipals) {
                                Add-Evidence -Principal $principal -Reason "Admin Equivalence Edge: AllowedToAct (RBCD) on Domain Controller $($dc.Name)" -Context @{
                                    Target = $dc.Name
                                    Attack = "Compromise DC via RBCD impersonation"
                                }
                            }
                        }
                    }
                } catch {
                    Write-Verbose "Failed to parse RBCD SD for $($dc.Name): $_"
                }
            }
        }

        Write-Verbose "Checking for auditing high-privilege built-in groups..."
        foreach ($groupName in @('Print Operators', 'Server Operators', 'Backup Operators', 'Account Operators', 'DnsAdmins')) {
            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
            if (-not $group) { continue }

            $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue

            foreach ($member in $members) {
                if ($member.objectClass -eq 'user') {
                    Add-Evidence -Principal $member.SamAccountName -Reason "Membership in dangerous built-in group '$groupName' - provides privilege escalation paths" -Context @{
                        Group      = $groupName
                        Member     = $member.SamAccountName
                        MemberDN   = $member.DistinguishedName
                        AttackPath = switch ($groupName) {
                            'Print Operators' { 'Load printer drivers on DCs -> Execute code as SYSTEM' }
                            'Server Operators' { 'Modify services on DCs -> Execute code as SYSTEM' }
                            'Backup Operators' { 'Backup SAM/SYSTEM -> Extract credentials -> Full domain compromise' }
                            'Account Operators' { 'Modify non-protected accounts -> Add to privileged groups' }
                            'DnsAdmins' { 'Load arbitrary DLL in DNS service on DC -> Execute as SYSTEM' }
                            default { 'Privilege escalation via built-in group rights' }
                        }
                    }
                }
            }
        }

        # Build findings from evidence
        foreach ($principal in $principalEvidence.Keys) {
            $evidence = $principalEvidence[$principal]
            $criticalEvidence = $evidence | Where-Object { $_.Reason -match 'Domain Root|AdminSDHolder|DCSync|Domain Controller|Privileged account|PKI|Unconstrained|AllowedToDelegate|AllowedToAct|ReadLAPSPassword|ReadGMSAPassword|WriteGPLink|Shadow Credentials|Certificate|Constrained Delegation|RBCD|LAPS password|DNS zone|Exchange|WriteSPN' }

            $severity = if ($criticalEvidence.Count -gt 0) { 'Critical' } else { 'High' }
            $severityLevel = if ($severity -eq 'Critical') { 4 } else { 3 }

            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Admin Equivalence'
            $finding.Issue = 'Domain Admin Equivalent Access Detected'
            $finding.Severity = $severity
            $finding.SeverityLevel = $severityLevel
            $finding.AffectedObject = $principal
            $finding.Description = "Principal '$principal' holds permissions that provide Domain Admin-equivalent control: $($evidence.Reason -join '; ')."
            $finding.Impact = 'Compromise of this principal would allow attackers to seize control of protected groups, the domain naming context, PKI infrastructure, or perform DCSync.'
            $finding.Remediation = @"
Review and remove the excessive permissions listed in the evidence:
1. Restrict Domain Naming Context and AdminSDHolder control.
2. Lock down AD CS/PKI containers in the Configuration Partition.
3. Audit and remove Unconstrained Delegation from non-DC computers.
4. Restrict control over DNSAdmins and Print Operators.
5. Remove Constrained/RBCD delegation paths to Domain Controllers.
6. Audit LAPS and GMSA password read permissions.
7. Restrict WriteGPLink permissions on Domain and OU objects.
8. Clear adminCount attribute for 'ghost' accounts.
9. Remove Shadow Credentials if not using Windows Hello for Business.
10. Clear SID History injection entries.
"@
            $finding.Details = @{
                Evidence = $evidence
                Domain   = $domain.DNSRoot
            }
            $findings += $finding
        }

        Write-Verbose "Audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during equivalence audit: $_"
        throw
    }
}

#endregion
