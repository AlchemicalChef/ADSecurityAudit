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
        # This is based on the TrustedSec/Bloodhound/SpectreOps research, im just implementing it here. 
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

        # Capture machines where broad principals have administrative-level control
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
            # If they have adminCount=1 but are NOT in a protected group currently
            if (-not $protectedMembers.Contains($user.DistinguishedName) -and $user.SamAccountName -ne "krbtgt") {
                
                $finding = [PSCustomObject]@{
                    Category       = 'Admin Equivalence'
                    Issue          = 'AdminSDHolder Ghost Account'
                    Severity       = 'Medium'
                    AffectedObject = $user.SamAccountName
                    Description    = "User has 'adminCount=1' but is not a member of any protected group. This may indicate a leftover administrative account or a persistence backdoor where ACLs are frozen by SDProp."
                    Remediation    = "Clear the 'adminCount' attribute (set to 0) and enable permission inheritance on the object. Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/adminsdholder-protected-accounts-and-groups"
                    Details        = @{
                        UserDN = $user.DistinguishedName
                        Domain = $domain.DNSRoot
                    }
                }
                $findings += $finding
            }
        }

        Write-Verbose "Scanning for Shadow Credentials (msDS-KeyCredentialLink)..."

        $shadowCreds = Get-ADObject -LDAPFilter "(msDS-KeyCredentialLink=*)" -Properties msDS-KeyCredentialLink, samAccountName, objectClass -ErrorAction SilentlyContinue

        foreach ($obj in $shadowCreds) {
            $finding = [PSCustomObject]@{
                Category       = 'Admin Equivalence'
                Issue          = 'Shadow Credentials Detected'
                Severity       = 'High'
                AffectedObject = $obj.Name
                Description    = "Object has 'msDS-KeyCredentialLink' populated. Unless Windows Hello for Business is deployed, this indicates a potential 'Shadow Credentials' attack (Whisker/Certipy) allowing account takeover."
                Remediation    = "Investigate the 'msDS-KeyCredentialLink' attribute. If not legitimate WHfB, clear the attribute immediately. Reference: https://posts.specterops.io/shadow-credentials-abusing-key-credential-link-translation-to-en-9d8f9fb12be8"
                Details        = @{
                    ObjectDN    = $obj.DistinguishedName
                    ObjectClass = $obj.objectClass
                    Domain      = $domain.DNSRoot
                }
            }
            $findings += $finding
        }

        Write-Verbose "Detecting Shadow Credentials attack surface (msDS-KeyCredentialLink write access)..."
        $keyCredLinkGuid = '5b47d60f-6090-40b2-9f37-2a4de88f3063'

        $criticalComputers = Get-ADComputer -Filter * -Properties nTSecurityDescriptor, OperatingSystem -ErrorAction SilentlyContinue

        foreach ($computer in $criticalComputers) {
            foreach ($ace in $computer.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                $objectType = $ace.ObjectType.ToString().ToLower()

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                    if ($ace.ObjectType -eq [Guid]::Empty -or $objectType -eq $keyCredLinkGuid) {
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
            if (-not $user) { continue }

            foreach ($ace in $user.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                $objectType = $ace.ObjectType.ToString().ToLower()

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                    if ($ace.ObjectType -eq [Guid]::Empty -or $objectType -eq $keyCredLinkGuid) {
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
        $spnGuid = 'f3a64788-5306-11d1-a9c5-0000f80367c1'

        foreach ($kvp in $sensitivePrincipals.GetEnumerator()) {
            $sam = $kvp.Key
            $dn = $kvp.Value

            $user = Get-ADUser -Identity $dn -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $user) { continue }

            foreach ($ace in $user.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                $objectType = $ace.ObjectType.ToString().ToLower()

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                    if ($ace.ObjectType -eq [Guid]::Empty -or $objectType -eq $spnGuid) {
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

        # Admin Equivalence operational edges and hidden write vectors
        Write-Verbose "Analyzing Admin Equivalence Operational Edges (ExecuteDCOM, WriteSPN, New LAPS)..."

        # 1. ExecuteDCOM & CanPSRemote groups allow remote code execution on DCs when mapped to local groups
        $sessionGroups = @('Distributed COM Users', 'Remote Management Users')
        foreach ($groupName in $sessionGroups) {
            $group = Get-ADGroup -Identity $groupName -Properties Members -ErrorAction SilentlyContinue
            if (-not $group) { continue }

            $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
            foreach ($member in $members) {
                if ($member.objectClass -eq 'user') {
                    Add-Evidence -Principal $member.SamAccountName -Reason "Admin Equivalence Edge: ExecuteDCOM/CanPSRemote via '$groupName'" -Context @{
                        Target = 'Domain Controllers'
                        Risk   = 'Remote code execution on DCs via DCOM or WinRM'
                    }
                }
            }
        }

        # 2. AddAllowedToAct (write msDS-AllowedToActOnBehalfOfOtherIdentity on Domain Controllers)
        $rbcdGuid = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
        foreach ($dc in $dcComputers) {
            $dcObj = Get-ADComputer -Identity $dc.DistinguishedName -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $dcObj -or -not $dcObj.nTSecurityDescriptor) { continue }

            foreach ($ace in $dcObj.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll' -and ($ace.ObjectType -eq $rbcdGuid -or $ace.ObjectType -eq [Guid]::Empty)) {
                    Add-Evidence -Principal $principal -Reason "Admin Equivalence Edge: AddAllowedToAct (Write RBCD) on $($dc.Name)" -Context @{
                        Target = $dc.Name
                        Risk   = 'Attacker can add their machine to RBCD and impersonate DA'
                    }
                }
            }
        }

        # 3. WriteSPN (targeted kerberoasting) on sensitive accounts
        foreach ($kvp in $sensitivePrincipals.GetEnumerator()) {
            $targetDn = $kvp.Value
            $targetUser = Get-ADUser -Identity $targetDn -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $targetUser -or -not $targetUser.nTSecurityDescriptor) { continue }

            foreach ($ace in $targetUser.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll' -and ($ace.ObjectType -eq $spnGuid -or $ace.ObjectType -eq [Guid]::Empty)) {
                    Add-Evidence -Principal $principal -Reason "Admin Equivalence Edge: WriteSPN on Sensitive Account $($kvp.Key)" -Context @{
                        Target = $kvp.Key
                        Risk   = 'Targeted Kerberoasting (SPN Jacking)'
                    }
                }
            }
        }

        Write-Verbose "Scanning for SID History Injection..."
        
        $sidHistoryUsers = Get-ADUser -LDAPFilter "(sIDHistory=*)" -Properties sIDHistory -ErrorAction SilentlyContinue
        
        foreach ($user in $sidHistoryUsers) {
            foreach ($sid in $user.sIDHistory) {
                $sidStr = $sid.ToString()
                
                # Risk 1: Same Domain SID (Illegal in standard migration)
                if ($sidStr -like "$domainSID*") {
                    $findings += [PSCustomObject]@{
                        Category       = 'Admin Equivalence'
                        Issue          = 'SID History Injection (Same Domain)'
                        Severity       = 'Critical'
                        AffectedObject = $user.SamAccountName
                        Description    = "User contains a SID from the CURRENT domain in its SID History ($sidStr). This is a definitive sign of a Golden Ticket or SID History injection attack."
                        Remediation    = "Immediate Incident Response required. Reset the account and investigate origin. Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-sidhistory"
                        Details        = @{
                            UserDN       = $user.DistinguishedName
                            InjectedSID  = $sidStr
                            Domain       = $domain.DNSRoot
                        }
                    }
                }
                
                # Risk 2: Privileged RID (500=Admin, 512=DomainAdmins, 519=EnterpriseAdmins)
                if ($sidStr -match '-(500|512|519)$') {
                    $findings += [PSCustomObject]@{
                        Category       = 'Admin Equivalence'
                        Issue          = 'Privileged SID in History'
                        Severity       = 'Critical'
                        AffectedObject = $user.SamAccountName
                        Description    = "User has a highly privileged SID ($sidStr) in their SID History. They possess Domain Admin rights regardless of group membership."
                        Remediation    = "Clear the sIDHistory attribute immediately unless this is a verified migration account. Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-sidhistory"
                        Details        = @{
                            UserDN       = $user.DistinguishedName
                            PrivilegedSID = $sidStr
                            Domain       = $domain.DNSRoot
                        }
                    }
                }
            }
        }

        Write-Verbose "Scanning for legacy Logon Script abuse..."
        
        $scriptUsers = Get-ADUser -LDAPFilter "(scriptPath=*)" -Properties scriptPath -ErrorAction SilentlyContinue
        foreach ($user in $scriptUsers) {
            $path = $user.scriptPath
            
            $findings += [PSCustomObject]@{
                Category       = 'Legacy Attack Vector'
                Issue          = 'Legacy Logon Script Defined'
                Severity       = 'Low'
                AffectedObject = $user.SamAccountName
                Description    = "User has a legacy logon script defined: '$path'. Attackers can modify this file to achieve code execution upon user logon."
                Remediation    = "Migrate to Group Policy Preferences and clear the 'scriptPath' attribute. Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/logon-script-issues"
                Details        = @{
                    UserDN     = $user.DistinguishedName
                    ScriptPath = $path
                    Domain     = $domain.DNSRoot
                }
            }
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
            if (-not $object) { continue }

            foreach ($ace in $object.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|AllExtendedRights') {
                    Add-Evidence -Principal $principal -Reason "$($target.Name) control via $($ace.ActiveDirectoryRights)" -Context @{
                        Target             = $target.Name
                        DistinguishedName  = $target.DistinguishedName
                        Rights             = $ace.ActiveDirectoryRights.ToString()
                        AccessControlType  = $ace.AccessControlType
                        Inheritance        = if ($ace.IsInherited) { 'Inherited' } else { 'Explicit' }
                    }
                }
            }
        }

        Write-Verbose "Performing AdminSDHolder ACL Analysis..."
        $adminSdHolder = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$domainDN" -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
        if ($adminSdHolder) {
            foreach ($ace in $adminSdHolder.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }
                
                # ANY modification right here is fatal
                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite') {
                    $findings += [PSCustomObject]@{
                        Category       = 'Admin Equivalence'
                        Issue          = 'AdminSDHolder ACL Compromise'
                        Severity       = 'Critical'
                        AffectedObject = 'AdminSDHolder'
                        Description    = "Principal '$principal' has dangerous rights ($($ace.ActiveDirectoryRights)) on AdminSDHolder. This grants persistent Domain Admin rights via SDProp."
                        Remediation    = "Remove the ACE immediately and check all protected groups for 'adminCount=1' users. Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/adminsdholder-protected-accounts-and-groups"
                        Details        = @{
                            Principal = $principal
                            Rights    = $ace.ActiveDirectoryRights.ToString()
                            Domain    = $domain.DNSRoot
                        }
                    }
                }
            }
        }

        # Analyzing AD CS Infrastructure in Configuration Partition...
        $pkiServicesDN = "CN=Public Key Services,CN=Services,$configContext"
        $pkiTargets = @(
            @{ Name = 'Certificate Templates'; DistinguishedName = "CN=Certificate Templates,$pkiServicesDN"; RiskType = 'ADCS_Template_Control' },
            @{ Name = 'Certification Authorities'; DistinguishedName = "CN=Certification Authorities,$pkiServicesDN"; RiskType = 'ADCS_CA_Control' },
            @{ Name = 'NTAuthCertificates'; DistinguishedName = "CN=NTAuthCertificates,$pkiServicesDN"; RiskType = 'ADCS_NTAuth_Control' }
        )

        foreach ($target in $pkiTargets) {
            $object = Get-ADObject -Identity $target.DistinguishedName -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $object) { continue }

            foreach ($ace in $object.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|WriteProperty') {
                    Add-Evidence -Principal $principal -Reason "Critical control over PKI object '$($target.Name)' via $($ace.ActiveDirectoryRights)" -Context @{
                        Target            = "PKI Infrastructure"
                        DistinguishedName = $target.DistinguishedName
                        Rights            = $ace.ActiveDirectoryRights.ToString()
                        AttackVector      = "Potential ESC1/ESC6 Misconfiguration Injection"
                    }
                }
            }
        }

        Write-Verbose "Auditing Certificate Services control (ESC attack vectors)..."
        try {
            $pkiContainer = "CN=Public Key Services,CN=Services,$configContext"
            $certAuthorities = Get-ADObject -SearchBase $pkiContainer -Filter {objectClass -eq 'pKIEnrollmentService'} -Properties nTSecurityDescriptor, dNSHostName -ErrorAction SilentlyContinue

            foreach ($ca in $certAuthorities) {
                foreach ($ace in $ca.nTSecurityDescriptor.Access) {
                    $principal = $ace.IdentityReference.Value

                    if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                    if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|WriteProperty') {
                        Add-Evidence -Principal $principal -Reason "Control over Certificate Authority '$($ca.Name)' - enables certificate-based attacks (ESC1-ESC8)" -Context @{
                            Target            = 'Certificate Authority'
                            CAName            = $ca.Name
                            DNSHostName       = $ca.dNSHostName
                            DistinguishedName = $ca.DistinguishedName
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AttackPath        = 'Modify CA settings/templates -> Issue privileged certificates -> Authenticate as any user'
                        }
                    }
                }
            }

            $certTemplates = Get-ADObject -SearchBase $pkiContainer -Filter {objectClass -eq 'pKICertificateTemplate'} -Properties nTSecurityDescriptor, displayName -ErrorAction SilentlyContinue

            foreach ($template in $certTemplates) {
                foreach ($ace in $template.nTSecurityDescriptor.Access) {
                    $principal = $ace.IdentityReference.Value

                    if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                    if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|WriteProperty|Enroll') {
                        Add-Evidence -Principal $principal -Reason "Control/Enrollment on certificate template '$($template.displayName)' - potential certificate abuse" -Context @{
                            Target            = 'Certificate Template'
                            TemplateName      = $template.displayName
                            DistinguishedName = $template.DistinguishedName
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AttackPath        = 'Enroll in vulnerable template OR modify template settings -> Obtain privileged certificate'
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Certificate Services enumeration failed: $_"
        }

        Write-Verbose "Checking Constrained Delegation to Domain Controllers..."
        $dcComputers = Get-ADComputer -Filter "primaryGroupID -eq 516" -ErrorAction SilentlyContinue
        $dcNames = $dcComputers.Name
        
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
            $hasProtocolTransition = (Get-ADObject -Identity $delegator.DistinguishedName -Properties TrustedToAuthForDelegation -ErrorAction SilentlyContinue).TrustedToAuthForDelegation

            if ($hasProtocolTransition) {
                $targets = $allowedServices | ForEach-Object {
                    $parts = $_ -split '/'
                    if ($parts.Count -ge 2) { $parts[1] } else { $_ }
                }

                Add-Evidence -Principal $delegator.samAccountName -Reason "Constrained delegation WITH protocol transition on '$($delegator.samAccountName)' - allows impersonation to sensitive services" -Context @{
                    Target               = 'Constrained Delegation + Protocol Transition'
                    Account              = $delegator.samAccountName
                    DistinguishedName    = $delegator.DistinguishedName
                    ObjectClass          = $delegator.objectClass
                    AllowedToDelegate    = $allowedServices -join '; '
                    TargetHosts          = $targets -join '; '
                    AttackPath           = 'S4U2Self allows impersonation of ANY user to delegated services without authentication'
                }
            }
        }

        Write-Verbose "Checking RBCD (AllowedToActOnBehalfOfOtherIdentity) on Domain Controllers..."
        foreach ($dc in $dcComputers) {
            $dcObj = Get-ADComputer -Identity $dc.DistinguishedName -Properties msDS-AllowedToActOnBehalfOfOtherIdentity -ErrorAction SilentlyContinue

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
                    Write-Verbose "Failed to parse RBCD SD for $($dc.Name)"
                }
            }
        }

        Write-Verbose "Identifying resource-based constrained delegation attack surfaces..."
        $rbcdObjects = Get-ADObject -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, samAccountName, objectClass -ErrorAction SilentlyContinue

        foreach ($rbcdTarget in $rbcdObjects) {
            try {
                $sd = $rbcdTarget.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                $acl = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $acl.SetSecurityDescriptorBinaryForm($sd)

                foreach ($ace in $acl.Access) {
                    $principal = $ace.IdentityReference.Value

                    if ($principal -in $legitimatePrincipals) { continue }

                    Add-Evidence -Principal $principal -Reason "Resource-Based Constrained Delegation rights on '$($rbcdTarget.samAccountName)' - allows impersonation attacks" -Context @{
                        Target             = 'RBCD'
                        TargetObject       = $rbcdTarget.samAccountName
                        DistinguishedName  = $rbcdTarget.DistinguishedName
                        ObjectClass        = $rbcdTarget.objectClass
                        DelegatedPrincipal = $principal
                        AttackPath         = 'Control delegated principal -> Impersonate users to target -> Compromise target system'
                    }
                }
            }
            catch {
                Write-Verbose "Failed to parse RBCD ACL for $($rbcdTarget.samAccountName): $_"
            }
        }

        Write-Verbose "Checking for LAPS Password Reading Rights..."
        $lapsGuid = "ba19577d-37b2-4921-a637-429a1d99da82"

        $computers = Get-ADComputer -Filter * -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
        foreach ($comp in $computers) {
            if (-not $comp.nTSecurityDescriptor) { continue }
            foreach ($ace in $comp.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }
                
                if (($ace.ActiveDirectoryRights -match 'ExtendedRight' -and $ace.ObjectType -eq $lapsGuid) -or 
                    ($ace.ActiveDirectoryRights -match 'GenericAll')) {
                    
                    if ($principal -in $broadPrincipals) {
                        Add-Evidence -Principal $principal -Reason "Admin Equivalence Edge: ReadLAPSPassword (LAPS Leak) on $($comp.Name)" -Context @{
                            Target = $comp.Name
                            Risk = "Broad group can read local admin password"
                        }
                    }
                }
            }
        }

        Write-Verbose "Checking for LAPS password read/write permissions (LAPS privilege escalation)..."
        $lapsPasswordGuid = '9a9a021e-4a5b-11d1-a9c3-0000f80367c1'
        $lapsPasswordExpGuid = 'e362ed86-b728-0842-b27d-2dea7a9df218'

        $lapsComputers = Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd', nTSecurityDescriptor -ErrorAction SilentlyContinue | Where-Object { $_.'ms-Mcs-AdmPwd' }

        foreach ($computer in $lapsComputers) {
            foreach ($ace in $computer.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                $objectType = $ace.ObjectType.ToString().ToLower()

                if ($ace.ActiveDirectoryRights -match 'ReadProperty|GenericAll|GenericRead') {
                    if ($ace.ObjectType -eq [Guid]::Empty -or $objectType -eq $lapsPasswordGuid) {
                        Add-Evidence -Principal $principal -Reason "LAPS password read access on computer $($computer.Name) - allows local admin credential theft" -Context @{
                            Target            = 'LAPS Password'
                            ComputerName      = $computer.Name
                            DistinguishedName = $computer.DistinguishedName
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AccessControlType = $ace.AccessControlType
                            AttackPath        = 'Read LAPS password -> Local Admin -> Lateral Movement'
                        }
                    }
                }

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite') {
                    if ($ace.ObjectType -eq [Guid]::Empty -or $objectType -eq $lapsPasswordExpGuid) {
                        Add-Evidence -Principal $principal -Reason "LAPS password expiration write access on computer $($computer.Name) - can persist rogue credentials" -Context @{
                            Target            = 'LAPS Expiration Control'
                            ComputerName      = $computer.Name
                            DistinguishedName = $computer.DistinguishedName
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AccessControlType = $ace.AccessControlType
                            AttackPath        = 'Delay rotation -> Reuse stolen credentials -> Maintain access'
                        }
                    }
                }
            }
        }

        Write-Verbose "Checking for GMSA Password Reading Rights..."
        $gmsaAccounts = Get-ADServiceAccount -Filter * -Properties nTSecurityDescriptor, msDS-ManagedPassword -ErrorAction SilentlyContinue

        foreach ($gmsa in $gmsaAccounts) {
            if (-not $gmsa.nTSecurityDescriptor) { continue }
            foreach ($ace in $gmsa.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                $canRead = $false
                if ($ace.ActiveDirectoryRights -match 'GenericAll') { $canRead = $true }
                if ($ace.ActiveDirectoryRights -match 'ReadProperty' -or $ace.ActiveDirectoryRights -match 'GenericRead') {
                   $canRead = $true 
                }

                if ($canRead) {
                    Add-Evidence -Principal $principal -Reason "Admin Equivalence Edge: ReadGMSAPassword on $($gmsa.Name)" -Context @{
                        Target = $gmsa.Name
                        Risk = "Retrieve GMSA cleartext password"
                    }
                }
            }
        }

        Write-Verbose "Checking for Exchange Server escalation vectors..."
        try {
            $exchangeServers = Get-ADObject -Filter {objectClass -eq 'msExchExchangeServer'} -Properties distinguishedName, name -ErrorAction SilentlyContinue

            if ($exchangeServers) {
                $exchangeWinPerms = Get-ADGroup -Filter "Name -eq 'Exchange Windows Permissions'" -ErrorAction SilentlyContinue

                if ($exchangeWinPerms) {
                    $members = Get-ADGroupMember -Identity $exchangeWinPerms -ErrorAction SilentlyContinue

                    $domainObj = Get-ADObject -Identity $domainDN -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue

                    foreach ($ace in $domainObj.nTSecurityDescriptor.Access) {
                        if ($ace.IdentityReference.Value -like '*Exchange*') {
                            if ($ace.ActiveDirectoryRights -match 'WriteDacl') {
                                foreach ($member in $members) {
                                    Add-Evidence -Principal $member.SamAccountName -Reason "Member of 'Exchange Windows Permissions' with WriteDacl on domain - enables PrivExchange attack" -Context @{
                                        Target     = 'Exchange PrivExchange'
                                        Group      = 'Exchange Windows Permissions'
                                        Member     = $member.SamAccountName
                                        Rights     = 'WriteDacl on Domain Root'
                                        AttackPath = 'Compromise Exchange server -> Coerce authentication -> Relay to LDAP -> Grant DCSync rights -> Full domain compromise'
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Exchange enumeration failed: $_"
        }

        Write-Verbose "Checking DNS zone control for privilege escalation..."
        try {
            $dnsZones = Get-ADObject -Filter {objectClass -eq 'dnsZone'} -SearchBase "DC=DomainDnsZones,$domainDN" -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue

            foreach ($zone in $dnsZones) {
                foreach ($ace in $zone.nTSecurityDescriptor.Access) {
                    $principal = $ace.IdentityReference.Value

                    if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                    if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|CreateChild|DeleteChild') {
                        Add-Evidence -Principal $principal -Reason "Control over DNS zone '$($zone.Name)' - enables DNS poisoning and WPAD attacks" -Context @{
                            Target            = 'DNS Zone'
                            ZoneName          = $zone.Name
                            DistinguishedName = $zone.DistinguishedName
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AttackPath        = 'Modify DNS records -> Redirect traffic -> Capture credentials -> Lateral movement'
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "DNS zone enumeration failed: $_"
        }

        Write-Verbose "Checking GPO Linking Rights (WriteGPLink)..."
        $gpLinkGuid = "f30e3bc2-9ff0-11d1-b603-0000f80367c1"
        $domainObj = Get-ADObject -Identity $domainDN -Properties nTSecurityDescriptor
        foreach ($ace in $domainObj.nTSecurityDescriptor.Access) {
             $principal = $ace.IdentityReference.Value
             if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }
             
             if ($ace.ActiveDirectoryRights -match 'WriteProperty' -and ($ace.ObjectType -eq $gpLinkGuid -or $ace.ObjectType -eq [Guid]::Empty)) {
                 Add-Evidence -Principal $principal -Reason "Admin Equivalence Edge: WriteGPLink on Domain" -Context @{
                     Target = "Domain Root"
                     Attack = "Link malicious GPO to domain root"
                 }
             }
        }

        # Identify computers where broad groups have administrative control
        Write-Verbose "Evaluating computer objects for broad administrative control..."
        $computers = Get-ADComputer -Filter * -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue

        foreach ($computer in $computers) {
            if (-not $computer.nTSecurityDescriptor) { continue }

            foreach ($ace in $computer.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }
                if ($principal -notin $broadPrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite') {
                    $computerExposure += [PSCustomObject]@{
                        ComputerName      = $computer.Name
                        DistinguishedName = $computer.DistinguishedName
                        Principal         = $principal
                        Rights            = $ace.ActiveDirectoryRights.ToString()
                        AccessControlType = $ace.AccessControlType
                    }
                }
            }
        }

        Write-Verbose "Identifying computers with Unconstrained Delegation exposed to takeover..."
        # Exclude DCs (516), focus on member servers acting as honeypots
        $udComputers = Get-ADComputer -Filter "userAccountControl -band 524288 -and primaryGroupID -ne 516" -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue

        foreach ($computer in $udComputers) {
            if (-not $computer.nTSecurityDescriptor) { continue }
            foreach ($ace in $computer.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|ExtendedRight') {
                     Add-Evidence -Principal $principal -Reason "Control over Unconstrained Delegation Host '$($computer.Name)'" -Context @{
                        Target            = 'Unconstrained Delegation Honeypot'
                        ComputerName      = $computer.Name
                        DistinguishedName = $computer.DistinguishedName
                        Rights            = $ace.ActiveDirectoryRights.ToString()
                        Risk              = "Attacker can coerce DA auth, steal TGT, and impersonate DA"
                    }
                }
            }
        }

        Write-Verbose "Identifying unconstrained delegation vulnerabilities..."
        $unconstrainedDelegation = Get-ADComputer -Filter {(TrustedForDelegation -eq $true) -and (PrimaryGroupID -ne 516)} -Properties TrustedForDelegation, servicePrincipalName, OperatingSystem -ErrorAction SilentlyContinue

        foreach ($computer in $unconstrainedDelegation) {
            Add-Evidence -Principal "SYSTEM on $($computer.Name)" -Reason "Unconstrained Kerberos delegation on $($computer.Name) - allows ticket harvesting and impersonation attacks" -Context @{
                Target            = 'Unconstrained Delegation'
                ComputerName      = $computer.Name
                DistinguishedName = $computer.DistinguishedName
                OperatingSystem   = $computer.OperatingSystem
                AttackPath        = 'Compromise host -> Extract TGTs from memory -> Impersonate any user including Domain Admins'
                SPNs              = $computer.servicePrincipalName -join '; '
            }
        }

        $unconstrainedUsers = Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation, servicePrincipalName -ErrorAction SilentlyContinue

        foreach ($user in $unconstrainedUsers) {
            Add-Evidence -Principal $user.SamAccountName -Reason "User account '$($user.SamAccountName)' has unconstrained delegation - allows full Kerberos impersonation" -Context @{
                Target            = 'Unconstrained Delegation (User)'
                Account           = $user.SamAccountName
                DistinguishedName = $user.DistinguishedName
                AttackPath        = 'Compromise service account -> Request service ticket -> Impersonate any user'
                SPNs              = $user.servicePrincipalName -join '; '
            }
        }

        # Identify privileged service accounts and correlate with exposed hosts
        Write-Verbose "Discovering privileged service accounts and host bindings..."
        $privilegedGroupDNs = foreach ($name in $sensitiveGroupNames) {
            (Get-ADGroup -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue).DistinguishedName
        } | Where-Object { $_ }

        $serviceHostMap = @{}
        $serviceAccounts = Get-ADUser -LDAPFilter "(servicePrincipalName=*)" -Properties servicePrincipalName -ErrorAction SilentlyContinue

        foreach ($account in $serviceAccounts) {
            $groupMembership = Get-ADPrincipalGroupMembership -Identity $account -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DistinguishedName
            if (-not ($groupMembership | Where-Object { $_ -in $privilegedGroupDNs })) { continue }

            foreach ($spn in $account.servicePrincipalName) {
                $spnParts = $spn -split '/'
                if ($spnParts.Count -lt 2) { continue }

                $hostPart = ($spnParts[1] -split ':')[0]
                $hostName = ($hostPart -split '\.')[0].ToUpper()

                if (-not $serviceHostMap.ContainsKey($hostName)) {
                    $serviceHostMap[$hostName] = [System.Collections.ArrayList]::new()
                }
                [void]$serviceHostMap[$hostName].Add([PSCustomObject]@{
                    Account = $account.SamAccountName
                    SPN     = $spn
                })
            }
        }

        foreach ($exposure in $computerExposure) {
            $hostName = $exposure.ComputerName.ToUpper()
            if (-not $serviceHostMap.ContainsKey($hostName)) { continue }

            foreach ($serviceInfo in $serviceHostMap[$hostName]) {
                Add-Evidence -Principal $exposure.Principal -Reason "Privileged service account '$($serviceInfo.Account)' with SPN '$($serviceInfo.SPN)' runs on $($exposure.ComputerName) where $($exposure.Principal) have admin-equivalent control" -Context @{
                    ComputerName      = $exposure.ComputerName
                    ComputerDN        = $exposure.DistinguishedName
                    Principal         = $exposure.Principal
                    Rights            = $exposure.Rights
                    ServiceAccount    = $serviceInfo.Account
                    ServicePrincipal  = $serviceInfo.SPN
                }
            }
        }

        # Detect direct control of Domain Controller computer objects
        if ($domainControllersContainer) {
            Write-Verbose "Analyzing Domain Controller objects for takeover paths..."
            $dcComputers = Get-ADComputer -SearchBase $domainControllersContainer -Filter * -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue

            foreach ($dc in $dcComputers) {
                foreach ($ace in $dc.nTSecurityDescriptor.Access) {
                    $principal = $ace.IdentityReference.Value
                    if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                    if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteOwner|WriteDacl|GenericWrite') {
                        Add-Evidence -Principal $principal -Reason "Control over Domain Controller object $($dc.Name) via $($ace.ActiveDirectoryRights)" -Context @{
                            Target             = 'Domain Controller'
                            ComputerName       = $dc.Name
                            DistinguishedName  = $dc.DistinguishedName
                            Rights             = $ace.ActiveDirectoryRights.ToString()
                        }
                    }
                }
            }
        }

        # Identify linked GPOs affecting the domain or Domain Controllers
        Write-Verbose "Evaluating GPO control that can influence privileged scopes..."
        $gpoTargets = @($domain.DNSRoot)
        if ($domainControllersContainer) { $gpoTargets += $domainControllersContainer }

        $linkedGpos = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($target in $gpoTargets) {
            $inheritance = Get-GPInheritance -Target $target -ErrorAction SilentlyContinue
            if (-not $inheritance) { continue }
            foreach ($link in $inheritance.GpoLinks) {
                if ($link.Enabled -and $link.GpoId) { [void]$linkedGpos.Add($link.GpoId.Guid) }
            }
        }

        foreach ($gpoGuid in $linkedGpos) {
            $gpo = Get-GPO -Guid $gpoGuid -ErrorAction SilentlyContinue
            $gpoDisplayName = if ($gpo) { $gpo.DisplayName } else { $gpoGuid }
            $gpoObject = Get-ADObject -Identity "CN={$gpoGuid},CN=Policies,CN=System,$domainDN" -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $gpoObject) { continue }

            foreach ($ace in $gpoObject.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteOwner|WriteDacl|GenericWrite|WriteProperty') {
                    Add-Evidence -Principal $principal -Reason "Control over GPO '$gpoDisplayName' linked to privileged scope via $($ace.ActiveDirectoryRights)" -Context @{
                        Target            = 'Group Policy'
                        GpoName           = $gpoDisplayName
                        GpoGuid           = $gpoGuid
                        DistinguishedName = $gpoObject.DistinguishedName
                        Rights            = $ace.ActiveDirectoryRights.ToString()
                    }
                }
            }
        }

        # Detect ability to reset or modify highly privileged accounts
        Write-Verbose "Inspecting sensitive privileged accounts for takeover rights..."
        $passwordResetGuid = '00299570-246d-11d0-a768-00aa006e0529'

        foreach ($kvp in $sensitivePrincipals.GetEnumerator()) {
            $sam = $kvp.Key
            $dn = $kvp.Value
            $user = Get-ADUser -Identity $dn -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $user) { continue }

            foreach ($ace in $user.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                $objectType = $ace.ObjectType.ToString().ToLower()
                $canReset = $false

                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteOwner|WriteDacl|GenericWrite') { $canReset = $true }
                if ($ace.ActiveDirectoryRights -match 'ExtendedRight' -and ($ace.ObjectType -eq [Guid]::Empty -or $objectType -eq $passwordResetGuid)) { $canReset = $true }

                if ($canReset) {
                    Add-Evidence -Principal $principal -Reason "Takeover of privileged account $sam via $($ace.ActiveDirectoryRights)" -Context @{
                        Target            = 'Privileged Account'
                        Account           = $sam
                        DistinguishedName = $dn
                        Rights            = $ace.ActiveDirectoryRights.ToString()
                    }
                }
            }
        }

        # Identify group owners where privileged members are present
        $privilegedPrincipalDns = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($dn in $sensitivePrincipals.Values) { [void]$privilegedPrincipalDns.Add($dn) }
        foreach ($dn in $privilegedGroupDNs) { [void]$privilegedPrincipalDns.Add($dn) }

        Write-Verbose "Checking ownership of groups containing privileged members..."
        $groupsWithOwners = Get-ADGroup -Filter * -Properties Members, nTSecurityDescriptor -ErrorAction SilentlyContinue

        foreach ($group in $groupsWithOwners) {
            if (-not $group.Members -or -not $group.nTSecurityDescriptor) { continue }
            $hasPrivilegedMember = $false
            foreach ($memberDn in $group.Members) {
                if ($privilegedPrincipalDns.Contains($memberDn)) {
                    $hasPrivilegedMember = $true
                    break
                }
            }
            if (-not $hasPrivilegedMember) { continue }

            $ownerSid = $group.nTSecurityDescriptor.Owner
            if (-not $ownerSid) { continue }
            try { $owner = $ownerSid.Translate([System.Security.Principal.NTAccount]).Value } catch { $owner = $ownerSid.Value }

            if ($owner -in $legitimatePrincipals) { continue }

            Add-Evidence -Principal $owner -Reason "Owner of group '$($group.Name)' that contains privileged members" -Context @{
                Group              = $group.Name
                Owner              = $owner
                MembersInclude     = 'Privileged Principals'
            }
        }

        Write-Verbose "Auditing high-privilege built-in groups (Print Operators, Server Operators, etc.)..."
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

        # Track replication rights to identify full DCSync capability
        $dcsyncRights = @{
            'DS-Replication-Get-Changes'              = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            'DS-Replication-Get-Changes-All'          = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
            'DS-Replication-Get-Changes-In-Filtered-Set' = '89e95b76-444d-4c62-991a-0facbeda640c'
        }

        $replicationAccess = @{}
        $domainObject = Get-ADObject -Identity $domainDN -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue

        if ($domainObject) {
            foreach ($ace in $domainObject.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if (-not $replicationAccess.ContainsKey($principal)) { $replicationAccess[$principal] = [System.Collections.Generic.HashSet[string]]::new() }

                if ($ace.ActiveDirectoryRights -match 'GenericAll') { [void]$replicationAccess[$principal].Add('GenericAll') }

                if ($ace.ActiveDirectoryRights -match 'ExtendedRight|GenericAll') {
                    $objectType = $ace.ObjectType.ToString()
                    foreach ($rightName in $dcsyncRights.Keys) {
                        if ($ace.ActiveDirectoryRights -match 'GenericAll' -or $objectType -eq $dcsyncRights[$rightName]) {
                            [void]$replicationAccess[$principal].Add($rightName)
                        }
                    }
                }
            }

            foreach ($principal in $replicationAccess.Keys) {
                $rights = $replicationAccess[$principal]
                if ($rights.Contains('GenericAll') -or ($rights.Contains('DS-Replication-Get-Changes') -and $rights.Contains('DS-Replication-Get-Changes-All'))) {
                    Add-Evidence -Principal $principal -Reason "DCSync replication rights: $($rights -join ', ')" -Context @{
                        Target            = 'Domain Root'
                        Rights            = $rights -join ', '
                        Requirement       = 'DCSync requires Get-Changes and Get-Changes-All'
                    }
                }
            }
        }

        # Detect ability to change membership of privileged groups
        $memberAttributeGuid = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
        foreach ($groupName in $sensitiveGroupNames) {
            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $group) { continue }

            foreach ($ace in $group.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                $objectType = $ace.ObjectType.ToString().ToLower()
                $hasMembershipControl = $false

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                    if ($ace.ObjectType -eq [Guid]::Empty -or $objectType -eq $memberAttributeGuid) { $hasMembershipControl = $true }
                }
                if ($ace.ActiveDirectoryRights -match 'WriteDacl|WriteOwner|GenericAll') { $hasMembershipControl = $true }

                if ($hasMembershipControl) {
                    Add-Evidence -Principal $principal -Reason "Modify membership of $groupName via $($ace.ActiveDirectoryRights)" -Context @{
                        Group              = $groupName
                        Rights             = $ace.ActiveDirectoryRights.ToString()
                        AccessControlType  = $ace.AccessControlType
                    }
                }
            }
        }

        Write-Verbose "Checking for direct AddMember rights on privileged groups..."
        foreach ($groupName in @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')) {
            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $group) { continue }

            foreach ($ace in $group.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'Self|WriteMember') {
                    Add-Evidence -Principal $principal -Reason "AddMember/Self right on '$groupName' - can add any account to privileged group" -Context @{
                        Group              = $groupName
                        DistinguishedName  = $group.DistinguishedName
                        Rights             = $ace.ActiveDirectoryRights.ToString()
                        ObjectType         = $ace.ObjectType
                        AttackPath         = 'Add controlled account to group -> Inherit privileges -> Domain compromise'
                    }
                }
            }
        }

        Write-Verbose "Checking for weak password configurations on privileged accounts..."
        foreach ($kvp in $sensitivePrincipals.GetEnumerator()) {
            $sam = $kvp.Key
            $dn = $kvp.Value

            $user = Get-ADUser -Identity $dn -Properties UserAccountControl, PasswordNeverExpires, PasswordNotRequired -ErrorAction SilentlyContinue
            if (-not $user) { continue }

            $uac = $user.UserAccountControl

            if ($uac -band 0x0080) {
                Add-Evidence -Principal $sam -Reason "Privileged account '$sam' has reversible password encryption enabled - plaintext password retrieval possible" -Context @{
                    Target            = 'Weak Password Config'
                    Account           = $sam
                    DistinguishedName = $dn
                    Issue             = 'Reversible Encryption Enabled'
                    AttackPath        = 'DCSync or domain compromise -> Retrieve plaintext password -> Account takeover'
                }
            }

            if ($uac -band 0x0020) {
                Add-Evidence -Principal $sam -Reason "Privileged account '$sam' does not require a password - immediate takeover risk" -Context @{
                    Target            = 'Weak Password Config'
                    Account           = $sam
                    DistinguishedName = $dn
                    Issue             = 'Password Not Required'
                    AttackPath        = 'Set empty password -> Authenticate as user -> Full privileges'
                }
            }

            if ($user.PasswordNeverExpires) {
                Add-Evidence -Principal $sam -Reason "Privileged account '$sam' has non-expiring password - increases compromise window" -Context @{
                    Target            = 'Weak Password Config'
                    Account           = $sam
                    DistinguishedName = $dn
                    Issue             = 'Password Never Expires'
                    AttackPath        = 'Stale credentials remain valid indefinitely -> Extended attack window'
                }
            }
        }

        Write-Verbose "Checking for control over OUs containing privileged resources..."
        $privilegedOUs = [System.Collections.Generic.HashSet[string]]::new()

        foreach ($dn in $sensitivePrincipals.Values) {
            $ouPath = $dn -replace '^CN=[^,]+,' , ''
            [void]$privilegedOUs.Add($ouPath)
        }

        foreach ($groupDN in $privilegedGroupDNs) {
            $ouPath = $groupDN -replace '^CN=[^,]+,' , ''
            [void]$privilegedOUs.Add($ouPath)
        }

        foreach ($ouDN in $privilegedOUs) {
            try {
                $ou = Get-ADObject -Identity $ouDN -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
                if (-not $ou) { continue }

                foreach ($ace in $ou.nTSecurityDescriptor.Access) {
                    $principal = $ace.IdentityReference.Value

                    if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                    if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|CreateChild|DeleteChild') {
                        Add-Evidence -Principal $principal -Reason "Control over OU '$($ou.Name)' containing privileged objects - indirect privilege escalation" -Context @{
                            Target            = 'Organizational Unit'
                            OUName            = $ou.Name
                            DistinguishedName = $ouDN
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AttackPath        = 'Modify OU permissions -> Control child objects (users/groups) -> Privilege escalation'
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Failed to check OU $ouDN : $_"
            }
        }

        Write-Verbose "Identifying GenericAll/WriteOwner on computer objects for lateral movement..."
        $computerVulnerabilities = @()

        foreach ($computer in $computers) {
            if (-not $computer.nTSecurityDescriptor) { continue }

            foreach ($ace in $computer.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'GenericAll') {
                    $computerVulnerabilities += [PSCustomObject]@{
                        ComputerName = $computer.Name
                        Principal    = $principal
                        Rights       = $ace.ActiveDirectoryRights.ToString()
                    }
                }
            }
        }

        if ($computerVulnerabilities.Count -gt 0 -and $domainControllersContainer) {
            $dcNames = (Get-ADComputer -SearchBase $domainControllersContainer -Filter * -ErrorAction SilentlyContinue).Name

            foreach ($vuln in $computerVulnerabilities) {
                if ($vuln.ComputerName -in $dcNames) { continue }

                Add-Evidence -Principal $vuln.Principal -Reason "GenericAll on computer '$($vuln.ComputerName)' - enables resource-based constrained delegation and local admin access" -Context @{
                    Target       = 'Computer Object Control'
                    ComputerName = $vuln.ComputerName
                    Rights       = $vuln.Rights
                    AttackPath   = 'Write msDS-AllowedToActOnBehalfOfOtherIdentity -> S4U2Self impersonation -> Local admin -> Lateral movement'
                }
            }
        }

        foreach ($principal in $principalEvidence.Keys) {
            $evidence = $principalEvidence[$principal]
            $criticalEvidence = $evidence | Where-Object { $_.Reason -match 'Domain Root|AdminSDHolder|DCSync|Domain Controller|Privileged account|PKI|Unconstrained|AllowedToDelegate|AllowedToAct|ReadLAPSPassword|ReadGMSAPassword|WriteGPLink|Shadow Credentials|Certificate|Constrained Delegation|RBCD|LAPS password|DNS zone|Exchange|WriteSPN' }

            $severity = if ($criticalEvidence.Count -gt 0) { 'Critical' } else { 'High' }
            $severityLevel = if ($severity -eq 'Critical') { 4 } else { 3 }

            $finding = [PSCustomObject]@{
                Category       = 'Domain Admin Equivalence'
                Issue          = 'Domain Admin Equivalent Access Detected'
                Severity       = $severity
                SeverityLevel  = $severityLevel
                AffectedObject = $principal
                Description    = "Principal '$principal' holds permissions that provide Domain Admin-equivalent control: $($evidence.Reason -join '; ')."
                Impact         = 'Compromise of this principal would allow attackers to seize control of protected groups, the domain naming context, PKI infrastructure, or perform DCSync.'
                Remediation    = @"
Review and remove the excessive permissions listed in the evidence:
1. Restrict Domain Naming Context and AdminSDHolder control. (Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/adminsdholder-protected-accounts-and-groups)
2. Lock down AD CS/PKI containers (Certificate Templates/Authorities) in the Configuration Partition. (Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/certification-authority-security-guidance)
3. Audit and remove Unconstrained Delegation from non-DC computers. (Reference: https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
4. Restrict control over DNSAdmins and Print Operators. (Reference: https://aka.ms/PrivilegedGroups)
5. Remove Constrained/RBCD delegation paths to Domain Controllers. (Reference: https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
6. Audit LAPS and GMSA password read permissions - restrict to authorized admins only. (Reference: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
7. Restrict WriteGPLink permissions on Domain and OU objects. (Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/gp-permission-model)
8. Clear adminCount attribute for 'ghost' accounts and restore permission inheritance. (Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/adminsdholder-protected-accounts-and-groups)
9. Remove Shadow Credentials (msDS-KeyCredentialLink) if not using Windows Hello for Business. (Reference: https://posts.specterops.io/shadow-credentials-abusing-key-credential-link-translation-to-en-9d8f9fb12be8)
10. Clear SID History injection entries, especially same-domain SIDs. (Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-sidhistory)
"@
                Details        = @{
                    Evidence = $evidence
                    Domain   = $domain.DNSRoot
                }
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
