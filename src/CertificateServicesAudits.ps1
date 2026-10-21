#region Certificate Services (AD CS) Audits

function Test-ADCertificateServices {
    <#
    .SYNOPSIS
        Audits AD CS certificate templates and CAs for ESC1/ESC2/ESC3/ESC7.
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Starting AD Certificate Services security audit..."
    $findings = @()

    $lowPrivilegedPrincipals = @(
        'Authenticated Users'
        'Domain Users'
        'Domain Computers'
        'Everyone'
    )

    try {
        # Check if AD CS is installed
        $__adServer = Get-ADSecurityAuditTargetServerValue
        $configContext = Get-ADRootDSEValue -Property configurationNamingContext -Server $__adServer
        $pkiContainer = "CN=Public Key Services,CN=Services,$configContext"
        
        try {
            # -SearchScope OneLevel, not the default Subtree - see the
            # matching comment in CertificateServicesExtendedAudits.ps1.
            # Subtree would also return the "Certificate Templates"
            # container object itself, which has no template attributes
            # and would otherwise be silently iterated as if it were a
            # real template.
            $certTemplates = Get-ADObject -SearchBase "CN=Certificate Templates,$pkiContainer" -SearchScope OneLevel -Filter * -Properties * -Server $__adServer -ErrorAction Stop
        }
        catch {
            Write-Verbose "AD Certificate Services not found or accessible. Skipping AD CS audit."
            return $findings
        }
        
        Write-Verbose "Analyzing $($certTemplates.Count) certificate templates..."
        
        # Get the domain for checking enrollment permissions
        $domain = Get-ADDomain -Server $__adServer
        
        # Define low-privileged enrollment principals that make ESC1 exploitable
        $lowPrivilegedPrincipals = @(
            'Authenticated Users'
            'Domain Users'
            'Domain Computers'
            'Everyone'
        )
        
        foreach ($template in $certTemplates) {
            # Get template name for reporting
            $templateName = $template.Name
            if ($template.displayName) {
                $templateName = $template.displayName
            }
            
            # Get enrollment permissions
            #
            # Get-ADObject -Properties nTSecurityDescriptor, not
            # Get-Acl -Path "AD:...": Get-Acl against the "AD:" PSDrive
            # has NO -Server parameter at all and reads via whatever
            # domain/DC the AD: drive itself defaults to (the calling
            # session's ambient domain) - completely bypassing this
            # module's -Server override, unlike every other AD read here.
            # nTSecurityDescriptor returns the identical
            # ActiveDirectorySecurity object type (.Access, etc.) via a
            # real Get-AD* cmdlet, which IS -Server-aware.
            $templateAcl = $null
            try {
                $templateAcl = (Get-ADObject -Identity $template.DistinguishedName -Properties nTSecurityDescriptor -Server $__adServer -ErrorAction Stop).nTSecurityDescriptor
            }
            catch {
                Write-Verbose "Could not get ACL for template '$templateName': $_"
            }
            
            # Check if low-privileged users can enroll
            $hasLowPrivEnrollment = $false
            $enrollmentPrincipals = @()
            
            if ($templateAcl) {
                foreach ($ace in $templateAcl.Access) {
                    # Check for Enroll or AutoEnroll rights
                    # ExtendedRight with specific GUIDs: 
                    # Enroll: 0e10c968-78fb-11d2-90d4-00c04f79dc55
                    # AutoEnroll: a05b8cc2-17bc-4802-a710-e7c15ab866a2
                    if ($ace.ActiveDirectoryRights -match 'ExtendedRight|GenericAll') {
                        $principalName = $ace.IdentityReference.Value
                        
                        foreach ($lowPriv in $lowPrivilegedPrincipals) {
                            if ($principalName -match [regex]::Escape($lowPriv)) {
                                $hasLowPrivEnrollment = $true
                                $enrollmentPrincipals += $principalName
                            }
                        }
                    }
                }
            }
            # A template can grant the same low-priv principal enrollment
            # via more than one ACE (e.g. separate Enroll and AutoEnroll
            # extended-right ACEs) - dedupe so the same name doesn't appear
            # twice in one finding's principal list.
            $enrollmentPrincipals = @($enrollmentPrincipals | Select-Object -Unique)
            
            # ESC1: Template allows SAN AND has overly permissive enrollment rights
            $enrollmentFlag = $template.'msPKI-Enrollment-Flag'
            $certNameFlag = $template.'msPKI-Certificate-Name-Flag'
            
            # Check if template allows Subject Alternative Name (SAN)
            # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1
            if ($certNameFlag -band 1) {
                # Only critical if low-privileged users can enroll
                if ($hasLowPrivEnrollment) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Certificate Services'
                    $finding.Issue = 'Certificate Template Allows Subject Alternative Name (ESC1)'
                    $finding.Severity = 'Critical'
                    $finding.SeverityLevel = 4
                    $finding.AffectedObject = $templateName
                    $finding.Description = "Certificate template '$templateName' allows enrollees to specify Subject Alternative Names AND allows enrollment by low-privileged principals ($($enrollmentPrincipals -join ', ')). This is a critical ESC1 vulnerability."
                    $finding.Impact = "Attackers can request certificates for arbitrary accounts (including Domain Admins) and authenticate as those users."
                    $finding.Remediation = "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag OR restrict enrollment permissions to only trusted administrators. Current low-priv enrollers: $($enrollmentPrincipals -join ', ')"
                    $finding.EstimatedEffort = 'Medium - requires disabling "supply subject in request" or restricting enrollment rights, and confirming which systems currently request from this template before changing it.'
                    $finding.KnownRisks = 'Disabling attacker-controllable SAN (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) can break legitimate workflows that rely on supplying a SAN at request time, such as some non-Windows or automated enrollment clients.'
                    $finding.BackupRollback = 'Moderate - AD CS templates are versioned, so a prior version''s settings can be restored and republished; however, any certificates already issued during the vulnerable window remain valid until revoked or expired, so this isn''t a full rollback of the exposure itself.'
                    $finding.Details = @{
                        DistinguishedName = $template.DistinguishedName
                        CertificateNameFlag = $certNameFlag
                        EnrollmentFlag = $enrollmentFlag
                        EnrollmentPrincipals = $enrollmentPrincipals -join '; '
                        ESCType = 'ESC1'
                    }
                    $findings += $finding
                }
                else {
                    # SAN allowed but enrollment is restricted - lower severity warning
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Certificate Services'
                    $finding.Issue = 'Certificate Template Allows Subject Alternative Name (Restricted)'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $templateName
                    $finding.Description = "Certificate template '$templateName' allows enrollees to specify Subject Alternative Names, but enrollment appears restricted to privileged users."
                    $finding.Impact = "If enrollment permissions are weakened, this template could become an ESC1 vulnerability."
                    $finding.Remediation = "Consider removing the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag if not required. Monitor enrollment permissions."
                    $finding.EstimatedEffort = 'Medium - same underlying mechanism as the unrestricted ESC1 finding, but exposure is narrower (fewer principals can enroll), so validate the smaller set of dependent systems before changing.'
                    $finding.KnownRisks = 'Disabling attacker-controllable SAN can break legitimate workflows among the restricted set of principals that currently rely on supplying a SAN at request time.'
                    $finding.BackupRollback = 'Moderate - restore a prior template version if a legitimate workflow breaks; certificates already issued remain valid until revoked or expired.'
                    $finding.Details = @{
                        DistinguishedName = $template.DistinguishedName
                        CertificateNameFlag = $certNameFlag
                        EnrollmentFlag = $enrollmentFlag
                    }
                    $findings += $finding
                }
            }
            
            # ESC2: Template can be used for any purpose (no EKU restrictions)
            $ekus = $template.'msPKI-Certificate-Application-Policy'
            $ekusV1 = $template.'pKIExtendedKeyUsage'
            
            # Check for no EKU or "Any Purpose" EKU (2.5.29.37.0)
            $hasNoEKU = (-not $ekus -or $ekus.Count -eq 0) -and (-not $ekusV1 -or $ekusV1.Count -eq 0)
            $hasAnyPurpose = ($ekus -contains '2.5.29.37.0') -or ($ekusV1 -contains '2.5.29.37.0')
            
            if ($hasNoEKU -or $hasAnyPurpose) {
                $severity = if ($hasLowPrivEnrollment) { 'High' } else { 'Medium' }
                $severityLevel = if ($hasLowPrivEnrollment) { 3 } else { 2 }
                
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Certificate Services'
                $finding.Issue = 'Certificate Template with No EKU Restrictions (ESC2)'
                $finding.Severity = $severity
                $finding.SeverityLevel = $severityLevel
                $finding.AffectedObject = $templateName
                $finding.Description = "Certificate template '$templateName' has no Extended Key Usage (EKU) restrictions or allows 'Any Purpose', allowing certificates to be used for any purpose including authentication."
                $finding.Impact = "Certificates can be used for unintended purposes including client authentication, code signing, or encryption."
                $finding.Remediation = "Configure specific EKUs for the template to limit certificate usage to intended purposes only."
                $finding.EstimatedEffort = 'Medium - requires validating which application relies on the current broad EKU set (e.g. a cert used for both client authentication and code signing) before narrowing it.'
                $finding.KnownRisks = 'Restricting EKUs can break legitimate uses that rely on the current broad EKU set.'
                $finding.BackupRollback = 'Moderate - restore the template''s prior EKU configuration (via a template export/backup, e.g. PSPKI or certutil) if a legitimate use breaks; certificates already issued remain valid until revoked or expired.'
                $finding.Details = @{
                    DistinguishedName = $template.DistinguishedName
                    HasNoEKU = $hasNoEKU
                    HasAnyPurpose = $hasAnyPurpose
                    LowPrivEnrollment = $hasLowPrivEnrollment
                    ESCType = 'ESC2'
                }
                $findings += $finding
            }
            
            # ESC3: Enrollment Agent template
            # Certificate Request Agent OID: 1.3.6.1.4.1.311.20.2.1
            $isEnrollmentAgent = ($ekus -contains '1.3.6.1.4.1.311.20.2.1') -or ($ekusV1 -contains '1.3.6.1.4.1.311.20.2.1')
            
            if ($isEnrollmentAgent -and $hasLowPrivEnrollment) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Certificate Services'
                $finding.Issue = 'Enrollment Agent Template with Low-Privilege Enrollment (ESC3)'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $templateName
                $finding.Description = "Certificate template '$templateName' is an Enrollment Agent template that allows enrollment by low-privileged principals."
                $finding.Impact = "Attackers can obtain an Enrollment Agent certificate and use it to enroll for certificates on behalf of other users, including privileged accounts."
                $finding.Remediation = "Restrict enrollment permissions to only trusted Enrollment Agents. Implement enrollment agent restrictions at the CA level."
                $finding.EstimatedEffort = 'Medium - restricting who can enroll for the enrollment-agent template requires confirming which automated on-behalf-of enrollment process currently uses it.'
                $finding.KnownRisks = 'Restricting enrollment agent template access can break an automated on-behalf-of enrollment process that currently relies on the broader access.'
                $finding.BackupRollback = 'Easy - restore the enrollment permission on the template if needed; effective immediately.'
                $finding.Details = @{
                    DistinguishedName = $template.DistinguishedName
                    EnrollmentPrincipals = $enrollmentPrincipals -join '; '
                    ESCType = 'ESC3'
                }
                $findings += $finding
            }
            
            # Check for low RA signatures required
            $raSignatures = $template.'msPKI-RA-Signature'
            if ($raSignatures -eq 0 -and $hasLowPrivEnrollment) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Certificate Services'
                $finding.Issue = 'Certificate Template Does Not Require RA Signatures'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $templateName
                $finding.Description = "Certificate template '$templateName' does not require Registration Authority signatures and allows low-privileged enrollment."
                $finding.Impact = "Reduces oversight for certificate issuance and increases risk of unauthorized certificate requests."
                $finding.Remediation = "For sensitive templates, require at least one RA signature to add an approval layer."
                $finding.EstimatedEffort = 'Medium - enforcing a required-signature count needs coordination with whichever process actually enrolls from this template, since that process may not yet have an authorized enrollment-agent certificate in its chain.'
                $finding.KnownRisks = 'Enforcing an RA signature requirement will break any enrollment workflow that doesn''t already have an authorized enrollment-agent certificate, until that workflow is updated.'
                $finding.BackupRollback = 'Easy - revert the required-signature count to 0 on the template; effective immediately for new requests.'
                $finding.Details = @{
                    DistinguishedName = $template.DistinguishedName
                    RASignaturesRequired = $raSignatures
                }
                $findings += $finding
            }

            # ESC17: Server Authentication EKU + enrollee-supplied SAN +
            # low-priv enrollment + no manager approval. Disclosed by the
            # Digitrace team (Alexander Neff & Phil Knüfer) in early 2026 -
            # new enough that even commercial AD CS scanners generally only
            # "detect and flag" it rather than fully validate it. A near-
            # identical shape to ESC1 above, checking for Server
            # Authentication EKU (1.3.6.1.5.5.7.3.1) instead of Client
            # Authentication - a template like this lets any low-privileged
            # enrollee obtain a valid, trusted TLS certificate for ANY
            # internal hostname (WSUS, Exchange, SCCM, etc.), which combined
            # with DNS zone abuse enables a rogue-server-with-a-trusted-cert
            # attack against every client that trusts that hostname. Notably,
            # an administrator who "fixed" ESC1 by switching a template's EKU
            # from Client to Server Authentication - without also removing
            # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT - has unknowingly created
            # exactly this exposure, so this specifically catches templates
            # that look "already remediated" for ESC1 but aren't.
            $hasServerAuthEku = ($ekus -contains '1.3.6.1.5.5.7.3.1') -or ($ekusV1 -contains '1.3.6.1.5.5.7.3.1')
            # CT_FLAG_PEND_ALL_REQUESTS = 0x2 (manager approval required);
            # its absence means certificates are issued automatically.
            $noManagerApproval = -not ($enrollmentFlag -band 0x2)

            if ($hasServerAuthEku -and ($certNameFlag -band 1) -and $hasLowPrivEnrollment -and $noManagerApproval) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Certificate Services'
                $finding.Issue = 'Certificate Template Allows Arbitrary Server Certificate (ESC17)'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $templateName
                $finding.Description = "Certificate template '$templateName' has the Server Authentication EKU, allows enrollees to specify the Subject Alternative Name, requires no manager approval, and is enrollable by low-privileged principals ($($enrollmentPrincipals -join ', '))."
                $finding.Impact = "Any low-privileged enrollee can obtain a valid, CA-trusted TLS certificate for ANY internal hostname - including WSUS, Exchange, SCCM, or SharePoint servers - regardless of who actually owns that hostname. Combined with DNS zone manipulation (see DNS Security findings), this lets an attacker stand up a rogue server that clients trust as genuine over HTTPS, bypassing the protection HTTPS is meant to provide entirely. A template 'fixed' for ESC1 by simply changing its EKU from Client to Server Authentication, without also removing enrollee-supplied-subject or restricting enrollment, is exactly this exposure."
                $finding.Remediation = "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from this template, OR restrict enrollment to only the specific service accounts/administrators that legitimately need a server certificate from it, OR require manager approval so each request is reviewed before issuance."
                $finding.EstimatedEffort = 'Medium - same considerations as ESC1: confirm which systems currently request server certificates from this template before narrowing SAN supply or enrollment rights.'
                $finding.KnownRisks = 'Restricting enrollee-supplied SAN or enrollment rights can break legitimate automated server-certificate provisioning that currently relies on this template''s current configuration.'
                $finding.BackupRollback = 'Moderate - AD CS templates are versioned, so a prior version''s settings can be restored and republished; certificates already issued during the vulnerable window remain valid until revoked or expired.'
                $finding.Details = @{
                    DistinguishedName    = $template.DistinguishedName
                    CertificateNameFlag  = $certNameFlag
                    EnrollmentFlag       = $enrollmentFlag
                    EnrollmentPrincipals = $enrollmentPrincipals -join '; '
                    ESCType              = 'ESC17'
                }
                $findings += $finding
            }
        }
        
        # Check Certificate Authority permissions (ESC7)
        try {
            # -SearchScope OneLevel, not the default Subtree - a Subtree
            # search also returns the "Enrollment Services" container
            # object itself (no dNSHostName/cACertificate/real ACL of
            # interest), which was previously iterated here as if it were
            # a real CA, producing a bogus/confusing ACL check and
            # potential finding attributed to a "CA" named "Enrollment
            # Services" that isn't actually a Certificate Authority.
            $certAuthorities = Get-ADObject -SearchBase "CN=Enrollment Services,$pkiContainer" -SearchScope OneLevel -Filter * -Properties * -Server $__adServer -ErrorAction Stop
            
            foreach ($ca in $certAuthorities) {
                $acl = $null
                try {
                    # Get-ADObject -Properties nTSecurityDescriptor, not
                    # Get-Acl -Path "AD:..." - see the matching comment
                    # above on the template ACL read for why.
                    $acl = (Get-ADObject -Identity $ca.DistinguishedName -Properties nTSecurityDescriptor -Server $__adServer -ErrorAction Stop).nTSecurityDescriptor
                }
                catch {
                    Write-Verbose "Could not get ACL for CA '$($ca.Name)': $_"
                }

                if ($acl) {
                    # A CA's ACL can grant the same principal the same
                    # dangerous right via more than one ACE (one per object
                    # type) - dedupe per check so a repeated ACE doesn't
                    # produce a repeated finding.
                    $__seenEsc7Hit = @{}
                    $__seenLowPrivCaHit = @{}
                    foreach ($access in $acl.Access) {
                        # Check for dangerous permissions on CA
                        if ($access.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner' -and 
                            $access.IdentityReference -notmatch 'Enterprise Admins|Domain Admins|SYSTEM|Administrators') {
                            
                            $__esc7Key = "$($access.IdentityReference)|$($access.ActiveDirectoryRights)"
                            if (-not $__seenEsc7Hit.ContainsKey($__esc7Key)) {
                                $__seenEsc7Hit[$__esc7Key] = $true

                                $finding = [ADSecurityFinding]::new()
                                $finding.Category = 'Certificate Services'
                                $finding.Issue = 'Overly Permissive CA Permissions (ESC7)'
                                $finding.Severity = 'Critical'
                                $finding.SeverityLevel = 4
                                $finding.AffectedObject = $ca.Name
                                $finding.Description = "Certificate Authority '$($ca.Name)' has overly permissive access granted to $($access.IdentityReference)."
                                $finding.Impact = "Unauthorized users could modify CA configuration, enable vulnerable templates, issue fraudulent certificates, or compromise the entire PKI infrastructure."
                                $finding.Remediation = "Remove excessive permissions and ensure only Enterprise Admins and CA administrators have full control."
                                $finding.EstimatedEffort = 'Medium - removing Manage CA / Manage Certificates rights from an unexpected principal on the CA object''s own ACL; confirm with the PKI team it isn''t a legitimate delegated administrator.'
                                $finding.KnownRisks = 'Procedural - confirm the principal isn''t an active, legitimate delegated CA administrator before removing their rights.'
                                $finding.BackupRollback = 'Easy - re-add the removed permission via the CA console''s Security tab; effective immediately, no data loss.'
                                $finding.Details = @{
                                    DistinguishedName = $ca.DistinguishedName
                                    Identity = $access.IdentityReference.Value
                                    Rights = $access.ActiveDirectoryRights.ToString()
                                    ESCType = 'ESC7'
                                }
                                $findings += $finding
                            }
                        }
                        
                        # Check for ManageCA or ManageCertificates permissions
                        if ($access.ActiveDirectoryRights -match 'ExtendedRight') {
                            # ManageCA: 0e10c968-78fb-11d2-90d4-00c04f79dc55
                            # ManageCertificates: a05b8cc2-17bc-4802-a710-e7c15ab866a2
                            foreach ($lowPriv in $lowPrivilegedPrincipals) {
                                if ($access.IdentityReference.Value -match [regex]::Escape($lowPriv)) {
                                    $__lowPrivCaKey = "$($access.IdentityReference)|$($access.ActiveDirectoryRights)"
                                    if ($__seenLowPrivCaHit.ContainsKey($__lowPrivCaKey)) { break }
                                    $__seenLowPrivCaHit[$__lowPrivCaKey] = $true

                                    $finding = [ADSecurityFinding]::new()
                                    $finding.Category = 'Certificate Services'
                                    $finding.Issue = 'Low-Privilege CA Management Rights'
                                    $finding.Severity = 'High'
                                    $finding.SeverityLevel = 3
                                    $finding.AffectedObject = $ca.Name
                                    $finding.Description = "Certificate Authority '$($ca.Name)' grants extended rights to low-privileged principal '$($access.IdentityReference)'."
                                    $finding.Impact = "Low-privileged users may be able to manage the CA or certificates, potentially approving pending requests or modifying CA configuration."
                                    $finding.Remediation = "Review and remove CA management rights from low-privileged principals."
                                    $finding.EstimatedEffort = 'Medium - removing the CA Manager role assignment from an unexpected principal via the Certification Authority console; confirm the principal doesn''t actively perform day-to-day CA management first.'
                                    $finding.KnownRisks = 'Procedural - low technical risk unless the principal genuinely manages CA operations, in which case they lose that capability until re-added.'
                                    $finding.BackupRollback = 'Easy - re-add the role assignment via the CA console; effective immediately, no data loss.'
                                    $finding.Details = @{
                                        DistinguishedName = $ca.DistinguishedName
                                        Identity = $access.IdentityReference.Value
                                        Rights = $access.ActiveDirectoryRights.ToString()
                                    }
                                    $findings += $finding
                                    break
                                }
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not enumerate Certificate Authorities: $_"
        }
        
        Write-Verbose "AD Certificate Services audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during AD CS audit: $_"
        throw
    }
}

#endregion
