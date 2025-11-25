#region Certificate Services (AD CS) Audits

function Test-ADCertificateServices {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting AD Certificate Services security audit..."
    $findings = @()
    
    try {
        # Check if AD CS is installed
        $configContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
        $pkiContainer = "CN=Public Key Services,CN=Services,$configContext"
        
        try {
            $certTemplates = Get-ADObject -SearchBase "CN=Certificate Templates,$pkiContainer" -Filter * -Properties * -ErrorAction Stop
        }
        catch {
            Write-Verbose "AD Certificate Services not found or accessible. Skipping AD CS audit."
            return $findings
        }
        
        Write-Verbose "Analyzing $($certTemplates.Count) certificate templates..."
        
        # Get the domain for checking enrollment permissions
        $domain = Get-ADDomain
        
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
            $templateAcl = $null
            try {
                $templateAcl = Get-Acl -Path "AD:$($template.DistinguishedName)" -ErrorAction SilentlyContinue
            }
            catch {
                Write-Verbose "Could not get ACL for template '$templateName'"
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
                $finding.Details = @{
                    DistinguishedName = $template.DistinguishedName
                    RASignaturesRequired = $raSignatures
                }
                $findings += $finding
            }
        }
        
        # Check Certificate Authority permissions (ESC7)
        try {
            $certAuthorities = Get-ADObject -SearchBase "CN=Enrollment Services,$pkiContainer" -Filter * -Properties * -ErrorAction Stop
            
            foreach ($ca in $certAuthorities) {
                $acl = Get-Acl -Path "AD:$($ca.DistinguishedName)" -ErrorAction SilentlyContinue
                
                if ($acl) {
                    foreach ($access in $acl.Access) {
                        # Check for dangerous permissions on CA
                        if ($access.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner' -and 
                            $access.IdentityReference -notmatch 'Enterprise Admins|Domain Admins|SYSTEM|Administrators') {
                            
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = 'Certificate Services'
                            $finding.Issue = 'Overly Permissive CA Permissions (ESC7)'
                            $finding.Severity = 'Critical'
                            $finding.SeverityLevel = 4
                            $finding.AffectedObject = $ca.Name
                            $finding.Description = "Certificate Authority '$($ca.Name)' has overly permissive access granted to $($access.IdentityReference)."
                            $finding.Impact = "Unauthorized users could modify CA configuration, enable vulnerable templates, issue fraudulent certificates, or compromise the entire PKI infrastructure."
                            $finding.Remediation = "Remove excessive permissions and ensure only Enterprise Admins and CA administrators have full control."
                            $finding.Details = @{
                                DistinguishedName = $ca.DistinguishedName
                                Identity = $access.IdentityReference.Value
                                Rights = $access.ActiveDirectoryRights.ToString()
                                ESCType = 'ESC7'
                            }
                            $findings += $finding
                        }
                        
                        # Check for ManageCA or ManageCertificates permissions
                        if ($access.ActiveDirectoryRights -match 'ExtendedRight') {
                            # ManageCA: 0e10c968-78fb-11d2-90d4-00c04f79dc55
                            # ManageCertificates: a05b8cc2-17bc-4802-a710-e7c15ab866a2
                            foreach ($lowPriv in $lowPrivilegedPrincipals) {
                                if ($access.IdentityReference.Value -match [regex]::Escape($lowPriv)) {
                                    $finding = [ADSecurityFinding]::new()
                                    $finding.Category = 'Certificate Services'
                                    $finding.Issue = 'Low-Privilege CA Management Rights'
                                    $finding.Severity = 'High'
                                    $finding.SeverityLevel = 3
                                    $finding.AffectedObject = $ca.Name
                                    $finding.Description = "Certificate Authority '$($ca.Name)' grants extended rights to low-privileged principal '$($access.IdentityReference)'."
                                    $finding.Impact = "Low-privileged users may be able to manage the CA or certificates, potentially approving pending requests or modifying CA configuration."
                                    $finding.Remediation = "Review and remove CA management rights from low-privileged principals."
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
