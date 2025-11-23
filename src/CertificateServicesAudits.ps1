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
        
        foreach ($template in $certTemplates) {
            # ESC1: Template allows SAN and has overly permissive enrollment rights
            $enrollmentFlag = $template.'msPKI-Enrollment-Flag'
            $certNameFlag = $template.'msPKI-Certificate-Name-Flag'
            
            # Check if template allows Subject Alternative Name (SAN)
            if ($certNameFlag -band 1) {  # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Certificate Services'
                $finding.Issue = 'Certificate Template Allows Subject Alternative Name (ESC1)'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $template.Name
                $finding.Description = "Certificate template '$($template.Name)' allows enrollees to specify Subject Alternative Names, which can be exploited for privilege escalation."
                $finding.Impact = "Attackers can request certificates for arbitrary accounts (including Domain Admins) and authenticate as those users."
                $finding.Remediation = "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag or restrict enrollment permissions to only trusted administrators."
                $finding.Details = @{
                    DistinguishedName = $template.DistinguishedName
                    CertificateNameFlag = $certNameFlag
                    EnrollmentFlag = $enrollmentFlag
                }
                $findings += $finding
            }
            
            # ESC2: Template can be used for any purpose
            $ekus = $template.'msPKI-Certificate-Application-Policy'
            if (-not $ekus -or $ekus.Count -eq 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Certificate Services'
                $finding.Issue = 'Certificate Template with No EKU Restrictions (ESC2)'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $template.Name
                $finding.Description = "Certificate template '$($template.Name)' has no Extended Key Usage (EKU) restrictions, allowing certificates to be used for any purpose."
                $finding.Impact = "Certificates can be used for unintended purposes including authentication, code signing, or encryption."
                $finding.Remediation = "Configure specific EKUs for the template to limit certificate usage to intended purposes only."
                $finding.Details = @{
                    DistinguishedName = $template.DistinguishedName
                }
                $findings += $finding
            }
            
            # Check for low RA signatures required
            $raSignatures = $template.'msPKI-RA-Signature'
            if ($raSignatures -and $raSignatures -eq 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Certificate Services'
                $finding.Issue = 'Certificate Template Does Not Require RA Signatures'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $template.Name
                $finding.Description = "Certificate template '$($template.Name)' does not require Registration Authority signatures for high-value certificates."
                $finding.Impact = "Reduces oversight for certificate issuance and increases risk of unauthorized certificate requests."
                $finding.Remediation = "For sensitive templates, require at least one RA signature to add an approval layer."
                $finding.Details = @{
                    DistinguishedName = $template.DistinguishedName
                }
                $findings += $finding
            }
        }
        
        # Check Certificate Authority permissions
        try {
            $certAuthorities = Get-ADObject -SearchBase "CN=Enrollment Services,$pkiContainer" -Filter * -Properties * -ErrorAction Stop
            
            foreach ($ca in $certAuthorities) {
                $acl = Get-Acl -Path "AD:$($ca.DistinguishedName)" -ErrorAction SilentlyContinue
                
                if ($acl) {
                    foreach ($access in $acl.Access) {
                        # Check for dangerous permissions on CA
                        if ($access.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner' -and 
                            $access.IdentityReference -notmatch 'Enterprise Admins|Domain Admins|SYSTEM') {
                            
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = 'Certificate Services'
                            $finding.Issue = 'Overly Permissive CA Permissions'
                            $finding.Severity = 'Critical'
                            $finding.SeverityLevel = 4
                            $finding.AffectedObject = $ca.Name
                            $finding.Description = "Certificate Authority '$($ca.Name)' has overly permissive access granted to $($access.IdentityReference)."
                            $finding.Impact = "Unauthorized users could modify CA configuration, issue fraudulent certificates, or compromise the entire PKI infrastructure."
                            $finding.Remediation = "Remove excessive permissions and ensure only Enterprise Admins and CA administrators have full control."
                            $finding.Details = @{
                                DistinguishedName = $ca.DistinguishedName
                                Identity = $access.IdentityReference
                                Rights = $access.ActiveDirectoryRights
                            }
                            $findings += $finding
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

