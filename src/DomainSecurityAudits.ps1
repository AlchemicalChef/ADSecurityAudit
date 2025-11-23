#region Domain Security Settings

function Test-ADDomainSecurity {
    [CmdletBinding()]
    param()
    
    Write-Verbose "Starting domain security settings audit..."
    $findings = @()
    
    try {
        $domain = Get-ADDomain
        
        # Check password policy
        $defaultPasswordPolicy = Get-ADDefaultDomainPasswordPolicy
        
        if ($defaultPasswordPolicy.MinPasswordLength -lt 14) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Weak Minimum Password Length'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = 'Default Domain Password Policy'
            $finding.Description = "Minimum password length is set to $($defaultPasswordPolicy.MinPasswordLength) characters."
            $finding.Impact = "Short passwords are easier to crack through brute-force and dictionary attacks."
            $finding.Remediation = "Increase minimum password length to at least 14 characters: Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 -Identity $($domain.DNSRoot)"
            $finding.Details = @{
                CurrentLength = $defaultPasswordPolicy.MinPasswordLength
                RecommendedLength = 14
            }
            $findings += $finding
        }
        
        if ($defaultPasswordPolicy.ComplexityEnabled -eq $false) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Password Complexity Disabled'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.AffectedObject = 'Default Domain Password Policy'
            $finding.Description = "Password complexity requirements are disabled."
            $finding.Impact = "Users can set simple, easily guessable passwords, significantly increasing the risk of compromise."
            $finding.Remediation = "Enable password complexity: Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled `$true -Identity $($domain.DNSRoot)"
            $finding.Details = @{
                ComplexityEnabled = $defaultPasswordPolicy.ComplexityEnabled
            }
            $findings += $finding
        }
        
        if ($defaultPasswordPolicy.ReversibleEncryptionEnabled -eq $true) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Reversible Encryption Enabled Domain-Wide'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.AffectedObject = 'Default Domain Password Policy'
            $finding.Description = "Reversible password encryption is enabled at the domain level."
            $finding.Impact = "All passwords are stored in a format equivalent to plaintext, making them easily retrievable by attackers."
            $finding.Remediation = "Disable reversible encryption immediately: Set-ADDefaultDomainPasswordPolicy -ReversibleEncryptionEnabled `$false -Identity $($domain.DNSRoot)"
            $finding.Details = @{
                ReversibleEncryptionEnabled = $defaultPasswordPolicy.ReversibleEncryptionEnabled
            }
            $findings += $finding
        }
        
        # Check domain functional level
        $domainLevel = $domain.DomainMode
        $forestLevel = (Get-ADForest).ForestMode
        
        $deprecatedLevels = @('Windows2000Domain', 'Windows2003Domain', 'Windows2008Domain', 'Windows2008R2Domain', 'Windows2012Domain')
        
        if ($domainLevel -in $deprecatedLevels) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Outdated Domain Functional Level'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = 'Domain Functional Level'
            $finding.Description = "Domain functional level is set to '$domainLevel', which is outdated."
            $finding.Impact = "Older functional levels lack modern security features and may support deprecated authentication protocols."
            $finding.Remediation = "Raise domain functional level after ensuring all DCs are running a supported OS: Set-ADDomainMode -Identity $($domain.DNSRoot) -DomainMode Windows2016Domain (or higher)"
            $finding.Details = @{
                CurrentLevel = $domainLevel
                ForestLevel = $forestLevel
                RecommendedLevel = 'Windows2016Domain or higher'
            }
            $findings += $finding
        }
        
        # Check for Recycle Bin (best practice)
        $recycleBinFeature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'"
        if ($recycleBinFeature.EnabledScopes.Count -eq 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'AD Recycle Bin Not Enabled'
            $finding.Severity = 'Low'
            $finding.SeverityLevel = 1
            $finding.AffectedObject = 'AD Recycle Bin Feature'
            $finding.Description = "Active Directory Recycle Bin is not enabled."
            $finding.Impact = "Deleted AD objects cannot be easily restored, making recovery from accidental deletions or attacks more difficult."
            $finding.Remediation = "Enable AD Recycle Bin: Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $($domain.Forest)"
            $finding.Details = @{
                Feature = 'Recycle Bin'
                Status = 'Disabled'
            }
            $findings += $finding
        }
        
        # Check for computers with old OS versions
        Write-Verbose "Checking for legacy operating systems..."
        $computers = Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate
        
        $legacyOS = @(
            'Windows XP', 'Windows Vista', 'Windows 7', 'Windows 8', 'Windows 8.1',
            'Windows Server 2003', 'Windows Server 2008', 'Windows Server 2012', 'Windows Server 2012 R2'
        )
        
        $legacyComputers = $computers | Where-Object {
            $os = $_.OperatingSystem
            if ($os) {
                foreach ($legacyPattern in $legacyOS) {
                    if ($os -match [regex]::Escape($legacyPattern)) {
                        return $true
                    }
                }
            }
            return $false
        }
        
        if ($legacyComputers) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Security'
            $finding.Issue = 'Legacy Operating Systems in Domain'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = 'Domain Computers'
            $finding.Description = "Found $($legacyComputers.Count) computer(s) running unsupported/legacy operating systems."
            $finding.Impact = "Legacy systems lack security updates and are vulnerable to known exploits, providing easy entry points for attackers."
            $finding.Remediation = "Upgrade or isolate legacy systems. Remove computer accounts for decommissioned systems."
            $finding.Details = @{
                Count = $legacyComputers.Count
                Computers = ($legacyComputers | Select-Object Name, OperatingSystem, LastLogonDate -First 50)
            }
            $findings += $finding
        }

        # Check AzureADSSOACC password rotation
        Write-Verbose "Checking Azure AD Seamless SSO computer accounts..."
        $azureSsoAccounts = Get-ADComputer -LDAPFilter "(samaccountname=AZUREADSSOACC$)" -Properties PasswordLastSet, Enabled

        foreach ($account in $azureSsoAccounts) {
            $passwordAge = if ($account.PasswordLastSet) { (Get-Date) - $account.PasswordLastSet } else { [TimeSpan]::MaxValue }

            if ($passwordAge.TotalDays -gt 30) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Domain Security'
                $finding.Issue = 'Stale AzureADSSOACC Kerberos Key'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $account.SamAccountName
                $finding.Description = "Azure AD Seamless SSO computer account password has not been rotated within the last 30 days."
                $finding.Impact = "Stale Kerberos decryption keys increase the risk of credential compromise for Seamless SSO."
                $finding.Remediation = "Roll over the Azure AD Seamless SSO Kerberos decryption key using Azure AD Connect or the Update-AzureADSSOForest PowerShell cmdlet. Reference: https://learn.microsoft.com/azure/active-directory/hybrid/tshoot-connect-sso#roll-over-the-kerberos-decryption-key"
                $finding.Details = @{
                    PasswordLastSet = $account.PasswordLastSet
                    PasswordAgeDays = if ($passwordAge -ne [TimeSpan]::MaxValue) { [int]$passwordAge.TotalDays } else { 'Unknown' }
                    Reference = 'https://learn.microsoft.com/azure/active-directory/hybrid/tshoot-connect-sso#roll-over-the-kerberos-decryption-key'
                }
                $findings += $finding
            }
        }
        
        Write-Verbose "Domain security settings audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during domain security audit: $_"
        throw
    }
}

#endregion

