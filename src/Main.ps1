#region Main Audit Function

function Start-ADSecurityAudit {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ExportPath = ".",
        
        [Parameter()]
        [int]$InactiveDaysThreshold = 90,
        
        [Parameter()]
        [int]$PasswordAgeThreshold = 180,
        
        [Parameter()]
        [string[]]$IncludeTests,
        
        [Parameter()]
        [string[]]$ExcludeTests = @(),
        
        [Parameter()]
        [switch]$IncludePrivilegedUsersReport
    )
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    
    if (-not (Test-Path $ExportPath)) {
        Write-Error "Export path does not exist: $ExportPath"
        return
    }
    
    $testFile = Join-Path $ExportPath "test_write_$(Get-Random).tmp"
    try {
        [System.IO.File]::WriteAllText($testFile, "test")
        Remove-Item $testFile -Force
    }
    catch {
        Write-Error "Export path is not writable: $ExportPath. Error: $_"
        return
    }
    
    $logPath = Join-Path $ExportPath "ADSecurityAudit_Log_$timestamp.txt"
    $transcriptStarted = $false
    try {
        Start-Transcript -Path $logPath -Force -ErrorAction Stop
        $transcriptStarted = $true
    }
    catch {
        Write-Warning "Failed to start transcript at $logPath. Continuing without transcript. Error: $_"
    }
    
    try {
        $startTime = Get-Date
        Write-Host "`n==================================================" -ForegroundColor Cyan
        Write-Host "Active Directory Security Assessment" -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "Start Time: $startTime`n" -ForegroundColor Gray
        
        # Verify AD module is available
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Error "Active Directory PowerShell module is not installed. Please install RSAT tools."
            return
        }
        
        Import-Module ActiveDirectory -ErrorAction Stop
        
        Write-Verbose "Testing Domain Controller connectivity..."
        try {
            $domain = Get-ADDomain -ErrorAction Stop
            $dc = Get-ADDomainController -Discover -ErrorAction Stop
            
            if (-not (Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet)) {
                Write-Warning "Cannot reach Domain Controller: $($dc.HostName). Proceeding anyway..."
            }
            else {
                Write-Verbose "Successfully connected to Domain Controller: $($dc.HostName)"
            }
        }
        catch {
            Write-Error "Failed to connect to Active Directory Domain: $_"
            return
        }
        
        Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Green
        Write-Host "Domain DN: $($domain.DistinguishedName)`n" -ForegroundColor Green
        
        # Define all tests
        $allTests = @{
            'UserAccounts' = { Test-ADUserSecurity -InactiveDaysThreshold $InactiveDaysThreshold -PasswordAgeThreshold $PasswordAgeThreshold }
            'PrivilegedGroups' = { Test-ADPrivilegedGroups }
            'AdminSDHolder' = { Test-AdminSDHolder }
            'GroupPolicies' = { Test-ADGroupPolicies }
            'ReplicationSecurity' = { Test-ADReplicationSecurity }
            'DomainSecurity' = { Test-ADDomainSecurity }
            'DangerousPermissions' = { Test-ADDangerousPermissions }
            'CertificateServices' = { Test-ADCertificateServices }
            'KRBTGTAccount' = { Test-KRBTGTAccount -MaxPasswordAgeDays 180 }
            'DomainTrusts' = { Test-ADDomainTrusts }
            'LAPSDeployment' = { Test-LAPSDeployment }
            'AuditPolicyConfiguration' = { Test-AuditPolicyConfiguration }
            'ConstrainedDelegation' = { Test-ConstrainedDelegation }
        }
        
        # Determine which tests to run
        if ($IncludeTests) {
            $testsToRun = $allTests.Keys | Where-Object { $_ -in $IncludeTests -and $_ -notin $ExcludeTests }
        }
        else {
            $testsToRun = $allTests.Keys | Where-Object { $_ -notin $ExcludeTests }
        }
        
        # Run tests and collect findings
        $allFindings = @()
        
        foreach ($testName in $testsToRun) {
            Write-Host "Running test: $testName..." -ForegroundColor Yellow
            
            try {
                $testResults = & $allTests[$testName]
                $allFindings += $testResults
                
                $criticalCount = ($testResults | Where-Object { $_.Severity -eq 'Critical' }).Count
                $highCount = ($testResults | Where-Object { $_.Severity -eq 'High' }).Count
                $mediumCount = ($testResults | Where-Object { $_.Severity -eq 'Medium' }).Count
                $lowCount = ($testResults | Where-Object { $_.Severity -eq 'Low' }).Count
                
                Write-Host "  Found: $criticalCount Critical, $highCount High, $mediumCount Medium, $lowCount Low`n" -ForegroundColor Gray
            }
            catch {
                Write-Warning "Test '$testName' failed: $_"
            }
        }
        
        # Enumerate privileged users if requested
        $privilegedUsers = $null
        if ($IncludePrivilegedUsersReport) {
            Write-Host "Enumerating privileged users..." -ForegroundColor Yellow
            try {
                $privilegedUsers = Get-ADPrivilegedUsers
                Write-Host "  Found: $($privilegedUsers.Count) privileged users`n" -ForegroundColor Gray
            }
            catch {
                Write-Warning "Failed to enumerate privileged users: $_"
            }
        }
        
        $endTime = Get-Date
        $duration = $endTime - $startTime
        
        # Generate summary
        Write-Host "`n==================================================" -ForegroundColor Cyan
        Write-Host "Audit Summary" -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        
        $summary = @{
            Critical = ($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
            High = ($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
            Medium = ($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
            Low = ($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count
        }
        
        Write-Host "Total Findings: $($allFindings.Count)" -ForegroundColor White
        Write-Host "  Critical: $($summary.Critical)" -ForegroundColor Red
        Write-Host "  High: $($summary.High)" -ForegroundColor DarkRed
        Write-Host "  Medium: $($summary.Medium)" -ForegroundColor Yellow
        Write-Host "  Low: $($summary.Low)" -ForegroundColor Gray
        
        if ($privilegedUsers) {
            Write-Host "`nPrivileged Users: $($privilegedUsers.Count)" -ForegroundColor White
        }
        
        Write-Host "`nDuration: $($duration.TotalSeconds) seconds" -ForegroundColor Gray
        
        # Export results
        if ($allFindings.Count -gt 0) {
            # Export to JSON
            $jsonPath = Join-Path $ExportPath "AD_Security_Audit_$timestamp.json"
            $allFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
            Write-Host "`nDetailed report exported to: $jsonPath" -ForegroundColor Green
            
            # Export to HTML
            $htmlPath = Join-Path $ExportPath "AD_Security_Audit_$timestamp.html"
            Export-ADSecurityReportHTML -Findings $allFindings -OutputPath $htmlPath -Domain $domain.DNSRoot -Summary $summary -Duration $duration -PrivilegedUsers $privilegedUsers
            Write-Host "HTML report exported to: $htmlPath" -ForegroundColor Green
            
            # Export to CSV
            $csvPath = Join-Path $ExportPath "AD_Security_Audit_$timestamp.csv"
            $allFindings | Select-Object Category, Issue, Severity, AffectedObject, Description, Impact, Remediation, DetectedDate | 
                Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "CSV report exported to: $csvPath" -ForegroundColor Green
        }
        
        # Export privileged users report
        if ($privilegedUsers -and $privilegedUsers.Count -gt 0) {
            $privilegedUsersCsvPath = Join-Path $ExportPath "AD_Privileged_Users_$timestamp.csv"
            
            $privilegedUsers | Select-Object SamAccountName, DisplayName, UserPrincipalName, Enabled, PasswordLastSet, `
                PasswordNeverExpires, LastLogonDate, AdminCount, PrivilegedGroupsString, Title, Department, `
                DoesNotRequirePreAuth, TrustedForDelegation, HasSPN, SPNCount | 
                Export-Csv -Path $privilegedUsersCsvPath -NoTypeInformation -Encoding UTF8
            
            Write-Host "Privileged users report exported to: $privilegedUsersCsvPath" -ForegroundColor Green
        }
        
        Write-Host "`n==================================================" -ForegroundColor Cyan
        Write-Host "Audit Complete" -ForegroundColor Cyan
        Write-Host "==================================================`n" -ForegroundColor Cyan
        
        return $allFindings
    }
    finally {
        if ($transcriptStarted) {
            Stop-Transcript | Out-Null
        }
    }
}

