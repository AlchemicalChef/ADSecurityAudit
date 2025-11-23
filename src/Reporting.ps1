function Export-ADSecurityReportHTML {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Findings,
        
        [Parameter(Mandatory)]
        [string]$OutputPath,
        
        [Parameter(Mandatory)]
        [string]$Domain,
        
        [Parameter(Mandatory)]
        [hashtable]$Summary,
        
        [Parameter(Mandatory)]
        [timespan]$Duration,
        
        [Parameter()]
        [array]$PrivilegedUsers = $null
    )
    
    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Group findings by severity
    $criticalFindings = $Findings | Where-Object { $_.Severity -eq 'Critical' } | Sort-Object Category
    $highFindings = $Findings | Where-Object { $_.Severity -eq 'High' } | Sort-Object Category
    $mediumFindings = $Findings | Where-Object { $_.Severity -eq 'Medium' } | Sort-Object Category
    $lowFindings = $Findings | Where-Object { $_.Severity -eq 'Low' } | Sort-Object Category
    
    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Security Assessment Report - $(HtmlEncode $Domain)</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 20px rgba(0,0,0,0.1); border-radius: 8px; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 15px; margin-bottom: 20px; }
        h2 { color: #34495e; margin-top: 30px; margin-bottom: 15px; padding: 10px; background: #ecf0f1; border-left: 4px solid #3498db; }
        h3 { color: #555; margin-top: 20px; margin-bottom: 10px; }
        .header-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px; }
        .header-info div { padding: 10px; }
        .header-info strong { display: block; color: #7f8c8d; font-size: 0.9em; margin-bottom: 5px; }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .summary-card { padding: 25px; border-radius: 8px; color: white; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .summary-card .count { font-size: 3em; font-weight: bold; margin-bottom: 10px; }
        .summary-card .label { font-size: 1.1em; text-transform: uppercase; letter-spacing: 1px; }
        .critical-card { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
        .high-card { background: linear-gradient(135deg, #e67e22 0%, #d35400 100%); }
        .medium-card { background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); }
        .low-card { background: linear-gradient(135deg, #95a5a6 0%, #7f8c8d 100%); }
        .finding { margin-bottom: 25px; padding: 20px; border-radius: 5px; border-left: 5px solid; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .finding.critical { border-left-color: #e74c3c; background: #fef5f5; }
        .finding.high { border-left-color: #e67e22; background: #fef9f5; }
        .finding.medium { border-left-color: #f39c12; background: #fffcf5; }
        .finding.low { border-left-color: #95a5a6; background: #f9fafb; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 10px; }
        .finding-title { font-size: 1.3em; font-weight: 600; color: #2c3e50; }
        .severity-badge { padding: 6px 15px; border-radius: 20px; font-weight: bold; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }
        .severity-critical { background: #e74c3c; color: white; }
        .severity-high { background: #e67e22; color: white; }
        .severity-medium { background: #f39c12; color: white; }
        .severity-low { background: #95a5a6; color: white; }
        .finding-meta { display: flex; gap: 20px; margin-bottom: 15px; font-size: 0.9em; color: #7f8c8d; flex-wrap: wrap; }
        .finding-meta span { display: flex; align-items: center; }
        .finding-meta strong { margin-right: 5px; color: #555; }
        .finding-section { margin: 15px 0; padding: 15px; background: white; border-radius: 4px; }
        .finding-section h4 { color: #555; margin-bottom: 10px; font-size: 1em; text-transform: uppercase; letter-spacing: 0.5px; }
        .finding-section p { color: #666; line-height: 1.7; }
        .privileged-users-table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; }
        .privileged-users-table th { background: #34495e; color: white; padding: 12px; text-align: left; font-weight: 600; }
        .privileged-users-table td { padding: 10px; border-bottom: 1px solid #ecf0f1; }
        .privileged-users-table tr:nth-child(even) { background: #f8f9fa; }
        .privileged-users-table tr:hover { background: #e8f4f8; }
        .status-enabled { color: #27ae60; font-weight: bold; }
        .status-disabled { color: #e74c3c; font-weight: bold; }
        .footer { margin-top: 50px; padding-top: 20px; border-top: 2px solid #ecf0f1; text-align: center; color: #7f8c8d; font-size: 0.9em; }
        .warning-box { background: #fff3cd; border-left: 4px solid #f39c12; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .warning-box p { color: #856404; margin: 5px 0; }
        @media print { body { background: white; padding: 0; } .container { box-shadow: none; } }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Active Directory Security Assessment Report</h1>
        
        <div class="warning-box">
            <p><strong>⚠️ CONFIDENTIAL SECURITY REPORT</strong></p>
            <p>This report contains sensitive security information about your Active Directory environment. Handle with care and share only with authorized personnel.</p>
        </div>
        
        <div class="header-info">
            <div><strong>DOMAIN</strong><span style="font-size: 1.2em; color: #2c3e50;">$(HtmlEncode $Domain)</span></div>
            <div><strong>REPORT DATE</strong><span style="font-size: 1.2em; color: #2c3e50;">$reportDate</span></div>
            <div><strong>SCAN DURATION</strong><span style="font-size: 1.2em; color: #2c3e50;">$([math]::Round($Duration.TotalSeconds, 2)) seconds</span></div>
            <div><strong>TOTAL FINDINGS</strong><span style="font-size: 1.2em; color: #2c3e50;">$($Findings.Count)</span></div>
        </div>
        
        <h2>📊 Executive Summary</h2>
        <div class="summary-cards">
            <div class="summary-card critical-card">
                <div class="count">$($Summary.Critical)</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high-card">
                <div class="count">$($Summary.High)</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium-card">
                <div class="count">$($Summary.Medium)</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low-card">
                <div class="count">$($Summary.Low)</div>
                <div class="label">Low</div>
            </div>
        </div>
"@
    
    # Add privileged users section if available
    if ($PrivilegedUsers -and $PrivilegedUsers.Count -gt 0) {
        $html += @"
        <h2>👥 Privileged Users Summary</h2>
        <p style="margin-bottom: 15px; color: #555;">The following $($PrivilegedUsers.Count) user accounts have membership in one or more privileged groups. Review these accounts regularly to ensure appropriate access levels.</p>
        <div style="overflow-x: auto;">
            <table class="privileged-users-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Display Name</th>
                        <th>Enabled</th>
                        <th>Privileged Groups</th>
                        <th>Password Last Set</th>
                        <th>Last Logon</th>
                        <th>Security Flags</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($user in ($PrivilegedUsers | Sort-Object -Property @{Expression={$_.PrivilegedGroups.Count}; Descending=$true}, SamAccountName)) {
            $enabledClass = if ($user.Enabled) { 'status-enabled' } else { 'status-disabled' }
            $enabledText = if ($user.Enabled) { 'Yes' } else { 'No' }
            
            $securityFlags = @()
            if ($user.PasswordNeverExpires) { $securityFlags += 'Pwd Never Expires' }
            if ($user.DoesNotRequirePreAuth) { $securityFlags += 'No PreAuth' }
            if ($user.TrustedForDelegation) { $securityFlags += 'Delegation' }
            if ($user.HasSPN) { $securityFlags += "SPN($($user.SPNCount))" }
            $flagsText = if ($securityFlags.Count -gt 0) { HtmlEncode ($securityFlags -join ', ') } else { '-' }
            
            $passwordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'Never' }
            $lastLogon = if ($user.LastLogonDate) { $user.LastLogonDate.ToString('yyyy-MM-dd') } else { 'Never' }
            
            $html += @"
                    <tr>
                        <td><strong>$(HtmlEncode $user.SamAccountName)</strong></td>
                        <td>$(HtmlEncode $user.DisplayName)</td>
                        <td class="$enabledClass">$enabledText</td>
                        <td style="font-size: 0.85em;">$(HtmlEncode $user.PrivilegedGroupsString)</td>
                        <td>$passwordLastSet</td>
                        <td>$lastLogon</td>
                        <td style="font-size: 0.85em;">$flagsText</td>
                    </tr>
"@
        }
        
        $html += @"
                </tbody>
            </table>
        </div>
"@
    }
    
    # Add findings by severity
    if ($criticalFindings) {
        $html += "<h2>🔴 Critical Severity Findings</h2>"
        foreach ($finding in $criticalFindings) {
            $html += Get-FindingHTML -Finding $finding
        }
    }
    
    if ($highFindings) {
        $html += "<h2>🟠 High Severity Findings</h2>"
        foreach ($finding in $highFindings) {
            $html += Get-FindingHTML -Finding $finding
        }
    }
    
    if ($mediumFindings) {
        $html += "<h2>🟡 Medium Severity Findings</h2>"
        foreach ($finding in $mediumFindings) {
            $html += Get-FindingHTML -Finding $finding
        }
    }
    
    if ($lowFindings) {
        $html += "<h2>⚪ Low Severity Findings</h2>"
        foreach ($finding in $lowFindings) {
            $html += Get-FindingHTML -Finding $finding
        }
    }
    
    $html += @"
        <div class="footer">
            <p><strong>Generated by ADSecurityAudit Module v1.0.0</strong></p>
            <p>This report should be treated as confidential and shared only with authorized personnel.</p>
            <p>Review findings, prioritize remediation by severity, and implement security best practices.</p>
        </div>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

function Get-FindingHTML {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ADSecurityFinding]$Finding
    )
    
    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }
    
    $severityClass = $Finding.Severity.ToLower()
    $description = HtmlEncode $Finding.Description
    $impact = HtmlEncode $Finding.Impact
    $remediation = HtmlEncode $Finding.Remediation
    $issue = HtmlEncode $Finding.Issue
    $category = HtmlEncode $Finding.Category
    $affectedObject = HtmlEncode $Finding.AffectedObject
    
    # Handle multi-line remediation
    $remediation = $remediation -replace "`r`n", '<br>' -replace "`n", '<br>'
    
    return @"
        <div class="finding $severityClass">
            <div class="finding-header">
                <div class="finding-title">$issue</div>
                <span class="severity-badge severity-$severityClass">$($Finding.Severity)</span>
            </div>
            <div class="finding-meta">
                <span><strong>Category:</strong> $category</span>
                <span><strong>Affected Object:</strong> $affectedObject</span>
                <span><strong>Detected:</strong> $($Finding.DetectedDate.ToString('yyyy-MM-dd HH:mm'))</span>
            </div>
            <div class="finding-section">
                <h4>📝 Description</h4>
                <p>$description</p>
            </div>
            <div class="finding-section">
                <h4>⚠️ Impact</h4>
                <p>$impact</p>
            </div>
            <div class="finding-section">
                <h4>✅ Remediation</h4>
                <p>$remediation</p>
            </div>
        </div>
"@
}

#endregion

