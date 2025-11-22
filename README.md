**This is very alpha, please use at your own risk until I can test edge cases**

# Active Directory Security Audit 

A comprehensive PowerShell module for identifying misconfigurations and security vulnerabilities within Active Directory environments.

## Features

### Core Auditing Capabilities

- **User Account Auditing**: Detects AS-REP Roasting vulnerabilities, weak encryption, reversible passwords, unconstrained delegation, Kerberoasting risks, and inactive accounts
- **Privileged Group Analysis**: Identifies excessive membership, nested groups, and disabled users in critical groups
- **AdminSDHolder Security**: Scans for risky permissions and unauthorized modifications that could lead to persistent compromise
- **Group Policy Assessment**: Detects over-permissioned GPOs, insecure SYSVOL permissions, and mislinked policies
- **DCSync Detection**: Identifies unauthorized replication permissions that enable credential dumping attacks
- **Domain Security Settings**: Evaluates password policies, functional levels, and legacy systems
- **Dangerous Permissions**: Locates overly permissive rights on critical AD objects

### Advanced Security Features

- **Certificate Services (AD CS) Vulnerabilities**: Scans for exploitable certificate templates (ESC1/ESC2/ESC3) where attackers can request certificates for privilege escalation, and audits Certificate Authority permissions
- **KRBTGT Password Age Analysis**: Monitors KRBTGT account password age to prevent Golden Ticket attacks, alerting when passwords exceed the recommended 180-day rotation threshold
- **Domain Trust Security**: Comprehensive auditing of trust relationships including SID filtering status, selective authentication validation, trust direction analysis, and bidirectional trust detection
- **LAPS Deployment Verification**: Validates Local Administrator Password Solution (LAPS) schema installation, checks computer coverage percentage, and identifies systems with static local admin passwords
- **Audit Policy Configuration**: Verifies critical audit policies are enabled on domain controllers, validates SACL configurations on sensitive objects, and ensures proper security event logging
- **Constrained Delegation Analysis**: Identifies accounts with constrained delegation, dangerous protocol transition (T2A4D), and resource-based constrained delegation (RBCD) configurations

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Active Directory PowerShell Module (RSAT)
- Domain Administrator or equivalent permissions for full audit
- Windows Server 2016 or later (recommended)
- Network connectivity to Domain Controllers
- Appropriate read permissions for AD Certificate Services (if installed)

## Installation

1. Copy the module to your PowerShell modules directory:
\`\`\`powershell
$modulePath = "$env:ProgramFiles\WindowsPowerShell\Modules\ADSecurityAudit"
New-Item -Path $modulePath -ItemType Directory -Force
Copy-Item -Path ".\ADSecurityAudit-Enhanced.psm1" -Destination "$modulePath\ADSecurityAudit.psm1"
\`\`\`

2. Import the module:
\`\`\`powershell
Import-Module ADSecurityAudit
\`\`\`

## Usage

### Basic Audit
Run a complete security audit with default settings:
\`\`\`powershell
Start-ADSecurityAudit -OutputPath "C:\ADReports"
\`\`\`

### Advanced Options
Customize the audit with additional parameters:
\`\`\`powershell
Start-ADSecurityAudit -OutputPath "C:\ADReports" -Verbose
\`\`\`

### Output Formats
The script generates three report formats:
- **HTML Report**: Color-coded interactive report with severity indicators
- **CSV Export**: Detailed findings in spreadsheet format for analysis
- **JSON Export**: Machine-readable format for integration with SIEM or automation tools

## Security Findings Categories

The audit generates findings across multiple severity levels:

### Critical Findings
- Exploitable AD CS certificate templates
- KRBTGT password not rotated (Golden Ticket risk)
- Unconstrained delegation on user accounts
- DCSync permissions granted to non-admin users
- Domain trusts without SID filtering

### High Findings
- Weak password policies
- Accounts with password never expires
- Service accounts with SPNs using weak encryption
- Missing LAPS deployment on computers
- Disabled critical audit policies
- Constrained delegation with protocol transition

### Medium Findings
- Nested groups in privileged groups
- Stale privileged accounts
- Missing selective authentication on trusts
- Low LAPS coverage percentage
- Resource-based constrained delegation configurations

### Low Findings
- Informational findings about domain configuration
- Baseline security posture indicators

## Report Interpretation

### HTML Report Structure
- **Executive Summary**: Overview of total findings by severity
- **Critical Issues**: Immediate action required
- **Detailed Findings**: Complete list with remediation guidance
- **Affected Objects**: Lists of users, groups, computers, and objects requiring attention

### Remediation Guidance
Each finding includes:
- **Description**: What the vulnerability is
- **Impact**: Why it matters for security
- **Affected Objects**: Specific accounts, groups, or systems
- **Remediation**: Step-by-step fix instructions

## Common Security Issues Detected

### Certificate Services Vulnerabilities
- Certificate templates allowing SAN specification (ESC1)
- Templates with overly permissive enrollment rights (ESC2)
- Enrollment agent templates (ESC3)
- CA permissions allowing unauthorized certificate issuance

### Kerberos Security
- KRBTGT password older than 180 days
- Accounts with unconstrained delegation
- Accounts with constrained delegation and protocol transition
- Service accounts with weak Kerberos encryption (RC4)

### Trust Relationships
- Trusts without SID filtering (allows SID history attacks)
- Bidirectional trusts increasing attack surface
- Missing selective authentication on external trusts
- Stale or misconfigured trust relationships

### Local Administrator Security
- Computers without LAPS protection
- Static local admin passwords enabling lateral movement
- Missing LAPS schema extensions

### Monitoring & Logging
- Disabled audit policies for critical events
- Missing SACLs on AdminSDHolder container
- Insufficient logging for privilege escalation detection

## Troubleshooting

### Common Issues

**Module Import Failure**
\`\`\`powershell
# Ensure RSAT is installed
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online
\`\`\`

**Permission Denied**
- Run PowerShell as Administrator
- Verify account has Domain Admin or equivalent permissions
- Check network connectivity to Domain Controllers

**Certificate Services Checks Failing**
- Requires AD CS to be installed in the environment
- Needs permissions to query Certificate Authority
- Gracefully skips if AD CS is not present

**Incomplete LAPS Results**
- Verify LAPS schema extensions are installed
- Check permissions to read ms-Mcs-AdmPwd attribute
- Confirms LAPS GPO deployment

## Security Best Practices

Based on audit findings, implement these security controls:

1. **Rotate KRBTGT Password**: Every 180 days (twice with 24-hour intervals)
2. **Deploy LAPS**: Achieve 100% coverage on all workstations and servers
3. **Review Certificate Templates**: Remove unnecessary templates, restrict enrollment rights
4. **Enable Audit Policies**: Configure advanced audit policies for AD object access
5. **Harden Trust Relationships**: Enable SID filtering, use selective authentication
6. **Remove Unconstrained Delegation**: Migrate to constrained or resource-based delegation
7. **Implement Tiered Access Model**: Separate Tier 0 administrative accounts
8. **Regular Audits**: Run this script monthly to track security posture improvements

## Automation & Integration

### Scheduled Audits
Create a scheduled task to run audits automatically:
\`\`\`powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"Import-Module ADSecurityAudit; Start-ADSecurityAudit -OutputPath 'C:\ADReports'`""
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 2am
Register-ScheduledTask -TaskName "AD Security Audit" -Action $action -Trigger $trigger -RunLevel Highest
\`\`\`

### SIEM Integration
Import JSON reports into your SIEM for correlation and alerting:
\`\`\`powershell
# Example: Send findings to Splunk HEC
$findings = Get-Content "C:\ADReports\AD_Security_Findings_*.json" | ConvertFrom-Json
foreach ($finding in $findings) {
    Send-SplunkEvent -Finding $finding
}
\`\`\`

## Contributing

Contributions are welcome! Please ensure:
- Code follows PowerShell best practices
- New checks include proper error handling
- Findings have clear remediation guidance
- Changes are tested in lab environment first

## License

MIT License - Use at your own risk. Always test in non-production environments first.

## Disclaimer

This tool performs read-only operations but requires elevated privileges. Always:
- Review the code before running in production
- Test in a lab environment first
- Ensure you have proper authorization
- Backup your environment before making remediation changes
- Understand the impact of recommended remediations

## Version History

### v1.0 (Release)
- Added Certificate Services vulnerability scanning (ESC1/ESC2/ESC3)
- Added KRBTGT password age monitoring
- Added comprehensive trust relationship auditing
- Added LAPS deployment verification
- Added audit policy configuration validation
- Added constrained delegation analysis
- Enhanced reporting with new critical findings

### v0.1 (Original)
- Initial release with core AD security auditing
- Privileged group analysis
- DCSync detection
- AdminSDHolder security checks
- Basic delegation auditing

## Support

For issues, questions, or feature requests:
- Review the Troubleshooting section
- Check PowerShell event logs for detailed error messages
- Ensure all prerequisites are met
- Test with `-Verbose` flag for detailed output

## Acknowledgments

Built upon industry-standard Active Directory security assessment methodologies and inspired by:
- Microsoft Security Best Practices
- MITRE ATT&CK Framework (Active Directory techniques)
- Purple Knight Active Directory Security Assessment Tool
- BloodHound graph theory for AD privilege escalation paths
