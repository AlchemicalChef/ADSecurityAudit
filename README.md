# Active Directory Security Audit 

A comprehensive PowerShell module for identifying misconfigurations and security vulnerabilities within Active Directory environments.

## 🎯 Features

- **User Account Auditing**: Detects AS-REP Roasting vulnerabilities, weak encryption, reversible passwords, unconstrained delegation, Kerberoasting risks, and inactive accounts
- **Privileged Group Analysis**: Identifies excessive membership, nested groups, and disabled users in critical groups
- **AdminSDHolder Security**: Scans for risky permissions and unauthorized modifications that could lead to persistent compromise
- **Group Policy Assessment**: Detects over-permissioned GPOs, insecure SYSVOL permissions, and mislinked policies
- **DCSync Detection**: Identifies unauthorized replication permissions that enable credential dumping attacks
- **Domain Security Settings**: Evaluates password policies, functional levels, and legacy systems
- **Dangerous Permissions**: Locates overly permissive rights on critical AD objects

## 📋 Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Active Directory PowerShell Module (RSAT)
- Domain Administrator or equivalent permissions for full audit
- Windows Server 2016 or later (recommended)

## 🚀 Installation

1. Copy the module to your PowerShell modules directory:
```powershell
$modulePath = "$env:ProgramFiles\WindowsPowerShell\Modules\ADSecurityAudit"
New-Item -Path $modulePath -ItemType Directory -Force
Copy-Item -Path ".\ADSecurityAudit.psm1" -Destination $modulePath
