@{
    RootModule = 'ADSecurityAudit.psm1'
    ModuleVersion = '1.0.0'
    GUID = '7eaedb96-5ee9-4cdf-9ebf-c5618a0d2f14'
    Author = 'AlchemicalChef'
    CompanyName = 'Community'
    Copyright = '(c) 2025 AlchemicalChef. All rights reserved.'
    Description = 'Comprehensive Active Directory security auditing and reporting.'
    PowerShellVersion = '5.1'
    RequiredModules = @('ActiveDirectory')
    FunctionsToExport = @(
        'Start-ADSecurityAudit',
        'Test-ADUserSecurity',
        'Test-ADPrivilegedGroups',
        'Test-AdminSDHolder',
        'Test-ADGroupPolicies',
        'Test-ADReplicationSecurity',
        'Test-ADDomainSecurity',
        'Test-ADDangerousPermissions',
        'Get-ADPrivilegedUsers',
        'Test-ADCertificateServices',
        'Test-KRBTGTAccount',
        'Test-ADDomainTrusts',
        'Test-LAPSDeployment',
        'Test-AuditPolicyConfiguration',
        'Test-ConstrainedDelegation'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('ActiveDirectory', 'Security', 'Audit')
            LicenseUri = 'https://opensource.org/licenses/MIT'
            ProjectUri = 'https://github.com/AlchemicalChef/ADSecurityAudit'
            IconUri = ''
            ReleaseNotes = 'Initial module manifest for ADSecurityAudit.'
        }
    }
}
