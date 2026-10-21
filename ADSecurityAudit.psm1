<#
.SYNOPSIS
    Comprehensive Active Directory Audit and Reporting

.DESCRIPTION
    This module provides extensive capabilities to audit Active Directory environments
    for misconfigurations and security vulnerabilities. It evaluates user accounts,
    group policies, permissions, replication configurations, and AdminSDHolder objects.

.NOTES
    Author: AlchemicalChef
    Version: 1.30.0
    Requires: Active Directory PowerShell Module, Windows Server 2016+

.EXAMPLE
    Import-Module .\ADSecurityAudit.psm1
    Start-ADSecurityAudit -Verbose -ExportPath "C:\Reports"
#>
#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

$script:ModuleRoot = $PSScriptRoot

# Single source of truth for the module version used at runtime (e.g. in the
# HTML report footer). Read from the manifest instead of being hardcoded a
# second time, so the two can never drift out of sync again.
try {
    $script:ModuleVersion = (Import-PowerShellDataFile -Path (Join-Path $script:ModuleRoot 'ADSecurityAudit.psd1')).ModuleVersion
}
catch {
    Write-Verbose "Could not read ModuleVersion from manifest: $_"
    $script:ModuleVersion = 'Unknown'
}

$moduleScripts = @(
    'src/Common.ps1',
    'src/Scoring.ps1',
    # Data-only: the current EstimatedEffort/KnownRisks/BackupRollback/
    # OperationalNotes text per Issue name, used by
    # Merge-ADFindingNarrativeGaps (Common.ps1) to backfill those fields
    # when recreating a report from an older JSON export. Must load after
    # Common.ps1 (defines the function that reads it) but has no
    # dependency on load order relative to the check files below - it's
    # pure data, referenced only by Issue name string.
    'src/FindingNarrativeLibrary.ps1',
    'src/UserAudits.ps1',
    'src/GroupAudits.ps1',
    'src/AdminSDAudits.ps1',
    'src/GpoAudits.ps1',
    'src/ReplicationAudits.ps1',
    'src/DomainSecurityAudits.ps1',
    'src/PermissionsAudits.ps1',
    'src/PrivilegedUsers.ps1',
    'src/CertificateServicesAudits.ps1',
    'src/CertificateServicesExtendedAudits.ps1',
    'src/KrbtgtAudits.ps1',
    'src/DomainTrustAudits.ps1',
    'src/LapsAudits.ps1',
    'src/ManagedServiceAccountAudits.ps1',
    'src/DpapiAudits.ps1',
    'src/AccountComputerHygieneAudits.ps1',
    'src/AuditPolicyAudits.ps1',
    'src/DelegationAudits.ps1',
    'src/DomainAdminEquivalence.ps1',
    'src/MachineAccountQuotaAudits.ps1',
    'src/DomainHardeningAudits.ps1',
    'src/CoercionRelayAudits.ps1',
    'src/LsaProtectionAudits.ps1',
    'src/DnsSecurityAudits.ps1',
    'src/LegacyAuthAudits.ps1',
    'src/KerberosHardeningAudits.ps1',
    'src/StaleObjectDepthAudits.ps1',
    'src/DomainControllerIntegrityAudits.ps1',
    'src/SchemaAudits.ps1',
    'src/GpoSecretsAudits.ps1',
    'src/KnownVulnAudits.ps1',
    'src/ExchangeEscalationAudits.ps1',
    'src/RodcSecurityAudits.ps1',
    'src/ControlPaths.ps1',
    'src/ForestConsolidation.ps1',
    'src/RetestComparison.ps1',
    'src/RemediationState.ps1',
    'src/RemediationBurndown.ps1',
    'src/MaturityTrend.ps1',
    'src/Main.ps1',
    'src/Reporting.ps1'
)

foreach ($moduleScript in $moduleScripts) {
    $scriptPath = Join-Path -Path $script:ModuleRoot -ChildPath $moduleScript

    if (-not (Test-Path $scriptPath)) {
        throw "Required module file not found: $scriptPath"
    }

    . $scriptPath
}

Export-ModuleMember -Function @(
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
    'Test-ADCSExtended',
    'Test-ADCSChaseFallback',
    'Test-ADCSWeakCertificateBinding',
    'Test-KRBTGTAccount',
    'Test-ADDomainTrusts',
    'Test-LAPSDeployment',
    'Test-ADManagedServiceAccountSecurity',
    'Test-AuditPolicyConfiguration',
    'Test-ConstrainedDelegation',
    'Test-ADDomainAdminEquivalence',
    'Test-ADMachineAccountQuota',
    'Test-ADDomainHardeningFlags',
    'Test-ADCoercionAndRelayExposure',
    'Test-ADLsaProtection',
    'Test-ADDnsSecurity',
    'Test-ADLegacyAuthSurface',
    'Test-ADKerberosHardening',
    'Test-ADStaleObjectDepth',
    'Test-ADDomainControllerIntegrity',
    'Test-ADSchemaIntegrity',
    'Test-ADKdsRootKeySecurity',
    'Test-ADDpapiBackupKeySecurity',
    'Test-ADAccountComputerHygiene',
    'Test-ADGpoDeployedSecrets',
    'Test-ADKnownDCVulnerabilities',
    'Test-ADExchangeEscalation',
    'Test-ADRodcSecurity',
    'Get-ADControlPathGraph',
    'Test-ADControlPaths',
    'Export-ADControlPathGraphBloodHound',
    'Get-ADForestConsolidation',
    'Export-ADForestConsolidationHTML',
    'Get-ADRetestComparison',
    'Export-ADRetestComparisonHTML',
    'Set-ADRemediationState',
    'Get-ADRemediationState',
    'Get-ADMaturityTrend',
    'Get-ADRemediationBurndown',
    'Export-ADMaturityTrendHTML',
    'Export-ADSecurityReportHTML',
    'Export-ADSecurityReportHTMLFromJson',
    'Export-ADSecurityReportCSVFromJson',
    'Get-ADRiskScore',
    'Set-ADFindingMetadata',
    'Get-ADFindingMetadataMap',
    'Get-ADTier0Principal',
    'Invoke-ADQueryWithRetry',
    'ConvertTo-SafeCsvValue'
)
