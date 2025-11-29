# Module-level variables

$Script:SeverityLevels = @{
    Critical = 4
    High = 3
    Medium = 2
    Low = 1
    Info = 0
}

$Script:ThresholdCriticalGroupSize = 5
$Script:ThresholdStandardGroupSize = 10
$Script:ThresholdInactiveDays = 90
$Script:ThresholdPasswordAgeDays = 180

$Script:ProtectedGroups = @(
    'Domain Admins'
    'Enterprise Admins'
    'Schema Admins'
    'Administrators'
    'Account Operators'
    'Server Operators'
    'Backup Operators'
    'Print Operators'
    'Domain Controllers'
    'Read-only Domain Controllers'
    'Group Policy Creator Owners'
    'Cryptographic Operators'
    'Distributed COM Users'
)

# Extended Rights GUIDs - these are for checking ACEs with ExtendedRight permissions
# Note: WriteOwner, WriteDacl, GenericAll, GenericWrite are standard AD rights checked via 
# ActiveDirectoryRights property, NOT via GUIDs
$Script:DangerousExtendedRights = @{
    'DS-Replication-Get-Changes' = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes-All' = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes-In-Filtered-Set' = '89e95b76-444d-4c62-991a-0facbeda640c'
    'User-Force-Change-Password' = '00299570-246d-11d0-a768-00aa006e0529'
    'DS-Replication-Manage-Topology' = '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Synchronize' = '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
}

# Property GUIDs for checking WriteProperty permissions
$Script:DangerousPropertyGuids = @{
    'Member' = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
    'msDS-KeyCredentialLink' = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
    'ServicePrincipalName' = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
    'msDS-AllowedToActOnBehalfOfOtherIdentity' = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
    'GPLink' = 'f30e3bc2-9ff0-11d1-b603-0000f80367c1'
    'ms-Mcs-AdmPwd' = 'ba19577d-37b2-4921-a637-429a1d99da82'
    'ms-LAPS-Password' = 'd95f499a-f5dd-4796-a2d5-6a3fba6a8e34'
    'ms-LAPS-EncryptedPassword' = 'f3531ec6-6330-4f8e-8d39-7c7867f0e4a4'
}

# Standard AD rights that indicate dangerous permissions (checked via -match on ActiveDirectoryRights)
$Script:DangerousStandardRights = @(
    'GenericAll'
    'GenericWrite'
    'WriteDacl'
    'WriteOwner'
    'AllExtendedRights'
)

# Keep legacy variable name for backward compatibility
$Script:DangerousRights = $Script:DangerousExtendedRights

class ADSecurityFinding {
    [string]$Category
    [string]$Issue
    [string]$Severity
    [int]$SeverityLevel
    [string]$Description
    [string]$Impact
    [string]$Remediation
    [string]$AffectedObject
    [hashtable]$Details
    [datetime]$DetectedDate

    ADSecurityFinding() {
        $this.DetectedDate = Get-Date
        $this.Details = @{}
    }
}

# Retry helper function for AD queries with exponential backoff
function Invoke-ADQueryWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Query,

        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 2,
        [string]$OperationName = "AD Query"
    )

    $attempt = 0
    $lastError = $null

    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            return (& $Query)
        }
        catch {
            $lastError = $_
            Write-Verbose "$OperationName failed (attempt $attempt/$MaxAttempts): $_"

            if ($attempt -lt $MaxAttempts) {
                $wait = $DelaySeconds * [math]::Pow(2, $attempt - 1)
                Start-Sleep -Seconds $wait
            }
        }
    }

    Write-Warning "$OperationName failed after $MaxAttempts attempts: $lastError"
    return $null
}

# Sanitize values for CSV export to prevent formula injection
function ConvertTo-SafeCsvValue {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    process {
        if ([string]::IsNullOrEmpty($Value)) {
            return $Value
        }

        # Prefix with single quote if value starts with characters that could be interpreted as formulas
        if ($Value -match '^[=+\-@\t\r]') {
            return "'" + $Value
        }

        return $Value
    }
}
