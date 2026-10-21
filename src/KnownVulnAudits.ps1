#region Known DC Vulnerabilities by Patch/Build Audit
#
# Flags Domain Controller exposure to the highest-impact AD CVEs strictly
# from OS build/version, installed CU/hotfix level, and service/config
# state - ZeroLogon (CVE-2020-1472), MS17-010/EternalBlue, MS14-068,
# PrintNightmare (CVE-2021-34527), CVE-2026-41089 and CVE-2026-72982 (two
# distinct unauthenticated Netlogon RCEs), and BadSuccessor/dMSA escalation
# exposure on Windows Server 2025-level Domain Controllers, including (as
# of v1.18.0) a per-DC CVE-2025-53779 KDC-side patch-level (UBR)
# classification.
# PingCastle-comparable check(s): S-Vuln-MS14-068, S-Vuln-MS17_010, A-Krbtgt, A-DC-Spooler,
# A-BadSuccessor.
#
# DETECTION ONLY: every determination here comes from reading
# Win32_OperatingSystem (build/version/install date), installed hotfixes
# (Get-HotFix / Win32_QuickFixEngineering), and the Print Spooler service
# state - the same category of read used elsewhere in this module (e.g.
# Test-ADCoercionAndRelayExposure's Spooler check). This module NEVER
# sends an exploit, authentication bypass, ticket forgery, coercion
# request, or any other PoC traffic to any host; a DC is judged vulnerable
# purely by whether its patch level/build/config falls below a documented,
# inline-cited fix threshold.

# Documented fix thresholds for the legacy, build/patch-detectable CVEs.
# FixDate is the Patch Tuesday (or out-of-band) release date of the first
# public fix; a DC is treated as protected once ANY reliable evidence
# (latest installed hotfix date, or an OS install/media date that already
# postdates the fix) is on or after that date. Kept as a single table so
# every threshold is cited in one place rather than scattered through the
# check logic below.
$Script:KnownVulnFixThresholds = @{
    # Verified against MSRC (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472)
    # on 2026-09-20. Fix date unchanged since prior review (last checked 2026-07-09).
    ZeroLogon = @{
        Issue       = 'DC Missing ZeroLogon Patch'
        Cve         = 'CVE-2020-1472'
        FixDate     = [datetime]'2020-08-11'
        FixNote     = 'August 11, 2020 cumulative/security-only updates (e.g. KB4565351 / KB4571694 / KB4565349 / KB4565354 depending on OS) - initial Netlogon secure-channel enforcement fix.'
        Description = 'Netlogon Remote Protocol elevation-of-privilege (ZeroLogon) allows an unauthenticated attacker on the network to reset the DC computer account password and obtain Domain Admin-equivalent access.'
    }
    # Verified against MSRC (https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
    # on 2026-09-20. Fix date unchanged since prior review (last checked 2026-07-09).
    MS17010 = @{
        Issue       = 'DC Vulnerable to MS17-010'
        Cve         = 'MS17-010 (CVE-2017-0143 through CVE-2017-0148)'
        FixDate     = [datetime]'2017-03-14'
        FixNote     = 'March 14, 2017 Patch Tuesday updates (e.g. KB4012212 / KB4012213 / KB4013389 depending on OS) - SMBv1 remote code execution fix (EternalBlue).'
        Description = 'Unauthenticated SMBv1 remote code execution (EternalBlue) allows full compromise of the Domain Controller over the network with no credentials.'
    }
    # Verified against MSRC (https://msrc.microsoft.com/blog/2014/11/additional-information-about-cve-2014-6324/)
    # on 2026-09-20. Fix date unchanged since prior review (last checked 2026-07-09).
    MS14068 = @{
        Issue       = 'DC Vulnerable to MS14-068'
        Cve         = 'CVE-2014-6324'
        FixDate     = [datetime]'2014-11-18'
        FixNote     = 'November 18, 2014 out-of-band update (KB3011780) - Kerberos PAC signature validation fix.'
        Description = 'A forged Kerberos PAC can claim Domain Admin group membership for any authenticated low-privilege user, which the unpatched KDC accepts without validating the signature.'
    }
    # Verified against MSRC (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)
    # on 2026-09-20. Fix date unchanged since prior review (last checked 2026-07-09).
    PrintNightmare = @{
        Issue       = 'PrintNightmare Exposure on DC'
        Cve         = 'CVE-2021-34527'
        FixDate     = [datetime]'2021-07-06'
        FixNote     = 'July 6, 2021 out-of-band update - Print Spooler remote code execution / local privilege escalation fix. Only relevant while the Spooler service is running.'
        Description = 'An authenticated user can remotely install a malicious printer driver via the Print Spooler service (RpcAddPrinterDriver) and achieve SYSTEM-level code execution on the DC.'
    }
    # Verified 2026-07-09 against multiple independent sources citing MSRC
    # directly: SecurityWeek, Tenable, Zero Day Initiative, Help Net
    # Security, and CERT-EU (https://cert.europa.eu/publications/security-advisories/2026-007/).
    # Fix date (May 12, 2026), CVSS 9.8, and unauthenticated pre-auth RCE via
    # a Netlogon stack-based buffer overflow are consistent across all of
    # them. CERT-EU's advisory (citing MSRC) additionally gives verified
    # per-OS fixed-build boundaries rather than KB numbers, which several
    # lower-quality aggregator sites gave inconsistently and were NOT relied
    # on here: Server 2016 < 10.0.14393.9140, Server 2019 < 10.0.17763.8755,
    # Server 2022 < 10.0.20348.5074, Server 2022 23H2 < 10.0.25398.2330,
    # Server 2025 < 10.0.26100.32772. This function's threshold below
    # intentionally stays FixDate-only (not per-OS build), consistent with
    # how the other three legacy CVE checks in this table work; the CERT-EU
    # build numbers are recorded here for reference / a future refinement.
    # Active in-the-wild exploitation was reported by Belgium's CCB
    # starting May 29, 2026, per the same sources.
    # Re-checked 2026-09-20: fix date, CVSS, and exploitation status unchanged
    # since prior review. Renamed this key from Netlogon2026 to
    # Netlogon2026May (and its Issue/finding text left unchanged) because a
    # SECOND, unrelated Netlogon RCE - CVE-2026-72982, disclosed on MSRC
    # 2026-09-08 (see Netlogon2026Sep below) - shipped in the September 2026
    # Patch Tuesday. Same component (MS-NRPC), same CVSS 9.8, same
    # unauthenticated pre-auth class, but two distinct CVEs fixed by two
    # distinct updates - a DC patched for one is not necessarily patched for
    # the other, hence the disambiguated names.
    Netlogon2026May = @{
        Issue       = 'DC Missing CVE-2026-41089 Patch (Netlogon RCE)'
        Cve         = 'CVE-2026-41089'
        FixDate     = [datetime]'2026-05-12'
        FixNote     = 'May 12, 2026 Patch Tuesday cumulative updates - Netlogon Remote Protocol (MS-NRPC) packet-handling stack buffer overflow fix. Per-OS fixed-build boundaries (CERT-EU, citing MSRC): Server 2016 >= 10.0.14393.9140, Server 2019 >= 10.0.17763.8755, Server 2022 >= 10.0.20348.5074, Server 2022 23H2 >= 10.0.25398.2330, Server 2025 >= 10.0.26100.32772. Confirm the exact KB number for your specific OS build via Windows Update / the Microsoft Update Catalog, since third-party aggregator KB numbers for this CVE have been inconsistent.'
        Description = 'An unauthenticated, network-only attacker can trigger a stack-based buffer overflow in the Netlogon RPC interface (MS-NRPC) and achieve SYSTEM-level remote code execution on the Domain Controller, with no credentials or user interaction required (CVSS 9.8). Reported under active exploitation in the wild starting May 29, 2026 (Belgium CCB advisory).'
    }
    # Added 2026-09-20 per files/13-dc-known-cve-2026-72982-netlogon-rce.md.
    # Verified directly against MSRC's Security Update Guide entry for
    # CVE-2026-72982 (released Sep 8, 2026) and cross-checked against
    # independent Patch Tuesday writeups (CrowdStrike, Action1, Talos, ZDI),
    # all consistent on CVSS 9.8, CWE-121 (stack-based buffer overflow), and
    # unauthenticated network-only RCE. NOT confirmed exploited in the wild
    # as of this writing (unlike CVE-2026-41089/Netlogon2026May above).
    # Per-OS fixed builds confirmed directly against Microsoft's own KB
    # support articles for the September 8, 2026 cumulative updates: Server
    # 2016 (KB5122878) >= 10.0.14393.9512, Server 2019 (KB5122876) >=
    # 10.0.17763.9245, Server 2022 (KB5122882) >= 10.0.20348.5622. The
    # Server 2025 fixed build was NOT independently confirmed via a
    # dedicated Microsoft KB article at the time of this addition - confirm
    # via the Microsoft Update Catalog before relying on it. As with
    # Netlogon2026May, this function's threshold intentionally stays
    # FixDate-only (not per-OS build); the confirmed builds above are
    # recorded here for reference / a future refinement.
    Netlogon2026Sep = @{
        Issue       = 'DC Missing CVE-2026-72982 Patch (Netlogon RCE)'
        Cve         = 'CVE-2026-72982'
        FixDate     = [datetime]'2026-09-08'
        FixNote     = 'September 8, 2026 Patch Tuesday cumulative updates - a second, distinct Netlogon Remote Protocol (MS-NRPC) packet-handling stack buffer overflow fix (unrelated to the May 2026 CVE-2026-41089 fix). Confirmed per-OS fixed builds: Server 2016 (KB5122878) >= 10.0.14393.9512, Server 2019 (KB5122876) >= 10.0.17763.9245, Server 2022 (KB5122882) >= 10.0.20348.5622. Server 2025 fixed build not independently confirmed at authoring time - confirm the exact KB/build for your OS via Windows Update / the Microsoft Update Catalog before considering a Server 2025 DC remediated.'
        Description = 'An unauthenticated, network-only attacker can trigger a stack-based buffer overflow in the Netlogon RPC interface (MS-NRPC) and achieve SYSTEM-level remote code execution on the Domain Controller, with no credentials or user interaction required (CVSS 9.8). A distinct vulnerability from CVE-2026-41089, sharing the same component and severity class; not confirmed exploited in the wild as of this writing, but multiple vendors group it with a broader September 2026 cluster of unauthenticated, wormable-class RCEs and recommend prioritizing patching regardless of confirmed in-the-wild status given the Domain Controller blast radius.'
    }
}

# Windows Server 2025 shipped build number. BadSuccessor (delegated Managed
# Service Account / dMSA privilege-escalation exposure, disclosed 2025) is
# only meaningful on DCs running this build or later, since dMSA is a
# Server 2025 feature - guard the check to that build so older DCs never
# generate a false positive.
#
# Re-checked 2026-09-20: dMSA remains exclusive to Windows Server 2025; no
# evidence found of Microsoft backporting the feature to Server
# 2016/2019/2022 via cumulative update, so the build-26100+ guard below
# does not need widening.
#
# As of v1.18.0 this base-build guard is paired with a per-DC UBR
# (Update Build Revision) read - see $Script:KnownVulnBadSuccessorPatchedUBR
# and Get-ADKnownVulnUBR below - to distinguish DCs patched for
# CVE-2025-53779 (build 26100.4946+) from unpatched ones. The base-build
# guard itself is unchanged: it still just answers "does this DC even have
# dMSA," irrespective of patch level.
$Script:KnownVulnServer2025Build = 26100

# UBR (Update Build Revision - the third component of a Windows build
# number, e.g. the 4946 in 26100.4946) at or above which a Server
# 2025-level DC has Microsoft's August 12, 2025 cumulative update
# (KB5063878, OS build 26100.4946) installed, which added KDC-side
# validation requiring a mutual (two-sided) dMSA/target link before the
# KDC honors it - closing the original one-sided-link escalation path
# described in CVE-2025-53779.
# Verified 2026-07-09 directly against Microsoft's own KB5063878 support
# article (support.microsoft.com/en-us/topic/august-12-2025-kb5063878-...
# -e4b87262-75c8-4fef-9df7-4a18099ee294): "August 12, 2025 - KB5063878
# (OS Build 26100.4946)" confirms the KB-to-build mapping used here.
#
# NOTE: per independent post-patch research (Akamai, "BadSuccessor Is
# Dead, Long Live BadSuccessor(?)", confirmed 2026-07-09), this patch does
# not fully close the underlying technique - a mutually-paired dMSA/target
# relationship still allows credential/privilege abuse if an attacker
# controls both sides. A DC classified "Patched" below is therefore not
# "safe" the way a fixed ZeroLogon/MS17-010/MS14-068/PrintNightmare DC is;
# the finding continues to fire for patched DCs with adjusted text rather
# than disappearing.
$Script:KnownVulnBadSuccessorPatchedUBR = 4946

# Per-OS-build fixed-UBR reference tables for the two Netlogon RCE CVEs
# (files/25-known-vuln-per-os-build-refinement.md). Keyed by OS build
# number (14393 = Server 2016, 17763 = Server 2019, 20348 = Server 2022).
# Values are drawn directly from the per-OS fixed-build boundaries already
# cited inline above for each CVE (CERT-EU for Netlogon2026May, Microsoft's
# own KB support articles for Netlogon2026Sep) - the UBR is simply the
# third component of each documented build number (e.g. 14393.9140 ->
# UBR 9140). Server 2025 is intentionally NOT a key here for either CVE:
# neither fixed UBR was independently confirmed at authoring time, so
# Server 2025 DCs continue to use FixDate-only evaluation below, exactly
# as they did before this refinement.
$Script:KnownVulnNetlogon2026MayPatchedUBR = @{
    14393 = 9140   # Server 2016, per CERT-EU (10.0.14393.9140)
    17763 = 8755   # Server 2019, per CERT-EU (10.0.17763.8755)
    20348 = 5074   # Server 2022, per CERT-EU (10.0.20348.5074)
}
$Script:KnownVulnNetlogon2026SepPatchedUBR = @{
    14393 = 9512   # Server 2016 (KB5122878), 10.0.14393.9512
    17763 = 9245   # Server 2019 (KB5122876), 10.0.17763.9245
    20348 = 5622   # Server 2022 (KB5122882), 10.0.20348.5622
}

function Get-ADKnownVulnUBR {
    <#
    .SYNOPSIS
        Reads the Windows Update Build Revision (UBR) from a remote
        computer's registry.
    .DESCRIPTION
        Read-only: opens the remote HKLM hive via .NET's
        [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey (the standard
        remote-registry API - functionally equivalent to `reg.exe query
        \\computer\HKLM\...`) and reads the single existing
        'UBR' value under 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'.
        No writes, no code execution, no service interaction of any kind.
    .PARAMETER ComputerName
        The remote Domain Controller to read the UBR from.
    .OUTPUTS
        [int] the UBR value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    $baseKey = $null
    $subKey  = $null
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine, $ComputerName)
        $subKey = $baseKey.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion')
        if (-not $subKey) {
            throw "CurrentVersion registry key not found on '$ComputerName'."
        }
        $ubr = $subKey.GetValue('UBR', $null)
        if ($null -eq $ubr) {
            throw "UBR value not present under CurrentVersion on '$ComputerName'."
        }
        return [int]$ubr
    }
    finally {
        if ($subKey)  { $subKey.Dispose() }
        if ($baseKey) { $baseKey.Dispose() }
    }
}

function Test-ADKnownDCVulnerabilities {
    <#
    .SYNOPSIS
        Audits Domain Controllers for known high-impact AD CVE exposure,
        determined strictly from patch/build/config - never by exploitation.
    .DESCRIPTION
        For each Domain Controller, reads:
          1. Win32_OperatingSystem (BuildNumber, Caption, InstallDate).
          2. Installed hotfixes (Get-HotFix / Win32_QuickFixEngineering),
             using the most recent InstalledOn date as the DC's effective
             patch date.
          3. Print Spooler service state (reused for the PrintNightmare
             check only; independent of, and in addition to,
             Test-ADCoercionAndRelayExposure's own Spooler finding).

        Then flags, per documented fix threshold (see
        $Script:KnownVulnFixThresholds):
          - DC Missing ZeroLogon Patch (CVE-2020-1472)
          - DC Vulnerable to MS17-010 (EternalBlue)
          - DC Vulnerable to MS14-068 (Kerberos PAC forgery)
          - PrintNightmare Exposure on DC (CVE-2021-34527) - only when the
            Spooler service is also running.
          - DC Missing CVE-2026-41089 Patch (Netlogon RCE) - unauthenticated,
            critical (CVSS 9.8) Netlogon RPC remote code execution against
            any DC, evaluated with the same patch-date evidence as the
            other build/patch-only checks above.
          - DC Missing CVE-2026-72982 Patch (Netlogon RCE) - a second,
            distinct unauthenticated, critical (CVSS 9.8) Netlogon RPC
            remote code execution, patched by a separate September 2026
            update; a DC patched for CVE-2026-41089 is not necessarily
            patched for this one, so both are checked independently.
          - BadSuccessor / dMSA Escalation Exposure - only on Domain
            Controllers running Windows Server 2025 (build >=
            $Script:KnownVulnServer2025Build), since dMSA is a Server 2025
            feature. Microsoft shipped a partial KDC-side fix for the
            original one-sided-link escalation as CVE-2025-53779 (August
            2025, build 26100.4946+). As of v1.18.0, each Server
            2025-level DC additionally has its UBR (Update Build Revision)
            read via remote registry to classify it as patched (UBR >=
            $Script:KnownVulnBadSuccessorPatchedUBR) or unpatched for
            CVE-2025-53779; a DC whose UBR cannot be read is reported with
            an unknown patch status rather than silently assumed patched.
            Independent research has shown the underlying dMSA-linking
            primitive still enables related credential/privilege abuse
            even on patched DCs - so the finding continues to fire (with
            adjusted text and, when every affected DC is confirmed
            patched, a reduced severity) rather than disappearing once
            patched.

        Each DC is evaluated independently and degrades gracefully if it
        cannot be reached (Verbose warning only; no finding is raised for
        that DC).

        Detection only - every determination is a version/patch/config
        read. No exploitation, authentication bypass, ticket forging,
        coercion, relay, or PoC traffic is ever sent to any host.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Starting Known DC Vulnerabilities (patch/build) audit..."
    $findings = @()

    # -------------------------------------------------------------------
    # Enumerate Domain Controllers.
    # -------------------------------------------------------------------
    $domainControllers = @()
    try {
        # Get-ADSecurityAuditDomainController, not a bare
        # Get-ADDomainController -Filter * - the latter is forest-wide
        # regardless of -Server; see Common.ps1 for why.
        $domainControllers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADSecurityAuditDomainController (known-vuln audit)' -Query {
            Get-ADSecurityAuditDomainController -Server (Get-ADSecurityAuditTargetServerValue)
        })
    }
    catch {
        Write-Warning "Test-ADKnownDCVulnerabilities: failed to enumerate Domain Controllers: $_"
    }

    if (-not $domainControllers -or $domainControllers.Count -eq 0) {
        Write-Verbose "Test-ADKnownDCVulnerabilities: no Domain Controllers to evaluate; no findings."
        return $findings
    }

    $perDcState = [System.Collections.ArrayList]::new()

    $zeroLogonDCs      = [System.Collections.ArrayList]::new()
    $ms17010DCs        = [System.Collections.ArrayList]::new()
    $ms14068DCs        = [System.Collections.ArrayList]::new()
    $printNightmareDCs = [System.Collections.ArrayList]::new()
    $netlogon2026DCs   = [System.Collections.ArrayList]::new()
    $netlogon2026SepDCs = [System.Collections.ArrayList]::new()
    $server2025DCs     = [System.Collections.ArrayList]::new()
    $badSuccessorPatchedDCs   = [System.Collections.ArrayList]::new()
    $badSuccessorUnpatchedDCs = [System.Collections.ArrayList]::new()
    $badSuccessorUnknownDCs   = [System.Collections.ArrayList]::new()

    foreach ($dc in $domainControllers) {
        $dcName = if ($dc.HostName) { $dc.HostName } elseif ($dc.Name) { $dc.Name } else { "$dc" }
        Write-Verbose "Test-ADKnownDCVulnerabilities: evaluating DC '$dcName'..."

        $dcState = [ordered]@{
            DomainController = $dcName
            Reachable        = $false
            OSCaption        = $null
            OSBuildNumber    = $null
            OSInstallDate    = $null
            LatestHotfixDate = $null
            EffectivePatchDate = $null
            SpoolerStatus    = $null
            UBR              = $null
            BadSuccessorPatchStatus = $null
            Netlogon2026MayUBR         = $null
            Netlogon2026MayPatchStatus = $null
            Netlogon2026SepUBR         = $null
            Netlogon2026SepPatchStatus = $null
            Error            = $null
        }

        # --- OS build/version/install date ---
        try {
            $osInfo = Invoke-ADQueryWithRetry -OperationName "Get-CimInstance Win32_OperatingSystem on $dcName" -Query {
                Get-CimInstance -ComputerName $dcName -ClassName Win32_OperatingSystem -ErrorAction Stop |
                    Select-Object Caption, BuildNumber, InstallDate
            }

            if ($osInfo) {
                $dcState.Reachable     = $true
                $dcState.OSCaption     = "$($osInfo.Caption)"
                $dcState.OSBuildNumber = [int]$osInfo.BuildNumber
                if ($osInfo.InstallDate) {
                    $dcState.OSInstallDate = [datetime]$osInfo.InstallDate
                }

                if ($dcState.OSBuildNumber -ge $Script:KnownVulnServer2025Build) {
                    [void]$server2025DCs.Add($dcName)
                }
            }
        }
        catch {
            Write-Verbose "Test-ADKnownDCVulnerabilities: could not read Win32_OperatingSystem on '$dcName': $_"
            $dcState.Error = "$_"
        }

        # --- Installed hotfix level (most recent InstalledOn date) ---
        try {
            $hotfixes = Invoke-ADQueryWithRetry -OperationName "Get-HotFix on $dcName" -Query {
                Get-HotFix -ComputerName $dcName -ErrorAction Stop
            }

            if ($hotfixes) {
                $dcState.Reachable = $true
                $latest = $hotfixes |
                    Where-Object { $_.InstalledOn } |
                    Sort-Object InstalledOn -Descending |
                    Select-Object -First 1
                if ($latest) {
                    $dcState.LatestHotfixDate = [datetime]$latest.InstalledOn
                }
            }
        }
        catch {
            Write-Verbose "Test-ADKnownDCVulnerabilities: could not read installed hotfixes on '$dcName' (Get-HotFix): $_"
            if (-not $dcState.Error) { $dcState.Error = "$_" }
        }

        # Effective patch date: the later of the OS install date (covers a
        # freshly built/reimaged DC whose media already postdates a fix,
        # even before any separate QFE record exists) and the most recent
        # installed hotfix. A DC is only as patched as the newer of the two.
        $candidateDates = @($dcState.OSInstallDate, $dcState.LatestHotfixDate) | Where-Object { $_ }
        if ($candidateDates.Count -gt 0) {
            $dcState.EffectivePatchDate = ($candidateDates | Sort-Object -Descending | Select-Object -First 1)
        }

        # --- Print Spooler service state (for PrintNightmare only) ---
        try {
            $spooler = Invoke-ADQueryWithRetry -OperationName "Get-Service Spooler on $dcName" -Query {
                Get-Service -ComputerName $dcName -Name 'Spooler' -ErrorAction Stop
            }
            if ($spooler) {
                $dcState.Reachable    = $true
                $dcState.SpoolerStatus = "$($spooler.Status)"
            }
        }
        catch {
            Write-Verbose "Test-ADKnownDCVulnerabilities: could not query Spooler service state on '$dcName': $_"
            if (-not $dcState.Error) { $dcState.Error = "$_" }
        }

        # --- UBR (Update Build Revision) - BadSuccessor / CVE-2025-53779
        #     patch-level classification, Server 2025-level DCs only ---
        if ($dcState.OSBuildNumber -ge $Script:KnownVulnServer2025Build) {
            try {
                $ubr = Invoke-ADQueryWithRetry -OperationName "Read UBR registry value on $dcName" -Query {
                    Get-ADKnownVulnUBR -ComputerName $dcName
                }
                if ($null -ne $ubr) {
                    $dcState.UBR = [int]$ubr
                    if ($dcState.UBR -ge $Script:KnownVulnBadSuccessorPatchedUBR) {
                        $dcState.BadSuccessorPatchStatus = 'Patched'
                        [void]$badSuccessorPatchedDCs.Add($dcName)
                    }
                    else {
                        $dcState.BadSuccessorPatchStatus = 'Unpatched'
                        [void]$badSuccessorUnpatchedDCs.Add($dcName)
                    }
                }
                else {
                    $dcState.BadSuccessorPatchStatus = 'Unknown'
                    [void]$badSuccessorUnknownDCs.Add($dcName)
                }
            }
            catch {
                Write-Verbose "Test-ADKnownDCVulnerabilities: could not read UBR on '$dcName' (e.g. remote registry access denied); BadSuccessor patch level reported as unknown, not assumed patched: $_"
                $dcState.BadSuccessorPatchStatus = 'Unknown'
                [void]$badSuccessorUnknownDCs.Add($dcName)
                if (-not $dcState.Error) { $dcState.Error = "$_" }
            }
        }

        # --- Per-OS-build UBR classification for the two Netlogon RCE
        #     CVEs (files/25-known-vuln-per-os-build-refinement.md) ---
        # Additive precision alongside the FixDate-only evaluation below;
        # only performed for OS builds with an independently-confirmed
        # fixed UBR. Reuses Get-ADKnownVulnUBR unmodified - the same
        # generic remote-registry read already used for the BadSuccessor
        # classification above.
        if ($dcState.OSBuildNumber -and $Script:KnownVulnNetlogon2026MayPatchedUBR.ContainsKey($dcState.OSBuildNumber)) {
            try {
                $ubrMay = Invoke-ADQueryWithRetry -OperationName "Read UBR registry value on $dcName (CVE-2026-41089 classification)" -Query {
                    Get-ADKnownVulnUBR -ComputerName $dcName
                }
                if ($null -ne $ubrMay) {
                    $dcState.Netlogon2026MayUBR = [int]$ubrMay
                    if ($dcState.Netlogon2026MayUBR -ge $Script:KnownVulnNetlogon2026MayPatchedUBR[$dcState.OSBuildNumber]) {
                        $dcState.Netlogon2026MayPatchStatus = 'Patched'
                    }
                    else {
                        $dcState.Netlogon2026MayPatchStatus = 'Unpatched'
                    }
                }
                else {
                    $dcState.Netlogon2026MayPatchStatus = 'Unknown'
                }
            }
            catch {
                Write-Verbose "Test-ADKnownDCVulnerabilities: could not read UBR on '$dcName' for CVE-2026-41089 per-OS-build classification; reported as unknown, never assumed patched: $_"
                $dcState.Netlogon2026MayPatchStatus = 'Unknown'
                if (-not $dcState.Error) { $dcState.Error = "$_" }
            }
        }

        if ($dcState.OSBuildNumber -and $Script:KnownVulnNetlogon2026SepPatchedUBR.ContainsKey($dcState.OSBuildNumber)) {
            try {
                $ubrSep = Invoke-ADQueryWithRetry -OperationName "Read UBR registry value on $dcName (CVE-2026-72982 classification)" -Query {
                    Get-ADKnownVulnUBR -ComputerName $dcName
                }
                if ($null -ne $ubrSep) {
                    $dcState.Netlogon2026SepUBR = [int]$ubrSep
                    if ($dcState.Netlogon2026SepUBR -ge $Script:KnownVulnNetlogon2026SepPatchedUBR[$dcState.OSBuildNumber]) {
                        $dcState.Netlogon2026SepPatchStatus = 'Patched'
                    }
                    else {
                        $dcState.Netlogon2026SepPatchStatus = 'Unpatched'
                    }
                }
                else {
                    $dcState.Netlogon2026SepPatchStatus = 'Unknown'
                }
            }
            catch {
                Write-Verbose "Test-ADKnownDCVulnerabilities: could not read UBR on '$dcName' for CVE-2026-72982 per-OS-build classification; reported as unknown, never assumed patched: $_"
                $dcState.Netlogon2026SepPatchStatus = 'Unknown'
                if (-not $dcState.Error) { $dcState.Error = "$_" }
            }
        }

        if (-not $dcState.Reachable) {
            Write-Verbose "Test-ADKnownDCVulnerabilities: DC '$dcName' unreachable; skipping (no finding for this DC)."
            [void]$perDcState.Add([PSCustomObject]$dcState)
            continue
        }

        # --- Evaluate the three build/patch-only CVE thresholds ---
        if ($dcState.EffectivePatchDate) {
            if ($dcState.EffectivePatchDate -lt $Script:KnownVulnFixThresholds.ZeroLogon.FixDate) {
                [void]$zeroLogonDCs.Add($dcName)
            }
            if ($dcState.EffectivePatchDate -lt $Script:KnownVulnFixThresholds.MS17010.FixDate) {
                [void]$ms17010DCs.Add($dcName)
            }
            if ($dcState.EffectivePatchDate -lt $Script:KnownVulnFixThresholds.MS14068.FixDate) {
                [void]$ms14068DCs.Add($dcName)
            }
            if ($dcState.SpoolerStatus -eq 'Running' -and $dcState.EffectivePatchDate -lt $Script:KnownVulnFixThresholds.PrintNightmare.FixDate) {
                [void]$printNightmareDCs.Add($dcName)
            }
        }
        else {
            # No reliable patch-date evidence at all (neither an OS install
            # date nor any hotfix record) - cannot rule the DC IN or OUT for
            # the legacy CVEs, so it is reported for manual review rather
            # than silently assumed patched or silently assumed vulnerable.
            Write-Verbose "Test-ADKnownDCVulnerabilities: no OS install date or hotfix record available for '$dcName'; cannot determine legacy-CVE patch status from this data alone."
        }

        # --- Netlogon2026May / Netlogon2026Sep final determination ---
        # Per files/25-known-vuln-per-os-build-refinement.md: a CONCLUSIVE
        # UBR classification (Patched or Unpatched) for this DC is
        # authoritative and takes precedence over the FixDate-only result -
        # this is what removes the FixDate-only over-reporting ambiguity
        # described in that doc. An INCONCLUSIVE UBR read (Unknown - e.g.
        # remote registry access failed or was unreachable) falls back to
        # the ORIGINAL, unchanged FixDate-only evaluation for that DC,
        # rather than being treated as an automatic flag - this refinement
        # is additive precision on top of FixDate-only evaluation, not a
        # replacement, so a DC this refinement can't get a confident read
        # from is evaluated exactly as it always was, never more
        # aggressively just because a registry read happened to fail.
        if ($dcState.Netlogon2026MayPatchStatus -eq 'Patched') {
            # Confirmed patched by UBR - do not flag, regardless of FixDate.
        }
        elseif ($dcState.Netlogon2026MayPatchStatus -eq 'Unpatched') {
            [void]$netlogon2026DCs.Add($dcName)
        }
        elseif ($dcState.EffectivePatchDate -and $dcState.EffectivePatchDate -lt $Script:KnownVulnFixThresholds.Netlogon2026May.FixDate) {
            [void]$netlogon2026DCs.Add($dcName)
        }

        if ($dcState.Netlogon2026SepPatchStatus -eq 'Patched') {
            # Confirmed patched by UBR - do not flag, regardless of FixDate.
        }
        elseif ($dcState.Netlogon2026SepPatchStatus -eq 'Unpatched') {
            [void]$netlogon2026SepDCs.Add($dcName)
        }
        elseif ($dcState.EffectivePatchDate -and $dcState.EffectivePatchDate -lt $Script:KnownVulnFixThresholds.Netlogon2026Sep.FixDate) {
            [void]$netlogon2026SepDCs.Add($dcName)
        }

        [void]$perDcState.Add([PSCustomObject]$dcState)
    }

    # -------------------------------------------------------------------
    # Finding: DC Missing ZeroLogon Patch
    # -------------------------------------------------------------------
    if ($zeroLogonDCs.Count -gt 0) {
        $info = $Script:KnownVulnFixThresholds.ZeroLogon
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Known DC Vulnerabilities'
        $finding.Issue = $info.Issue
        $finding.Severity = 'Critical'
        $finding.SeverityLevel = 4
        $finding.AffectedObject = ($zeroLogonDCs -join ', ')
        $finding.Description = "$($zeroLogonDCs.Count) Domain Controller(s) show no patch/build evidence on or after the $($info.Cve) (ZeroLogon) fix date of $($info.FixDate.ToString('yyyy-MM-dd')): $($zeroLogonDCs -join ', ')."
        $finding.Impact = $info.Description
        $finding.Remediation = "Install the $($info.FixNote) Verify with `Get-HotFix -ComputerName <DC>` and enforce Netlogon secure-channel signing/sealing (`FullSecureChannelProtection`) once all DCs and trusts are updated."
        $finding.EstimatedEffort = 'High - requires coordinated cumulative/security-update patching across every DC in the domain in the same maintenance window; a Critical, unauthenticated, actively-weaponized flaw is not something to patch piecemeal.'
        $finding.KnownRisks = 'Minimal regression risk from this specific 2020 fix; there is no legitimate functionality reliant on the vulnerable Netlogon behavior it closes.'
        $finding.BackupRollback = 'Moderate - the update can technically be uninstalled via WSUS/DISM if it causes a regression, but doing so re-opens a Critical vulnerability with public exploit tooling, so treat this as a one-way step in practice.'
        $finding.Details = @{
            Cve                       = $info.Cve
            FixDate                   = $info.FixDate.ToString('yyyy-MM-dd')
            FixNote                   = $info.FixNote
            AffectedDomainControllers = @($zeroLogonDCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADKnownDCVulnerabilities: no DC found missing the ZeroLogon patch."
    }

    # -------------------------------------------------------------------
    # Finding: DC Vulnerable to MS17-010
    # -------------------------------------------------------------------
    if ($ms17010DCs.Count -gt 0) {
        $info = $Script:KnownVulnFixThresholds.MS17010
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Known DC Vulnerabilities'
        $finding.Issue = $info.Issue
        $finding.Severity = 'Critical'
        $finding.SeverityLevel = 4
        $finding.AffectedObject = ($ms17010DCs -join ', ')
        $finding.Description = "$($ms17010DCs.Count) Domain Controller(s) show no patch/build evidence on or after the $($info.Cve) fix date of $($info.FixDate.ToString('yyyy-MM-dd')): $($ms17010DCs -join ', ')."
        $finding.Impact = $info.Description
        $finding.Remediation = "Install the $($info.FixNote) If SMBv1 is not required, also disable it entirely (`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`)."
        $finding.EstimatedEffort = 'High - requires coordinated patching across every DC in the same maintenance window.'
        $finding.KnownRisks = 'No legitimate functionality relies on the vulnerable SMBv1 code path this fixes; the only realistic risk is from unrelated compatibility issues in the broader cumulative update, which standard patch-testing practice covers.'
        $finding.BackupRollback = 'Moderate - the update can technically be uninstalled, but doing so reopens EternalBlue, a vulnerability class historically responsible for mass-scale ransomware outbreaks (WannaCry/NotPetya) - do not roll back except as a genuine emergency measure with compensating network controls in place.'
        $finding.Details = @{
            Cve                       = $info.Cve
            FixDate                   = $info.FixDate.ToString('yyyy-MM-dd')
            FixNote                   = $info.FixNote
            AffectedDomainControllers = @($ms17010DCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADKnownDCVulnerabilities: no DC found vulnerable to MS17-010."
    }

    # -------------------------------------------------------------------
    # Finding: DC Vulnerable to MS14-068
    # -------------------------------------------------------------------
    if ($ms14068DCs.Count -gt 0) {
        $info = $Script:KnownVulnFixThresholds.MS14068
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Known DC Vulnerabilities'
        $finding.Issue = $info.Issue
        $finding.Severity = 'Critical'
        $finding.SeverityLevel = 4
        $finding.AffectedObject = ($ms14068DCs -join ', ')
        $finding.Description = "$($ms14068DCs.Count) Domain Controller(s) show no patch/build evidence on or after the $($info.Cve) (MS14-068) fix date of $($info.FixDate.ToString('yyyy-MM-dd')): $($ms14068DCs -join ', ')."
        $finding.Impact = $info.Description
        $finding.Remediation = "Install the $($info.FixNote) This is a long-superseded out-of-band fix; any DC still missing it should also be checked for currency against all subsequent cumulative updates."
        $finding.EstimatedEffort = 'High - requires coordinated patching across every DC in the same maintenance window.'
        $finding.KnownRisks = 'No legitimate functionality relies on the unpatched Kerberos PAC validation behavior; this is a decade-old out-of-band fix with essentially universal applicability by now.'
        $finding.BackupRollback = 'Moderate - the update can technically be uninstalled, but doing so reopens a well-documented forged-PAC Domain Admin escalation path.'
        $finding.Details = @{
            Cve                       = $info.Cve
            FixDate                   = $info.FixDate.ToString('yyyy-MM-dd')
            FixNote                   = $info.FixNote
            AffectedDomainControllers = @($ms14068DCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADKnownDCVulnerabilities: no DC found vulnerable to MS14-068."
    }

    # -------------------------------------------------------------------
    # Finding: PrintNightmare Exposure on DC
    # -------------------------------------------------------------------
    if ($printNightmareDCs.Count -gt 0) {
        $info = $Script:KnownVulnFixThresholds.PrintNightmare
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Known DC Vulnerabilities'
        $finding.Issue = $info.Issue
        $finding.Severity = 'High'
        $finding.SeverityLevel = 3
        $finding.AffectedObject = ($printNightmareDCs -join ', ')
        $finding.Description = "$($printNightmareDCs.Count) Domain Controller(s) are running the Print Spooler service AND show no patch/build evidence on or after the $($info.Cve) (PrintNightmare) fix date of $($info.FixDate.ToString('yyyy-MM-dd')): $($printNightmareDCs -join ', ')."
        $finding.Impact = $info.Description
        $finding.Remediation = "Install the $($info.FixNote) As defense-in-depth regardless of patch level, disable and stop the Spooler service on all Domain Controllers unless print serving from a DC is an explicit, documented requirement."
        $finding.EstimatedEffort = 'Medium - the patch itself needs the same coordinated maintenance-window rollout as other DC cumulative updates, but the faster practical fix (stopping the Print Spooler service on DCs) is a single-service change per DC.'
        $finding.KnownRisks = 'Applying the patch carries no legitimate compatibility risk; disabling Spooler as the faster interim fix removes DC print/driver-install capability, which is essentially never a legitimate DC function.'
        $finding.BackupRollback = 'Easy for the Spooler-disable route (service restarts immediately); Moderate for the cumulative-update route (same considerations as other DC patches).'
        $finding.OperationalNotes = 'This finding overlaps with the separate "Print Spooler Running on Domain Controller" finding - disabling the service is the faster of the two available fixes if patching must wait.'
        $finding.Details = @{
            Cve                       = $info.Cve
            FixDate                   = $info.FixDate.ToString('yyyy-MM-dd')
            FixNote                   = $info.FixNote
            AffectedDomainControllers = @($printNightmareDCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADKnownDCVulnerabilities: no DC found exposed to PrintNightmare (either Spooler not running or patch level current)."
    }

    # -------------------------------------------------------------------
    # Finding: DC Missing CVE-2026-41089 Patch (Netlogon RCE)
    # -------------------------------------------------------------------
    if ($netlogon2026DCs.Count -gt 0) {
        $info = $Script:KnownVulnFixThresholds.Netlogon2026May
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Known DC Vulnerabilities'
        $finding.Issue = $info.Issue
        $finding.Severity = 'Critical'
        $finding.SeverityLevel = 4
        $finding.AffectedObject = ($netlogon2026DCs -join ', ')
        $finding.Description = "$($netlogon2026DCs.Count) Domain Controller(s) show no patch/build evidence on or after the $($info.Cve) fix date of $($info.FixDate.ToString('yyyy-MM-dd')): $($netlogon2026DCs -join ', ')."
        $finding.Impact = $info.Description
        $finding.Remediation = "Install the $($info.FixNote) Treat as emergency-patch priority given active in-the-wild exploitation reported since late May / early June 2026 - verify with `Get-HotFix -ComputerName <DC>` and confirm against the current MSRC Update Guide entry for $($info.Cve) before considering a DC remediated."
        $finding.EstimatedEffort = 'High - requires coordinated patching across every DC in the same maintenance window; multiple vendors explicitly warn that a partially-patched DC fleet is an indefensible state given active in-the-wild exploitation.'
        $finding.KnownRisks = 'No legitimate functionality relies on the vulnerable Netlogon packet-handling code path; the risk of leaving any single DC unpatched is that it remains a viable, unauthenticated, actively-exploited entry point to the rest of the domain.'
        $finding.BackupRollback = 'Moderate - the update can technically be uninstalled if it causes a regression, but doing so reopens an actively-exploited, unauthenticated remote-code-execution vulnerability on a domain controller.'
        $finding.Details = @{
            Cve                       = $info.Cve
            FixDate                   = $info.FixDate.ToString('yyyy-MM-dd')
            FixNote                   = $info.FixNote
            AffectedDomainControllers = @($netlogon2026DCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADKnownDCVulnerabilities: no DC found missing the CVE-2026-41089 (Netlogon RCE) patch."
    }

    # -------------------------------------------------------------------
    # Finding: DC Missing CVE-2026-72982 Patch (Netlogon RCE)
    # -------------------------------------------------------------------
    if ($netlogon2026SepDCs.Count -gt 0) {
        $info = $Script:KnownVulnFixThresholds.Netlogon2026Sep
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Known DC Vulnerabilities'
        $finding.Issue = $info.Issue
        $finding.Severity = 'Critical'
        $finding.SeverityLevel = 4
        $finding.AffectedObject = ($netlogon2026SepDCs -join ', ')
        $finding.Description = "$($netlogon2026SepDCs.Count) Domain Controller(s) show no patch/build evidence on or after the $($info.Cve) fix date of $($info.FixDate.ToString('yyyy-MM-dd')): $($netlogon2026SepDCs -join ', ')."
        $finding.Impact = $info.Description
        $finding.Remediation = "Install the $($info.FixNote) Verify with `Get-HotFix -ComputerName <DC>` and confirm against the current MSRC Update Guide entry for $($info.Cve) before considering a DC remediated. Note this is a separate patch from the one required for CVE-2026-41089 - a DC already patched for that CVE is not necessarily patched for this one."
        $finding.EstimatedEffort = 'High - requires coordinated patching across every DC in the same maintenance window; a partially-patched DC fleet leaves a viable, unauthenticated, network-reachable entry point on any unpatched DC.'
        $finding.KnownRisks = 'No legitimate functionality relies on the vulnerable Netlogon packet-handling code path; the risk of leaving any single DC unpatched is that it remains a viable, unauthenticated entry point to the rest of the domain.'
        $finding.BackupRollback = 'Moderate - the update can technically be uninstalled if it causes a regression, but doing so reopens an unauthenticated remote-code-execution vulnerability on a domain controller.'
        $finding.Details = @{
            Cve                       = $info.Cve
            FixDate                   = $info.FixDate.ToString('yyyy-MM-dd')
            FixNote                   = $info.FixNote
            AffectedDomainControllers = @($netlogon2026SepDCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADKnownDCVulnerabilities: no DC found missing the CVE-2026-72982 (Netlogon RCE) patch."
    }

    # -------------------------------------------------------------------
    # Finding: BadSuccessor / dMSA Escalation Exposure
    # -------------------------------------------------------------------
    if ($server2025DCs.Count -gt 0) {
        $hasUnpatchedOrUnknown = ($badSuccessorUnpatchedDCs.Count -gt 0) -or ($badSuccessorUnknownDCs.Count -gt 0)

        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Known DC Vulnerabilities'
        $finding.Issue = 'BadSuccessor / dMSA Escalation Exposure'
        if ($hasUnpatchedOrUnknown) {
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
        }
        else {
            # Every Server 2025-level DC is confirmed patched (UBR >=
            # threshold) for CVE-2025-53779 - the original one-sided-link
            # escalation path is closed. Reduced (not suppressed) severity:
            # independent research shows a mutually-paired dMSA/target
            # relationship still allows credential/privilege abuse when an
            # attacker controls both sides, so this remains a
            # delegation/ACL exposure to review, not a clean bill of health.
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
        }
        $finding.AffectedObject = ($server2025DCs -join ', ')
        $finding.Description = "$($server2025DCs.Count) Domain Controller(s) are running Windows Server 2025 (build >= $($Script:KnownVulnServer2025Build)), which introduces delegated Managed Service Accounts (dMSA): $($server2025DCs -join ', '). Patch-level (UBR) breakdown for CVE-2025-53779: $($badSuccessorPatchedDCs.Count) patched (UBR >= $($Script:KnownVulnBadSuccessorPatchedUBR))$(if ($badSuccessorPatchedDCs.Count -gt 0) { ": $($badSuccessorPatchedDCs -join ', ')" }); $($badSuccessorUnpatchedDCs.Count) unpatched$(if ($badSuccessorUnpatchedDCs.Count -gt 0) { ": $($badSuccessorUnpatchedDCs -join ', ')" }); $($badSuccessorUnknownDCs.Count) unknown patch level (UBR unreadable)$(if ($badSuccessorUnknownDCs.Count -gt 0) { ": $($badSuccessorUnknownDCs -join ', ')"})."
        $finding.Impact = "The dMSA feature ('BadSuccessor') originally let any principal with CreateChild/msDS-DelegatedManagedServiceAccount rights over an OU create a dMSA and link it one-sidedly to an existing account to inherit that account's effective privileges and Kerberos keys - abusable against any account, including Tier-0. Microsoft's August 2025 fix (CVE-2025-53779, build 26100.4946+) made the KDC require a mutual (two-sided) link before honoring the relationship, closing that direct path on DCs confirmed patched above, but does not restrict who can create a dMSA or write its link attributes - independent research has shown a controlled dMSA can still be paired with a target the attacker also controls to extract that target's credentials, even on a fully patched DC. Any DC reported above as unpatched or unknown patch level remains exposed to the original one-sided-link escalation as well."
        $finding.Remediation = "Ensure all Server 2025 DCs are updated to at least the August 2025 cumulative update (KB5063878, build 26100.4946) or later, which addresses CVE-2025-53779 - prioritize any DC listed above as unpatched or unknown patch level (an unreadable UBR should be treated as unpatched until confirmed otherwise, e.g. remote registry access was denied). Independently of patch level, audit and restrict who holds CreateChild/msDS-DelegatedManagedServiceAccount and generic-write rights on OUs and on dMSA objects themselves, especially anywhere at or above Tier-0; monitor for unexpected dMSA creation and changes to the migration-link attributes; consult current Microsoft/vendor guidance before treating any specific configuration as fully mitigated."
        $finding.EstimatedEffort = 'High - requires both patching every affected Server 2025 DC to the fixed build and, independently of patch level, an OU/dMSA-object permissions review across the environment (per Microsoft/Akamai guidance, the patch alone doesn''t restrict who can create or link a dMSA).'
        $finding.KnownRisks = 'Independent Akamai research confirmed that even on a fully patched DC, a dMSA an attacker controls can still be paired with a target account the attacker also controls to extract that target''s credentials, so patching alone does not fully close the exposure - the permissions review is a genuine, separate, needed step, not padding.'
        $finding.BackupRollback = 'Easy - the patch itself is a normal cumulative update with standard rollback options; the permissions tightening (restricting CreateChild/msDS-DelegatedManagedServiceAccount rights) can be reverted by re-granting the prior delegation if needed.'
        $finding.OperationalNotes = 'Enable auditing on dMSA creation and migration-link attribute changes (both the dMSA''s link and the superseded account''s link), per Akamai''s own detection guidance, since the technique remains relevant even after patching.'
        $finding.Details = @{
            AffectedDomainControllers          = @($server2025DCs)
            Server2025BuildThreshold           = $Script:KnownVulnServer2025Build
            BadSuccessorPatchedUBRThreshold    = $Script:KnownVulnBadSuccessorPatchedUBR
            PatchedDomainControllers           = @($badSuccessorPatchedDCs)
            UnpatchedDomainControllers         = @($badSuccessorUnpatchedDCs)
            UnknownPatchStatusDomainControllers = @($badSuccessorUnknownDCs)
            PerDomainControllerState           = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADKnownDCVulnerabilities: no Windows Server 2025-level DC found; BadSuccessor/dMSA check not applicable."
    }

    Write-Verbose "Completed Known DC Vulnerabilities (patch/build) audit. Findings: $($findings.Count)"
    return $findings
}

#endregion
