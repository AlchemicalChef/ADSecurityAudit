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
        [switch]$IncludePrivilegedUsersReport,

        # Multi-domain-forest override: forces every AD query in this run
        # (domain lookup, DC discovery, and every audit test) to explicitly
        # target this domain/DC rather than letting the AD module's default
        # "serverless" bind resolve against the invoking account's own
        # logon domain. Accepts a domain FQDN (e.g. 'domainb.corp.com') or
        # a specific DC FQDN/hostname (e.g. 'dc01.domainb.corp.com').
        # DEFAULT WHEN OMITTED: the current user's own domain
        # ($env:USERDNSDOMAIN) - not the machine's joined domain - is used
        # automatically, so the common case ("audit my own domain") no
        # longer depends on the AD module's ambient resolution at all. Pass
        # -Server explicitly only when you need to target a domain OTHER
        # than your own account's domain (e.g. auditing Domain B while
        # logged in as a Domain A account), or when running under
        # alternate credentials via `runas /netonly` (see
        # Resolve-ADSecurityAuditTargetServer in Common.ps1 for why the
        # default can't reliably detect that case on its own).
        [Parameter()]
        [string]$Server,

        # User-declared additions to the Tier-0 scope, on top of the
        # built-in privileged groups/DCs/AdminSDHolder that
        # Get-ADTier0Principal already resolves on its own (see
        # Common.ps1). Pass one or more distinguished names of objects
        # that are Tier-0 in THIS environment even though they aren't
        # nested in a built-in privileged group - e.g. a backup service
        # account with rights over every DC, or a custom-named
        # "Tier0-Admins" group. Consumed by every check that calls
        # Get-ADTier0Principal (currently ControlPaths.ps1's
        # Test-ADControlPaths/Get-ADControlPathGraph,
        # ExchangeEscalationAudits.ps1, and the constrained-delegation
        # Tier-0-target check in DomainAdminEquivalence.ps1).
        [Parameter()]
        [string[]]$AdditionalTier0DN = @()
    )
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $effectiveServer = $null

    # Fixed: -ExportPath (e.g. ".\foldername") was passed straight into
    # Join-Path/[System.IO.File]::WriteAllText below while still relative.
    # See Resolve-ADSecurityAuditPath in Common.ps1 for the full
    # explanation - short version: a later raw .NET write-test call
    # resolves relative paths differently than the PowerShell cmdlets
    # above it do, so a perfectly valid relative -ExportPath could
    # silently be checked against the wrong directory and throw "Export
    # path is not writable". Resolving to an absolute path up front (pure
    # string computation, doesn't require the path to exist) avoids that
    # entirely, and makes every downstream Join-Path/New-Item/Write-Host
    # message operate on (and print) an unambiguous absolute path.
    try {
        $ExportPath = Resolve-ADSecurityAuditPath -Path $ExportPath
    }
    catch {
        Write-Error "Could not resolve -ExportPath '$ExportPath' to an absolute path: $_"
        return
    }

    # Reset run-scope notes (e.g. a "PDC-only" check running against an
    # explicitly-named non-PDC DC) so notes from a previous
    # Start-ADSecurityAudit call in the same PowerShell session never leak
    # into this run's HTML report - see Common.ps1.
    Reset-ADRunScopeNotes

    # Reset (then repopulate) the shared additional-Tier-0-scope list on
    # every run, same reasoning as Reset-ADRunScopeNotes above: without
    # this, a value from a previous Start-ADSecurityAudit call in the same
    # PowerShell session (or its absence) would leak into this run.
    $Script:AdditionalTier0DistinguishedNames = @($AdditionalTier0DN)
    
    if (-not (Test-Path $ExportPath)) {
        try {
            Write-Verbose "Start-ADSecurityAudit: export path '$ExportPath' does not exist; creating it..."
            New-Item -Path $ExportPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Error "Export path does not exist and could not be created: $ExportPath. Error: $_"
            return
        }
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
    Start-Transcript -Path $logPath -Force
    
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

        # Resolve the effective server: the explicit -Server value if one
        # was passed, otherwise the current user's own domain
        # ($env:USERDNSDOMAIN) by default rather than leaving "no -Server"
        # ambient/ambiguous - see Resolve-ADSecurityAuditTargetServer for
        # why. $effectiveServer is $null only when neither is available
        # (e.g. a local, non-domain logon session), in which case behavior
        # is unchanged from before this feature existed.
        $effectiveServer = Resolve-ADSecurityAuditTargetServer -Server $Server

        # Multi-domain-forest override (see -Server param comment above):
        # installs a -Server default for every Get-AD*/Set-AD* call made
        # anywhere in this run - not just the two calls immediately below,
        # but every audit test's own Get-ADDomain/Get-ADObject/Get-ADUser/
        # Get-ADComputer/etc. calls too - so the whole run targets the
        # domain the operator specified (or their own domain, by default)
        # instead of whatever domain the invoking account's default AD
        # binding would otherwise resolve to. Always cleared in the outer
        # finally block below, so it never leaks into a later
        # Start-ADSecurityAudit call in the same session.
        if ($effectiveServer) {
            $serverSource = if ($Server) { 'explicit -Server' } else { "your own domain, `$env:USERDNSDOMAIN" }
            if (Get-ADSecurityAuditServerIsExplicitDC) {
                # $Server named one specific DC (not a domain name) - every
                # per-DC check in this run is narrowed to ONLY that DC, not
                # just the default/domain-wide query target. Say so here,
                # not just in -Verbose output, since this is a real
                # coverage-scope decision worth surfacing by default.
                Write-Host "Server override: '$effectiveServer' is an explicit, specific Domain Controller ($serverSource) - every AD query, including per-DC checks (audit policy, Kerberos hardening, RODC posture, etc.), is scoped to ONLY this DC for the rest of the run. Other Domain Controllers in the domain will not be evaluated.`n" -ForegroundColor Cyan
            }
            else {
                Write-Host "Server override: '$effectiveServer' (the domain's PDC Emulator, resolved from $serverSource) is the default/domain-wide query target for this run. Per-DC checks still enumerate and evaluate EVERY Domain Controller in the domain.`n" -ForegroundColor Cyan
            }
            Set-ADSecurityAuditTargetServer -Server $effectiveServer
        }

        Write-Verbose "Testing Domain Controller connectivity..."
        try {
            $domainParams = @{ ErrorAction = 'Stop' }
            if ($effectiveServer) { $domainParams['Server'] = $effectiveServer }
            $domain = Get-ADDomain @domainParams

            # Attempt to discover multiple DCs for failover
            $domainControllers = @()
            try {
                # Get-ADSecurityAuditDomainController (Common.ps1), not a
                # bare Get-ADDomainController -Filter *: the latter queries
                # the forest-wide Configuration container and returns every
                # domain's DCs regardless of -Server, which could silently
                # hand $connectedDC below a DC from the WRONG domain even
                # with an active -Server override.
                $domainControllers = Get-ADSecurityAuditDomainController -Server $effectiveServer | Select-Object -First 3
            }
            catch {
                Write-Verbose "Could not enumerate all DCs, falling back to discovery: $_"
            }

            if (-not $domainControllers -or $domainControllers.Count -eq 0) {
                if ($effectiveServer) {
                    # An override is active (explicit or the user-domain
                    # default): do NOT fall back to -Discover here. DC
                    # Locator's -Discover uses subnet/site mapping (or the
                    # caller's own logon domain) to pick a DC, which is the
                    # exact "resolves to the wrong domain" behavior the
                    # override exists to bypass. Resolve directly against
                    # the requested target instead.
                    $domainControllers = @(Get-ADDomainController -Identity $effectiveServer -Server $effectiveServer -ErrorAction Stop)
                }
                else {
                    $domainControllers = @(Get-ADDomainController -Discover -ErrorAction Stop)
                }
            }

            # Find a reachable DC
            $connectedDC = $null
            foreach ($dc in $domainControllers) {
                Write-Verbose "Testing connectivity to DC: $($dc.HostName)"
                if (Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet) {
                    $connectedDC = $dc
                    Write-Verbose "Successfully connected to Domain Controller: $($dc.HostName)"
                    break
                }
                else {
                    Write-Verbose "Cannot reach Domain Controller: $($dc.HostName)"
                }
            }

            if (-not $connectedDC) {
                Write-Warning "Cannot reach any discovered Domain Controllers. Proceeding with default DC..."
                $connectedDC = $domainControllers[0]
            }

            $dc = $connectedDC
        }
        catch {
            Write-Error "Failed to connect to Active Directory Domain: $_"
            return
        }
        
        Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Green
        Write-Host "Domain DN: $($domain.DistinguishedName)`n" -ForegroundColor Green
        
        # Define all tests - including the new DomainAdminEquivalence test
        $allTests = @{
            'UserAccounts' = { Test-ADUserSecurity -InactiveDaysThreshold $InactiveDaysThreshold -PasswordAgeThreshold $PasswordAgeThreshold }
            'PrivilegedGroups' = { Test-ADPrivilegedGroups }
            'AdminSDHolder' = { Test-AdminSDHolder }
            'GroupPolicies' = { Test-ADGroupPolicies }
            'ReplicationSecurity' = { Test-ADReplicationSecurity }
            'DomainSecurity' = { Test-ADDomainSecurity }
            'DangerousPermissions' = { Test-ADDangerousPermissions }
            'CertificateServices' = { Test-ADCertificateServices }
            'ADCSExtended' = { Test-ADCSExtended }
            'ADCSChaseFallback' = { Test-ADCSChaseFallback }
            'ADCSWeakCertificateBinding' = { Test-ADCSWeakCertificateBinding }
            'KRBTGTAccount' = { Test-KRBTGTAccount -MaxPasswordAgeDays 180 }
            'DomainTrusts' = { Test-ADDomainTrusts }
            'LAPSDeployment' = { Test-LAPSDeployment }
            'AuditPolicyConfiguration' = { Test-AuditPolicyConfiguration }
            'ConstrainedDelegation' = { Test-ConstrainedDelegation }
            'DomainAdminEquivalence' = { Test-ADDomainAdminEquivalence }
            'MachineAccountQuota' = { Test-ADMachineAccountQuota -Server $effectiveServer }
            'DomainHardeningFlags' = { Test-ADDomainHardeningFlags }
            'CoercionAndRelayExposure' = { Test-ADCoercionAndRelayExposure }
            'LsaProtection' = { Test-ADLsaProtection }
            'DnsSecurity' = { Test-ADDnsSecurity }
            'LegacyAuthSurface' = { Test-ADLegacyAuthSurface }
            'KerberosHardening' = { Test-ADKerberosHardening }
            'StaleObjectDepth' = { Test-ADStaleObjectDepth }
            'DomainControllerIntegrity' = { Test-ADDomainControllerIntegrity }
            'SchemaIntegrity' = { Test-ADSchemaIntegrity }
            'KdsRootKeySecurity' = { Test-ADKdsRootKeySecurity }
            'DpapiBackupKeySecurity' = { Test-ADDpapiBackupKeySecurity }
            'AccountComputerHygiene' = { Test-ADAccountComputerHygiene }
            'GpoDeployedSecrets' = { Test-ADGpoDeployedSecrets }
            'KnownDCVulnerabilities' = { Test-ADKnownDCVulnerabilities }
            'ExchangeEscalation' = { Test-ADExchangeEscalation }
            'RodcSecurity' = { Test-ADRodcSecurity }
            'ControlPaths' = { Test-ADControlPaths }
            'ManagedServiceAccounts' = { Test-ADManagedServiceAccountSecurity }
        }
        
        # Determine which tests to run
        if ($IncludeTests) {
            $testsToRun = $allTests.Keys | Where-Object { $_ -in $IncludeTests -and $_ -notin $ExcludeTests }
        }
        else {
            $testsToRun = $allTests.Keys | Where-Object { $_ -notin $ExcludeTests }
        }

        # Reported gap: neither the HTML nor CSV report gave any
        # indication of which checks did NOT run (deliberately excluded
        # via -IncludeTests/-ExcludeTests, or attempted and failed with an
        # exception - previously only a console Write-Warning, invisible
        # to anyone reading the report later rather than watching the
        # console live), or which checks ran and found nothing (a "clean"
        # result is indistinguishable from "never ran" once you're only
        # looking at the findings list, since neither produces a finding).
        # $testCoverage tracks EVERY entry in $allTests - not just
        # $testsToRun - so a reader gets the full picture: for every
        # possible check, whether it ran clean, ran and found something,
        # failed, or was excluded from this run.
        $testCoverage = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($testName in ($allTests.Keys | Sort-Object)) {
            if ($testName -notin $testsToRun) {
                $testCoverage.Add([PSCustomObject]@{
                    TestName     = $testName
                    Status       = 'Excluded'
                    FindingCount = 0
                    ErrorMessage = $null
                })
            }
        }

        # Run tests and collect findings
        $allFindings = @()
        $totalTestCount = @($testsToRun).Count
        $currentTestIndex = 0
        
        foreach ($testName in $testsToRun) {
            $currentTestIndex++
            Write-Progress -Activity "Running Active Directory Security Audit" `
                -Status "Test $currentTestIndex of $totalTestCount`: $testName" `
                -PercentComplete (($currentTestIndex / [math]::Max(1, $totalTestCount)) * 100)
            Write-Host "Running test: $testName..." -ForegroundColor Yellow
            
            try {
                $testResults = & $allTests[$testName]
                
                # Handle both ADSecurityFinding objects and PSCustomObject (from DomainAdminEquivalence)
                if ($testResults) {
                    foreach ($result in $testResults) {
                        # Convert PSCustomObject to ADSecurityFinding if needed
                        if ($result -is [PSCustomObject] -and $result -isnot [ADSecurityFinding]) {
                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = $result.Category
                            $finding.Issue = $result.Issue
                            $finding.Severity = $result.Severity
                            $finding.SeverityLevel = if ($result.SeverityLevel) { $result.SeverityLevel } else {
                                switch ($result.Severity) {
                                    'Critical' { 4 }
                                    'High' { 3 }
                                    'Medium' { 2 }
                                    'Low' { 1 }
                                    default { 0 }
                                }
                            }
                            $finding.AffectedObject = $result.AffectedObject
                            $finding.Description = $result.Description
                            $finding.Impact = $result.Impact
                            $finding.Remediation = $result.Remediation
                            $finding.EstimatedEffort = $result.EstimatedEffort
                            $finding.KnownRisks = $result.KnownRisks
                            $finding.BackupRollback = $result.BackupRollback
                            $finding.OperationalNotes = $result.OperationalNotes
                            $finding.Details = if ($result.Details) { $result.Details } else { @{} }
                            $finding.TestName = $testName
                            $allFindings += $finding
                        }
                        else {
                            # $result is already a genuine [ADSecurityFinding] -
                            # tag it in place (mutation persists, same
                            # reference-type reasoning as Set-ADFindingMetadata's
                            # own docs) rather than only tagging the converted-
                            # from-PSCustomObject branch above, so EVERY finding
                            # added to $allFindings carries TestName regardless
                            # of which check-authoring style produced it.
                            $result.TestName = $testName
                            $allFindings += $result
                        }
                    }
                }
                
                $criticalCount = ($testResults | Where-Object { $_.Severity -eq 'Critical' }).Count
                $highCount = ($testResults | Where-Object { $_.Severity -eq 'High' }).Count
                $mediumCount = ($testResults | Where-Object { $_.Severity -eq 'Medium' }).Count
                $lowCount = ($testResults | Where-Object { $_.Severity -eq 'Low' }).Count
                
                Write-Host "  Found: $criticalCount Critical, $highCount High, $mediumCount Medium, $lowCount Low`n" -ForegroundColor Gray

                $testCoverage.Add([PSCustomObject]@{
                    TestName     = $testName
                    Status       = 'Completed'
                    FindingCount = @($testResults).Count
                    ErrorMessage = $null
                })
            }
            catch {
                Write-Warning "Test '$testName' failed: $_"
                $testCoverage.Add([PSCustomObject]@{
                    TestName     = $testName
                    Status       = 'Failed'
                    FindingCount = 0
                    ErrorMessage = "$_"
                })
            }
        }
        
        Write-Progress -Activity "Running Active Directory Security Audit" -Completed
        
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

        # Defensive: flatten $allFindings before ANY consumer touches it -
        # including the summary counts just below. A jagged/nested array -
        # a top-level element that is itself a sub-array of several
        # findings, rather than one - can slip in above if any invoked
        # test scriptblock emits more than one array to its own output
        # pipeline (the assembly loop's `else` branch then appends that
        # whole array as a single nested element instead of spreading it
        # into individual findings). Left unflattened, the summary counts
        # below would silently undercount (Where-Object can't see into a
        # nested array element's .Severity), and Set-ADFindingMetadata
        # further down - which has a strongly-typed
        # [ADSecurityFinding]$Finding parameter - throws "Cannot process
        # argument transformation on parameter 'Finding'" the moment its
        # tagging loop reaches such an element, failing after
        # Stop-Transcript has already run in the finally block and before
        # any report file is written. Get-ADRiskScore/Get-ADRetestComparison
        # already defend against this on their own inputs via this same
        # helper; applying it here, immediately after assembly, protects
        # every downstream consumer instead of just scoring.
        $allFindings = @(ConvertTo-ADFlatFindingsArray -Findings $allFindings)
        
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

        # Tag every finding with MITRE / ANSSI / Weight from the central mapping
        # table so findings are born score/MITRE-aware (v1.2.0 contract layer).
        # EstimatedEffort/KnownRisks/BackupRollback/OperationalNotes (v1.24.0)
        # are set directly in each check alongside Description/Impact/
        # Remediation (see src/*.ps1), so no separate tagging pass is needed
        # for those fields.
        foreach ($finding in $allFindings) {
            [void](Set-ADFindingMetadata -Finding $finding)
        }

        # Compute the risk score, per-category sub-scores, and ANSSI maturity.
        $riskScore = Get-ADRiskScore -Findings $allFindings
        
        Write-Host "Total Findings: $($allFindings.Count)" -ForegroundColor White
        Write-Host "  Critical: $($summary.Critical)" -ForegroundColor Red
        Write-Host "  High: $($summary.High)" -ForegroundColor DarkRed
        Write-Host "  Medium: $($summary.Medium)" -ForegroundColor Yellow
        Write-Host "  Low: $($summary.Low)" -ForegroundColor Gray

        Write-Host "`nRisk Score: $($riskScore.TotalScore)/100 (higher = worse)" -ForegroundColor White
        Write-Host "ANSSI Maturity: $($riskScore.MaturityLabel)" -ForegroundColor White
        if ($riskScore.CategoryScores -and $riskScore.CategoryScores.Count -gt 0) {
            $worst = $riskScore.CategoryScores[0]
            Write-Host "Worst Category: $($worst.Category) ($($worst.Score)/100)" -ForegroundColor Gray
        }
        
        if ($privilegedUsers) {
            Write-Host "`nPrivileged Users: $($privilegedUsers.Count)" -ForegroundColor White
        }
        
        Write-Host "`nDuration: $($duration.TotalSeconds) seconds" -ForegroundColor Gray
        
        # Export results.
        # FIXED (reported): this used to be gated on
        # "$allFindings.Count -gt 0", so a fully clean run (every check
        # ran and found nothing - arguably the best possible outcome, and
        # exactly the case where "what was actually checked" matters most
        # to show) produced NO report files at all: no JSON, no HTML, no
        # CSV, no score sidecar - nothing on disk to prove the audit ran,
        # let alone what it covered. Always export now; an empty findings
        # JSON is just "[]" (valid, and Get-ADRiskScore/ConvertFrom-Json
        # both already handle a zero-finding array correctly - see their
        # own empty-collection guards), and the HTML/CSV Test Coverage
        # section is exactly what makes a genuinely clean run look
        # different from a run that produced no report for some other
        # reason.
        if ($true) {
            Write-Progress -Activity "Exporting Audit Reports" -Status "Writing JSON report..." -PercentComplete 10

            # Export to JSON
            $jsonPath = Join-Path $ExportPath "AD_Security_Audit_$timestamp.json"
            # A zero-finding run (now exported unconditionally - see the
            # "Export results" comment above) needs special-casing here:
            # piping an EMPTY array to ConvertTo-Json produces zero
            # pipeline objects, so ConvertTo-Json emits an empty STRING,
            # not "[]" - Out-File would then write a 0-byte file that
            # Export-ADSecurityReportHTMLFromJson's ConvertFrom-Json (or
            # any other consumer) cannot parse at all. Write valid empty-
            # array JSON explicitly instead; the non-empty path is
            # untouched (still piped, exactly as before - a single-finding
            # run's already-relied-upon "comes back needing
            # ConvertTo-ADFlatFindingsArray to re-wrap" shape is
            # unchanged).
            if ($allFindings.Count -eq 0) {
                '[]' | Out-File -FilePath $jsonPath -Encoding UTF8
            }
            else {
                $allFindings | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
            }
            Write-Host "`nDetailed report exported to: $jsonPath" -ForegroundColor Green
            
            # Export to HTML
            Write-Progress -Activity "Exporting Audit Reports" -Status "Building HTML report..." -PercentComplete 40
            $htmlPath = Join-Path $ExportPath "AD_Security_Audit_$timestamp.html"

            # Notes recorded THIS run/session (e.g. a "PDC-only" check
            # running against an explicitly-named non-PDC DC) - see
            # Get-ADRunScopeNotes in Common.ps1 (v1.23.9, unrelated to the
            # now-removed offline/-Snapshot mode).
            $runScopeNotes = @(Get-ADRunScopeNotes)
            if ($runScopeNotes.Count -gt 0) {
                Write-Host "Run scope note: $($runScopeNotes.Count) note(s) about how this run was scoped - see the HTML report's 'Run Scope Information' section.`n" -ForegroundColor Yellow
            }

            Export-ADSecurityReportHTML -Findings $allFindings -OutputPath $htmlPath -Domain $domain.DNSRoot -Summary $summary -Duration $duration -PrivilegedUsers $privilegedUsers -RiskScore $riskScore -RunScopeNotes $runScopeNotes -TestCoverage $testCoverage
            Write-Host "HTML report exported to: $htmlPath" -ForegroundColor Green
            
            # Export to CSV with formula injection protection
            # NOTE (output contract): existing columns are never reordered or
            # removed. New flat fields are APPENDED after DetectedDate.
            #
            # Single source of truth for this column list is now
            # ConvertTo-ADFindingsCsvRows (Common.ps1) - shared with
            # Export-ADSecurityReportCSVFromJson's offline rebuild path,
            # so the two can no longer independently drift out of sync
            # with each other the way this CSV previously drifted from
            # the JSON export it's meant to mirror (see that function's
            # own docs for the history).
            Write-Progress -Activity "Exporting Audit Reports" -Status "Writing CSV report..." -PercentComplete 70
            $csvPath = Join-Path $ExportPath "AD_Security_Audit_$timestamp.csv"
            ConvertTo-ADFindingsCsvRows -Findings $allFindings |
                Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "CSV report exported to: $csvPath" -ForegroundColor Green

            # Export the score / maturity / MITRE roll-up as a sidecar JSON so
            # the summary does not pollute the per-finding CSV/JSON schema.
            $scorePath = Join-Path $ExportPath "AD_Security_Score_$timestamp.json"
            $riskScore | ConvertTo-Json -Depth 6 | Out-File -FilePath $scorePath -Encoding UTF8
            Write-Host "Score summary exported to: $scorePath" -ForegroundColor Green

            # Export test coverage (what ran clean, what found something,
            # what failed, what was excluded) as its own sidecar JSON and
            # CSV - same "don't pollute the per-finding schema" reasoning
            # as the score sidecar above. This is the ONLY durable record
            # of coverage for a run: the console Write-Warning/Write-Host
            # lines above are gone the moment the console scrolls past
            # them or the run was non-interactive, and neither the
            # findings JSON/CSV/HTML previously carried this information
            # in any form - a check that failed or was excluded looked
            # identical to a check that ran and found nothing.
            $testCoverageSorted = @($testCoverage | Sort-Object TestName)
            $testCoveragePath = Join-Path $ExportPath "AD_Security_TestCoverage_$timestamp.json"
            $testCoverageSorted | ConvertTo-Json -Depth 4 | Out-File -FilePath $testCoveragePath -Encoding UTF8
            Write-Host "Test coverage exported to: $testCoveragePath" -ForegroundColor Green

            $testCoverageCsvPath = Join-Path $ExportPath "AD_Security_TestCoverage_$timestamp.csv"
            $testCoverageSorted | ForEach-Object {
                [PSCustomObject]@{
                    TestName     = $_.TestName | ConvertTo-SafeCsvValue
                    Status       = $_.Status
                    FindingCount = $_.FindingCount
                    ErrorMessage = $_.ErrorMessage | ConvertTo-SafeCsvValue
                }
            } | Export-Csv -Path $testCoverageCsvPath -NoTypeInformation -Encoding UTF8
            Write-Host "Test coverage CSV exported to: $testCoverageCsvPath" -ForegroundColor Green
        }
        
        # Export privileged users report with formula injection protection
        if ($privilegedUsers -and $privilegedUsers.Count -gt 0) {
            $privilegedUsersCsvPath = Join-Path $ExportPath "AD_Privileged_Users_$timestamp.csv"

            $privilegedUsers | Select-Object SamAccountName, DisplayName, UserPrincipalName, Enabled, PasswordLastSet, `
                PasswordNeverExpires, LastLogonDate, AdminCount, PrivilegedGroupsString, Title, Department, `
                DoesNotRequirePreAuth, TrustedForDelegation, HasSPN, SPNCount |
                ForEach-Object {
                    [PSCustomObject]@{
                        SamAccountName = $_.SamAccountName | ConvertTo-SafeCsvValue
                        DisplayName = $_.DisplayName | ConvertTo-SafeCsvValue
                        UserPrincipalName = $_.UserPrincipalName | ConvertTo-SafeCsvValue
                        Enabled = $_.Enabled
                        PasswordLastSet = $_.PasswordLastSet
                        PasswordNeverExpires = $_.PasswordNeverExpires
                        LastLogonDate = $_.LastLogonDate
                        AdminCount = $_.AdminCount
                        PrivilegedGroupsString = $_.PrivilegedGroupsString | ConvertTo-SafeCsvValue
                        Title = $_.Title | ConvertTo-SafeCsvValue
                        Department = $_.Department | ConvertTo-SafeCsvValue
                        DoesNotRequirePreAuth = $_.DoesNotRequirePreAuth
                        TrustedForDelegation = $_.TrustedForDelegation
                        HasSPN = $_.HasSPN
                        SPNCount = $_.SPNCount
                    }
                } |
                Export-Csv -Path $privilegedUsersCsvPath -NoTypeInformation -Encoding UTF8

            Write-Host "Privileged users report exported to: $privilegedUsersCsvPath" -ForegroundColor Green
        }
        
        Write-Progress -Activity "Exporting Audit Reports" -Completed
        
        Write-Host "`n==================================================" -ForegroundColor Cyan
        Write-Host "Audit Complete" -ForegroundColor Cyan
        Write-Host "==================================================`n" -ForegroundColor Cyan
        
        return $allFindings
    }
    finally {
        if ($effectiveServer) {
            Clear-ADSecurityAuditTargetServer
        }
        Stop-Transcript
    }
}
