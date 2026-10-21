@{
    RootModule = 'ADSecurityAudit.psm1'
    ModuleVersion = '1.30.5'
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
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('ActiveDirectory', 'Security', 'Audit', 'Compliance')
            LicenseUri = 'https://opensource.org/licenses/MIT'
            ProjectUri = 'https://github.com/AlchemicalChef/ADSecurityAudit'
            IconUri = ''
            ReleaseNotes = @'
v1.30.5 - Bug fix: several findings didn't show their own comparison values
- Reported from real testing: 'Schema defaultSecurityDescriptor Modified'
  listed which schema classes were flagged, but never showed what the
  actual vs. expected defaultSecurityDescriptor values actually WERE -
  the exact data the check exists to compare. Root cause: the comparison
  data (ExpectedSddl/ActualSddl) was only ever written to Details, and
  Reporting.ps1 only specially renders Details for the 'Attack Paths'
  category - for every other category, including this one, Details is
  invisible in the HTML report and only shows up as a compact embedded
  JSON blob in the CSV column, never in a human-readable form.
- Fixed: both the Expected (Microsoft-documented default) and Actual
  (currently set on this schema) SDDL strings now appear directly in
  the finding's own Description text, where every report format
  displays them - no need to open the raw JSON or decode a CSV blob.
  Also split what was one aggregated multi-class finding into one
  finding per modified class, matching this project's established
  one-finding-per-affected-object convention (and making each class's
  own comparison unambiguous rather than needing to match values back
  to class names in a joined list). Remediation text now suggests
  ConvertFrom-SddlString to decode either value, since the raw SDDL
  strings for user/computer in particular are 1000+ characters and not
  practically hand-readable.
- Prompted by that report, systematically scanned every finding block in
  the codebase (162 total) for the same class of bug - a comparison/
  measured value present in Details but absent from Description. Most
  candidates the scan initially flagged turned out to be false
  positives on manual inspection (the codebase already surfaces the
  meaningful DERIVED value - e.g. ".Days" instead of a raw timestamp -
  correctly in Description; the scan's heuristic just couldn't match a
  renamed variable). Two further genuine instances were found and fixed
  the same way:
  - 'Stale AzureADSSOACC Kerberos Key' (DomainSecurityAudits.ps1):
    Description said only "has not been rotated within the last 30
    days" with no indication of the actual age or last-set date - both
    now included directly.
  - 'Enterprise Key Admins Permissions Not Scoped to
    msDS-KeyCredentialLink' (PermissionsAudits.ps1): Description said
    only that rights were "not scoped" without showing what ObjectType
    GUID the ACE actually was scoped to, versus the expected
    msDS-KeyCredentialLink GUID - both now shown directly.
- Verified all three fixes via real execution (mocked AD cmdlets): each
  produces exactly the expected finding, with the actual/expected
  values now visible in Description.
- No Issue string, Category, or Scoring.ps1 mapping change for any of
  the three - this release is a Description/output-detail fix only.

v1.30.4 - Packaged synthetic fixture samples + new-check validation workflow
- New tools/synthetic-fixtures-samples/: the actual, real (not
  hand-written) output from tools/New-ADSecurityAuditSyntheticFixtures.ps1
  - all four tiers (25/50/75/100%) of JSON findings, score sidecars,
  rebuilt HTML, and rebuilt CSV - checked in as reference samples, plus a
  README.md documenting what they are, how to regenerate them, and a
  step-by-step checklist for validating a NEW check before it ships
  (confirm its Scoring.ps1 entry exists, confirm it renders in the
  expected Category/tier, confirm the score sidecar moves as expected,
  write/extend its Pester test, run the full suite).
- Fixed a real .gitignore collision found by actually testing with git:
  the blanket AD_Security_Audit_*.json/.html/.csv and
  AD_Security_Score_*.json patterns (which exist to keep real audit
  output out of the repo) matched these new sample filenames exactly, so
  `git add` would have silently dropped them. Added explicit negation
  exceptions scoped to tools/synthetic-fixtures-samples/ only - verified
  with a real `git add -A` that the samples now stage correctly while
  genuine audit output elsewhere in the repo is still correctly ignored.
- tools/New-ADSecurityAuditSyntheticFixtures.ps1's own .NOTES section now
  points at this samples folder.
- README.md's Test Coverage section links to the samples folder and
  checklist.
- No detection-logic, scoring, or output-contract changes - this release
  is packaging and documentation only.

v1.30.3 - First real PowerShell-execution validation pass of this whole delta-scan series
- A real PowerShell 7.6.6 runtime became available partway through this
  release series (previously every change in v1.30.0-v1.30.2 was
  verified by hand-tracing PowerShell semantics only, with no way to
  actually parse or run any of it). This release is the result of
  finally running that validation:
  - Full AST parse of every file in src/, tools/, and tests/ (87 files):
    zero syntax errors.
  - The entire module (all 44 src/*.ps1 files) dot-sources cleanly with
    zero errors; every new and modified function loads correctly.
  - Direct execution (with mocked AD cmdlets, no Pester available in
    this environment - see below) of the highest-risk logic from this
    series: the Netlogon UBR/FixDate fallback regression fix (v1.30.0,
    all 4 interaction cases verified), the AD Display Specifier Tampered
    rework (v1.30.1) including the EXACT reported false positive
    (remoteStorageServicePoint/RsAdmin.msc - confirmed fixed) plus
    genuinely suspicious UNC/LOLBAS/extension cases (confirmed still
    flagged), and the three new Pester-covered checks from v1.30.2
    (AdminSDHolder Inheritance Re-Enabled, Legacy LAPS SearchFlags,
    SPN-Holding Account Also Has DCSync Rights) - all pass.
  - Pester itself could not be installed or built in this environment:
    PowerShell Gallery is network-blocked, and building Pester from its
    own GitHub source requires compiling a C# assembly via the .NET SDK,
    which is not available here either. The direct-execution validation
    above is not a substitute for a real Pester run, but it is real
    execution of the actual code paths, not just static analysis.
- Fixed a genuine bug in tools/New-ADSecurityAuditSyntheticFixtures.ps1
  (new in v1.30.2), found ONLY by actually running it: every synthetic
  finding was tagged with one shared "Synthetic Fixture" Category.
  Get-ADRiskScore's own scoring model computes each category's score
  independently (with diminishing returns) and takes the MAX across
  categories as TotalScore - concentrating every finding into one
  category saturated it almost immediately, so all four tiers (25/50/75/
  100%) came back with the identical TotalScore=100, defeating the
  entire point of a four-tier maturity demonstration. Fixed by having
  the tool extract each Issue's REAL Category directly from its own
  $finding.Category assignment in src/*.ps1 (a source-code scan, not a
  guess) before building synthetic findings. Verified after the fix: the
  25% tier now genuinely differs (TotalScore=92, 20 categories
  represented) from the 50/75/100% tiers (21/27/29 categories - though
  TotalScore itself still saturates at 100 for those three once enough
  Critical-weight findings concentrate in any one category, which is a
  faithful reflection of the real "weakest link" scoring model, not a
  remaining bug - the category-count and per-category-score breakdown is
  where the tier gradient is genuinely visible for higher tiers).
- Ran the fixed generator end-to-end with -GenerateReports: confirmed
  real HTML (with correct per-category grouping and finding counts) and
  CSV (with EstimatedEffort/KnownRisks/BackupRollback correctly
  backfilled from FindingNarrativeLibrary.ps1 via Merge-ADFindingNarrativeGaps,
  not left as placeholder text) output for all four tiers.
- No detection-logic or output-contract changes to any check beyond the
  synthetic-fixture-generator fix above; all Issue/Scoring/Category
  behavior for real (non-synthetic) findings is unchanged from v1.30.2.

v1.30.2 - Follow-up fixes: real schema-default data, test coverage gaps, formatting, tooling
- 'Schema defaultSecurityDescriptor Modified' (SchemaAudits.ps1) is no
  longer a permanent stub. $Script:SchemaDefaultSecurityDescriptors is
  now populated with the actual current default SDDL for the user,
  computer, group, and organizationalUnit classes, sourced directly from
  Microsoft's own AD Schema Reference class pages
  (learn.microsoft.com/windows/win32/adschema/c-*), not reconstructed
  from memory. Known caveat carried forward: Microsoft's public
  reference documents these values through Windows Server 2012 only; no
  later change has been found documented, but this has not been
  independently re-verified against a current, unmodified schema.
- 'AD Display Specifier Tampered' reformatted: when a single entry
  matches more than one higher-risk pattern (e.g. a non-SYSVOL UNC path
  AND a risky file extension), the matched reasons now render as a
  bulleted list instead of a run-on joined sentence, using this
  project's own existing Description-newline-to-<br> HTML rendering
  convention (already used elsewhere, e.g. Domain Admin Equivalence/
  ESC4 findings).
- New Pester coverage for three files that had NONE at all despite
  shipping new v1.30.0 checks: tests/AdminSDAudits.Tests.ps1
  (AdminSDHolder Inheritance Re-Enabled), tests/LapsAudits.Tests.ps1
  (Legacy LAPS SearchFlags Exposes Password), and
  tests/ReplicationAudits.Tests.ps1 (SPN-Holding Account Also Has DCSync
  Rights). The DCSync cross-check tests use SID-format identity strings
  rather than "DOMAIN\name" strings deliberately - the real code path
  resolves non-SID identities via a live .NET NTAccount.Translate() call
  that would fail outside a domain-joined context; a SID string bypasses
  that call entirely and keeps the tests fully offline.
- New tools/New-ADSecurityAuditSyntheticFixtures.ps1: generates synthetic
  AD_Security_Audit_*.json findings files (and, with -GenerateReports,
  their HTML/CSV reports) at four failure-density tiers - 25/50/75/100%
  of every Issue this project's own $Script:ADFindingMetadataMap knows
  about - to exercise report rendering across the maturity spectrum
  without a real Active Directory environment. Every synthetic finding
  is clearly labeled "[SYNTHETIC TEST DATA]"; this proves report
  RENDERING works, not that detection logic is correct - it is not a
  substitute for testing against a real domain or a real Pester run.
- No detection-logic or output-contract changes beyond the
  defaultSecurityDescriptor table populating (which lets an
  already-shipped, already-scored Issue actually fire for the first
  time) and the Display Specifier Description formatting change.

v1.30.1 - Bug fix: AD Display Specifier Tampered rework (real false positive reported)
- Fixes a real false positive reported after v1.30.0 shipped:
  'remoteStorageServicePoint' (a native, Microsoft-defined AD schema
  class dating to Windows 2000 Server, part of the old Remote Storage
  feature) was flagged for its adminContextMenu entry pointing at
  RsAdmin.msc - a completely standard, Microsoft-shipped MMC console.
  The check's core assumption ("flag anything not under SYSVOL") was
  wrong: plenty of legitimate, built-in entries point at local system
  consoles/executables under %SystemRoot%\System32, which is the
  normal, healthy default state of a domain.
- Reworked detection to flag inherently-suspicious PATTERNS instead of
  an allowlist of "known good" locations: a URL, a UNC path outside
  SYSVOL\<domain>\Policies\, or a per-user-writable directory - plus two
  new, independent signals sourced from published community guidance
  (not this project's own invented heuristics): a command naming a
  binary from the LOLBAS (Living Off The Land Binaries And Scripts)
  project's well-established commonly-abused set (certutil, mshta,
  regsvr32, rundll32, wscript/cscript, bitsadmin, msiexec, installutil,
  msbuild, cmstp, forfiles, wmic, powershell/pwsh, regsvcs, regasm,
  msdt, odbcconf, control - matching MITRE ATT&CK T1218/T1216), and a
  command with a script/direct-execution file extension Microsoft's own
  built-in registrations never use (.hta/.vbs/.vbe/.js/.jse/.wsf/.wsh/
  .scr/.ps1/.psm1/.chm/.hlp).
- Every finding from this check now carries an explicit, prominent
  statement that it DOES NOT VALIDATE WHETHER THE REFERENCED FILE OR
  URL IS ACTUALLY MALICIOUS - it only flags a pattern published guidance
  associates with elevated risk for this kind of registration
  (Details.MaliciousnessNotValidated = $true, plus the same statement in
  the finding's own Impact text).
- Changed output shape: previously every suspicious entry across the
  whole domain was aggregated into ONE finding with a single long,
  comma-joined Description string. Now emits ONE FINDING PER SUSPICIOUS
  ENTRY, matching this project's established one-finding-per-affected-
  object convention used everywhere else in the codebase - easier to
  triage, sort, and filter.
- No schema/output-contract change beyond the per-entry finding split
  above; Issue string, Category, and Scoring.ps1 mapping are unchanged.

v1.30.0 - PingCastle+ Delta Scan Implementation Pass (files/14-20, 23, 25-27; #21/22/28 deferred)
- Ships eleven of the fourteen docs queued in 00-IMPLEMENTATION-ORDER.md
  from the 2026-09 PingCastle+ delta scan and codebase health scan, in
  the order that table recommends. #21 (GPO/endpoint hardening), #22
  (PSGuerrilla infrastructure hygiene), and #28 (real-BloodHound-
  collection diff) are DEFERRED to a future release: each explicitly
  needs lab/real-collection verification before merging per its own doc,
  and #28/#22 in particular touch BloodHound-adjacent surface area this
  pass deliberately avoided expanding into.
- New checks: ESC15/EKUwu (CVE-2024-49019, files/14), PIM_TRUST trust
  attribute (files/19), SPN-holder + DCSync-rights cross-check
  (files/23), GPO LM-hash-storage + legacy FRS SYSVOL replication
  (files/20), rogue-DC surface + DC registration integrity (files/16,
  also closes the previously-false 'S-DCRegistration' claim in
  StaleObjectDepthAudits.ps1), schema/persistence-tampering: vulnerable
  schema class, defaultSecurityDescriptor tampering, DisplaySpecifier
  tampering, AdminSDHolder inheritance re-enabled (files/15), key-
  material exposure: gMSA KDS root key, domain DPAPI backup key, legacy
  LAPS SearchFlags (files/17), account/computer hygiene gaps: Guest
  account enabled, never-joined computer, ghost-SPN delegation,
  Distributed COM Users/Performance Log Users membership (files/18).
- New refinement: per-OS-build (UBR) precision for both Netlogon RCE
  checks (CVE-2026-41089/CVE-2026-72982), alongside FixDate-only
  evaluation for OS builds with no independently-confirmed fixed UBR
  (files/25).
- New extension: cross-domain risk annotation (previously Domain-Trusts-
  only) generalized into a shared helper and applied to Test-
  ADControlPaths' Attack-Paths findings whose hop chain reaches another
  domain in the same consolidation run; Test-ADExchangeEscalation was
  evaluated and found not applicable, since it never names a cross-
  domain target (files/27).
- New offline command: Get-ADRemediationBurndown, combining
  Get-ADRemediationState and Get-ADMaturityTrend to project a domain's
  score/maturity trajectory if in-progress remediation completes at the
  pace the historical trend shows (files/26).
- KNOWN FOLLOW-UP: SchemaAudits.ps1's defaultSecurityDescriptor reference
  table ($Script:SchemaDefaultSecurityDescriptors) ships EMPTY - populate
  it from a verified schema source before relying on that specific
  check; it safely no-ops until then. The never-joined-computer
  heuristic introduced this pass has not been lab-validated against a
  live pre-staged object. Two factual corrections were made to this
  release during self-review before it shipped (not left as follow-ups):
  the FRS/DFSR migration-state check was rewritten to run
  `dfsrmig.exe /GetGlobalState` remotely rather than misreading a raw AD
  attribute, and the DPAPI backup key check was corrected to target the
  real BCKUPKEY_* secret objects under CN=System rather than a
  non-existent "CN=DPAPI" container.

v1.29.2 - Codebase Health Scan (Claim-vs-Code Audit, Safety Posture, Enhancement Pitches)
- Documentation-only pass; no code changes. Full report: health-scan-2026-09-summary.md.
- Critical-priority detection-only safety check: clean, no boundary violations found.
- Confirmed gap: 'S-DCRegistration' claimed in StaleObjectDepthAudits.ps1's header with no logic behind it - corroborates files/16-rogue-dc-registration-integrity.md, already written up from the PingCastle delta scan.
- Confirmed bug: README Version History had v1.29.0 out of order and v1.29.1 missing entirely - written up as files/24-readme-version-history-drift.md.
- Partial-coverage note: A-CertTempAnyone is claimed in the wrong file (logic lives in a sibling file's ESC1 check).
- Everything else verified clean: all other PingCastle-comparable claims trace to real logic; zero dead-weight Scoring.ps1 entries (143/143 reachable); FunctionsToExport/$allTests/module dot-sourcing all internally consistent; ADSecurityFinding schema provably additive-only; neither historical bug class (emoji/mojibake encoding, .modal[hidden] CSS specificity) has recurred in newer code.
- 4 enhancement ideas pitched (not expanded): remediation burn-down projection, extending ForestConsolidation's cross-domain annotation pattern, a real-BloodHound-collection diff, and reusing Get-ADKnownVulnUBR for a refinement already flagged in KnownVulnAudits.ps1's own comments.

v1.29.1 - AD Security-Tool Delta Scan (PingCastle+ Comparison Refresh)
- Bug-fix and documentation pass - no new detection logic added directly.
- Fixed: 'Bidirectional Domain Trust' had no TrustType scoping and fired on ordinary intra-forest ParentChild/TreeRoot/CrossLink/Shortcut trusts. Added tests/DomainTrustAudits.Tests.ps1, which didn't exist before.
- Investigated three other PingCastle bug-fix candidates (1500-member group truncation, BUILTIN\Users exclusion, SMB2 negotiate-response parsing) - none apply to this codebase's implementation.
- Investigated the Sept 2026 CISA/NSA/ASD guidance's DCSync detection redesign - it's a SIEM/event-log concern, not applicable to this static-config tool.
- Added PSGuerrilla to the comparison-tool roster (newly discovered this pass).
- Wrote 10 feature-request docs (files/14-23) covering 26 new-rule/changed-rule candidates from PingCastle, Purple Knight, PSGuerrilla, and the CISA/NSA/ASD guidance, tracked in the new 00-IMPLEMENTATION-ORDER.md. None implemented in this pass.

v1.29.0 - New Check: CVE-2026-72982 (Second, Distinct Netlogon RCE)
- New: Test-ADKnownDCVulnerabilities now also checks for CVE-2026-72982, a critical (CVSS 9.8) unauthenticated Windows Netlogon RCE disclosed by Microsoft on Sep 8, 2026 - a separate vulnerability from the already-tracked CVE-2026-41089, patched by a separate update. A DC patched for one is not necessarily patched for the other, so both are evaluated independently against their own fix-date threshold.
- Renamed the internal $Script:KnownVulnFixThresholds key for the existing May 2026 Netlogon CVE from Netlogon2026 to Netlogon2026May to disambiguate it from the new Netlogon2026Sep entry; the Issue string and finding text for CVE-2026-41089 are unchanged.
- New Scoring.ps1 entry for the new Issue string ('DC Missing CVE-2026-72982 Patch (Netlogon RCE)'), reusing the existing T1210 MITRE mapping.
- New Pester coverage in tests/KnownVulnAudits.Tests.ps1: fix/no-fix cases for CVE-2026-72982, and a dedicated test confirming the two Netlogon checks fire independently of each other.
- Fixed a pre-existing test-data bug found in the same file: two tests used a 2015-01-01 date while asserting the MS14-068 (fix date 2014-11-18) finding fires, which would fail since 2015 postdates that fix; changed to 2010-01-01.
- README updated (feature bullet, Known DC Vulnerabilities summary, Version History).
- Per files/13-dc-known-cve-2026-72982-netlogon-rce.md - implements that feature request in full.

v1.28.1 - External-Intelligence Refresh (CVEs, MITRE, Hotfix Dates)
- Data/citation correction pass - no new checks, no schema changes.
- Fixed: $Script:MitreTechniqueNames was missing display names for four technique ids already used in $Script:ADFindingMetadataMap (T1078, T1098.007, T1547.005, T1552.005). Added, verified against current MITRE ATT&CK (v19.2).
- Fixed: two stale MITRE display names (T1484.001, T1557.001) updated to match MITRE ATT&CK v19's renames.
- Fixed: T1562.002 was revoked by MITRE ATT&CK v19 in favor of T1685.001 - updated the name table and all four Issue entries that referenced the old id, in this same commit.
- Re-verified against MSRC: ZeroLogon, MS17-010, MS14-068, PrintNightmare, and CVE-2026-41089 fix-date thresholds are all unchanged. Re-confirmed the BadSuccessor/dMSA build-26100 guard doesn't need widening (no backport to earlier OS builds found).

v1.28.0 - Eight New AD CS Checks: ESC5, ESC9, ESC10, ESC11, ESC13, ESC14, ESC16, ESC17
- New: ESC17 (Test-ADCertificateServices) - Server Authentication EKU + enrollee-supplied SAN + low-priv enrollment + no manager approval. Disclosed by the Digitrace team in early 2026; new enough that even commercial AD CS scanners generally only flag it rather than fully validate it.
- New: ESC5 (Test-ADCSExtended) - weak ACLs on non-template PKI container objects (Public Key Services, AIA, Certification Authorities, Enrollment Services, KRA, OID), extending the existing ESC4 template-ACL pattern.
- New: ESC9 - a template with CT_FLAG_NO_SECURITY_EXTENSION (0x80000) combined with low-privileged enrollment.
- New: ESC13 - a template's Issuance Policy OID linked (msDS-OIDToGroupLink) to a privileged group, combined with a client-auth EKU and low-priv enrollment.
- New: ESC11 and ESC16 (Test-ADCSChaseFallback) - unencrypted CA RPC enrollment (InterfaceFlags missing IF_ENFORCEENCRYPTICERTREQUEST) and CA-wide security-extension disabling (DisableExtensionList), both reusing the same remote-registry connection already opened for the chase-fallback/ESC6 checks.
- New: ESC10 (new Test-ADCSWeakCertificateBinding) - reads CertificateBackdatingCompensation on Domain Controllers. Deliberately does NOT check the more commonly-cited StrongCertificateBindingEnforcement value, since Microsoft made full enforcement permanent and unconditional as of the September 9, 2025 security update, making that older value moot to check on a patched DC.
- New: ESC14 (DomainAdminEquivalence.ps1) - a weak (Issuer+Subject) altSecurityIdentities mapping on a privileged account, plus a new evidence edge for write access to that attribute (checked against both its own schema GUID and the broader Public-Information property-set GUID that can also grant write access to it).
- Excludes ESC12 (CA private key on external HSM device) - requires CA-server shell access to verify, outside this module's AD-object/registry detection model.

v1.27.1 - Cleanup: Removed Orphaned ForcedFail Fixture Files Left Behind by v1.25.0
- Cleanup only - no check logic, scoring, or test behavior changed. When offline/-Snapshot mode was removed in v1.25.0, that release's notes claimed the ForcedFail fixture ecosystem was removed too, but only tools/Test-ForcedFailFixture.ps1, tests/ForcedFailFixture.Tests.ps1, and tests/InvokeADRuleSet.Tests.ps1 had actually been deleted; tests/fixtures/ForcedFail-{100,60,25}pct-Snapshot.json and tools/build-forcedfail-fixtures.py were left behind, only marked "not currently runnable" in a fixtures README. That README also called the two .ps1 files "dev-branch only" - true of this branch at the time, not of the repository as a whole: both files, plus tests/InvokeADRuleSet.Tests.ps1, still exist on main. Confirmed via full-repo grep that nothing on this branch loaded or executed the JSON fixtures or the Python generator before removing them.
- Removed: tools/build-forcedfail-fixtures.py, the three tests/fixtures/ForcedFail-*pct-Snapshot.json files, tests/fixtures/README.md, and the now-empty tests/fixtures/ directory.
- Kept: tools/Build-ADFindingNarrativeLibrary.ps1 - unrelated, still actively used and tested.

v1.27.0 - Eight New Checks from ASD/CISA/NSA/CCCS/NCSC-NZ/NCSC-UK's AD-Compromise Guidance
- New: account lockout policy checks (Account Lockout Disabled / Account Lockout Threshold Above Recommended Maximum) in Test-ADDomainSecurity.
- New: "Account is sensitive and cannot be delegated" check for Domain Admins/Enterprise Admins/Schema Admins members in Test-ADUserSecurity.
- New: built-in Administrator (RID 500) check - enabled with a stale/never-set password, identified by SID so renaming the account isn't penalized.
- New: "Domain Computers" added to the control-path graph's broad-principal classification (ControlPaths.ps1) - a dangerous ACE or Tier-0 membership held by this group is as broad a path as one held by Domain Users.
- New: ESC6 check (CA-Wide SAN Attribute Flag Enabled) in Test-ADCSChaseFallback, reusing the same policy\EditFlags registry read already done for the chase-fallback bit.
- New: cross-domain sIDHistory hygiene catch-all (SID History Attribute Populated) in Test-ADDomainAdminEquivalence, beyond the existing same-domain and privileged-RID checks.
- New: LSA Protection (RunAsPPL) check, new Test-ADLsaProtection - the primary mitigation for Skeleton Key and similar LSASS-tampering techniques.
- New: NTLM restriction check (RestrictNTLMInDomain) in Test-ADLegacyAuthSurface, distinct from the existing LmCompatibilityLevel (LM/NTLMv1 downgrade) check.
- Of the 17 AD-compromise techniques covered by the source guidance, 16 already had solid coverage in this module; these eight close the remaining gaps in its preventive/configuration mitigations (its event-log/SIEM detection guidance is a different tool category, intentionally out of scope here).

v1.26.0 - gMSA Password-Retrieval Audit, User-Declarable Tier-0 Scope, GPO Restricted Groups/Ownership
- New: gMSA/managed-password retrieval-rights audit (Test-ADManagedServiceAccountSecurity) - flags PrincipalsAllowedToRetrieveManagedPassword grants to broad principals or, on a privileged gMSA, to any non-Tier-0 principal.
- New: user-declarable additional Tier-0 scope via Start-ADSecurityAudit -AdditionalTier0DN, picked up automatically by every check built on Get-ADTier0Principal.
- Extended: the constrained-delegation-target check now covers the full Tier-0 set, not just Domain Controllers.
- New: GPO Restricted Groups audit (local group membership pushed via GPO) and a GPO ownership check resolved by SID rather than name (new Resolve-ADPrincipalNameToSid helper).
- Fixed: "GPO Linked to Domain Controllers with Weak Permissions" now resolves the actual DC-containing OU dynamically instead of matching a hardcoded "OU=Domain Controllers" string.

v1.25.0 - Removed Offline/-Snapshot Mode; Export-ADSecurityReportHTMLFromJson Is Now the Supported Re-Analysis Path
- BREAKING: Removed offline/-Snapshot mode in its entirety. Get-ADSnapshot, Invoke-ADRuleSet, and ConvertTo-ADHashtable no longer exist; Start-ADSecurityAudit no longer accepts -FromSnapshot or -AllowLiveFallbackForUnsupportedTests; every Test-* function's [hashtable]$Snapshot parameter and offline code branch has been removed, leaving only each function's live AD query path. Export-ADSecurityReportHTML no longer accepts -RunMode, -SnapshotCollectedDate, or -OfflineSkipNotes, and the HTML report's "Offline / Snapshot-Based Report" and "Offline Mode Coverage Notes" boxes are gone.
- Why: the JSON findings export every live run already produces, together with Export-ADSecurityReportHTMLFromJson (kept, unchanged, and now the sole supported way to regenerate/re-share the HTML report with no live AD access), already covered the real use case without the maintenance cost of a second, independent offline code path across all 27 Test-* functions - a cost documented at length across the v1.19.0-v1.19.1 "offline-parity backlog" entries below and every "Offline Mode Coverage Notes" admission that offline re-analysis could produce different findings than an equivalent live run.
- Kept, unaffected: the JSON findings export itself, Export-ADSecurityReportHTMLFromJson, Export-ADSecurityReportCSVFromJson, and the v1.23.9 "Run Scope Information" report section (unrelated feature - Get-ADRunScopeNotes/Add-ADRunScopeNote/Reset-ADRunScopeNotes are untouched).
- Migration: existing .json snapshot files produced by Get-ADSnapshot -ToJson are no longer usable with -FromSnapshot, which no longer exists. If you have scripts calling -FromSnapshot, switch to running Start-ADSecurityAudit live and, if you need to regenerate the HTML report later, run Export-ADSecurityReportHTMLFromJson against its JSON findings output instead. Note this is not a like-for-like replacement for point-in-time re-analysis: Export-ADSecurityReportHTMLFromJson rebuilds the HTML view of already-computed findings (recomputing only the risk score - see its own documented LIMITATIONS) and does not re-run detection logic against a frozen AD state the way -FromSnapshot did.
- Test suite: removed the "Snapshot mode"/-Snapshot Pester coverage from the affected test files (live-mode coverage in those same files is unchanged) and the dedicated Invoke-ADRuleSet/Get-ADSnapshot infrastructure tests.

v1.24.2 - Example ForcedFail Snapshot Fixtures, New Computer Unconstrained-Delegation Check, Trust Date-Cast Fix
- Added three tiered, entirely synthetic tests/fixtures/ForcedFail-{100,60,25}pct-Snapshot.json -FromSnapshot fixtures (fake domain, no real environment/identities) exercising the full pipeline end-to-end with no live AD access, generated from one parameterized tools/build-forcedfail-fixtures.py script so all three stay consistent as checks change. Run via tools/Test-ForcedFailFixture.ps1 -Tier <100|60|25> or the tests/ForcedFailFixture.Tests.ps1 Pester smoke test.
- New finding: "Computer Account with Unconstrained Delegation" (Test-ConstrainedDelegation) - found by tracing the new fixtures against the codebase, Test-ADUserSecurity already flagged bare unconstrained delegation on USER accounts but no equivalent existed for COMPUTER accounts, despite that being the far more common and consequential place to find it in practice. Domain Controllers are correctly excluded.
- Fixed: Test-ADDomainTrusts' snapshot-mode trust-age check could fail to evaluate correctly when Snapshot.Trusts[].Modified comes back as a string after a JSON round-trip, lacking the same defensive [datetime] cast already established in UserAudits.ps1/KrbtgtAudits.ps1 for their own date fields.
- Corrected a minor (currently-harmless) inaccuracy in the fixtures' "clean-state" encryption-type values, and a self-caught data-loss bug in the fixture generator script itself (a stray comment silently dropped a dict key) introduced and fixed within the same editing pass.
- New Pester coverage: tests/ForcedFailFixture.Tests.ps1, tests/ConstrainedDelegation.Tests.ps1, tests/DomainTrustAudits.Tests.ps1.

v1.24.0 - Test Coverage Tracking, Duplicate-Finding Fixes, and RC4/DNS Identity-Resolution Fixes
- Added Test Coverage tracking: every check now reports Completed/Failed/Excluded (not just console output) via new AD_Security_TestCoverage_<timestamp>.json/.csv sidecars and a "Test Coverage" HTML report section; extended through Get-ADRetestComparison (new UnconfirmedFindings bucket so an excluded/failed check can no longer be mistaken for genuine remediation), Get-ADMaturityTrend, and Get-ADForestConsolidation.
- Added Export-ADSecurityReportCSVFromJson (the CSV equivalent of Export-ADSecurityReportHTMLFromJson) and a shared ConvertTo-ADFindingsCsvRows column builder.
- Fixed: a finding with any Severity other than Critical/High/Medium/Low would score correctly but never render in the HTML report at all, with no warning - added a catch-all "Other / Unclassified Severity Findings" section plus a Write-Warning.
- Fixed several offline/recreate-path gaps: missing EstimatedEffort/KnownRisks/BackupRollback backfill for two SPN findings, a "columnar" test-coverage-sidecar malformation, ADSecurityFinding metadata loss when recreating from JSON, DetectedDate rendering, -FromSnapshot never tracking test coverage, two unexported public functions (Export-ADSecurityReportCSVFromJson, Export-ADSecurityReportHTML), and -OutputPath not accepting a folder on the JSON-recreate exports.
- Fixed (found via a live lab run against a real 4-DC domain): 74 of 262 exported findings (28%) were exact duplicates caused by five ACE-iterating checks emitting one finding per raw ACE instead of deduplicating by (identity, rights) - AdminSDHolder ACL checks (AdminSDAudits.ps1, DomainAdminEquivalence.ps1), Exchange-in-AD escalation checks, and the DCSync replication-rights check all affected, both snapshot and live modes. This alone inflated one lab run's Critical-finding count and worst-category score to the maximum possible.
- Follow-up fix after a second lab run dropped duplicates to 1 remaining case: proactively audited every ACE-consuming check in the codebase (not just what fired in either lab run) and found the same per-ACE duplication pattern in DomainAdminEquivalence.ps1's shared Add-Evidence/Add-SnapshotEvidence helpers (backing 6 sub-checks feeding one aggregated finding - likely the largest real contributor, since a duplicate here shows as a repeated bullet inside one finding rather than a whole duplicate finding), PermissionsAudits.ps1 (Enterprise Key Admins, critical-OU sweep, Schema/Config NC ACL - 6 locations), CertificateServicesAudits.ps1 (ESC7, Low-Privilege CA Management Rights, enrollment-principal list), CertificateServicesExtendedAudits.ps1 (ESC4 principal list), and GpoAudits.ps1 (SYSVOL NTFS permissions). Confirmed ControlPaths.ps1 structurally immune by design (visited-node-tracked BFS, single-valued Owner per object). Test-ADReplicationSecurity's DCSync check now aggregates ALL rights an identity holds across every one of its ACEs into one finding (matching how a single GenericAll ACE already aggregated all three DCSync rights), rather than reporting each specific right as a separate, identical-looking finding.
- Fixed a "sub-finding gets lost in the flat report view" gap: Test-ADDnsSecurity's "Stale/Dangling DNS Zone Delegation" finding's per-delegation detail (which NameServer/glue IP) lived only in Details.StaleDelegations, which the HTML report never renders - now enumerated as bullets in Description, matching the convention already used elsewhere. Confirmed the CSV export was never affected (Details is always serialized to compact JSON regardless of shape).
- Fixed: Test-ADKerberosHardening's RC4 account check preferred SID over DistinguishedName when resolving Tier-0 principals via Get-ADObject; in the same lab run all 8 of 8 SID-based lookups failed silently while DN-based lookups succeeded elsewhere in the identical run. Now prefers DistinguishedName.
- Fixed: Test-ADDnsSecurity's delegation-staleness check produced a malformed, doubled zone name (e.g. "_msdcs.ad.local..ad.local") when the DNS cmdlet returned a child zone name with a trailing root dot; the "already fully-qualified" match now trims it first.
- New Pester coverage: tests/RetestComparison.Tests.ps1, tests/MaturityTrend.Tests.ps1, tests/ForestConsolidation.Tests.ps1, tests/InvokeADRuleSet.Tests.ps1, tests/DuplicateAceFindingDedup.Tests.ps1, tests/KerberosHardeningIdentityResolution.Tests.ps1, plus new cases in tests/DnsSecurityAudits.Tests.ps1/tests/ReportingFromJson.Tests.ps1/tests/ReportingCSVFromJson.Tests.ps1.

v1.23.9 - Surface "PDC-Only Check Ran Against a Non-PDC DC" as a Report-Level Run Scope Note
- Added: a new "Run Scope Information" section in the HTML report (and a console notice) whenever -Server named an explicit, specific Domain Controller that is NOT the domain's actual PDC Emulator. This module's "PDC-only" checks (Test-ADMachineAccountQuota, Test-ADDomainSecurity) correctly still ran and returned real answers in this scenario - domain/forest-wide attributes are readable from any DC - but previously gave no indication that they queried the named DC directly rather than the PDC, which a reader could reasonably assume never happens for a "PDC-only" check.
- New mechanism in Common.ps1, parallel to (but distinct from) the existing offline-skip-notes tracker: Add-ADRunScopeNote / Get-ADRunScopeNotes / Reset-ADRunScopeNotes. Populated by Resolve-ADSecurityAuditTargetServer itself, at the exact point it already determines whether -Server names an explicit DC (vs. a domain name resolved to the PDC) - the one place in the codebase that already knows both the named DC and, cheaply, the domain's real PDC (a DC can always answer Get-ADDomain about its own domain, so this adds no new reachability dependency).
- Get-ADSnapshot now persists any notes recorded during collection into the snapshot itself (Snapshot.RunScopeNotes), so a later -FromSnapshot analysis - which performs no live resolution of its own - still surfaces a scoping condition that was true at collection time. Start-ADSecurityAudit merges live-run notes with any carried snapshot notes (de-duplicated by message) before rendering.
- Export-ADSecurityReportHTML gained a -RunScopeNotes parameter and renders the new section for both live and offline runs, unconditionally on whether there's anything to show - unlike the existing "Offline Mode Coverage Notes" box, which only ever applies to -FromSnapshot runs.
- New Pester coverage: tests/RunScopeNotes.Tests.ps1 (note accumulation/reset, PDC-match/mismatch detection including case-insensitivity, and graceful no-op behavior when -Server is a domain name or the PDC lookup itself fails).

v1.23.8 - Fixed: "Insufficient Domain Controller Count" Undercounted (and primaryGroupID False Positives) When -Server Named One Specific DC
- Fixed (reported): Test-ADStaleObjectDepth's "Insufficient Domain Controller Count" redundancy check reused the SAME -Server-scoped $domainControllers list used by the DC subnet/site-registration probe. When -Server named one specific DC (the operator's own DC-only scoping, correctly narrowing per-DC PROBES to just that DC), this count check incorrectly reported "the domain has only 1 Domain Controller" regardless of how many DCs the domain actually has - a redundancy assessment of the whole domain has no business being narrowed by which DC(s) probing was scoped to.
- Fixed (found during investigation of the above): the SAME -Server-scoped list was also used to decide which computer objects are legitimately recognized as Domain Controllers for the primaryGroupID=516 legitimacy check. Narrowing it to one explicitly-named DC caused every OTHER real DC's computer object in the domain to be misclassified as a non-DC holding a suspicious primaryGroupID 516 - a false-positive "Non-Default primaryGroupID (Membership Hiding)" finding against a perfectly legitimate DC.
- Root cause and fix: added a new -IgnoreExplicitDCScope switch to Get-ADSecurityAuditDomainController (Common.ps1) that still uses the resolved -Server value as the QUERY TARGET (so it works even when only one DC is reachable for the engagement) but always returns every DC belonging to the resolved domain, bypassing the "narrow to just the named DC" behavior that's correct for per-DC probes but wrong for domain-wide DC-inventory questions. Test-ADStaleObjectDepth now collects a second, always-unscoped DC inventory using this switch and uses it for both the count check and the primaryGroupID legitimacy check, while the existing -Server-scoped list continues to correctly narrow the subnet/site-registration probe itself.
- Get-ADSnapshot gained two new fields (TotalDomainControllerCount, AllDomainControllerComputerObjectDNs), collected the same unscoped way, so a snapshot collected with -Server narrowed to one DC still preserves the domain's true DC count/legitimacy data for later -FromSnapshot analysis. Older snapshots that predate this fix fall back to the previous (possibly-narrowed) behavior, with a Verbose note explaining the accuracy caveat.
- Also fixed a related inconsistency found during the same investigation: Get-ADTargetDomainController (used by Test-ADDnsSecurity and other single-DC-only live probes) previously picked the first DC returned by enumeration order - functionally harmless for these checks (AD-integrated DNS/LDAP state doesn't vary DC to DC) but inconsistent with this module's "PDC-only checks use the domain's actual PDC" convention, and non-deterministic since Get-ADDomainController's -Filter does not guarantee PDC-first ordering. Now explicitly resolves and prefers the domain's PDC Emulator when the target is a domain name (falling back to the first enumerated DC only if the PDC can't be matched in the result set); an explicit, specific DC named via -Server continues to be honored exactly as given, never substituted.
- Documented (no logic change): added explicit "PDC-only check, noted accordingly" documentation to Test-ADMachineAccountQuota and Test-ADDomainSecurity, clarifying why these functions make a single domain/forest-wide query rather than enumerating DCs - both already correctly implemented the module's three-mode -Server contract (no -Server → current user's domain, enumerated/resolved to its PDC; -Server as a domain name → that domain's PDC; -Server as an explicit DC → honored exactly as given) via the existing Resolve-ADSecurityAuditTargetServer mechanism.
- Verified by code trace (not changed, already correct): Test-ADRodcSecurity, Test-AuditPolicyConfiguration, Test-ADDomainHardeningFlags, Get-ADControlPathGraph/Test-ADControlPaths, Test-ADKerberosHardening, and Test-ADLegacyAuthSurface already implement the module's three-mode -Server/DC-enumeration contract correctly via the existing Get-ADSecurityAuditDomainController + Get-ADSecurityAuditServerIsExplicitDC mechanism (no -Server enumerates every DC in the operator's own domain; -Server as a domain name enumerates every DC in that domain; -Server as an explicit DC narrows to only that DC). No changes made to these six pending confirmation of a specific reproduction, if one exists beyond the two confirmed bugs above.
- New Pester coverage: tests/StaleObjectDepthAudits.Tests.ps1 (true DC count and primaryGroupID legitimacy in both snapshot and live mode, including the old-snapshot fallback behavior; Get-ADSecurityAuditDomainController -IgnoreExplicitDCScope; Get-ADTargetDomainController's PDC-preference behavior).

v1.23.7 - Forest / Forest-Root Coverage Gaps (Functional Level, Tombstone Lifetime, Schema/Configuration NC ACLs)
- Added to Test-ADDomainSecurity: "Outdated Forest Functional Level" as its own finding (previously the forest mode was only ever surfaced as a Details sidecar under the domain-level functional-level finding, so a stale forest FL behind a current-looking domain FL never fired on its own) and "Short Tombstone Lifetime" (flags forest tombstoneLifetime below 180 days; an unset attribute is correctly treated as its [MS-ADTS]-specified 60-day default, not as "no value to report"). Both fully offline-capable: Get-ADSnapshot gained a new TombstoneLifetimeDays scalar field alongside the existing Forest.ForestMode.
- Added to Test-ADDangerousPermissions: non-standard-permissions checks on the Schema naming context and Configuration naming context head objects (Critical), following the same allowlist-based ACE review already used for AdminSDHolder and the critical-OU sweep. The Configuration NC check is deliberately narrower in scope than the existing Public Key Services container check - it audits the Configuration NC head object itself, which is broader (Sites/Subnets, Services, Extended-Rights, WellKnown Security Principals) but whose Impact text is intentionally conservative about any specific downstream attack chain, since that depends on inheritance in a given environment. Get-ADSnapshot gained two new ACL-collection targets: SchemaNamingContext and ConfigurationNamingContext.
- New Scoring.ps1 mapping entries: Outdated Forest Functional Level (T1078.002, vuln4_outdated_ffl, Weight 4 - matches the existing domain-level entry), Short Tombstone Lifetime (no MITRE technique - a recoverability/hygiene parameter, not an attack technique; vuln5_short_tombstone_lifetime, Weight 1 - matches AD Recycle Bin Not Enabled), Non-Standard Permissions on Schema/Configuration Naming Context (both T1098, vuln1_schema_nc_acl / vuln1_config_nc_acl, Weight 40 - matches the existing AdminSDHolder ACL-abuse entry).
- All four findings fact-checked against current Microsoft documentation before implementation: AD Recycle Bin requires Windows Server 2008 R2 forest mode, PAM requires Windows Server 2016 forest mode (confirmed via the PAM optional feature object's own RequiredForestMode property); an unset tombstoneLifetime defaults to 60 days per [MS-ADTS] 6.1.1.2.4.1.1, with 180 days only guaranteed on forests created with Windows Server 2003 SP1 or later installation media (not simply "any forest running a newer OS").

v1.23.6 - Detect CA Chase-Fallback Exposure (CVE-2026-54121 / "Certighost")
- Added Test-ADCSChaseFallback: reads each discovered Enterprise CA's policy\EditFlags registry value for the EDITF_ENABLECHASECLIENTDC bit (0x00100000), which enables the client-DC "chase" fallback CVE-2026-54121 ("Certighost", CVSS 8.8) abuses to obtain a certificate asserting a Domain Controller's identity from a low-privileged, attacker-controlled account. Flags Critical regardless of CA patch level, since the flag itself - not the patch state - is the exposure indicator; a patched CA with the flag still set remains configured in the historically risky state. Remediation cites both Microsoft's July 14, 2026 security update and the certutil -setreg policy\EditFlags -EDITF_ENABLECHASECLIENTDC stopgap. Read-only: one registry value read per discovered CA host, no certificate requests or exploitation traffic. Live-only (no snapshot representation, same as ESC8), registered as a new top-level 'ADCSChaseFallback' test.

v1.23.3 - Multi-Domain Forest -Server Reliability + Several Related Fixes
- Fixed: in a multi-domain forest, several classes of AD/GPO/ACL/SYSVOL calls could silently read from the wrong domain even when -Server was correctly set - the single biggest root cause being Get-ADDomainController's -Filter parameter set, which queries the forest-wide Configuration container regardless of which DC -Server binds to, so every per-DC probe (anonymous-bind, null-session, Kerberos hardening, legacy auth, audit policy, known-DC-vulnerability, stale-object depth, RODC security, control-path graph, coercion/relay, the main run's own DC connectivity check, and Get-ADSnapshot) could enumerate DCs from a domain other than the one requested. A new Get-ADSecurityAuditDomainController helper (Common.ps1) filters the same enumeration down to the resolved target domain.
- Fixed: the GroupPolicy module (Get-GPO/Get-GPInheritance/Get-GPPermission/Get-GPRegistryValue) was never covered by the -Server override at all - a completely separate wildcard (Get-GP*:Server) had to be added alongside the existing AD-cmdlet one.
- Fixed: certificate template (ESC4) and CA object (ESC7) ACL reads used Get-Acl -Path "AD:..." (no -Server parameter exists on that cmdlet); switched to Get-ADObject -Properties nTSecurityDescriptor, which is -Server-aware and returns an identical ACL object shape.
- Fixed: SYSVOL UNC paths (GPO permission check, GPO-deployed-secrets policy root) were built from the bare domain name, subject to the same "closest DC to the calling machine" DFS-referral ambiguity as DC-locator; both now embed the resolved -Server directly in the path.
- Fixed: -Server resolves to the target domain's PDC Emulator specifically (via Get-ADDomain's own .PDCEmulator), not a bare domain name or an arbitrary DC-locator pick - removing an entire category of ambiguity in one place. Get-ADTargetDomainController's -Identity-based resolution (used by live network probes) is fixed accordingly.
- Fixed: Enterprise Admins/Schema Admins/Enterprise Key Admins are forest-root-only groups; a -Server-scoped lookup against a child domain always found nothing and silently skipped the group with no finding and no indication why. Now falls back to resolving the forest root and re-querying there. New "Cross-Domain Privileged Group Membership" finding surfaces when a privileged group's members span domains.
- Fixed: every remaining Get-AD*/Get-GP* call across the module (~35 files) now explicitly passes -Server rather than relying solely on the $PSDefaultParameterValues global default, after the global mechanism was observed not to be reliably picked up for at least some calls in production use; see the MANDATORY PATTERN note on Get-ADSecurityAuditActiveServerOverride (Common.ps1) for the rule going forward. Verified null-safe: Set-ADSecurityAuditTargetServer's -Server carries [ValidateNotNullOrEmpty()], so the value passed through is always either a real server name or a clean $null, never an ambiguous empty string.
- Fixed: Get-ADRetestComparison/Export-ADRetestComparisonHTML's report header rendered GeneratedDate as raw PowerShell object text (ConvertTo-Json's expansion of an un-stringified [datetime]) instead of a date; fixed at the source and defensively on read via a new ConvertTo-ADFriendlyDateText helper.
- Fixed: the main audit's CSV export was missing SeverityLevel and Details columns that the JSON export and every finding object always carried.
- Fixed: AD CS Certificate Templates/Enrollment Services enumeration returned the container object itself alongside real templates/CAs (default Subtree search scope); now uses -SearchScope OneLevel.
- Added: Export-ADSecurityReportHTMLFromJson recreates the main audit HTML report directly from an AD_Security_Audit_*.json findings export, with no live AD access.
- Six audit functions (Test-ADUserSecurity, Get-ADPrivilegedUsers, Test-ADPrivilegedGroups, Test-ADDomainAdminEquivalence, Test-ADRodcSecurity, plus Test-AdminSDHolder/Test-ADDangerousPermissions/Test-ADGroupPolicies/Test-ADKerberosHardening/Test-ADDomainHardeningFlags/Test-ADLegacyAuthSurface) gained their own optional -Server parameter for standalone use outside Start-ADSecurityAudit.
- Credit: denandz (https://github.com/denandz) for the patch that independently identified and fixed the -Server global-default reliability issue, reconciled into and extended across the rest of this release.

v1.23.2 - Fix Get-ADRetestComparison Crash on a Jagged Findings Export
- Fixed: Get-ADRetestComparison (and Get-ADRiskScore, called from it) could crash with a confusing "Cannot convert the System.Object[] value ... to type System.Int32" error, plus several follow-on errors in the same loop, when a findings JSON export contained a jagged/nested element - a top-level array entry that was itself a sub-array of several findings rather than one. PowerShell's member-enumeration silently turns every property read on such an element into an array (e.g. $finding.Weight returns an array instead of an int), which then fails deep inside the scoring arithmetic rather than surfacing a clear shape problem. Reported from real production data comparing a v1.20.6 baseline against a v1.23.1 retest.
- Get-ADRiskScore's own $allFindings assembly in Main.ps1 was independently confirmed NOT to introduce this nesting (PowerShell's += operator flattens even a jagged upstream source one level), so the fix hardens the read/scoring path itself rather than assuming a specific upstream cause: a new shared ConvertTo-ADFlatFindingsArray helper (Common.ps1) recursively flattens a findings array, treating only true collections as nested (a Details hashtable is correctly left alone as finding-level content, not recursed into). Get-ADRiskScore now flattens its -Findings parameter defensively on every call (a no-op for the normal, already-flat case), and Get-ADRetestComparison flattens both the baseline and retest exports immediately after parsing them, before either Get-ADRiskScore or the finding-key-matching step sees them.
- New Pester coverage: Get-ADRiskScore and Get-ADRetestComparison are both confirmed to handle a deliberately jagged findings array/export correctly (same FindingCount/TotalScore as the equivalent flat input), plus direct unit tests for ConvertTo-ADFlatFindingsArray (one level of nesting, multiple levels, an already-flat no-op, an empty array, and confirming a Details hashtable's own nested array is left untouched).

v1.23.1 - Fix Get-ADMaturityTrend Silently Dropping Pre-v1.21.0 Score Sidecars
- Fixed: Get-ADMaturityTrend silently skipped (with only a console warning) any AD_Security_Score_*.json sidecar that predates v1.21.0's GeneratedDate/ModuleVersion fields, since it relied on GeneratedDate to sort runs chronologically. A domain with a long run history spanning that version boundary would see its older runs vanish from the trend without an obvious explanation - found via a follow-up backward-compatibility check, not the original acceptance criteria.
- Get-ADMaturityTrend now falls back to the sidecar file's own last-write time when GeneratedDate is missing or unparsable, so older runs are included instead of dropped. Every such run is explicitly flagged rather than silently blended in as if the date were authoritative: a new DateEstimated boolean on its Series entry, a top-level EstimatedDateCount on the result, a note in the returned Message naming the affected file(s), and a visible "estimated" badge (with a tooltip explaining why) on that row in Export-ADMaturityTrendHTML's per-run table.
- Only the displayed/sorted date is estimated - the run's own recorded TotalScore/MaturityLevel/CategoryScores are read and trended exactly as before; this fix does not touch score computation.
- New Pester coverage: a fixture sidecar in the pre-v1.21.0 shape (no GeneratedDate/ModuleVersion fields at all) is confirmed to appear in the trend, correctly flagged, rather than being dropped.

v1.23.0 - Exception / Remediation-State Tracking
- Added Set-ADRemediationState / Get-ADRemediationState: a small, hand-editable JSON state file (conventionally AD_Remediation_State.json, one per domain) keyed by the same Category+Issue+AffectedObject key Get-ADRetestComparison already uses (Get-ADFindingMatchKey), recording a status (Open/AcceptedRisk/InProgress/Remediated), optional owner, note, and date per finding. Set-ADRemediationState is an explicit read-modify-write upsert - re-running it for the same key updates the entry rather than duplicating it - not auto-discovery; this module never infers remediation intent on its own.
- Get-ADRetestComparison gained an optional -RemediationStatePath parameter: when supplied, StillOpenFindings and ChangedFindings are annotated with a RemediationState property (Status/Owner/Note/SetDate), defaulting untracked findings to Status='Open' with nulls. Purely additive - omitting the parameter behaves identically to before it existed (verified with a regression check), and the New/Resolved/StillOpen/Changed classification itself is unchanged.
- Export-ADRetestComparisonHTML's Still Open section now badges tracked findings by RemediationState.Status, reusing the existing severity-badge CSS pattern with a distinct (not alarming) color for AcceptedRisk, so a leadership reader can see at a glance which persisting findings are a deliberate decision vs. genuine neglect.
- Get-ADRiskScore's computed score is completely unaffected by remediation state - an AcceptedRisk finding still counts toward the score exactly as before. This is a display/reporting annotation only, never a scoring policy change.
- Explicitly out of scope for this pass (left for a future enhancement): no automatic expiry/review-date alerting on stale AcceptedRisk entries, and no ticket-system (JIRA/ServiceNow) integration - the Note field is free text for a human to paste a reference into. Consistent with this module's no-network-side-effects posture everywhere else.
- Hard dependency on v1.21.0's Get-ADRetestComparison, which must already exist - this is an additive extension of it, not a standalone feature.

v1.22.0 - Multi-run Maturity Trend History
- Added Get-ADMaturityTrend / Export-ADMaturityTrendHTML: an offline, file-based command that reads ALL of a domain's historical AD_Security_Score_<timestamp>.json sidecars (3, 10, 50 - however many exist) and produces a chronological trend - score/maturity over time, per-category trend, and a simple Improving/Flat/Regressing direction indicator per category and overall.
- Complementary to (not a replacement for) v1.21.0's Get-ADRetestComparison: that feature answers "what changed between these two specific runs" with finding-level detail; this one answers "what's the trajectory over N runs" with score/maturity/category trend lines only. Deliberately not merged into one function - finding-level matching across many runs gets combinatorially messier for limited additional value at that granularity.
- Sorts sidecars chronologically by each file's own recorded GeneratedDate (not filename, in case files were renamed/moved) - verified against a fixture where the newest run's filename was deliberately made to sort alphabetically first.
- Deliberately does NOT recompute scores under the current mapping table - the opposite design choice from Get-ADRetestComparison. Reads each sidecar's own historically-computed TotalScore/MaturityLevel as-is, since the point is seeing how the tool's own assessment evolved over the real historical record. Each run's own ModuleVersion is surfaced in the output and the HTML report's per-run table specifically so a score jump can be attributed to a tool change vs. an actual posture change.
- Direction classification is simple first-vs-last arithmetic with a tolerance band, not a statistical regression - consistent with this module's general preference for simple, auditable arithmetic (the same philosophy as Get-ADRiskScore's own diminishing-returns model).
- Handles 1-run input (no trend possible, clear message via the new Message field, not an error) and 2-run input (a plain pairwise delta) gracefully.
- Export-ADMaturityTrendHTML renders a score/maturity line chart and per-category sparklines via a new Get-ADSvgTrendLine helper (new time-series SVG territory - the existing gauge/category-bar helpers are single-value, not time-series), plus a plain per-run table surfacing ModuleVersion.
- No AD/LDAP queries, no credentials, no network access to any domain controller - pure offline aggregation of exports this module already produces. Not registered in Main.ps1's $allTests.

v1.21.0 - Retest / Configuration-Maturity Delta Comparison
- Added Get-ADRetestComparison / Export-ADRetestComparisonHTML: an offline, file-based comparison between two prior Start-ADSecurityAudit exports of the same domain (a pre-remediation baseline and a post-remediation retest) - answering "did remediation work, and by how much?" instead of a manual side-by-side eyeball diff of two HTML reports.
- Matches findings by Category+Issue+AffectedObject (the new shared Get-ADFindingMatchKey helper in Common.ps1) to classify each as New / Resolved / Still Open / Changed - a coarser Category+Issue-only key would hide partial remediation (e.g. 5 stale accounts down to 2 would show as one "still present" bucket instead of 3 Resolved + 2 Still Open).
- Both runs' scores are recomputed under the CURRENT Get-ADRiskScore mapping table rather than trusting either run's originally-stored score sidecar values, so a retest captured under a different module version stays apples-to-apples; each run's own recorded ModuleVersion/GeneratedDate is still surfaced (from the optional score sidecar) for context.
- Export-ADRetestComparisonHTML renders a standalone HTML report with a togglable Current State / Delta View, reusing the existing score gauge, category-bar, and finding-list components (Get-ADSvgGauge, Get-ADSvgCategoryBars, Get-FindingHTML) plus a new sibling Get-ADSvgCategoryDeltaBars helper for the paired baseline/retest category view. The view toggle's [hidden]-attribute panels include an explicit `.view-panel[hidden] { display: none; }` override so it does not regress the v1.20.3 modal-visibility bug.
- Get-ADRiskScore's output gained two additive fields, GeneratedDate and ModuleVersion, needed so the score sidecar can be identified by when/what version produced it - no existing field changed or removed.
- No AD/LDAP queries, no credentials, no network access to any domain controller - pure offline aggregation of exports this module already produces, same posture as Get-ADForestConsolidation. Not registered in Main.ps1's $allTests.

v1.20.5 - Implement A-NullSession-Comparable Detection (Null-Session Pipe/Share Access)
- DomainHardeningAudits.ps1's header comment had claimed A-NullSession-comparable coverage since the file was written, but no logic anywhere in the module read RestrictNullSessAccess/NullSessionPipes/NullSessionShares - found via the same header-vs-code audit that closed the A-AnonymousAuthorizedGPO gap in v1.20.4.
- Added a fourth check to Test-ADDomainHardeningFlags: audits 'Network access: Restrict anonymous access to Named Pipes and Shares' (RestrictNullSessAccess) for the disabled (0) state, checking GPOs linked to the Domain Controllers OU then the domain root first, falling back to a direct per-DC registry read when no linked GPO defines the value - the same GPO-then-live-fallback pattern LegacyAuthAudits.ps1 already uses for SMBv1/SMB-signing/LmCompatibilityLevel.
- Reuses LegacyAuthAudits.ps1's existing Get-ADLinkedGposOrdered and Get-ADPolicyRegistryValue rather than duplicating GPO-link resolution. The per-DC live-registry-read fallback (previously a private function nested inside Test-ADLegacyAuthSurface) was promoted to a shared Get-ADLiveRegistryValuePerDc helper in Common.ps1 so both modules call one implementation.
- Registry-value read only; no live SMB/null-session connection is ever attempted. Live-only and skipped entirely under -Snapshot (Add-ADOfflineSkipNote), consistent with this file's existing anonymous-bind check.
- New ADFindingMetadataMap entry ('Null-Session Pipe/Share Access Permitted', MITRE T1135, ANSSI vuln3_null_session_access, same weight/level as the neighboring Anonymous LDAP/RootDSE Binding Permitted finding).

v1.19.1 - Fix Test-ADControlPaths Crash, ZERO Live Connections Under -Snapshot (No Exceptions)
- Fixed: Test-ADControlPaths failed on every run with "Cannot bind argument to parameter 'EdgeList' because it is an empty collection." Add-ADControlPathEdge declared -EdgeList as Mandatory on an ArrayList; PowerShell's parameter binder rejects a Mandatory argument that is an empty collection, so the very first edge ever added to a fresh graph threw. Fixed with [AllowEmptyCollection()], matching the existing AllowEmptyString() treatment already given to -From/-To on the same function.
- Hardened -FromSnapshot's "no live AD access" contract to mean literally zero outbound connections, for environments where the DC genuinely is not reachable from the analysis machine (the whole point of re-analysing a JSON snapshot). v1.19.0 shipped several sub-checks that still fell back to live SMB/WinRM/AD calls when invoked with -Snapshot, contradicting its own documented contract - identified from a real -FromSnapshot run's transcript where warnings fired and live findings appeared despite the run being announced as offline. Every one of these is now a hard skip instead of a live fallback:
  - Test-ADGroupPolicies' SYSVOL file-share ACL check and Test-AuditPolicyConfiguration's per-DC auditpol check: previously fell back to live SMB/Invoke-Command access against real Domain Controllers. v1.19.0's release notes claimed this matched the precedent set by Test-ADCoercionAndRelayExposure/Test-ADLegacyAuthSurface, but that precedent is actually to SKIP an unrepresentable live-only sub-check entirely, never fall back to live I/O - v1.19.0's implementation did the opposite of what it claimed. Both now skip with a Write-Warning instead.
  - Test-ADGpoDeployedSecrets: previously still read SYSVOL file content live even when the GPO list came from the snapshot. Now skips entirely under -Snapshot.
  - Test-ADRodcSecurity: previously still performed one live Get-ADObject call per RODC even under -Snapshot. Now skips entirely (a partial skip was considered and rejected - it would have misreported every krbtgt_* account as orphaned rather than just losing coverage).
  - Test-ADStaleObjectDepth: its DC subnet/site registration check previously still queried Get-ADReplicationSubnet live even under -Snapshot. Now skipped entirely.
- Fixed several narrower live-fallback gaps found via a full-codebase sweep, all following the same anti-pattern (a live cmdlet called whenever a specific snapshot key was absent, rather than whenever -Snapshot itself was absent):
  - Test-ADUserSecurity: an unconditional live Get-ADGroup 'Protected Users' call ran even under -Snapshot; now resolved from Snapshot.Groups.
  - Get-ADTier0Principal (shared helper, used by 6+ tests including Test-ADRodcSecurity and Test-ADControlPaths): fell back to a live group-membership walk if -Snapshot was supplied without a 'Groups' key. Now returns an empty Tier-0 set instead.
  - Test-ADMachineAccountQuota: fell back to live Get-ADDomain/Get-ADObject if -Snapshot was supplied without a usable MachineAccountQuota value. Now skips with no live call.
  - Get-ADControlPathGraph (used by Test-ADControlPaths): the most significant of these - domain resolution, DC-list resolution, protected-group DN resolution, group-membership-edge collection, and (most importantly) the per-object ACL/ownership-edge sweep over every control-relevant object in the escalation chain could all still fall back to a live Get-ADDomain/Get-ADDomainController/Get-ADGroup/Get-ADObject call under -Snapshot. Every one of these is now hard-gated on -Snapshot itself, never on whether a specific key happened to be present. The ACL/ownership sweep in particular used to make one live per-object ACL read for every group in a privilege-escalation chain that wasn't AdminSDHolder/DomainRoot - under -Snapshot this now contributes MemberOf edges only for those objects (a coverage gap, recorded once as a single note, not per-object) rather than a live read per object.
- Closed two genuine online/offline finding-count discrepancies identified from a like-for-like live-vs-snapshot comparison: Test-ADCSExtended's ESC4 (dangerous certificate template ACLs) and its NTAuth/AIA/Root store weak-signature sweep were both documented as "live only - not captured in snapshot", but the data they need (per-template ACLs; NTAuth/AIA/Root cACertificate blobs) was either already in the snapshot (ESC4, since v1.19.0's ESC7 work) or trivial to add following the exact same pattern (NTAuth/AIA/Root, same risk profile as the CA cACertificate already collected). Both now run fully offline. Get-ADSnapshot gained three new ADCS fields: NTAuthCertificates, AIACertificates, RootCACertificates.
- Added a new "Offline Mode Coverage Notes" mechanism: every sub-check that doesn't run at all under -Snapshot now records a structured note (Add-ADOfflineSkipNote / Get-ADOfflineSkipNotes in src/Common.ps1) instead of only a Write-Warning/Write-Verbose line in the console transcript. The HTML report's offline-run banner no longer unconditionally claims "no live Active Directory or Domain Controller connections were made" without evidence - it's true for every run as of this release, and the report shows an explicit "Offline Mode Coverage Notes" table (Test / Sub-Check / Why) of everything that was skipped and why, not just a pointer to "see the run log". Start-ADSecurityAudit also prints a one-line console summary at the end of a -FromSnapshot run.
- Every fix above was verified with a full-codebase sweep for the specific anti-pattern that caused it (a live cmdlet reachable when -Snapshot is truthy) - not just the sites originally reported. As of this release, no built-in test performs any live AD/network access when invoked with -Snapshot.
- Note: Test-ADGpoDeployedSecrets' hard skip above is the one case worth calling out specifically - it scans SYSVOL file *content* (GPP cpassword, deployed scripts), which has no snapshot/attribute representation at all, so this is a genuine capability gap under -Snapshot, not a bug being papered over.

v1.19.0 - Offline/-Snapshot Parity for the Remaining 12 Live-Only Modules (Steps 18-29)
- This release combines the entire offline-parity backlog into a single update: Test-ADPrivilegedGroups, Test-AdminSDHolder, Test-ADReplicationSecurity, Test-ADDangerousPermissions, Test-ADGroupPolicies, Test-LAPSDeployment, Test-ConstrainedDelegation, Test-ADDomainTrusts, Test-AuditPolicyConfiguration, Test-ADDomainSecurity, Test-ADCertificateServices, and Test-ADDomainAdminEquivalence all now accept an optional -Snapshot parameter. As of this release, all 27 registered Start-ADSecurityAudit tests support -Snapshot, fully or partially - Invoke-ADRuleSet's "will be skipped under -FromSnapshot" list is now empty.
- New shared helper Resolve-ADSnapshotGroupMember (src/Common.ps1) resolves group membership recursively in-memory against a snapshot, mirroring Get-ADGroupMember [-Recursive] with no live AD access. Reused by the PrivilegedGroups, AdminSDHolder, and DomainAdminEquivalence checks.
- Additive Snapshot.* schema changes only - no existing field renamed or removed: three new Snapshot.ACLs targets (DomainControllersOU, UsersContainer, ComputersContainer); a HasAuditRules tri-state (true/false/null-if-undeterminable) field on every Snapshot.ACLs target; Snapshot.GPOs[].LinkedTo (built from a single gPLink pass instead of a live per-GPO reverse lookup); Snapshot.LapsSchema; Snapshot.PasswordPolicy, Snapshot.Forest, Snapshot.RecycleBinEnabled, and Domain.DomainMode; Snapshot.Trusts[] gains SIDFilteringQuarantined/SelectiveAuthentication/Created/Modified; Snapshot.Users[]/.Computers[] gain TrustedToAuthForDelegation; Snapshot.Computers[] gains HasRbcdConfigured, PasswordLastSet, HasShadowCredentials, and a per-computer Access ACL; Snapshot.Users[] gains scriptPath, HasShadowCredentials; new Snapshot.PrivilegedUserAcls (ACLs for adminCount=1 users specifically, not every user); Snapshot.ADCS.CertificateTemplates[]/.CertificateAuthorities[] gain per-object Access ACLs and templates gain msPKI-RA-Signature.
- Security-descriptor-shaped attributes (RBCD, shadow credentials) are represented as boolean presence flags derived from a targeted LDAP filter, never as the raw binary value - consistent with the "never store nTSecurityDescriptor/binary attributes wholesale" rule established in v1.18.1/v1.18.2.
- Three modules remain partially live-only by design, matching the precedent already set by Test-ADCoercionAndRelayExposure/Test-ADLegacyAuthSurface: Test-ADGroupPolicies' SYSVOL file-share ACL check and Test-AuditPolicyConfiguration's per-DC auditpol check are real-time machine/network state with no AD-schema equivalent and always run live, with a Write-Warning noting this when invoked under -Snapshot.
- All new snapshot collections follow the established safety discipline: named -Properties only (never -Properties *), every ACL flattened immediately via ConvertTo-ADFlatAce, and ContainsKey-only presence checks (an empty-but-valid collection must never trigger a live fallback).

v1.18.5 - Fix vUnknown Version, Add Offline Report Indicator, Fix Empty-Snapshot-Collection Live Fallback
- Fixed the HTML report showing "vUnknown" instead of the real module version: ReleaseNotes used an expandable here-string, and a literal $User mention in the 1.18.3 notes made Import-PowerShellDataFile reject the entire manifest and fall back to 'Unknown'. Switched ReleaseNotes to a literal here-string, closing off this whole bug class.
- Added an offline/live indicator to the HTML report: Export-ADSecurityReportHTML now takes -RunMode and -SnapshotCollectedDate, showing a mode badge, a dedicated offline warning banner, and the snapshot collection timestamp when run via -FromSnapshot.
- Fixed several already-snapshot-aware modules silently falling back to live queries when a snapshot collection was legitimately empty (e.g. zero trusts in a single-domain forest): removed the truthiness half of 21 "$Snapshot.ContainsKey(...) -and $Snapshot.X" checks across 13 files so ContainsKey alone decides whether snapshot data is used. Found via live execution testing, not static review.
- This release was verified end-to-end with a real PowerShell 7 runtime: full syntax-parse of all 41 files, a module import/export smoke test, and a full Start-ADSecurityAudit -FromSnapshot run producing valid JSON/HTML/CSV output.

v1.18.4 - Make -FromSnapshot Actually Offline
- Fixed Start-ADSecurityAudit -FromSnapshot silently making live AD/DC connections for 12 of 27 tests (AuditPolicyConfiguration, PrivilegedGroups, AdminSDHolder, GroupPolicies, ReplicationSecurity, DomainSecurity, DangerousPermissions, CertificateServices, DomainTrusts, LAPSDeployment, ConstrainedDelegation, DomainAdminEquivalence - none of which have -Snapshot support yet), contradicting its own "no live AD access" documentation. Invoke-ADRuleSet now skips unsupported tests by default (with a warning) instead of falling back to live queries. Added an opt-in -AllowLiveFallbackForUnsupportedTests switch on both Invoke-ADRuleSet and Start-ADSecurityAudit to restore the old behaviour for anyone who wants a partial-live run. Start-ADSecurityAudit -FromSnapshot now also prints which tests will be skipped before the run starts.

v1.18.3 - Fix Test-ADUserSecurity Regression Under -FromSnapshot
- Fixed Test-ADUserSecurity failing under -FromSnapshot with "Cannot process argument transformation on parameter 'User' ... the adapter cannot set the value of property 'Name'": a regression from 1.18.2. Test-PrivilegedUser's $User parameter was strongly typed as [Microsoft.ActiveDirectory.Management.ADUser], which broke once Snapshot.Users held flattened PSCustomObjects instead of raw ADUser objects. The parameter is now untyped since the function only reads .MemberOf.

v1.18.2 - Fix -FromSnapshot Duplicate-Key Error
- Fixed Start-ADSecurityAudit -FromSnapshot failing with a "duplicated keys 'ObjectGuid' and 'ObjectGUID'" error: Domain, DomainControllers, Users, and Computers are now flattened to plain PSCustomObjects with an explicit property list (same pattern as Groups/GPOs/ADCS/Trusts) instead of being stored as raw AD cmdlet output, which could carry the same attribute under two differently-cased property names.

v1.18.1 - Fix Get-ADSnapshot Hang, Add Progress Bar, Auto-Create Output Folders
- Fixed the AD CS collection step in Get-ADSnapshot requesting -Properties * on every certificate template/CA object (including full nTSecurityDescriptor ACLs and other unused binary attributes), which made ConvertTo-Json -Depth 12 during -ToJson serialization look like an indefinite hang on any domain with more than a handful of templates. Now requests only the specific properties Test-ADCSExtended reads, and flattens to plain PSCustomObjects (same pattern as Groups/GPOs). Applied the same fix to domain-trust collection.
- Added a stage-based Write-Progress bar to Get-ADSnapshot (12 collection stages) and to Invoke-ADRuleSet's offline test loop, matching the progress bar already present in Start-ADSecurityAudit's live-mode loop.
- Added missing Write-Verbose start/completion messages for the domain and domain-controller collection steps in Get-ADSnapshot.
- -ExportPath (Start-ADSecurityAudit) and the -ToJson parent directory (Get-ADSnapshot) are now created automatically if they don't exist, instead of erroring out.
- README.md: fixed unfenced Usage-section example commands (now proper powershell code blocks) and corrected -OutputPath to the actual -ExportPath parameter name.

v1.18.0 - CVE-2026-41089 (Netlogon RCE) Detection + BadSuccessor Patch-Level Classification
- Added a new Test-ADKnownDCVulnerabilities check for CVE-2026-41089: a critical (CVSS 9.8), unauthenticated Netlogon RPC (MS-NRPC) remote code execution against Domain Controllers, patched by Microsoft's May 12, 2026 Patch Tuesday update and reported under active in-the-wild exploitation since late May / early June 2026. Detection is patch/build-level evidence only (`Get-HotFix`/OS install date), identical in mechanism to the existing ZeroLogon/MS17-010/MS14-068/PrintNightmare checks - no Netlogon protocol traffic, authentication attempt, or exploit code of any kind. New ADFindingMetadataMap entry (MITRE T1210, ANSSI `vuln1_netlogon_cve2026_41089_unpatched`).
- Refined the BadSuccessor / dMSA Escalation Exposure finding to distinguish Domain Controllers patched for CVE-2025-53779 (build 26100.4946+, August 2025) from unpatched ones, instead of flagging every Windows Server 2025 DC identically regardless of patch level. Adds a new read-only per-DC UBR (Update Build Revision) remote registry read (`Get-ADKnownVulnUBR`, via .NET's `RegistryKey.OpenRemoteBaseKey` - no writes, no code execution) for DCs already gated by the existing Server 2025 base-build guard; a DC whose UBR cannot be read is reported as unknown patch status rather than silently assumed patched. Per independent post-patch research (Akamai), the finding continues to fire even for confirmed-patched DCs - with severity reduced from High to Medium only once every affected DC in the environment is confirmed patched - because a mutually-paired dMSA/target relationship can still be abused if an attacker controls both sides.
- Both additions are additive-only to the `Details` hashtable (`PatchedDomainControllers`, `UnpatchedDomainControllers`, `UnknownPatchStatusDomainControllers`, per-DC `UBR`/`BadSuccessorPatchStatus` fields); the `ADSecurityFinding` schema, existing ZeroLogon/MS17-010/MS14-068/PrintNightmare checks, and `-Snapshot` behavior (this audit remains live-only) are all unaffected.
- New Pester coverage in tests/KnownVulnAudits.Tests.ps1 for both features: the CVE-2026-41089 vulnerable/patched evidence paths, the UBR patch/unpatched/boundary/unreadable classification paths, and the severity-reduction-on-full-patch behavior.
- Sourcing note: the CVE-2026-41089 fix date (May 12, 2026, CVSS 9.8) and the CVE-2025-53779 UBR threshold (26100.4946) were independently re-verified on 2026-07-09 against multiple sources citing MSRC directly (SecurityWeek, Tenable, Zero Day Initiative, CERT-EU, and Microsoft's own KB5063878 support article) and both match this release's thresholds exactly. CERT-EU also lists verified per-OS fixed-build boundaries for CVE-2026-41089 (see the inline comment above the Netlogon2026 threshold); several lower-quality aggregator sites gave inconsistent KB numbers for the same CVE and were not relied on.

v1.17.1 - External Intelligence Refresh (Q3 2026)
- Quarterly refresh of external references in Test-ADKnownDCVulnerabilities and the MITRE ATT&CK mapping table. No detection logic, schema, or output contract changes.
- Re-verified all four legacy CVE fix-date thresholds (ZeroLogon, MS17-010, MS14-068, PrintNightmare) directly against MSRC; all four dates were already correct. Added inline source-URL + verification-date citation comments so the next refresh has a starting point.
- Added the missing MITRE ATT&CK display name for T1068 (Exploitation for Privilege Escalation) to the MitreTechniqueNames table - it was already referenced by two findings (DC Missing ZeroLogon Patch, PrintNightmare Exposure on DC) but had no display-name entry, a drift point flagged by this project's own maintenance checklist.
- Corrected the BadSuccessor / dMSA Escalation Exposure finding text, which claimed no version-detectable patched state existed for the issue. Microsoft shipped a partial KDC-side fix (CVE-2025-53779, August 2025, build 26100.4946+) since that text was written; Description/Impact/Remediation now reflect the patch while noting independent research shows the underlying dMSA-linking primitive still enables related abuse post-patch. The detection guard itself (Server 2025 base build >= 26100) is unchanged - distinguishing patched from unpatched builds would require reading the OS UBR, which is a new detection surface and is out of scope for this refresh (see the accompanying feature-request docs).
- Flagged two new feature-request candidates (not implemented in this release): a new Test-ADKnownDCVulnerabilities-family check for CVE-2026-41089 (unauthenticated Netlogon RCE, patched May 2026, actively exploited), and build-revision (UBR)-based patch-level detection for the existing BadSuccessor guard.

v1.17.0 - Multi-Domain / Forest Consolidation
- Added Get-ADForestConsolidation / Export-ADForestConsolidationHTML: an offline, file-based post-processing feature (not a live-AD detection module, not part of the Main.ps1 test dispatch table) that reads two or more of this module's own prior AD_Security_Audit_/AD_Security_Score_ JSON exports - one per domain - and rolls them up into a forest-wide view: a forest score/maturity using the same worst-category (MAX) semantics as Get-ADRiskScore, a per-category heatmap (worst domain per category), a worst-first domain comparison table, cross-domain trust-risk enrichment (annotates Test-ADDomainTrusts findings with the target domain's own score/maturity when that domain's report is also supplied), and "not scanned this run" flags for domains missing versus a prior consolidated run. No AD queries, credentials, or network access of any kind - pure offline aggregation of exports this module already produces. Comparable in spirit to PingCastle's paid "Conso" report, offered for free and implemented independently against this project's own JSON schema.

v1.16.2 - HTML Report: Consolidated Findings
- Findings that fire once per affected object (e.g. AdminSDHolder ACL Compromise across several principals) previously rendered as N separate top-level findings with identical Impact/Remediation text. The HTML report now groups by Category+Issue and renders one consolidated finding per group, with Impact/Remediation/MITRE/ANSSI shown once and every affected object (with its own specific description and detection time) listed underneath. Single-object findings render exactly as before. JSON/CSV exports are unchanged - this is a report-rendering change only, not an output-schema change.

v1.16.1 - Bug-Fix Release
- Fixed HTML report/console mojibake caused by a missing UTF-8 BOM (emoji literals replaced with HTML numeric character references).
- Fixed Test-ADDnsSecurity calling the nonexistent Get-DnsServerZoneTransfer cmdlet; transfer settings now read from Get-DnsServerZone's own properties.
- Fixed "PrivilegedGroupsString cannot be found" error in Get-ADTier0Principal (property now declared at construction).
- Fixed a Join-Path array-argument bug in Test-ADGpoDeployedSecrets that broke the script-credential scan.
- Added a legacy PublicKey.Key fallback in Test-ADCSWeakCertificate for hosts where GetRSAPublicKey() isn't resolvable.
- Fixed Test-ADCoercionAndRelayExposure losing Spooler status and wasting retries whenever WebClient wasn't installed; the two services are now queried independently.
- Fixed 6 findings in DomainAdminEquivalence.ps1 with a blank Impact field.
- Rebalanced Get-ADRiskScore to a diminishing-returns model so category scores no longer saturate to 100 after just 2-3 Critical findings (numeric scores will differ from v1.16.0 and earlier).
- Reduced default retry attempts/backoff in Invoke-ADQueryWithRetry for faster overall runs.
- HTML report: category risk bars now render (CSS display fix), findings are collapsible with per-section Expand/Collapse All, and the Executive Summary cards link to their section.
- Added progress bars to the main audit loop and export steps.
- Reworded PingCastle references throughout docs/code as feature comparisons, with an independence disclaimer added to the README.
- README installation steps now lead with running the module in place, with the previous copy-based install kept as a documented secondary option including update steps.

v1.16.0 - Attack-Path Graph & Indirect-Privilege (Control-Path) Findings
- Added Get-ADControlPathGraph: builds a directed control-edge graph from dangerous ACEs (GenericAll/WriteDacl/WriteOwner/GenericWrite/AllExtendedRights, the dangerous extended-rights and property-write tables in Common.ps1, including the DS-Replication set), group membership, and object ownership, reusing the existing rights tables and the step-02 snapshot/Get-ADTier0Principal.
- Added Test-ADControlPaths: breadth-first search from every non-Tier-0 principal that holds a dangerous ACE or ownership edge to the Tier-0 set (Get-ADTier0Principal + Domain Controllers + AdminSDHolder + the domain head object), emitting a finding per reachable path with the full principal->...->target hop chain in Details.HopChain. A broad principal (Everyone/Authenticated Users/Domain Users/ANONYMOUS LOGON) on any path is always Critical. Also flags Tier-0 objects owned by a non-Tier-0 principal (implicit WriteDacl-equivalent control via ownership).
- Chains the module's existing per-object primitives so the few paths that actually lead to Domain Admins/Domain Controllers surface as their own findings, rather than relying on a human to connect a pile of individually-scored flat ACE findings.
- Detection only: every edge is derived from a read of nTSecurityDescriptor, group membership, or object ownership - the same categories of read already performed elsewhere in the module. No exploitation, coercion, relay, ticket forging, or PoC traffic is ever sent to any host. ACL/ownership edges are scoped to the Tier-0 target set plus every group on a chain toward it, rather than sweeping nTSecurityDescriptor across the entire domain.
- Added Export-ADControlPathGraphBloodHound: optional BloodHound-compatible generic-edge JSON export of the same graph, written as a separate artifact so the existing JSON/HTML/CSV findings export is unchanged.
- Added a 'Control Paths to Tier-0' HTML report section rendering each path's hop chain.
- Registered in Start-ADSecurityAudit's live test set and the offline rule registry; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): P-ControlPathIndirectEveryone, P-ControlPathIndirectMany, P-DCOwner, P-UnprotectedOU, P-DangerousExtendedRight).

v1.15.0 - Read-Only Domain Controller Security Posture
- Added Test-ADRodcSecurity: audits Read-Only Domain Controller configuration - Tier-0/privileged principals present in msDS-RevealedUsers (already cached) or the msDS-RevealOnDemandGroup allowed list (cross-referenced against Get-ADTier0Principal), password replication policy gaps (an allowed list that is too broad or a denied list missing expected privileged groups, via msDS-NeverRevealGroup), and orphaned RODC-specific krbtgt_* accounts left behind after an RODC was demoted/removed.
- Detection only: every determination is a read of RODC computer-object attributes (msDS-RevealedUsers, msDS-RevealOnDemandGroup, msDS-NeverRevealGroup) and a krbtgt_* account inventory cross-referenced against current RODC computer objects. No exploitation, coercion, relay, ticket forging, or PoC traffic is ever sent to any host.
- Clean exit when the domain has no RODCs.
- Snapshot-aware: accepts an optional -Snapshot parameter, falling back to live Get-ADDomainController/Get-ADObject reads when not supplied.
- Registered in Start-ADSecurityAudit's live test set and the offline rule registry; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): P-RODCAdminRevealed, P-RODCAllowedGroup, P-RODCDeniedGroup, P-RODCNeverReveal, P-RODCRevealOnDemand, P-RODCKrbtgtOrphan, P-RODCSYSVOLWrite).

v1.14.0 - Exchange-in-AD Privilege Escalation (Exchange Windows Permissions / WriteDACL)
- Added Test-ADExchangeEscalation: flags Exchange security groups (Exchange Windows Permissions, Exchange Trusted Subsystem, Exchange Servers, Exchange Enterprise Servers, Organization Management) holding GenericAll/WriteDacl/WriteOwner on the domain head object (PrivExchange-style escalation to DCSync), and the same principals holding those rights on AdminSDHolder. Fires on RESIDUAL ACEs even when Exchange has been fully decommissioned from the forest, since the ACE is not cleaned up automatically.
- Detection only: every determination is a read of nTSecurityDescriptor.Access on the domain head and CN=AdminSDHolder,CN=System,<domain>. No PrivExchange push-subscription request, NTLM relay, or any other exploitation/coercion/PoC traffic is ever sent to any host.
- Snapshot-aware with no schema change: reads from Snapshot.ACLs.DomainRoot / Snapshot.ACLs.AdminSDHolder (both already collected by Get-ADSnapshot since v1.3.0), so -FromSnapshot is fully supported without any collection changes.
- Registered in Start-ADSecurityAudit's live test set and the offline rule registry; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): P-ExchangePrivEsc, P-ExchangeAdminSDHolder).

v1.13.0 - Known DC Vulnerabilities by Patch/Build (MS14-068, MS17-010, ZeroLogon, PrintNightmare, BadSuccessor)
- Added Test-ADKnownDCVulnerabilities: flags DC exposure to ZeroLogon (CVE-2020-1472), MS17-010/EternalBlue, MS14-068, and PrintNightmare (CVE-2021-34527, only when the Spooler service is running) strictly from OS build/install date and installed hotfix level (Get-HotFix / Win32_QuickFixEngineering) against documented, inline-cited fix-date thresholds; also flags BadSuccessor/dMSA escalation exposure, guarded to Domain Controllers running Windows Server 2025 (build 26100+) since dMSA is a Server 2025-only feature.
- Detection only: every determination is a read of Win32_OperatingSystem, installed hotfixes, and the Print Spooler service state - the same category of read already used by Test-ADCoercionAndRelayExposure. No exploitation, authentication bypass, ticket forging, coercion, relay, or PoC traffic is ever sent to any host.
- Live-only: per-DC OS build, hotfix level, and Spooler state are real-time machine state with no snapshot equivalent, so this entire audit is skipped when invoked with -Snapshot (-FromSnapshot performs no live AD/network access), consistent with Test-ADLegacyAuthSurface and Test-ADCoercionAndRelayExposure.
- Registered in Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): S-Vuln-MS14-068, S-Vuln-MS17_010, A-Krbtgt, A-DC-Spooler, A-BadSuccessor).

v1.12.0 - GPO-Deployed Secrets & Insecure Settings (GPP cpassword, Script Credentials)
- Added Test-ADGpoDeployedSecrets: scans each GPO's SYSVOL policy folder for Group Policy Preferences (GPP) 'cpassword' values left over from MS14-025 (Groups.xml, Services.xml, ScheduledTasks.xml, Drives.xml, DataSources.xml, Printers.xml), credential-flavoured patterns embedded in deployed logon/startup scripts, and insecure settings pushed via GPO (Windows Firewall disabled, hidden file extensions, RDP Network Level Authentication disabled or an insecure RDP security layer).
- Detection only: a 'cpassword' hit is reported by PRESENCE and FILE PATH ONLY - the value is never decrypted, decoded, or included in the finding; a script-credential hit is reported by file and line number only, never the matched line's content. Streams SYSVOL trees file-by-file/line-by-line rather than loading them wholesale, so large environments don't time out. Never modifies, deletes, or reuses any discovered secret, and performs no exploitation, coercion, relay, or PoC traffic.
- GPO enumeration can read from Snapshot.GPOs when -Snapshot is supplied, but every SYSVOL/registry.pol read is live file-share I/O (not part of the current snapshot schema), so this audit always performs live, read-only I/O regardless of -Snapshot, consistent with the other live-only sub-checks in the module.
- Registered in Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): P-DelegationGPOData, P-DelegationFileDeployed, P-DelegationLoginScript, S-FirewallScript, S-FolderOptions, S-TerminalServicesGPO, A-AnonymousAuthorizedGPO).

v1.11.0 - Stale-Object & Hygiene Depth (PASSWD_NOTREQD, primaryGroupID, Duplicate SPNs, DC Registration)
- Added Test-ADStaleObjectDepth: audits accounts with PASSWD_NOTREQD set (userAccountControl 0x0020), non-default primaryGroupID on user and computer objects (membership-hiding, distinguishing the legitimate Domain Controllers RID 516 for genuine DCs from a suspicious 516/other RID elsewhere), duplicate Service Principal Names across users and computers (reporting every holder), Domain Controllers not covered by any AD Sites & Services subnet object, and insufficient Domain Controller count (fewer than 2).
- Detection only: reads userAccountControl and primaryGroupID bitmasks/values, builds a case-insensitive in-memory SPN index from already-queried user/computer objects, and reads DC inventory (Get-ADDomainController) and subnet objects (Get-ADReplicationSubnet). Never sets, clears, or otherwise modifies any account attribute, SPN, or Sites & Services object, and performs no exploitation, coercion, relay, or PoC traffic.
- Snapshot-aware for the PASSWD_NOTREQD, primaryGroupID, and duplicate-SPN checks (Snapshot.Users / Snapshot.Computers, extended this release to also collect PrimaryGroupID for users and ServicePrincipalNames/SamAccountName for computers) and the DC-count check (Snapshot.DomainControllers); the DC subnet/site registration check always performs one live, read-only Get-ADReplicationSubnet call (subnet objects are not part of the current snapshot schema) even when -Snapshot supplies the DC list, consistent with the other live-only sub-checks elsewhere in the module.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): S-PwdNotRequired, S-PrimaryGroup, S-C-PrimaryGroup, S-Duplicate, S-DC-SubnetMissing, A-NotEnoughDC, S-DCRegistration).

v1.10.0 - Kerberos Hardening Depth (AES Enforcement, FAST/Armoring, Cross-Trust TGT Delegation)
- Added Test-ADKerberosHardening: audits RC4 Kerberos encryption still being permitted (Tier-0 privileged accounts and krbtgt via msDS-SupportedEncryptionTypes, trusts missing TRUST_USES_AES_KEYS, and the domain-wide 'Configure encryption types allowed for Kerberos' GPO/registry policy), Kerberos Armoring (FAST) not enabled (KDC and client EnableCbacAndArmor policy), and cross-trust TGT delegation (trustAttributes CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION).
- Detection only: reads msDS-SupportedEncryptionTypes bitmasks, GPO-linked registry policy (falling back to a direct per-DC registry read only when no linked GPO defines a setting), and trustAttributes via Get-ADTrust. Never sets, clears, or otherwise modifies any account attribute, policy, or registry value, never forges or requests a Kerberos ticket, and performs no exploitation, coercion, relay, or PoC traffic.
- Snapshot-aware for the account-level RC4 check (Snapshot.Users + the Tier-0 set) and both trust-level checks (Snapshot.Trusts); the domain-wide encryption-type policy and Kerberos Armoring (FAST) checks are live-only GPO/registry reads and are skipped entirely when run from a snapshot (-FromSnapshot performs no live AD/network access), consistent with Test-ADLegacyAuthSurface and Test-ADCoercionAndRelayExposure.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): S-AesNotEnabled, T-AlgsAES, S-KerberosArmoring, S-KerberosArmoringDC, T-TGTDelegation).

v1.9.0 - Legacy Auth & Name-Poisoning Surface (SMBv1, Signing, LM/NTLMv1, LLMNR, WSUS-HTTP)
- Added Test-ADLegacyAuthSurface: audits legacy/weak authentication and name-resolution poisoning surface enforced (or left unenforced) via GPO/registry - SMBv1 enabled/not disabled by policy, SMB signing not required, LM/NTLMv1 authentication permitted (LmCompatibilityLevel < 3), LLMNR not disabled by policy, and WSUS delivered over HTTP (package-injection MITM surface).
- Detection only: reads GPO-linked registry policy values via Get-GPRegistryValue against each linked GPO's registry.pol (Domain Controllers OU first, then domain root), and falls back to a direct per-DC registry read only when no linked GPO defines a setting, so a locally configured (non-policy) value is still caught. Every finding's Details distinguishes a policy-enforced value (naming the source GPO) from one observed via live registry read with no enforcing policy found. Never sets, clears, or otherwise modifies any policy or registry value, and performs no exploitation, coercion, relay, or PoC traffic (e.g. no Responder-style poisoning or SMB relay is ever triggered).
- Live-only: GPO-linked registry policy state and per-DC registry reads are not part of the current snapshot schema, so this entire audit is skipped when run from a snapshot (-FromSnapshot performs no live AD/network access), consistent with Test-ADCoercionAndRelayExposure and the anonymous-bind probe in Test-ADDomainHardeningFlags.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): S-SMB-v1, A-SMB2SignatureNotEnabled, A-SMB2SignatureNotRequired, A-LMHashAuthorized, S-OldNtlm, A-NoGPOLLMNR, S-WSUS-HTTP).

v1.8.0 - AD-Integrated DNS Security (DnsAdmins, Zone Transfer, Insecure Updates, ADIDNS)
- Added Test-ADDnsSecurity: audits DnsAdmins group membership (a well-known Domain-Controller code-execution path via the DNS server's ServerLevelPluginDll mechanism), zone transfer exposure (transfers to any server or any NS-listed server, rather than an explicit secondary list), insecure (nonsecure) dynamic DNS updates, and overly broad CreateChild rights on AD-integrated zone objects granted to Authenticated Users/Everyone/ANONYMOUS LOGON (ADIDNS spoofing/MITM surface).
- Detection only: reads DnsAdmins group membership, AD-integrated zone object attributes (dNSProperty) and ACLs (nTSecurityDescriptor), and optionally the read-only Get-DnsServerZone/Get-DnsServerZoneTransfer cmdlets when the DnsServer RSAT module is available, falling back to a best-effort dNSProperty attribute parse otherwise. Never creates, deletes, or modifies a DNS record, zone, or plugin DLL configuration, and performs no exploitation, coercion, relay, or PoC traffic.
- Snapshot-aware for the DnsAdmins membership check (reads Snapshot.Groups); the zone transfer, dynamic update, and ADIDNS CreateChild checks are live-only (zone-level attributes/ACLs are not part of the current snapshot schema) and are skipped entirely when run from a snapshot (-FromSnapshot performs no live AD/network access), consistent with Test-ADCoercionAndRelayExposure and the anonymous-bind probe in Test-ADDomainHardeningFlags.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): P-DNSAdmin, P-DNSDelegation, A-DnsZoneTransfert, A-DnsZoneUpdate1, A-DnsZoneUpdate2, A-DnsZoneAUCreateChild).
- Fixed: the HTML report footer's module version string was hardcoded and had drifted out of sync with ModuleVersion since v1.7.0; it is now read from the module manifest at import time so it can no longer go stale.

v1.7.0 - AD CS Beyond ESC1/2/3/7 (ESC4, ESC8, ROCA, Weak PKI Crypto)
- Added Test-ADCSExtended: ESC4 (dangerous template ACLs granting Write/WriteDacl/WriteOwner/GenericAll/GenericWrite to low-privileged principals), a high-risk-without-approval check (enrollee-supplied subject/SAN or Any-Purpose EKU with no manager-approval gate, distinct from the existing ESC1/ESC2 checks), ESC8 (CA web enrollment reachable over HTTP without Extended Protection for Authentication), and a ROCA (CVE-2017-15361) / weak-signature-algorithm / weak-RSA-modulus sweep of the CA certificates and the NTAuth/AIA/Root store.
- Detection only: reads template/CA attributes, ACLs, and already-published certificate bytes; ESC8's only live-network step is a read-only remote check of the CA host's web-enrollment configuration. Never requests, forges, or relays a certificate, and sends no coercion/PoC traffic.
- Snapshot-aware where the data allows it: template/CA enumeration and the approval-gate and CA-certificate weak-crypto checks read from Snapshot.ADCS (unchanged snapshot schema). ESC4's per-template ACL read, the ESC8 CA-host probe, and the NTAuth/AIA/Root store sweep are live-only and are skipped entirely when run from a snapshot (-FromSnapshot performs no live AD/network access), consistent with Test-ADCoercionAndRelayExposure and the anonymous-bind probe in Test-ADDomainHardeningFlags.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): A-CertEnrollHttp, A-CertTempNoSecurity, A-CertTempAnyPurpose, A-CertTempAnyone, A-CertTempCustomSubject, A-CertROCA, A-CertWeakRsaComponent, A-MD5RootCert, A-SHA1RootCert).

v1.6.0 - Coercion & NTLM Relay Exposure
- Added Test-ADCoercionAndRelayExposure: audits each Domain Controller for the configuration that enables coerce-then-relay attacks - Print Spooler running (PrinterBug), WebClient running (WebDAV coercion), NTDS LDAPServerIntegrity not requiring signing, and LdapEnforceChannelBinding not requiring Extended Protection for Authentication (EPA).
- Detection only: reads service and NTDS registry state per DC (remote registry / Invoke-Command); never sends a coercion trigger, never relays, and performs no exploitation or PoC traffic.
- Live per-DC probes are skipped entirely when run from a snapshot (-FromSnapshot performs no live AD/network access), consistent with the anonymous-bind probe in Test-ADDomainHardeningFlags; the DC list itself is still read from the snapshot when supplied.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): A-DC-Coerce, A-DC-Spooler, A-DC-WebClient, A-DCLdapSign, A-DCLdapsChannelBinding).

v1.5.0 - Domain Hardening Flags
- Added Test-ADDomainHardeningFlags: audits dSHeuristics for dangerous positional flags (anonymous access, List Object security mode, AdminSDHolder exclusion mask weakening), flags broad membership (Authenticated Users/Everyone/ANONYMOUS LOGON) in the built-in Pre-Windows 2000 Compatible Access group, and performs a strictly read-only anonymous LDAP/RootDSE bind probe (success is the finding; refusal is secure).
- Snapshot-aware for dSHeuristics and Pre-Windows 2000 membership: Get-ADSnapshot now also collects DsHeuristics and PreWin2000Members. The anonymous-bind probe is a live network operation and is skipped when running from a snapshot (-FromSnapshot performs no live AD/network access).
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (MITRE T1556, T1078.002, T1087.002).

v1.4.0 - Machine Account Quota
- Added Test-ADMachineAccountQuota: audits ms-DS-MachineAccountQuota on the domain root, flagging the unmodified default of 10 (High) and any other non-zero value (Medium) that lets authenticated users self-service-join computer accounts, which can be abused for RBCD relay and SamAccountName-spoofing privilege escalation.
- Snapshot-aware from day one: Get-ADSnapshot now also collects ms-DS-MachineAccountQuota; Test-ADMachineAccountQuota reads it from a supplied -Snapshot or falls back to a live Get-ADObject read.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (MITRE T1136.002).

v1.3.0 - Collect-Once Snapshot, Rule-Runner & Offline Mode
- Added Get-ADSnapshot: one paged, read-only collection pass over users, computers, groups, GPOs, ACLs on key objects, AD CS config, DNS zones, trusts, and DC inventory, with -ToJson for serialisation.
- Added Invoke-ADRuleSet -Snapshot: dispatches Test-* functions against a snapshot, defensively splatting -Snapshot only to functions that declare it so snapshot-unaware modules are called live and never error.
- Added Start-ADSecurityAudit -FromSnapshot <path> for offline re-analysis (no live AD access) producing the same JSON/HTML/CSV report and score.
- Added shared Get-ADTier0Principal helper (privileged/Tier-0 principal set) for reuse by later features.
- Began retrofitting existing audit functions (Test-ADUserSecurity, Test-KRBTGTAccount) with an optional -Snapshot parameter; remaining modules will be retrofitted gradually in later steps.

v1.2.0 - Scoring, ANSSI Maturity & MITRE ATT&CK
- Added 0-100 risk score (higher = worse) with per-category sub-scores and a 1-5 ANSSI-style maturity level (Get-ADRiskScore).
- Added MITRE ATT&CK technique and ANSSI control tagging on every finding via a central mapping table (src/Scoring.ps1, Set-ADFindingMetadata).
- Added additive MitreTechnique, AnssiControl, and Weight fields to ADSecurityFinding (output schema is now additive-only / contract-stable).
- Added score gauge, maturity panel, and MITRE technique summary to the HTML report; appended new CSV columns and a score/maturity sidecar JSON.

v1.1.0 - Reliability & Security Improvements
- SECURITY: Fixed CSV injection vulnerability in report exports
- Added Domain Controller failover support for improved reliability
- Added Invoke-ADQueryWithRetry helper for network resilience (exponential backoff)
- Added result pagination for large AD queries (prevents timeouts in large environments)
- Converted 40+ silent failures to proper try/catch with verbose logging
- Improved error handling across all audit modules
- Added ConvertTo-SafeCsvValue function for safe CSV exports

v1.0.1 - Bug Fixes
- Fixed nested group detection in Test-ADPrivilegedGroups
- Fixed LAPS schema path lookup
- Fixed SID lookup in DCSync detection
- Fixed variable ordering in Test-ADDomainAdminEquivalence
- Fixed GUID case sensitivity issues
- Added Test-ADDomainAdminEquivalence to exported functions
- Improved ESC1 detection to check enrollment permissions
- Improved audit policy checking to actually verify auditpol settings
- Improved Kerberoasting detection with encryption type and password age checks
- Fixed orphaned adminCount detection to use recursive group membership

v1.0.0 - Initial Release
- Core AD security auditing capabilities
- Certificate Services vulnerability scanning
- KRBTGT password age monitoring
- Domain trust auditing
- LAPS deployment verification
- Audit policy validation
- Constrained delegation analysis
'@
        }
    }
}
