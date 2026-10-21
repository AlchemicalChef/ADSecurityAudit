# AUTO-EXTRACTED from src/*.ps1 finding-generation blocks. See
# tools/Build-ADFindingNarrativeLibrary.ps1 for how this is generated and
# how to regenerate it after adding/editing a check's EstimatedEffort/
# KnownRisks/BackupRollback/OperationalNotes text.
#
# Keyed by Issue name. Used ONLY to backfill these four fields on findings
# loaded from an older JSON export that predates them (or predates the
# specific Issue's current wording) - see Merge-ADFindingNarrativeGaps in
# Common.ps1. Never overwrites a field the loaded finding already has a
# non-blank value for.
$Script:ADFindingNarrativeLibrary = @{
    'Non-Standard Permissions on AdminSDHolder' = @{
        EstimatedEffort  = 'Medium - a single-object ACE removal, but AdminSDHolder''s SDProp mechanism propagates the corrected ACL to every protected (Tier-0) object domain-wide, so confirm the trustee isn''t a legitimate delegated Tier-0 management tool first.'
        KnownRisks       = 'Procedural - confirm the trustee isn''t an intentional, currently-used Tier-0 delegation before removing; there is no realistic legitimate compatibility break otherwise.'
        BackupRollback   = 'Moderate - export the current ACL first; full effect across every protected object depends on SDProp''s next propagation cycle, not just AD replication.'
        OperationalNotes = ''
    }
    'Deny ACE on AdminSDHolder' = @{
        EstimatedEffort  = 'Low - removing a single unexpected Deny ACE from one object.'
        KnownRisks       = 'Low technical risk removing an unexpected deny entry, but confirm it wasn''t intentionally placed to block a specific known-compromised or decommissioned account before removing it, since that would re-permit whatever it was blocking.'
        BackupRollback   = 'Moderate - export the AdminSDHolder ACL before changing it; the removal only reaches every protected object after SDProp''s next propagation cycle.'
        OperationalNotes = ''
    }
    'Orphaned adminCount Attribute' = @{
        EstimatedEffort  = 'Low - reset a single attribute and re-enable inheritance on one object.'
        KnownRisks       = 'Low technical risk; confirm the object isn''t intentionally kept protected for an undocumented reason before clearing.'
        BackupRollback   = 'Easy - reset adminCount and inheritance back if needed; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Insufficient Audit Policy Configuration' = @{
        EstimatedEffort  = 'Medium - a domain-wide GPO change validated across every DC.'
        KnownRisks       = 'Purely additive logging; essentially no access-control risk, but increases Security event log volume and may need log-size/SIEM capacity planning.'
        BackupRollback   = 'Easy - revert the GPO setting; effective at next Group Policy refresh, no data loss.'
        OperationalNotes = ''
    }
    'Advanced Audit Policy Verification Required' = @{
        EstimatedEffort  = 'Medium - a GPO change that must be validated on every DC, and confirmed not to be overridden by the legacy (non-advanced) Audit Policy category, a well-documented conflict between the two models.'
        KnownRisks       = 'Purely additive logging with essentially no access-control impact; the main practical effect is increased Security event log volume, which may require increasing log size/retention or SIEM ingestion capacity.'
        BackupRollback   = 'Easy - revert the GPO setting; effective at next Group Policy refresh, no data loss.'
        OperationalNotes = ''
    }
    'No Auditing on AdminSDHolder Object' = @{
        EstimatedEffort  = 'Low - adding a SACL entry to one object.'
        KnownRisks       = 'No access-control impact; increases Security event log volume for changes to this specific object.'
        BackupRollback   = 'Easy - remove the SACL entry; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'No Auditing on Domain Root Object' = @{
        EstimatedEffort  = 'Low - adding a SACL entry to one object.'
        KnownRisks       = 'No access-control impact; increases Security event log volume for changes to this specific object.'
        BackupRollback   = 'Easy - remove the SACL entry; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Certificate Template Allows Subject Alternative Name (ESC1)' = @{
        EstimatedEffort  = 'Medium - requires disabling "supply subject in request" or restricting enrollment rights, and confirming which systems currently request from this template before changing it.'
        KnownRisks       = 'Disabling attacker-controllable SAN (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) can break legitimate workflows that rely on supplying a SAN at request time, such as some non-Windows or automated enrollment clients.'
        BackupRollback   = 'Moderate - AD CS templates are versioned, so a prior version''s settings can be restored and republished; however, any certificates already issued during the vulnerable window remain valid until revoked or expired, so this isn''t a full rollback of the exposure itself.'
        OperationalNotes = ''
    }
    'Certificate Template Allows Subject Alternative Name (Restricted)' = @{
        EstimatedEffort  = 'Medium - same underlying mechanism as the unrestricted ESC1 finding, but exposure is narrower (fewer principals can enroll), so validate the smaller set of dependent systems before changing.'
        KnownRisks       = 'Disabling attacker-controllable SAN can break legitimate workflows among the restricted set of principals that currently rely on supplying a SAN at request time.'
        BackupRollback   = 'Moderate - restore a prior template version if a legitimate workflow breaks; certificates already issued remain valid until revoked or expired.'
        OperationalNotes = ''
    }
    'Certificate Template with No EKU Restrictions (ESC2)' = @{
        EstimatedEffort  = 'Medium - requires validating which application relies on the current broad EKU set (e.g. a cert used for both client authentication and code signing) before narrowing it.'
        KnownRisks       = 'Restricting EKUs can break legitimate uses that rely on the current broad EKU set.'
        BackupRollback   = 'Moderate - restore the template''s prior EKU configuration (via a template export/backup, e.g. PSPKI or certutil) if a legitimate use breaks; certificates already issued remain valid until revoked or expired.'
        OperationalNotes = ''
    }
    'Enrollment Agent Template with Low-Privilege Enrollment (ESC3)' = @{
        EstimatedEffort  = 'Medium - restricting who can enroll for the enrollment-agent template requires confirming which automated on-behalf-of enrollment process currently uses it.'
        KnownRisks       = 'Restricting enrollment agent template access can break an automated on-behalf-of enrollment process that currently relies on the broader access.'
        BackupRollback   = 'Easy - restore the enrollment permission on the template if needed; effective immediately.'
        OperationalNotes = ''
    }
    'Certificate Template Does Not Require RA Signatures' = @{
        EstimatedEffort  = 'Medium - enforcing a required-signature count needs coordination with whichever process actually enrolls from this template, since that process may not yet have an authorized enrollment-agent certificate in its chain.'
        KnownRisks       = 'Enforcing an RA signature requirement will break any enrollment workflow that doesn''t already have an authorized enrollment-agent certificate, until that workflow is updated.'
        BackupRollback   = 'Easy - revert the required-signature count to 0 on the template; effective immediately for new requests.'
        OperationalNotes = ''
    }
    'Certificate Template Allows Arbitrary Server Certificate (ESC17)' = @{
        EstimatedEffort  = 'Medium - same considerations as ESC1: confirm which systems currently request server certificates from this template before narrowing SAN supply or enrollment rights.'
        KnownRisks       = 'Restricting enrollee-supplied SAN or enrollment rights can break legitimate automated server-certificate provisioning that currently relies on this template''s current configuration.'
        BackupRollback   = 'Moderate - AD CS templates are versioned, so a prior version''s settings can be restored and republished; certificates already issued during the vulnerable window remain valid until revoked or expired.'
        OperationalNotes = ''
    }
    'Overly Permissive CA Permissions (ESC7)' = @{
        EstimatedEffort  = 'Medium - removing Manage CA / Manage Certificates rights from an unexpected principal on the CA object''s own ACL; confirm with the PKI team it isn''t a legitimate delegated administrator.'
        KnownRisks       = 'Procedural - confirm the principal isn''t an active, legitimate delegated CA administrator before removing their rights.'
        BackupRollback   = 'Easy - re-add the removed permission via the CA console''s Security tab; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Low-Privilege CA Management Rights' = @{
        EstimatedEffort  = 'Medium - removing the CA Manager role assignment from an unexpected principal via the Certification Authority console; confirm the principal doesn''t actively perform day-to-day CA management first.'
        KnownRisks       = 'Procedural - low technical risk unless the principal genuinely manages CA operations, in which case they lose that capability until re-added.'
        BackupRollback   = 'Easy - re-add the role assignment via the CA console; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Certificate Template with Weak ACL (ESC4)' = @{
        EstimatedEffort  = 'Medium - a single-template ACE removal, but confirm the trustee isn''t a legitimate certificate-lifecycle-management tool or service account before removing.'
        KnownRisks       = 'Procedural - confirm the trustee isn''t an active cert-management automation account before removing; no realistic legitimate technical break otherwise.'
        BackupRollback   = 'Moderate - export the template''s ACL (certutil -v -template or PSPKI) before changing it so the exact ACE can be restored if needed.'
        OperationalNotes = ''
    }
    'Weak ACL on PKI Container Object (ESC5)' = @{
        EstimatedEffort  = 'Medium - a container-level ACE removal; confirm the trustee isn''t a legitimate PKI-management tool or delegated administrator before removing.'
        KnownRisks       = 'Procedural - confirm the trustee isn''t an active PKI-management automation account or delegated admin before removing; no realistic legitimate technical break otherwise.'
        BackupRollback   = 'Moderate - export the container''s ACL (dsacls or PSPKI) before changing it so the exact ACE can be restored if needed.'
        OperationalNotes = ''
    }
    'Certificate Template Missing Security Extension (ESC9)' = @{
        EstimatedEffort  = 'Low - a single template flag; confirm no legitimate enrollment workflow depends on the omitted extension first (rare).'
        KnownRisks       = 'Minimal - clearing this flag only adds information to newly-issued certificates; it does not change any existing legitimate authentication behavior.'
        BackupRollback   = 'Easy - AD CS templates are versioned, so the prior flag value can be restored and republished if needed.'
        OperationalNotes = ''
    }
    'Certificate Template Issuance Policy Linked to Privileged Group (ESC13)' = @{
        EstimatedEffort  = 'Medium - confirm whether the OID-to-group link is an intentional AD FS claims scenario before removing it, since removing it changes real, currently-working claims-based access for legitimate users too.'
        KnownRisks       = 'Removing the group link breaks any legitimate AD FS claims-based access that currently depends on it - confirm the link is unintentional/unused before removing.'
        BackupRollback   = 'Easy - restore the msDS-OIDToGroupLink value on the OID object if needed; effective immediately.'
        OperationalNotes = ''
    }
    'SPN-Holding Account Also Has DCSync Rights' = @{
        EstimatedEffort  = 'Low - the same single-ACE removal already scoped in the standalone Unauthorized DCSync Permissions finding for this account, or a routine SPN removal/service-account migration, whichever side is decided on.'
        KnownRisks       = 'Removing DCSync rights or an SPN from an account that turns out to be a legitimate directory-sync or service account will break that tool/service until re-provisioned correctly (e.g. via a dedicated gMSA without DCSync rights) - confirm the account''s actual purpose before changing either side.'
        BackupRollback   = 'Moderate - export the current ACL and/or SPN value before changing either side so it can be restored if a legitimate dependency surfaces.'
        OperationalNotes = ''
    }
    'Trust Configured for Privileged Identity Management (PIM_TRUST)' = @{
        EstimatedEffort  = 'Low - a single trust-attribute bit toggle, but confirm with the trust''s owning teams before clearing it, since PIM trusts are typically deliberate cross-forest identity-management configurations.'
        KnownRisks       = 'Clearing PIM_TRUST restores standard SID filtering across the trust, which will break any legitimate Privileged Identity Management workflow that currently depends on the relaxed filtering - confirm the trust''s purpose with its owning teams before changing it.'
        BackupRollback   = 'Easy - the attribute can be re-set if a legitimate dependency surfaces; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'GPO Permits LM Hash Storage' = @{
        EstimatedEffort  = 'Low - a single GPO setting applied domain-wide; existing LM hashes clear naturally as passwords are next changed.'
        KnownRisks       = 'No legitimate modern workflow depends on LM hashes being stored; the only practical consideration is that existing LM hashes persist until each account''s next password change, not immediately.'
        BackupRollback   = 'Easy - revert the GPO setting; effective at next Group Policy refresh, no data loss.'
        OperationalNotes = ''
    }
    'Legacy FRS-Based SYSVOL Replication In Use' = @{
        EstimatedEffort  = 'High - a domain-wide replication-mechanism migration affecting every DC''s SYSVOL share; Microsoft''s own procedure requires progressing through and verifying each state (Prepared/Redirected/Eliminated) before advancing, and should be scheduled and tested rather than rushed.'
        KnownRisks       = 'A migration attempted without verifying full replication health at each intermediate state can leave some DCs serving a stale or incomplete SYSVOL, which can affect Group Policy application and logon scripts domain-wide - follow Microsoft''s documented state-by-state verification before advancing.'
        BackupRollback   = 'Difficult - FRS-to-DFSR migration state advances are one-directional by design (Microsoft does not support reverting from Eliminated back to FRS); back up SYSVOL content before starting and verify each intermediate state thoroughly rather than planning to roll back.'
        OperationalNotes = ''
    }
    'AdminSDHolder Inheritance Re-Enabled' = @{
        EstimatedEffort  = 'Low - toggling inheritance protection back on for a single object, but review the full resulting ACL afterward for anything unexpected that inheritance may have introduced.'
        KnownRisks       = 'Re-protecting from inheritance removes any inherited ACEs currently in effect on AdminSDHolder; confirm none of them were an intentional (if unusual) delegation before re-protecting, though this is not expected to be the case for this specific object.'
        BackupRollback   = 'Moderate - export the full current ACL (including inherited ACEs) before changing the protection flag, so anything unexpectedly lost can be reviewed and, if genuinely needed, re-added explicitly.'
        OperationalNotes = ''
    }
    'Vulnerable Schema Class Allows Arbitrary Object Creation' = @{
        EstimatedEffort  = 'Medium - schema changes require Schema Admins and are forest-wide, so validate the change in a lab before applying, and confirm no legitimate application depends on the current (vulnerable) configuration.'
        KnownRisks       = 'Schema modifications are forest-wide and cannot be easily reverted (schema attributes/classes can be deactivated but not fully deleted) - test any corrective change thoroughly in a lab first.'
        BackupRollback   = 'Difficult - schema changes are effectively permanent (classes/attributes can be deactivated, not removed); a system state backup of a schema-master DC before changing anything is the only real rollback path.'
        OperationalNotes = ''
    }
    'Schema defaultSecurityDescriptor Modified' = @{
        EstimatedEffort  = 'Medium - schema changes require Schema Admins and are forest-wide; validate the corrected SDDL in a lab before applying to production.'
        KnownRisks       = 'Restoring the default defaultSecurityDescriptor does not retroactively fix already-created objects that inherited the modified ACL at creation time - those objects need to be separately identified and remediated.'
        BackupRollback   = 'Difficult - schema attribute value changes are not easily reverted once objects have been created under the modified default; back up the current value and plan for a separate remediation pass on already-affected objects.'
        OperationalNotes = ''
    }
    'AD Display Specifier Tampered' = @{
        EstimatedEffort  = 'Low - removing a single attribute value on this DisplaySpecifier object, but confirm the referenced tool isn''t a legitimate (if unusually placed or named) admin console extension before removing.'
        KnownRisks       = 'Removing a legitimate admin console extension (if one happens to be configured this way) will break that specific right-click context-menu action for administrators - confirm before removing. This check only flags a specific set of published, inherently-suspicious patterns (placement, LOLBAS binary names, script extensions); it cannot and does not confirm actual malicious intent or behavior, and a malicious entry placed inside an otherwise-protected system directory with an otherwise-unremarkable name would not be caught by this LDAP-only check.'
        BackupRollback   = 'Easy - record the current adminContextMenu value before removing it; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Non-Default Access to gMSA KDS Root Key' = @{
        EstimatedEffort  = 'Low - a targeted ACE removal on one forest-level container, but confirm the principal isn''t a legitimate delegated PKI/identity-management tool before removing.'
        KnownRisks       = 'No legitimate gMSA host or consumer needs direct access to the KDS root key object itself (they retrieve their own gMSA''s password via msDS-ManagedPassword, not this key) - removing an unexpected grant has no legitimate compatibility impact unless it is an undocumented, currently-in-use PKI/identity tool, so confirm first.'
        BackupRollback   = 'Moderate - export the current ACL before removing the specific ACE(s) so they can be restored if a legitimate dependency surfaces.'
        OperationalNotes = ''
    }
    'Non-Default Access to Domain DPAPI Backup Key' = @{
        EstimatedEffort  = 'Low - a targeted ACE removal on one or a small handful of domain-level objects, but confirm the principal isn''t a legitimate, currently-used backup/recovery tool before removing.'
        KnownRisks       = 'No legitimate day-to-day workflow needs direct access to the domain DPAPI backup key objects themselves; removing an unexpected grant has no legitimate compatibility impact unless it turns out to be an undocumented, currently-in-use backup/recovery tool, so confirm first.'
        BackupRollback   = 'Moderate - export the current ACL before removing the specific ACE(s) so they can be restored if a legitimate dependency surfaces.'
        OperationalNotes = ''
    }
    'Legacy LAPS SearchFlags Exposes Password' = @{
        EstimatedEffort  = 'Medium - a schema attribute change (Schema Admins, schema-master DC) that also changes the effective access-control model for this attribute; validate in a lab first and confirm intended readers still have explicit CONTROL_ACCESS granted before applying to production.'
        KnownRisks       = 'Setting the confidential bit changes ms-Mcs-AdmPwd from a normal-read attribute to one requiring explicit CONTROL_ACCESS - any tooling or delegated group that currently reads it via ordinary read access will need that access re-granted as CONTROL_ACCESS afterward.'
        BackupRollback   = 'Difficult - schema attribute changes are effectively permanent (schema changes are not typically reverted); test thoroughly in a lab and confirm the full set of legitimate readers before applying.'
        OperationalNotes = ''
    }
    'Built-in Guest Account Enabled' = @{
        EstimatedEffort  = 'Low - a single account disable; confirm no legacy application specifically authenticates as Guest first.'
        KnownRisks       = 'Disabling Guest is safe in virtually all modern environments; confirm no legacy kiosk/anonymous-access workflow depends on it before disabling.'
        BackupRollback   = 'Easy - re-enable the account if needed; no data loss either way.'
        OperationalNotes = ''
    }
    'Computer Account Never Joined with No Password Set' = @{
        EstimatedEffort  = 'Low - removing or completing the join for each stale pre-staged object, but confirm with the provisioning team before removing in case the join is simply delayed rather than abandoned.'
        KnownRisks       = 'Removing an object that is actually mid-provisioning (rather than genuinely abandoned) will require re-staging it - confirm current provisioning status with the responsible team first.'
        BackupRollback   = 'Easy - a removed pre-staged object with no real join history can simply be re-created if needed; no real data loss.'
        OperationalNotes = ''
    }
    'Constrained Delegation Configured to Decommissioned SPN' = @{
        EstimatedEffort  = 'Low - removing one or more stale SPN entries from a single account''s delegation configuration.'
        KnownRisks       = 'Low - the target host doesn''t currently exist, so removing the stale delegation entry has no legitimate functional impact today; confirm the host is genuinely decommissioned (not simply temporarily offline) before removing.'
        BackupRollback   = 'Easy - re-add the SPN to msDS-AllowedToDelegateTo if the host turns out to still be in use under a different naming scenario; no data loss either way.'
        OperationalNotes = ''
    }
    'Broad Membership in Distributed COM Users or Performance Log Users' = @{
        EstimatedEffort  = 'Low - reviewing and removing membership from a typically-small, rarely-populated group.'
        KnownRisks       = 'Removing a member who genuinely needs remote DCOM activation or remote performance-counter collection rights will break that specific workflow until re-added - confirm with the member/owning team first.'
        BackupRollback   = 'Easy - re-add any member whose need is confirmed; effective on next Kerberos ticket refresh, no data loss.'
        OperationalNotes = ''
    }
    'Domain Controller Registration Inconsistent' = @{
        EstimatedEffort  = 'Medium - typically a single-object correction per affected DC, but requires confirming the DC''s intended current state (active, mid-promotion, or decommissioned) before deciding whether to correct or clean up metadata.'
        KnownRisks       = 'Correcting userAccountControl or Configuration-partition registration on a DC that is still mid-promotion/demotion, rather than genuinely stuck, could interfere with that in-progress operation - confirm the DC''s actual current state first.'
        BackupRollback   = 'Moderate - record the current attribute values before correcting them; effective on next AD replication cycle.'
        OperationalNotes = ''
    }
    'Rogue NTDS Settings Object Detected' = @{
        EstimatedEffort  = 'High - this requires an incident-response-style investigation (replication metadata, event log correlation, timeline reconstruction) before any cleanup action, not a routine configuration fix.'
        KnownRisks       = 'Deleting the object directly (rather than via documented DC metadata cleanup) can leave inconsistent replication metadata across the forest; treat this as a potential security incident requiring investigation before remediation, not a routine hygiene item.'
        BackupRollback   = 'N/A - this is a detection/investigation finding; remediation should follow Microsoft''s documented metadata-cleanup procedure once the object is confirmed non-legitimate.'
        OperationalNotes = ''
    }
    'Certificate Template Vulnerable to Schema V1 EKU Injection (ESC15)' = @{
        EstimatedEffort  = 'Medium - duplicating a template as Schema V2+ and re-pointing enrollment is a routine AD CS operation, but requires confirming which systems currently enroll against the V1 original before retiring it.'
        KnownRisks       = 'Retiring a Schema V1 template can break legacy clients or workflows (e.g. very old Windows Server versions, or agents predating Schema V2 support) that specifically enroll against a V1 template - confirm no legitimate dependency before retiring rather than duplicating.'
        BackupRollback   = 'Easy - the original Schema V1 template is unaffected by publishing a new V2+ duplicate alongside it; only retiring/unpublishing the V1 original needs to be reversible (re-publish it) if an unexpected dependency surfaces.'
        OperationalNotes = ''
    }
    'Certificate Template Allows High-Risk Enrollment Without Manager Approval' = @{
        EstimatedEffort  = 'Low - toggling the "CA certificate manager approval" flag on one template.'
        KnownRisks       = 'Enabling manager approval adds a manual approval step that will delay or block any automated enrollment workflow (autoenrollment, ACME-style automated issuance) that currently assumes instant issuance.'
        BackupRollback   = 'Easy - untick the approval requirement; effective immediately for new requests, no data loss.'
        OperationalNotes = ''
    }
    'CA Web Enrollment over HTTP (ESC8)' = @{
        EstimatedEffort  = 'Medium - requires enabling HTTPS web enrollment (certificate + IIS binding) and usually coordination with whoever manages the CA''s IIS instance; confirm no client submits enrollment requests over plain HTTP first.'
        KnownRisks       = 'Enforcing HTTPS-only web enrollment can break legacy clients or scripts that submit requests over plain HTTP until they''re updated to the HTTPS endpoint.'
        BackupRollback   = 'Moderate - revert the IIS binding/auth settings and re-enable the HTTP endpoint if needed; requires an IIS restart but no data loss.'
        OperationalNotes = 'HTTPS alone doesn''t fully close ESC8''s NTLM relay risk without Extended Protection for Authentication (EPA) also enabled - consider enabling EPA on the enrollment endpoint at the same time.'
    }
    'ROCA-Vulnerable Certificate Key' = @{
        EstimatedEffort  = 'High - revoking and reissuing a certificate requires coordinating with every consumer of that certificate, since revocation invalidates trust immediately and may need a maintenance window if the certificate is in active use (e.g. smart card logon, TLS).'
        KnownRisks       = 'ROCA-vulnerable RSA keys can, with sufficient compute, have their private key factored from the public key alone (CVE-2017-15361), so this is a confirmed, documented weakness, not a hypothetical one; revoking the certificate breaks authentication/encryption for everything relying on it until the replacement is deployed.'
        BackupRollback   = 'Hard/Limited - a revoked certificate cannot be un-revoked; the only path forward is issuing a new one with a key from an unaffected library, so keep the old certificate available read-only for verifying historically-signed artifacts if that''s needed.'
        OperationalNotes = ''
    }
    'Weak Signature Algorithm in PKI Trust Store' = @{
        EstimatedEffort  = 'Medium - reissuing affected certificates with a stronger signature algorithm (e.g. SHA-256+) and coordinating with every consumer of the old chain.'
        KnownRisks       = 'Modern OSes and browsers already reject SHA-1-signed certificates, but legacy embedded devices or older client OSes may only trust the SHA-1 chain and could lose connectivity until they''re updated to trust the new one.'
        BackupRollback   = 'Hard/Limited - like other certificate revocation/reissuance, this isn''t reversible to the old certificate''s validity; keep the old CA certificate available for verifying already-issued signatures if needed.'
        OperationalNotes = ''
    }
    'CA Chase-Fallback Enabled (CVE-2026-54121 / Certighost Exposure)' = @{
        EstimatedEffort  = 'High - before disabling the flag or patching, requires discovering which cross-domain/cross-forest enrollment workflows (if any) depend on the chase fallback across every CA, since Microsoft''s own advisory notes the registry mitigation was validated only in a lab and should be tested per-CA before production rollout.'
        KnownRisks       = 'Clearing the flag (or the patch''s added validation) can break certificate enrollment for legitimate cross-domain or cross-forest clients that rely on the CA''s chase behavior to resolve a client-DC hint the CA cannot otherwise reach directly.'
        BackupRollback   = 'Easy - the change is a single registry value; if a legitimate enrollment workflow breaks, re-enable EDITF_ENABLECHASECLIENTDC via certutil and restart CertSvc to restore the prior behavior immediately, with no data loss.'
        OperationalNotes = 'Re-enabling the flag as a rollback restores the CVE-2026-54121 exposure, so treat it as strictly temporary and monitor Certificate Services event ID 4886 (a cert request carrying a client-DC hint that doesn''t match a known DC) while investigating any dependency.'
    }
    'CA-Wide SAN Attribute Flag Enabled (ESC6)' = @{
        EstimatedEffort  = 'Medium - a single registry flag, but requires first identifying which templates/workflows (if any) currently rely on CA-wide SAN supply so their enrollment isn''t broken.'
        KnownRisks       = 'Clearing this flag breaks enrollment for any legitimate workflow that currently depends on supplying a SAN CA-wide (rather than via an individual template''s own Enrollee Supplies Subject setting) - identify and migrate those workflows to per-template configuration first.'
        BackupRollback   = 'Easy - the change is a single registry value; re-enable via certutil and restart CertSvc to restore the prior behavior immediately if something breaks, with no data loss.'
        OperationalNotes = ''
    }
    'CA RPC Enrollment Encryption Not Enforced (ESC11)' = @{
        EstimatedEffort  = 'Low - a single registry flag; the on-by-default setting is occasionally disabled for legacy client compatibility (e.g. Windows XP), so confirm no such client still enrolls against this CA before enabling.'
        KnownRisks       = 'Enabling packet-privacy enforcement will break enrollment for any client that cannot negotiate RPC_C_AUTHN_LEVEL_PKT_PRIVACY - in practice, only very old (pre-Vista-era) clients, which should not be enrolling in a modern environment regardless.'
        BackupRollback   = 'Easy - the change is a single registry value; revert with certutil -setreg CA\InterfaceFlags -IF_ENFORCEENCRYPTICERTREQUEST and restart CertSvc if something breaks.'
        OperationalNotes = ''
    }
    'CA-Wide Security Extension Disabled (ESC16)' = @{
        EstimatedEffort  = 'Low - a single registry list entry; this setting has no known legitimate ongoing use in a modern (KB5014754+) environment.'
        KnownRisks       = 'Minimal - re-enabling the extension only adds information to newly-issued certificates; it does not change any existing legitimate authentication behavior.'
        BackupRollback   = 'Easy - the change is a single registry value; re-add the OID to DisableExtensionList and restart CertSvc to restore the prior behavior if needed, with no data loss.'
        OperationalNotes = ''
    }
    'Weak Certificate Binding Compensation Enabled (ESC10)' = @{
        EstimatedEffort  = 'Medium - requires first confirming every certificate relying on the compensation window has been re-issued with strong mapping before removing the opt-out, or authentication for those certificates will break.'
        KnownRisks       = 'Removing this value before all weak-mapped certificates it was covering have been re-issued will break authentication for whatever legitimately still depends on the compensation window - confirm coverage first.'
        BackupRollback   = 'Easy - restore the prior CertificateBackdatingCompensation value if needed; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Print Spooler Running on Domain Controller' = @{
        EstimatedEffort  = 'Low - stop and disable a single service on each DC (or via GPO).'
        KnownRisks       = 'Disabling the Spooler service on a DC breaks any printing initiated directly from that DC itself, which is essentially never a legitimate DC role; it has no effect on printing by domain clients, which don''t route jobs through DCs.'
        BackupRollback   = 'Easy - re-enable and start the service; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'WebClient Service Enabled on Domain Controller' = @{
        EstimatedEffort  = 'Low - stop and disable a single service on each DC.'
        KnownRisks       = 'Disabling WebClient (WebDAV) removes WebDAV redirector functionality on the DC host itself, which is essentially never a legitimate DC use case.'
        BackupRollback   = 'Easy - re-enable and start the service; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'LDAP Signing Not Enforced on Domain Controller' = @{
        EstimatedEffort  = 'Medium - a domain/DC-wide GPO or registry setting; Microsoft''s own LDAP-signing hardening guidance recommends an audit period before enforcing.'
        KnownRisks       = 'Enforcing LDAP signing can break unsigned-LDAP clients, applications, or network appliances, a documented compatibility concern in Microsoft''s LDAP signing advisory.'
        BackupRollback   = 'Easy - revert the GPO/registry setting; effective at next policy refresh, no data loss.'
        OperationalNotes = 'Monitor Directory Service event ID 2887 (count of unsigned LDAP binds) before enforcing, per Microsoft''s own documented rollout guidance.'
    }
    'LDAP Channel Binding Not Enforced' = @{
        EstimatedEffort  = 'Medium - a domain-wide registry/GPO setting on every DC; Microsoft''s own guidance recommends a phased "when supported" rollout before enforcing, due to legacy client compatibility.'
        KnownRisks       = 'Enforcing LDAP channel binding can break LDAPS-based clients or appliances that don''t support channel binding tokens, per Microsoft''s own documented compatibility guidance.'
        BackupRollback   = 'Easy - revert the registry value/GPO setting; effective after next policy refresh/service restart, no data loss.'
        OperationalNotes = ''
    }
    'Everyone/Authenticated Users on a Control Path to Tier-0' = @{
        EstimatedEffort  = 'Medium - breaking one specific hop (a group nesting or ACE) in the chain; effort scales with how many hops and objects are involved for a given path.'
        KnownRisks       = 'Removing the identified hop could break a legitimate, if poorly documented, delegation model if the chain was set up intentionally rather than accidentally, so confirm with the object owner before removing.'
        BackupRollback   = 'Moderate - export the specific ACE or group membership being removed so it can be restored, then re-run this audit to confirm the path no longer resolves.'
        OperationalNotes = ''
    }
    'Owner of Tier-0 Object is Non-Privileged' = @{
        EstimatedEffort  = 'Low - a single ownership change on one object.'
        KnownRisks       = 'Low technical risk; object ownership implicitly carries WriteDacl-equivalent rights, so confirm no automation currently depends on the existing owner''s implicit rights before changing it.'
        BackupRollback   = 'Easy - reassign ownership back to the prior principal if needed; effective immediately.'
        OperationalNotes = ''
    }
    'User Account with Protocol Transition (T2A4D)' = @{
        EstimatedEffort  = 'Medium - a single-attribute change, but confirm whether the impersonation capability is still required before removing it; migrating to a Group Managed Service Account (as the remediation suggests) is a larger, separate project.'
        KnownRisks       = 'Protocol transition on a user account is a highly consequential but sometimes legitimate impersonation mechanism, so removing it can break the specific service still relying on it.'
        BackupRollback   = 'Easy - restore the TrustedToAuthForDelegation flag and delegation list on the account; effective at next Kerberos ticket request, no data loss.'
        OperationalNotes = ''
    }
    'User Account with Constrained Delegation' = @{
        EstimatedEffort  = 'Medium - a single-attribute change, but confirm the specific service-to-service authentication flow it supports is no longer required, or is otherwise reconfigured, before removing it.'
        KnownRisks       = 'Removing constrained delegation can break the specific service-to-service authentication flow it was configured for if still in active use.'
        BackupRollback   = 'Easy - restore the msDS-AllowedToDelegateTo attribute to its prior list of SPNs; effective at next Kerberos ticket request, no data loss.'
        OperationalNotes = ''
    }
    'Computer Account with Protocol Transition (T2A4D)' = @{
        EstimatedEffort  = 'Medium - a single-object attribute change, but confirm with the application owner (classically Exchange/IIS) whether protocol transition is still genuinely required before removing it.'
        KnownRisks       = 'Protocol transition (TrustedToAuthForDelegation) is legitimately used by some application servers to impersonate users without their credentials, so removing it can break that application''s functionality if still in use.'
        BackupRollback   = 'Easy - re-enable protocol transition and restore the msDS-AllowedToDelegateTo list on the computer object; effective at next Kerberos ticket request, no data loss.'
        OperationalNotes = ''
    }
    'Computer Account with Unconstrained Delegation' = @{
        EstimatedEffort  = 'Medium - requires discovering what the host actually delegates to and reconfiguring it with an equivalent constrained/RBCD replacement before disabling the flag, not just flipping it off.'
        KnownRisks       = 'Unconstrained delegation is one of the most consequential AD misconfigurations; disabling it without configuring an equivalent constrained/RBCD replacement first will break whatever legitimate multi-hop authentication currently depends on it.'
        BackupRollback   = 'Easy - revert the TRUSTED_FOR_DELEGATION flag; effective at next Kerberos ticket request, no data loss.'
        OperationalNotes = ''
    }
    'Resource-Based Constrained Delegation Configured' = @{
        EstimatedEffort  = 'Medium - a single-attribute change on the resource object, but confirm with the resource owner whether the delegation is an intentional, still-needed configuration.'
        KnownRisks       = 'RBCD is commonly used intentionally for modern constrained delegation without protocol transition, so removing it can break a legitimate service-to-service delegation scenario it was set up for.'
        BackupRollback   = 'Easy - restore the msDS-AllowedToActOnBehalfOfOtherIdentity attribute to its prior value; effective at next Kerberos ticket request, no data loss.'
        OperationalNotes = ''
    }
    'Non-Default Members in DnsAdmins' = @{
        EstimatedEffort  = 'Low - removing an unexpected member from one group.'
        KnownRisks       = 'DnsAdmins membership is a well-documented privilege-escalation vector (historical DNS-server-service DLL abuse); removing an unexpected member has no legitimate compatibility risk beyond that person losing DNS management rights, so confirm with them first.'
        BackupRollback   = 'Easy - re-add the member if needed; effective on next Kerberos ticket refresh, no data loss.'
        OperationalNotes = ''
    }
    'DNS Zone Transfer Allowed' = @{
        EstimatedEffort  = 'Low - restricting zone transfer to specific secondary server IPs is a single zone property.'
        KnownRisks       = 'Restricting zone transfer will break any legitimate secondary DNS server that currently relies on unrestricted transfer, so confirm the authorized secondary list first.'
        BackupRollback   = 'Easy - revert to the prior zone-transfer setting; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Insecure Dynamic DNS Updates Enabled' = @{
        EstimatedEffort  = 'Medium - switching to secure-only dynamic updates requires the zone to already be AD-integrated, and breaks self-registration for any non-domain-joined device currently updating its own record.'
        KnownRisks       = 'Switching to secure-only updates will break dynamic registration from any non-Windows or non-domain-joined device that currently self-registers (some Linux/IoT/appliance DHCP-DNS integrations), a documented Microsoft behavior.'
        BackupRollback   = 'Easy - revert the zone''s dynamic-update setting; effective immediately, no data loss to existing records.'
        OperationalNotes = ''
    }
    'Authenticated Users Can Create Child Objects in DNS Zone' = @{
        EstimatedEffort  = 'Medium - removing the broad create-child ACE and confirming no legitimate dynamic-update workflow depends on it, since this is actually the AD-integrated DNS zone''s default ACL for supporting computer self-registration.'
        KnownRisks       = 'This permission is the default AD-integrated DNS zone ACL that lets domain-joined computers dynamically register their own DNS records; removing it broadly can break legitimate machine self-registration unless replaced with a Secure-only dynamic update model plus targeted exceptions.'
        BackupRollback   = 'Moderate - export the zone''s current ACL first (dnscmd or Get-Acl on the zone''s AD object) and reapply if self-registration breaks; changes follow normal AD/DNS replication.'
        OperationalNotes = ''
    }
    'Stale/Dangling DNS Zone Delegation' = @{
        EstimatedEffort  = 'Low - removing a delegation (NS/glue) record pointing at a decommissioned name server.'
        KnownRisks       = 'A dangling delegation is itself a documented subdomain-takeover risk (an attacker registering the abandoned target can serve authoritative answers for that subdomain), so removing it eliminates a real exposure rather than introducing one.'
        BackupRollback   = 'Easy - re-create the delegation record if the name server is later reinstated; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'AdminSDHolder Ghost Account' = @{
        EstimatedEffort  = 'Low - a single adminCount reset plus re-enabling inheritance on one object.'
        KnownRisks       = 'Low technical risk; confirm the account isn''t intentionally protected for an undocumented but legitimate reason (e.g. a break-glass account) before clearing adminCount.'
        BackupRollback   = 'Easy - reset adminCount to 1 and disable inheritance again if needed; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Shadow Credentials Detected' = @{
        EstimatedEffort  = 'Low - clearing the msDS-KeyCredentialLink attribute is a single-attribute change on one object.'
        KnownRisks       = 'Removing an unauthorized key credential has no legitimate compatibility impact unless it is actually a currently-enrolled Windows Hello for Business or passwordless-auth key, so confirm the key isn''t legitimate before clearing.'
        BackupRollback   = 'Moderate - export the current msDS-KeyCredentialLink value before clearing so a legitimate key can be restored if the removal turns out to affect a real passwordless sign-in.'
        OperationalNotes = ''
    }
    'Weak Explicit Certificate Mapping on Privileged Account (ESC14)' = @{
        EstimatedEffort  = 'Medium - requires identifying the specific certificate this mapping should be bound to and updating altSecurityIdentities accordingly, coordinated with whoever manages the account''s smart card/certificate.'
        KnownRisks       = 'Replacing the mapping incorrectly (wrong SKI/key hash) will break this account''s certificate-based authentication until corrected - verify the target certificate before changing.'
        BackupRollback   = 'Easy - restore the prior altSecurityIdentities value if needed; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'SID History Injection (Same Domain)' = @{
        EstimatedEffort  = 'High - this is an active-compromise indicator, not a configuration fix; it requires incident-response engagement, forensic investigation, and likely a KRBTGT password reset (twice) if a Golden Ticket is suspected, not a single change.'
        KnownRisks       = 'Resetting the account or clearing sIDHistory while an attacker may still have persistence elsewhere (forged tickets, other backdoors) can tip them off without fully evicting them, so this needs IR judgment, not just a config change.'
        BackupRollback   = 'Hard/Limited - this isn''t a reversible setting; it''s an incident-response action (reset/disable the account and investigate origin) with no rollback concept.'
        OperationalNotes = 'Engage incident response before making changes if compromise is suspected, since a same-domain sIDHistory entry is a well-documented Golden Ticket/injection indicator rather than a misconfiguration.'
    }
    'Privileged SID in History' = @{
        EstimatedEffort  = 'Medium - clearing sIDHistory is simple technically, but confirming the account isn''t an active cross-domain migration in progress requires checking with whoever ran the migration.'
        KnownRisks       = 'If a domain migration is still underway, clearing sIDHistory before every migrated resource''s ACL has been updated to the new SID can break the migrated user''s access to resources that still only trust the old SID.'
        BackupRollback   = 'Hard/Limited - sIDHistory can''t be restored to its prior value without re-injecting it via the same migration tooling (e.g. ADMT) that originally populated it; treat clearing it as a one-way cleanup once confirmed unauthorized.'
        OperationalNotes = ''
    }
    'SID History Attribute Populated' = @{
        EstimatedEffort  = 'Low - clearing sIDHistory is a single-attribute change once a completed migration is confirmed.'
        KnownRisks       = 'Clearing sIDHistory before every migrated resource''s ACL has been updated to the new SID breaks the account''s access to resources that still only trust the old SID - confirm migration completion first.'
        BackupRollback   = 'Hard/Limited - sIDHistory can''t be restored without re-injecting it via the same migration tooling (e.g. ADMT) that originally populated it.'
        OperationalNotes = ''
    }
    'Legacy Logon Script Defined' = @{
        EstimatedEffort  = 'Low - a single scriptPath/userWorkstations-style attribute per account.'
        KnownRisks       = 'Removing or migrating a working legacy logon script could break whatever the script does for affected users until an equivalent modern (GPO-based) replacement is validated.'
        BackupRollback   = 'Easy - restore the scriptPath attribute to its prior value; effective at next logon, no data loss.'
        OperationalNotes = ''
    }
    'AdminSDHolder ACL Compromise' = @{
        EstimatedEffort  = 'Low - removing a single unauthorized ACE from one object (AdminSDHolder); SDProp then reapplies the corrected ACL to every protected object automatically.'
        KnownRisks       = 'Low technical risk; an unauthorized ACE here grants no legitimate capability, so removing it has no realistic compatibility impact beyond confirming it isn''t a very recent, still-being-configured delegation.'
        BackupRollback   = 'Moderate - export the current AdminSDHolder ACL (dsacls or Get-Acl) before removing the ACE so it can be restored if needed; the correction only reaches every protected Tier-0 object once SDProp''s next propagation cycle runs, not instantly.'
        OperationalNotes = 'SDProp runs on a periodic interval (roughly hourly by default), so previously-protected objects keep the old, compromised ACL until the next cycle completes.'
    }
    'Domain Admin Equivalent Access Detected' = @{
        EstimatedEffort  = 'High - the underlying access is typically composed of multiple pieces of evidence (nested groups, ACEs, ownership), each of which may need a separate fix, similar to breaking a control-path chain.'
        KnownRisks       = 'Removing any single contributing factor could break a legitimate, if undocumented, delegation if it was set up intentionally, so confirm with the principal''s owning team before changing each piece of evidence.'
        BackupRollback   = 'Moderate - export/record each ACE or membership being changed before removing it, then re-run the audit to confirm the effective access is gone.'
        OperationalNotes = ''
    }
    'Dangerous dsHeuristics Flag Set' = @{
        EstimatedEffort  = 'Low - a single attribute change on one forest-wide object.'
        KnownRisks       = 'Low risk resetting to the default, unless the specific bit was intentionally set for a documented reason (e.g. relaxed list-object mode); confirm before resetting.'
        BackupRollback   = 'Easy - revert to the previous dsHeuristics string value; effective forest-wide on next replication, no data loss.'
        OperationalNotes = ''
    }
    'Broad Membership in Pre-Windows 2000 Compatible Access' = @{
        EstimatedEffort  = 'Medium - removing Authenticated Users/Everyone from this legacy compatibility group; confirm no genuinely legacy (pre-Windows 2000 era) system still depends on it.'
        KnownRisks       = 'The group was created specifically for NT4/pre-Windows-2000 compatibility and grants read access to many user/group attributes to anyone in it; removing broad membership is safe in virtually all modern environments, but confirm no true legacy system remains.'
        BackupRollback   = 'Easy - re-add the removed principal if needed; effective on next Kerberos ticket refresh, no data loss.'
        OperationalNotes = ''
    }
    'Anonymous LDAP / RootDSE Binding Permitted' = @{
        EstimatedEffort  = 'Medium - disabling anonymous LDAP bind requires confirming no legacy or third-party application relies on anonymous read access first.'
        KnownRisks       = 'Some legacy or third-party applications (older Unix LDAP clients, network appliances) query AD anonymously for RootDSE/schema info or basic lookups and will break once anonymous bind is disabled.'
        BackupRollback   = 'Easy - revert the dsHeuristics anonymous-bind bit (or equivalent registry/GPO setting) to its prior value; effective at next LDAP bind attempt, no data loss.'
        OperationalNotes = ''
    }
    'Null-Session Pipe/Share Access Permitted' = @{
        EstimatedEffort  = 'Medium - restricting NullSessionPipes/NullSessionShares across every DC; confirm no legacy trust relationship or very old third-party tool relies on anonymous IPC$/named-pipe access.'
        KnownRisks       = 'Removing null-session access can break very old applications or trust setups that rely on anonymous IPC$ or named-pipe access, though this is rare in modern environments.'
        BackupRollback   = 'Easy - restore the prior registry/GPO values; effective at next policy refresh/service restart.'
        OperationalNotes = ''
    }
    'Weak Minimum Password Length' = @{
        EstimatedEffort  = 'Medium - a Default Domain Policy GPO change affecting every future password change; needs a short monitoring window as users adjust.'
        KnownRisks       = 'Minimal technical risk; may increase helpdesk load and require re-training users with short passwords, since the new minimum only applies at each account''s next password change.'
        BackupRollback   = 'Easy - revert the GPO value; effective at next Group Policy refresh, no data loss, not retroactive.'
        OperationalNotes = ''
    }
    'Password Complexity Disabled' = @{
        EstimatedEffort  = 'Medium - a Default Domain Policy GPO change affecting every future password change; needs a short monitoring window as users adjust.'
        KnownRisks       = 'Enforcing complexity starts rejecting non-compliant password changes going forward and may increase helpdesk password-reset volume, a documented operational side effect rather than a technical break.'
        BackupRollback   = 'Easy - revert the GPO setting; effective at next Group Policy refresh, no data loss, and not retroactive to existing passwords.'
        OperationalNotes = ''
    }
    'Reversible Encryption Enabled Domain-Wide' = @{
        EstimatedEffort  = 'Medium - disabling the setting alone doesn''t clear already-stored reversibly-encrypted password copies for existing accounts, so plan a follow-up forced password change for previously affected accounts.'
        KnownRisks       = 'The existing stored reversible-encryption copy persists for each account until its next password change, so disabling the GPO setting alone doesn''t retroactively protect current passwords, a documented Microsoft behavior.'
        BackupRollback   = 'Easy - revert the GPO setting; no data loss, though re-enabling doesn''t restore already-cleared reversible copies.'
        OperationalNotes = ''
    }
    'Account Lockout Disabled' = @{
        EstimatedEffort  = 'Medium - a Default Domain Policy GPO change; confirm any legitimate break-glass/service accounts that must never lock out are covered by a separate Fine-Grained Password Policy first, since this change applies domain-wide.'
        KnownRisks       = 'Enabling lockout can itself become a denial-of-service vector if an attacker deliberately fails logons for a target account to lock it out - a documented trade-off, not a reason to leave lockout disabled entirely.'
        BackupRollback   = 'Easy - revert the GPO setting; effective at next Group Policy refresh, no data loss.'
        OperationalNotes = ''
    }
    'Account Lockout Threshold Above Recommended Maximum' = @{
        EstimatedEffort  = 'Low - a single Default Domain Policy GPO value change.'
        KnownRisks       = 'Lowering the threshold increases the chance a legitimate user locks themselves out after a few genuine mistyped passwords, which may increase helpdesk password-reset/unlock volume.'
        BackupRollback   = 'Easy - revert the GPO setting; effective at next Group Policy refresh, no data loss.'
        OperationalNotes = ''
    }
    'Outdated Domain Functional Level' = @{
        EstimatedEffort  = 'High - every DC in the domain must already be at or above the target OS level before the raise succeeds, requiring a domain-wide inventory and sign-off before proceeding.'
        KnownRisks       = 'Low technical risk from the raise itself; the main risk is procedural - confirm no down-level DCs remain, and that domain-functional-level-gated features (e.g. Protected Users, Kerberos armoring/FAST support) aren''t silently unavailable at the current level.'
        BackupRollback   = 'Hard/Limited - like forest functional level, a raised domain functional level is designed not to be rolled back once every DC has adopted it; treat the raise as a one-way step.'
        OperationalNotes = ''
    }
    'Outdated Forest Functional Level' = @{
        EstimatedEffort  = 'High - every DC in every domain of the forest must already be running the target Windows Server version before the raise will succeed, so this needs a forest-wide inventory and sign-off from every domain admin, not just the forest root.'
        KnownRisks       = 'Low technical risk to clients or applications from the raise itself; the main risk is procedural - a raised forest functional level cannot be cleanly undone, so confirm no domain still has down-level DCs and that no AD-integrated product (e.g. Exchange) pins to the current level before proceeding.'
        BackupRollback   = 'Hard/Limited - per Microsoft documentation a forest functional level generally cannot be lowered once raised, with one narrow exception (Windows Server 2012 down to 2008 R2, only if the AD Recycle Bin has not been enabled); there is no attribute-level export or standard AD backup mechanism that undoes this change.'
        OperationalNotes = 'Raising the forest functional level does not raise domain functional levels, which are configured and must be raised separately if the goal is also to unlock domain-level features.'
    }
    'Domain Functional Level Could Be Raised' = @{
        EstimatedEffort  = 'High - every DC in the domain must already be running Windows Server 2025 before the raise succeeds, requiring a domain-wide OS upgrade/replacement project, not just a configuration change.'
        KnownRisks       = 'Low technical risk from the raise itself once every DC is eligible; the real cost is the DC OS upgrade project that has to happen first, not the functional-level change.'
        BackupRollback   = 'Hard/Limited - like other functional-level raises, this is designed as a one-way step once every DC has adopted it (per current Microsoft guidance a same-or-newer-generation rollback is possible under narrow conditions, but treat it as effectively permanent for planning purposes).'
        OperationalNotes = ''
    }
    'Forest Functional Level Could Be Raised' = @{
        EstimatedEffort  = 'High - every DC in every domain of the forest must already be running Windows Server 2025 before the raise will succeed, so this needs a forest-wide OS upgrade project and sign-off from every domain admin, not just the forest root.'
        KnownRisks       = 'Low technical risk to clients or applications from the raise itself; the real cost is the forest-wide DC OS upgrade project that has to happen first.'
        BackupRollback   = 'Hard/Limited - treat as effectively permanent for planning purposes, same as other forest functional level raises.'
        OperationalNotes = 'Raising the forest functional level does not raise domain functional levels on its own unless every DC in every domain is already running Windows Server 2025 (in which case Microsoft raises all domain levels automatically); otherwise each domain must still be raised separately.'
    }
    'Short Tombstone Lifetime' = @{
        EstimatedEffort  = 'Low - a single attribute change on one forest-wide object, reversible immediately, with no maintenance window needed.'
        KnownRisks       = 'Low technical risk; lengthening the value only extends the object-recovery and backup-usability window going forward and does not affect current authentication, replication, or application behavior.'
        BackupRollback   = 'Easy - revert tombstoneLifetime to its prior value with the same Set-ADObject command; takes effect as the change replicates, with no data-loss risk since increasing the value only lengthens, never shortens, the existing recovery window.'
        OperationalNotes = ''
    }
    'AD Recycle Bin Not Enabled' = @{
        EstimatedEffort  = 'Low - a single Enable-ADOptionalFeature command, one-time, no maintenance window.'
        KnownRisks       = 'Enabling AD Recycle Bin immediately converts every existing tombstoned object in the forest into the Recycle Bin''s deleted-object model - a documented one-time side effect, not a functional access risk.'
        BackupRollback   = 'Hard/Limited - per Microsoft documentation, AD Recycle Bin cannot be disabled once enabled; there is no toggle-back, only a full forest recovery, which is not a practical rollback option.'
        OperationalNotes = ''
    }
    'Legacy Operating Systems in Domain' = @{
        EstimatedEffort  = 'High - decommissioning or upgrading legacy-OS systems is an environment-wide project requiring an application-dependency inventory and phased migration, not a single change.'
        KnownRisks       = 'Decommissioning or isolating a legacy-OS system can break any application still tied to it (e.g. an old line-of-business app that only runs on that OS), so this needs a dependency inventory first.'
        BackupRollback   = 'Hard/Limited - upgrading or decommissioning a legacy host is generally a one-way project; where feasible, take a full backup or VM snapshot of the host before changing it as the practical safety net.'
        OperationalNotes = ''
    }
    'Stale AzureADSSOACC Kerberos Key' = @{
        EstimatedEffort  = 'Low - a single documented cmdlet (Update-AzureADSSOForest / Azure AD Connect) rolls the key over.'
        KnownRisks       = 'Rolling the Seamless SSO Kerberos key briefly invalidates in-flight SSO tickets for that mechanism, so users may need to re-authenticate once during the rollover, a documented Microsoft behavior rather than an outage.'
        BackupRollback   = 'Easy - the key can be rolled over again at any time via the same cmdlet; no data loss, and Microsoft''s own guidance is to roll it over regularly regardless.'
        OperationalNotes = ''
    }
    'Bidirectional Domain Trust' = @{
        EstimatedEffort  = 'High - narrowing a bidirectional trust to one-way is a structural, cross-forest/cross-domain decision requiring sign-off from the other domain''s owners and a dependency discovery of which direction of access is actually used.'
        KnownRisks       = 'Narrowing to one-way removes the ability for principals on the now-untrusted side to authenticate to resources on the other side, so a dependency check with the other domain''s owners is required before narrowing, not just a local change.'
        BackupRollback   = 'Moderate - trust direction can be reconfigured back to bidirectional via Active Directory Domains and Trusts (or netdom) at any time, effective quickly with no data loss, but requires the same cross-domain admin coordination to make the change again.'
        OperationalNotes = ''
    }
    'SID Filtering Disabled on External Trust' = @{
        EstimatedEffort  = 'Low - a single trust property toggle.'
        KnownRisks       = 'SID filtering blocks SID-history-based authorization across the trust, so if the other domain legitimately relies on SID history for migrated accounts to retain access, enabling filtering can break that access; confirm no active migration depends on it.'
        BackupRollback   = 'Easy - toggle SID filtering back off; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Forest Trust Without Selective Authentication' = @{
        EstimatedEffort  = 'Medium - enabling selective authentication requires then explicitly granting "Allowed to Authenticate" rights to every resource/group that legitimately needs cross-forest access, so plan a discovery pass of existing cross-forest access first.'
        KnownRisks       = 'Enabling selective authentication immediately blocks all cross-forest authentication except where an explicit Allowed-to-Authenticate ACE has been granted, so existing legitimate cross-forest access will break until those ACEs are added.'
        BackupRollback   = 'Easy - toggle selective authentication back off via Domains and Trusts; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Trust Password Not Recently Rotated' = @{
        EstimatedEffort  = 'Low - a single reset command per trust.'
        KnownRisks       = 'Resetting the trust password briefly interrupts the secure channel until both sides sync, so schedule it during a low-authentication-volume window; a mismatched reset (only one side updated) can break the trust until corrected, a documented Netlogon secure-channel behavior.'
        BackupRollback   = 'Easy - the secure channel can be re-reset on both sides if an issue arises; no data loss beyond a brief authentication interruption.'
        OperationalNotes = ''
    }
    'Exchange Group Holds WriteDACL on Domain Object' = @{
        EstimatedEffort  = 'Medium - removing this legacy right requires confirming the current Exchange version/CU no longer needs it and coordinating with the Exchange admin team.'
        KnownRisks       = 'Some Exchange functionality - particularly on older CUs that still expect this legacy permission model - can break if the right is removed while an in-place Exchange server still depends on it; confirm current CU-level guidance before removing.'
        BackupRollback   = 'Moderate - export the domain object''s ACL before removing the ACE so it can be restored if Exchange functionality is affected; changes follow normal AD replication.'
        OperationalNotes = ''
    }
    'Exchange-Related AdminSDHolder ACE' = @{
        EstimatedEffort  = 'Medium - a single-object ACE removal, but coordinate with the Exchange admin team to confirm the current Exchange version doesn''t still rely on it.'
        KnownRisks       = 'Removing an Exchange-related AdminSDHolder ACE that a currently-installed Exchange version still expects could break Exchange''s ability to manage protected mail-enabled accounts.'
        BackupRollback   = 'Moderate - export the AdminSDHolder ACL before removing the ACE; the correction only reaches every protected object after SDProp''s next propagation cycle.'
        OperationalNotes = ''
    }
    'Over-Permissioned GPO' = @{
        EstimatedEffort  = 'Medium - removing a non-standard Edit/FullControl right from one GPO; confirm the trustee isn''t a legitimate delegated owner.'
        KnownRisks       = 'Procedural - confirm the trustee isn''t an active, legitimate delegated GPO administrator before removing their rights.'
        BackupRollback   = 'Easy - restore the GPO permission via GPMC; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'GPO Linked to Domain Controllers with Weak Permissions' = @{
        EstimatedEffort  = 'Medium - removing a non-standard Edit/Write right from the GPO object itself; confirm the trustee isn''t a legitimate delegated GPO-management account.'
        KnownRisks       = 'Procedural - confirm the trustee isn''t a legitimate delegated GPO administrator for that specific GPO before removing their rights.'
        BackupRollback   = 'Easy - restore the GPO permission via GPMC; effective immediately, though the change still needs to replicate to all DCs.'
        OperationalNotes = ''
    }
    'Non-Standard GPO Owner' = @{
        EstimatedEffort  = 'Low - a single ownership change on one GPO object; confirm the current owner isn''t an intentional, actively-used delegated GPO-management account first.'
        KnownRisks       = 'Procedural - confirm the current owner isn''t a legitimate delegated GPO administrator for this specific GPO before changing ownership.'
        BackupRollback   = 'Easy - ownership can be changed back to the prior value at any time by an administrator; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Unlinked GPO' = @{
        EstimatedEffort  = 'Low - this is a hygiene finding; typical remediation is to delete the unused GPO or formally document/retain it.'
        KnownRisks       = 'Deleting an unlinked GPO is safe in the sense that it isn''t currently applied anywhere, but if it''s only temporarily unlinked (e.g. staged for a future rollout), deleting it loses that work - confirm with whoever created it first.'
        BackupRollback   = 'Moderate - back up the GPO with Backup-GPO before deleting so it can be restored with Restore-GPO if needed.'
        OperationalNotes = ''
    }
    'Insecure SYSVOL Permissions' = @{
        EstimatedEffort  = 'Medium - correcting ACLs on SYSVOL/NETLOGON shares (and their filesystem equivalents) on every DC, then validating legitimate scripts/GPOs still function for all clients.'
        KnownRisks       = 'Over-tightening SYSVOL permissions can break clients'' ability to read GPOs or logon scripts if a legitimate group loses access it was relying on; validate with a domain-wide policy refresh test after the change.'
        BackupRollback   = 'Moderate - export the current SYSVOL share/NTFS ACL (icacls or Get-Acl) before changing it, and allow for DFSR/FRS replication across all DCs before the change is fully in effect.'
        OperationalNotes = ''
    }
    'GPP cpassword Found in SYSVOL' = @{
        EstimatedEffort  = 'Medium - the embedded account''s password must be rotated everywhere it''s used (it''s already fully compromised) and the GPP item removed or recreated without cpassword.'
        KnownRisks       = 'The embedded password is trivially decryptable by any authenticated user, since Microsoft publicly released the AES key used for GPP cpassword encryption after MS14-025 - treat it as already fully compromised and rotate the account''s password before or immediately after removing the GPP item.'
        BackupRollback   = 'Hard/Limited - like the logon-script credential finding, this isn''t a reversible setting; the exposure already happened and the credential must be rotated, not restored.'
        OperationalNotes = ''
    }
    'Credentials Referenced in Logon/Startup Script' = @{
        EstimatedEffort  = 'High - the exposed credential must be rotated everywhere it''s used, and the script reworked to avoid embedding credentials (e.g. migrating to a gMSA), which may involve other teams if the account is shared.'
        KnownRisks       = 'The credential must be treated as already compromised, since any authenticated user can read SYSVOL; rotating it needs to be coordinated with everything else that uses the same account/password.'
        BackupRollback   = 'Hard/Limited - this isn''t a reversible setting; once a credential has been exposed via SYSVOL it must be rotated, not restored, and the exposure history can''t be undone.'
        OperationalNotes = ''
    }
    'Insecure Setting Deployed via GPO' = @{
        EstimatedEffort  = 'Medium - a single GPO setting change; confirm no application depends on the weaker current setting before tightening it.'
        KnownRisks       = 'Depends on the specific setting; generically, confirm no application or workflow relies on the current, weaker behavior before changing it.'
        BackupRollback   = 'Easy - revert the specific GPO setting; effective at next Group Policy refresh, no data loss.'
        OperationalNotes = ''
    }
    'GPO Grants Sensitive Logon Right to Broad Principal' = @{
        EstimatedEffort  = 'Medium - removing a broad principal from a User Rights Assignment in one GPO; confirm no legitimate broad-access scenario (e.g. an intentional kiosk deployment) depends on it.'
        KnownRisks       = 'Removing a broad principal from a sensitive logon right can lock out any system or service that currently relies on that broad grant, so confirm intent before narrowing.'
        BackupRollback   = 'Easy - revert the User Rights Assignment setting in the GPO; effective at next Group Policy refresh, no data loss.'
        OperationalNotes = ''
    }
    'GPO Deploys Restricted Groups Membership' = @{
        EstimatedEffort  = 'Medium - editing the Restricted Groups membership list in one GPO; confirm with the owning team which members are actually still needed before removing any.'
        KnownRisks       = 'Removing a member that legitimately needs local admin/RDP/backup rights on the affected computers will revoke that access at the next Group Policy refresh - confirm current legitimate use before narrowing.'
        BackupRollback   = 'Easy - restore the prior Restricted Groups membership list in the GPO; effective at next Group Policy refresh, no data loss.'
        OperationalNotes = ''
    }
    'Cross-Domain Privileged Group Membership' = @{
        EstimatedEffort  = 'Medium - removing a foreign-domain principal from a local privileged group; confirm with the other domain''s admins it isn''t an intentional, documented cross-domain admin delegation before removing.'
        KnownRisks       = 'Procedural - confirm with the other domain''s admins that the membership isn''t an intentional cross-domain delegation before removing, since doing so revokes that principal''s privileged access entirely.'
        BackupRollback   = 'Easy - re-add the principal to the group if needed; effective on next Kerberos ticket refresh, no data loss.'
        OperationalNotes = ''
    }
    'Excessive Privileged Group Membership' = @{
        EstimatedEffort  = 'Medium - requires reviewing each member for actual ongoing need rather than a single mechanical change, and coordinating with each member or their manager.'
        KnownRisks       = 'Removing a member who still has a legitimate ongoing need for privileged access will break their ability to perform that work until re-added, so this needs a per-member justification review, not a blanket removal.'
        BackupRollback   = 'Easy - re-add any member whose access need is confirmed; effective on next Kerberos ticket refresh, no data loss.'
        OperationalNotes = ''
    }
    'Nested Groups in Critical Privileged Group' = @{
        EstimatedEffort  = 'Medium - un-nesting a group from a Tier-0 group can silently revoke access for every member of the nested group, so first enumerate who''s actually inside it.'
        KnownRisks       = 'Because nested group membership is often not obvious in a quick review, un-nesting can unexpectedly revoke privileged access from many users at once if the nested group''s full membership wasn''t understood beforehand.'
        BackupRollback   = 'Easy - re-add the nested group as a member if needed; effective on next Kerberos ticket refresh, no data loss.'
        OperationalNotes = ''
    }
    'Disabled User in Privileged Group' = @{
        EstimatedEffort  = 'Low - removing one already-disabled account from one group.'
        KnownRisks       = 'Essentially none - the account is already disabled and cannot authenticate, so removing its group membership has no functional impact; confirm it isn''t an intentionally disabled-but-provisioned break-glass account first.'
        BackupRollback   = 'Easy - re-add if needed; effective immediately, no functional impact either way since the account is disabled.'
        OperationalNotes = ''
    }
    'RC4 Kerberos Encryption Still Permitted' = @{
        EstimatedEffort  = 'Medium - touches multiple privileged/service accounts and cross-realm trust configuration, and needs a short monitoring window before disabling RC4 domain-wide.'
        KnownRisks       = 'Authentication may break for clients, applications, or devices that cannot negotiate AES - commonly legacy non-Windows Kerberos clients, appliances/printers with RC4-only libraries, or older applications with hardcoded RC4 configs.'
        BackupRollback   = 'Easy - re-enable RC4 via msDS-SupportedEncryptionTypes/GPO; takes effect at next Kerberos ticket renewal/GPO refresh with no data loss.'
        OperationalNotes = 'Enable AES on accounts first and monitor for RC4-ticket issuance in DC logs before enforcing AES-only, so any remaining RC4-dependent client shows up before it''s cut off.'
    }
    'Kerberos Armoring (FAST) Not Enabled' = @{
        EstimatedEffort  = 'Medium - enabling requires the domain functional level and all clients to support FAST (Windows 8/Server 2012 R2+); Microsoft''s own guidance recommends a staged "Supported" rollout before "Always provide claims" enforcement.'
        KnownRisks       = 'Enforcing Kerberos armoring will break authentication for any client that doesn''t support FAST - older Windows versions and many non-Windows Kerberos implementations - so a "Supported" (not yet enforced) first step is Microsoft''s own documented recommendation.'
        BackupRollback   = 'Easy - revert the GPO setting to Not Defined/Supported; effective at next Group Policy refresh and Kerberos ticket renewal, no data loss.'
        OperationalNotes = ''
    }
    'Cross-Trust TGT Delegation Enabled' = @{
        EstimatedEffort  = 'Medium - disabling this trust attribute requires confirming no legitimate application performs Kerberos delegation across that trust boundary (e.g. a multi-forest SharePoint/SQL double-hop scenario).'
        KnownRisks       = 'Disabling cross-trust TGT delegation can break any application that legitimately performs Kerberos delegation across that trust boundary.'
        BackupRollback   = 'Moderate - trust attributes can be reconfigured back via netdom/PowerShell, but requires coordination with the other domain/forest''s admins to re-verify, like any other trust property change.'
        OperationalNotes = ''
    }
    'BadSuccessor / dMSA Escalation Exposure' = @{
        EstimatedEffort  = 'High - requires both patching every affected Server 2025 DC to the fixed build and, independently of patch level, an OU/dMSA-object permissions review across the environment (per Microsoft/Akamai guidance, the patch alone doesn''t restrict who can create or link a dMSA).'
        KnownRisks       = 'Independent Akamai research confirmed that even on a fully patched DC, a dMSA an attacker controls can still be paired with a target account the attacker also controls to extract that target''s credentials, so patching alone does not fully close the exposure - the permissions review is a genuine, separate, needed step, not padding.'
        BackupRollback   = 'Easy - the patch itself is a normal cumulative update with standard rollback options; the permissions tightening (restricting CreateChild/msDS-DelegatedManagedServiceAccount rights) can be reverted by re-granting the prior delegation if needed.'
        OperationalNotes = 'Enable auditing on dMSA creation and migration-link attribute changes (both the dMSA''s link and the superseded account''s link), per Akamai''s own detection guidance, since the technique remains relevant even after patching.'
    }
    'KRBTGT Password Age Exceeds Recommended Threshold' = @{
        EstimatedEffort  = 'Medium - a KRBTGT reset needs to be done twice, roughly a replication cycle apart, to fully invalidate old tickets - this is a documented, deliberate two-step process, not a single trivial change.'
        KnownRisks       = 'Resetting KRBTGT invalidates existing Kerberos tickets domain-wide once fully replicated; doing both resets in quick succession without allowing replication between them is the well-documented way to cause a temporary authentication disruption, so pace them one replication cycle apart.'
        BackupRollback   = 'Hard/Limited - a password reset cannot be undone to the old value, only reset again; if issues arise, the fix is to complete the second reset and let replication converge, not to revert.'
        OperationalNotes = ''
    }
    'KRBTGT Password Approaching Rotation Threshold' = @{
        EstimatedEffort  = 'Low - a routine, scheduled reset (or paced double reset) following Microsoft''s standard rotation cadence, timed for a low-usage window rather than reactive to an incident.'
        KnownRisks       = 'Same ticket-invalidation risk as an overdue rotation, but being proactive/scheduled reduces disruption since it can be timed for a low-usage window.'
        BackupRollback   = 'Hard/Limited - a password reset cannot be undone to the old value, only reset again.'
        OperationalNotes = ''
    }
    'KRBTGT Password Last Set Date Unknown' = @{
        EstimatedEffort  = 'Low - primarily an investigation into why the date is unreadable; if the password does turn out to be genuinely stale, treat it like the age-exceeded finding above.'
        KnownRisks       = 'Same ticket-invalidation risk as an overdue rotation once a reset is actually performed.'
        BackupRollback   = 'Hard/Limited - once reset, the password cannot be restored to a prior value.'
        OperationalNotes = 'Investigate why pwdLastSet is unreadable (a permissions or replication issue) before assuming the password is actually stale.'
    }
    'LAPS Not Deployed' = @{
        EstimatedEffort  = 'High - full deployment requires a one-time forest-wide schema extension, GPO creation, delegated read-rights setup, and a phased client/CSE rollout with a validation period - an environment-wide project, not a single change.'
        KnownRisks       = 'Low ongoing technical risk to normal operations; the one-time schema extension step is itself an irreversible forest-wide schema change, so test/confirm it in a non-production domain first if possible.'
        BackupRollback   = 'Hard/Limited - the schema extension itself can''t be undone (attributes are marked defunct, not removed, consistent with schema changes generally); the GPO/policy rollout portion, however, can be unlinked or removed cleanly at any time.'
        OperationalNotes = ''
    }
    'Incomplete LAPS Coverage' = @{
        EstimatedEffort  = 'Medium - extending the LAPS GPO/CSE to additional OUs or computers, and validating the schema attributes and client/CSE are present on the newly covered machines.'
        KnownRisks       = 'Low technical risk deploying LAPS more broadly; the main risk is procedural - confirm target computers are already schema-extended and have the LAPS client installed before expecting the GPO to take effect.'
        BackupRollback   = 'Easy - remove the GPO link/scope for the newly covered OUs if needed; LAPS-managed passwords already set remain valid, no data loss.'
        OperationalNotes = ''
    }
    'Expired LAPS Passwords' = @{
        EstimatedEffort  = 'Low - LAPS rotates each computer''s password on its own schedule; an expired password typically self-corrects at the next rotation unless something is blocking it.'
        KnownRisks       = 'Low risk; forcing an immediate rotation on affected computers just changes the local admin password, with no compatibility impact beyond any manual process needing to fetch the new password from AD afterward.'
        BackupRollback   = 'Easy - LAPS keeps rotating on its own; there is no rollback needed, since a new randomly generated password is the intended end state.'
        OperationalNotes = ''
    }
    'SMBv1 Enabled / Not Disabled by Policy' = @{
        EstimatedEffort  = 'Medium - disabling SMBv1 requires confirming no legacy device (old NAS, printer, embedded scanner, very old OS) still requires it, since this is a widely documented historical dependency.'
        KnownRisks       = 'Many legacy or embedded devices (older printers/scanners/NAS, very old Windows/Samba versions) only support SMBv1 and will lose file/print connectivity once it''s disabled.'
        BackupRollback   = 'Easy - re-enable the SMBv1 feature/GPO setting; effective after a restart/policy refresh, no data loss.'
        OperationalNotes = ''
    }
    'SMB Signing Not Required' = @{
        EstimatedEffort  = 'Medium - requiring SMB signing domain/DC-wide can affect performance and legacy client compatibility, so validate with a monitoring window per Microsoft''s own guidance.'
        KnownRisks       = 'Requiring SMB signing adds CPU overhead per SMB packet and can break or slow legacy SMB clients or devices that don''t support it.'
        BackupRollback   = 'Easy - revert the GPO setting; effective at next Group Policy refresh, no data loss.'
        OperationalNotes = ''
    }
    'LM/NTLMv1 Authentication Permitted' = @{
        EstimatedEffort  = 'Medium - raising the LAN Manager authentication level domain-wide can break very old clients/devices, so audit NTLM usage first, per Microsoft''s own documented audit-before-enforce guidance.'
        KnownRisks       = 'Enforcing NTLMv2-only will break authentication for legacy devices or applications that only support LM or NTLMv1 (older network appliances, some legacy SMB/CIFS-based systems).'
        BackupRollback   = 'Easy - revert the LAN Manager authentication level GPO setting; effective at next Group Policy refresh, no data loss.'
        OperationalNotes = ''
    }
    'LLMNR Not Disabled by Policy' = @{
        EstimatedEffort  = 'Low - a single GPO setting (Turn Off Multicast Name Resolution) applied domain-wide.'
        KnownRisks       = 'Disabling LLMNR removes a fallback name-resolution mechanism used when DNS fails to resolve a name, so environments with intermittent DNS issues could see minor resolution failures surface that LLMNR was previously masking.'
        BackupRollback   = 'Easy - revert the GPO setting; effective at next Group Policy refresh, no data loss.'
        OperationalNotes = ''
    }
    'WSUS Delivered over HTTP' = @{
        EstimatedEffort  = 'Medium - converting WSUS to HTTPS requires a certificate, an IIS binding change, and reconfiguring every client''s WSUS GPO to the new URL, a coordinated multi-step change across the fleet.'
        KnownRisks       = 'A botched certificate or binding change can temporarily break update delivery to every client pointed at that WSUS server until corrected; switching to HTTPS itself carries no other legitimate compatibility risk.'
        BackupRollback   = 'Moderate - revert the WSUS client GPO to the HTTP URL and the IIS binding to HTTP; requires a Group Policy refresh across clients to fully take effect.'
        OperationalNotes = ''
    }
    'NTLM Authentication Not Restricted in Domain' = @{
        EstimatedEffort  = 'High - fully restricting NTLM requires first auditing which applications/services still depend on it (often significant in legacy environments), then migrating or explicitly exempting each one, before enforcement can be raised to a deny level without breaking authentication.'
        KnownRisks       = 'Moving straight to a deny level without an audit period first will break authentication for any application, service, or legacy client that still relies on NTLM and has no Kerberos alternative configured - a real and common operational risk in mixed environments.'
        BackupRollback   = 'Easy - revert the GPO setting to 0 (Allow all); effective at next Group Policy refresh, no data loss.'
        OperationalNotes = ''
    }
    'LSA Protection (RunAsPPL) Not Enabled on Domain Controller' = @{
        EstimatedEffort  = 'Medium - a single registry value per DC, but requires a restart to take effect and should be preceded by auditing which LSA plugins/drivers are currently loaded (via audit mode) so none are unexpectedly blocked once enforced.'
        KnownRisks       = 'A currently-loaded LSA plugin or driver that does not meet Microsoft''s signing requirements will fail to load once LSA Protection is enabled, which can break third-party smart-card, authentication-extension, or security-vendor software that hooks LSA - audit first with LSA Protection in audit-only mode if available.'
        BackupRollback   = 'Easy - revert the registry value to 0 (or delete it) and restart the DC; no data loss.'
        OperationalNotes = ''
    }
    'Default Machine Account Quota Not Restricted' = @{
        EstimatedEffort  = 'Low - a single domain-wide attribute (ms-DS-MachineAccountQuota).'
        KnownRisks       = 'Lowering or zeroing this quota only prevents self-service computer joins by regular users; legitimate machine joins performed by an account with delegated Create Computer Objects rights are unaffected.'
        BackupRollback   = 'Easy - revert the ms-DS-MachineAccountQuota attribute to its prior value; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Non-Zero Machine Account Quota' = @{
        EstimatedEffort  = 'Low - a single domain-wide attribute (ms-DS-MachineAccountQuota).'
        KnownRisks       = 'Lowering the quota to zero only prevents self-service computer joins by regular users; legitimate machine joins via delegated Create Computer Objects rights are unaffected.'
        BackupRollback   = 'Easy - revert the ms-DS-MachineAccountQuota attribute to its prior value; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'gMSA Password Retrievable by Broad Principal' = @{
        EstimatedEffort  = 'Low - a single-attribute change on the gMSA object; confirm the actual hosting server(s) first so they remain in the narrowed list.'
        KnownRisks       = 'If the narrowed list omits a server that legitimately hosts this service, that server will fail to retrieve the password at its next rotation/lookup and the service will stop authenticating - confirm every real host before narrowing.'
        BackupRollback   = 'Easy - restore the prior PrincipalsAllowedToRetrieveManagedPassword value; takes effect immediately, no data loss.'
        OperationalNotes = ''
    }
    'Privileged gMSA Password Retrieval Not Tightly Scoped' = @{
        EstimatedEffort  = 'Low - a single-attribute change; requires confirming with the service owner which hosts are actually legitimate.'
        KnownRisks       = 'Removing a host that legitimately runs this service breaks its ability to authenticate as the gMSA at next password lookup - confirm current hosting before narrowing.'
        BackupRollback   = 'Easy - restore the prior PrincipalsAllowedToRetrieveManagedPassword value; takes effect immediately, no data loss.'
        OperationalNotes = ''
    }
    'Enterprise Key Admins Over-Privileged (Misconfiguration Bug)' = @{
        EstimatedEffort  = 'Medium - a single-object ACE removal, but on a forest-wide replicated object, so it warrants confirming with the relevant application owner (e.g. Exchange, ADFS, or backup/DR tooling that sometimes provisions Configuration-NC rights during setup) before removing, plus a short post-change monitoring window.'
        KnownRisks       = 'Removing the ACE could break a directory-integrated product that legitimately extends the Configuration container (commonly Exchange setup/recipient-update accounts, or certain backup/DR tools) if the trustee is a genuine service account rather than a misconfiguration.'
        BackupRollback   = 'Moderate - export the object''s current nTSecurityDescriptor (e.g. via dsacls or Get-Acl on the AD: PowerShell drive) before making the change so the exact ACE can be re-added if needed, and allow for AD replication convergence across all DCs before the removal is fully in effect forest-wide.'
        OperationalNotes = 'Since this ACE sits above the Public Key Services container this tool''s own AD CS checks already review separately, cross-check the trustee against any known certificate-services or Exchange install accounts before removing it, to avoid duplicating remediation effort on the wrong object.'
    }
    'Enterprise Key Admins Permissions Not Scoped to msDS-KeyCredentialLink' = @{
        EstimatedEffort  = 'Medium - a single-object ACE removal, but on a forest-wide replicated object, so it warrants confirming with the relevant application owner (e.g. Exchange, ADFS, or backup/DR tooling that sometimes provisions Configuration-NC rights during setup) before removing, plus a short post-change monitoring window.'
        KnownRisks       = 'Removing the ACE could break a directory-integrated product that legitimately extends the Configuration container (commonly Exchange setup/recipient-update accounts, or certain backup/DR tools) if the trustee is a genuine service account rather than a misconfiguration.'
        BackupRollback   = 'Moderate - export the object''s current nTSecurityDescriptor (e.g. via dsacls or Get-Acl on the AD: PowerShell drive) before making the change so the exact ACE can be re-added if needed, and allow for AD replication convergence across all DCs before the removal is fully in effect forest-wide.'
        OperationalNotes = 'Since this ACE sits above the Public Key Services container this tool''s own AD CS checks already review separately, cross-check the trustee against any known certificate-services or Exchange install accounts before removing it, to avoid duplicating remediation effort on the wrong object.'
    }
    'Dangerous Rights on Critical OU' = @{
        EstimatedEffort  = 'Medium - a single-object ACE removal, but on a forest-wide replicated object, so it warrants confirming with the relevant application owner (e.g. Exchange, ADFS, or backup/DR tooling that sometimes provisions Configuration-NC rights during setup) before removing, plus a short post-change monitoring window.'
        KnownRisks       = 'Removing the ACE could break a directory-integrated product that legitimately extends the Configuration container (commonly Exchange setup/recipient-update accounts, or certain backup/DR tools) if the trustee is a genuine service account rather than a misconfiguration.'
        BackupRollback   = 'Moderate - export the object''s current nTSecurityDescriptor (e.g. via dsacls or Get-Acl on the AD: PowerShell drive) before making the change so the exact ACE can be re-added if needed, and allow for AD replication convergence across all DCs before the removal is fully in effect forest-wide.'
        OperationalNotes = 'Since this ACE sits above the Public Key Services container this tool''s own AD CS checks already review separately, cross-check the trustee against any known certificate-services or Exchange install accounts before removing it, to avoid duplicating remediation effort on the wrong object.'
    }
    'Unauthorized DCSync Permissions' = @{
        EstimatedEffort  = 'Low - removing two specific extended-right ACEs (Replicating Directory Changes / Replicating Directory Changes All) from one object, a well-scoped ACE change.'
        KnownRisks       = 'Legitimate DCSync-capable accounts are normally limited to Domain Controllers, Domain/Enterprise Admins, and directory-sync tools like Azure AD Connect; removing an unauthorized grant has no legitimate compatibility impact unless it turns out to be an undocumented, currently-in-use sync or identity-governance tool, so confirm no such tool depends on it.'
        BackupRollback   = 'Moderate - export the domain object''s ACL before removing the specific extended-right ACEs so they can be restored if a legitimate sync tool is affected; changes follow normal AD replication.'
        OperationalNotes = ''
    }
    'Membership in Privileged Operations Group' = @{
        EstimatedEffort  = 'Medium - reviewing each member of the operations group (e.g. Backup/Server/Account/Print Operators) for actual ongoing need, rather than a single mechanical change.'
        KnownRisks       = 'Removing a member who still has a legitimate operational need for the group''s rights will break their ability to perform that work until re-added, so confirm with each member or their manager first.'
        BackupRollback   = 'Easy - re-add any member whose need is confirmed; effective on next Kerberos ticket refresh, no data loss.'
        OperationalNotes = ''
    }
    'Privileged Account Revealed to RODC' = @{
        EstimatedEffort  = 'Medium - the exposed account''s password must be reset and the Password Replication Policy corrected; this is a credential-exposure event on that RODC, not just a config change.'
        KnownRisks       = 'Once a password has been cached on an RODC it must be treated as exposed to anyone with local admin or physical access to that RODC, per the standard RODC security model (RODCs are assumed to be physically less secure); correcting the policy going forward does not undo the existing cached credential.'
        BackupRollback   = 'Hard/Limited - the credential exposure itself can''t be rolled back, only remediated by resetting the account''s password; the Password Replication Policy setting itself, however, can be easily reverted.'
        OperationalNotes = ''
    }
    'RODC Password Replication Policy Misconfigured' = @{
        EstimatedEffort  = 'Medium - editing the Allowed/Denied RODC Password Replication groups requires understanding which accounts should legitimately authenticate at that branch office, not just applying a blanket deny.'
        KnownRisks       = 'An overly restrictive policy can cause branch-office authentication failures or slow WAN-dependent logons for legitimate local users; an overly permissive one causes the credential-caching exposure covered by the related finding, so this needs the correct business-appropriate scope rather than simply "more restrictive."'
        BackupRollback   = 'Easy - revert the Password Replication Policy group membership changes; effective on next RODC password-caching evaluation, no data loss.'
        OperationalNotes = ''
    }
    'Orphaned RODC krbtgt Account' = @{
        EstimatedEffort  = 'Low - a single account deprovisioning/delete action for a decommissioned RODC.'
        KnownRisks       = 'Low risk deleting a krbtgt account for a genuinely decommissioned RODC; confirm the RODC is truly gone (not just temporarily offline) before deleting, since each RODC has its own dedicated krbtgt account by design.'
        BackupRollback   = 'Hard/Limited - a deleted RODC-specific krbtgt account isn''t restored; if the RODC is later reintroduced it needs a new krbtgt account provisioned as part of a fresh RODC installation.'
        OperationalNotes = ''
    }
    'Accounts with PASSWD_NOTREQD Set' = @{
        EstimatedEffort  = 'Low - clearing a single userAccountControl flag on one account, though note the account still keeps its current (possibly blank/weak) password until it''s actually changed.'
        KnownRisks       = 'Clearing the flag alone has no immediate compatibility impact, since the account keeps its current password until it''s next changed - this is a two-step fix (clear the flag, then force a password reset), not an instant risk elimination.'
        BackupRollback   = 'Easy - re-set the PASSWD_NOTREQD flag if needed; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Non-Default primaryGroupID (Membership Hiding)' = @{
        EstimatedEffort  = 'Medium - resetting primaryGroupID to the standard value requires first confirming the object genuinely isn''t a legitimate DC or service account with a documented reason for a non-default primary group, since this is also a known persistence/membership-hiding technique.'
        KnownRisks       = 'Legitimate reasons for a non-default primaryGroupID are rare, but confirm the object isn''t a genuinely misconfigured-but-legitimate service account before treating it purely as malicious persistence and resetting it.'
        BackupRollback   = 'Easy - revert the primaryGroupID attribute to its prior value; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Duplicate Service Principal Names' = @{
        EstimatedEffort  = 'Medium - Kerberos treats a duplicate SPN as ambiguous, and identifying which account should legitimately hold the SPN (versus the stale/incorrect one) requires investigation before removing it.'
        KnownRisks       = 'Removing the SPN from the wrong account (rather than the stale one) can break the legitimate service instead of fixing the conflict.'
        BackupRollback   = 'Easy - re-add the SPN to the account it was removed from via setspn; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'DC Subnet/Site Registration Gap' = @{
        EstimatedEffort  = 'Medium - creating the missing AD Sites and Services subnet object touches the forest-wide sites topology (Configuration NC), so validate the site boundary is correct before publishing it.'
        KnownRisks       = 'An incorrect subnet-to-site mapping can send clients or DCs to authenticate across a slow WAN link instead of a local DC, so getting the subnet/site boundary right matters more than simply filling the gap.'
        BackupRollback   = 'Easy - remove or correct the subnet object; effective as clients next look up their site, no data loss.'
        OperationalNotes = ''
    }
    'Insufficient Domain Controller Count' = @{
        EstimatedEffort  = 'High - adding DCs is an infrastructure project (server/VM provisioning, licensing, capacity planning, possibly a new site), not a configuration change, and needs coordination with infrastructure/capacity-planning teams.'
        KnownRisks       = 'No risk from adding a DC itself beyond the normal operational load of any new DC promotion (replication during initial sync); the risk this finding actually describes is the opposite - insufficient redundancy leaves directory availability exposed if the remaining DC(s) fail.'
        BackupRollback   = 'Easy - a newly added DC can be demoted/removed later if genuinely not needed, with no impact on existing DCs.'
        OperationalNotes = ''
    }
    'Kerberos Pre-Authentication Disabled' = @{
        EstimatedEffort  = 'Low - a single userAccountControl flag (DONT_REQ_PREAUTH) per account.'
        KnownRisks       = 'Disabling pre-auth exposes the account to offline AS-REP roasting; re-enabling pre-auth has no legitimate compatibility impact unless a genuinely pre-auth-incompatible legacy Kerberos client depends on that specific account, which is rare.'
        BackupRollback   = 'Easy - revert the DONT_REQ_PREAUTH flag; effective at next Kerberos authentication attempt, no data loss.'
        OperationalNotes = ''
    }
    'DES Encryption Enabled' = @{
        EstimatedEffort  = 'Low - a single msDS-SupportedEncryptionTypes attribute per account.'
        KnownRisks       = 'DES for Kerberos is only relevant to genuinely ancient clients (pre-Windows-7/Server-2008 era); removing it will break authentication only for such a legacy client if one still depends on this specific account, which is rare in a modern environment.'
        BackupRollback   = 'Easy - revert msDS-SupportedEncryptionTypes to its prior value; effective at next Kerberos ticket renewal, no data loss.'
        OperationalNotes = ''
    }
    'Reversible Password Encryption' = @{
        EstimatedEffort  = 'Low - a single userAccountControl flag (ENCRYPTED_TEXT_PWD_ALLOWED) per account.'
        KnownRisks       = 'The existing reversibly-encrypted copy of the password persists until the account''s next password change, so disabling the flag alone doesn''t retroactively protect the current password.'
        BackupRollback   = 'Easy - revert the flag; no data loss, though not retroactive to the already-stored reversible copy.'
        OperationalNotes = ''
    }
    'Password Never Expires' = @{
        EstimatedEffort  = 'Low - a single userAccountControl flag (DONT_EXPIRE_PASSWD) per account.'
        KnownRisks       = 'Removing "password never expires" starts the account''s normal expiration clock, which for a service account can cause an unexpected outage later when the password expires unless the account is migrated to a gMSA or someone tracks the new expiration date; confirm which type of account this is first.'
        BackupRollback   = 'Easy - revert the DONT_EXPIRE_PASSWD flag; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Unconstrained Delegation Enabled' = @{
        EstimatedEffort  = 'Medium - removing unconstrained delegation without configuring an equivalent constrained/RBCD replacement first can break the legitimate double-hop authentication scenario it was supporting, so this needs discovery of what the account/computer actually delegates to.'
        KnownRisks       = 'Unconstrained delegation is one of the most consequential AD misconfigurations (a compromised host with this flag can capture and reuse TGTs of any user who authenticates to it), but removing it without a replacement delegation model will break whatever legitimate multi-hop authentication currently depends on it.'
        BackupRollback   = 'Easy - revert the TRUSTED_FOR_DELEGATION flag; effective at next Kerberos ticket request, no data loss.'
        OperationalNotes = ''
    }
    'Inactive Enabled Account' = @{
        EstimatedEffort  = 'Low - disabling (not deleting) one account, a single attribute change.'
        KnownRisks       = 'Low risk disabling a genuinely inactive account; confirm it isn''t a seasonal or infrequently-used legitimate account (e.g. an annual-process service account) before disabling.'
        BackupRollback   = 'Easy - re-enable the account; effective immediately, no data loss.'
        OperationalNotes = ''
    }
    'Old Password' = @{
        EstimatedEffort  = 'Low - a single password reset/expiration action per account, though service accounts may need coordinated rotation everywhere the password is configured.'
        KnownRisks       = 'Forcing a password change requires the account owner to set a new password at next logon, a routine (if sometimes disruptive for service accounts) operational step; for service accounts, the manual rotation must be coordinated everywhere that account is configured.'
        BackupRollback   = 'Hard/Limited - a password can only be reset again, not restored to its previous (already known/old) value.'
        OperationalNotes = ''
    }
    'Privileged Account with SPN (Kerberoasting Risk)' = @{
        EstimatedEffort  = 'Medium - same as the non-privileged version, but the higher blast radius (a privileged account) makes coordinating the gMSA migration or password rotation with the service owner more urgent.'
        KnownRisks       = 'A privileged service account with an SPN and a weak/crackable password is a high-value Kerberoasting target, since cracking it yields privileged access directly; migrating to a gMSA is the standard fix but requires the hosting application to support it.'
        BackupRollback   = 'Easy - if gMSA migration isn''t viable, revert to the original account with a long/complex manually-set password; no data loss, though any ticket captured before the change remains crackable until the old password is retired.'
        OperationalNotes = ''
    }
    'User Account with SPN (Kerberoasting Risk)' = @{
        EstimatedEffort  = 'Medium - the real fix (migrating to a gMSA, or ensuring a long random password) is a bigger step than removing the SPN, since the SPN is what makes the service reachable via Kerberos; needs coordination with whoever manages the service.'
        KnownRisks       = 'A service account with an SPN and a weak/crackable password is vulnerable to Kerberoasting; migrating to a gMSA (which manages its own long, automatically-rotated password) is the standard fix but requires the hosting application to support gMSA authentication.'
        BackupRollback   = 'Easy - if gMSA migration isn''t viable for the application, revert to the original account with a manually-set long/complex password; no data loss, though any ticket captured before the change remains crackable until the old password is retired.'
        OperationalNotes = ''
    }
    'Privileged Account Not in Protected Users Group' = @{
        EstimatedEffort  = 'Medium - Protected Users enforces several non-configurable protections (no NTLM, no DES/RC4, no delegation, no long-lived TGT renewal) that can break dependent legitimate functionality, so Microsoft''s own guidance is to pilot it on a test group first.'
        KnownRisks       = 'Protected Users membership blocks NTLM authentication and Kerberos delegation for that account outright; any legitimate use of the account that relies on NTLM or delegation will break the moment it''s added.'
        BackupRollback   = 'Easy - remove the account from Protected Users; effective on next logon/ticket renewal, no data loss.'
        OperationalNotes = ''
    }
    'Privileged Account Not Configured as Sensitive and Cannot Be Delegated' = @{
        EstimatedEffort  = 'Low - a single account flag; takes effect at next ticket request, no other configuration required.'
        KnownRisks       = 'If this account genuinely needs to be delegated for a legitimate, currently-working scenario, enabling this flag will break that delegation - confirm the account has no legitimate delegation dependency first.'
        BackupRollback   = 'Easy - clear the flag again if needed; effective at next ticket request, no data loss.'
        OperationalNotes = ''
    }
    'Built-in Administrator Account Enabled and Not Recently Rotated' = @{
        EstimatedEffort  = 'Low - a password reset (and optionally disabling the account) on a single well-known object; confirm no automation or legacy process depends on this specific account first.'
        KnownRisks       = 'Disabling this account entirely is safe in virtually all modern environments, but confirm no legacy script or process authenticates as it directly before doing so, since it has no other owner to consult.'
        BackupRollback   = 'Easy - re-enable the account or reset the password again if needed; no data loss either way.'
        OperationalNotes = ''
    }
}
