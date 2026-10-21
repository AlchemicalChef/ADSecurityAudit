#region Scoring, ANSSI maturity & MITRE ATT&CK mapping
#
# This file is the SINGLE SOURCE OF TRUTH for the finding/output contract's
# metadata layer. It defines:
#
#   1. $Script:ADFindingMetadataMap - one table mapping each finding Issue
#      string to its MITRE ATT&CK technique, ANSSI-style control id, and a
#      risk weight. This is the ONE place to extend when new checks are added.
#   2. $Script:MitreTechniqueNames  - id -> human-readable technique name
#      (used only for report rendering).
#   3. Set-ADFindingMetadata        - tags a finding from the table.
#   4. Get-ADRiskScore              - computes a 0-100 total (higher = worse),
#      per-category sub-scores, and a 1-5 ANSSI-style maturity bucket.
#
# CONTRACT RULES (frozen for the remainder of the backlog):
#   * Finding fields are additive only (Details stays a hashtable).
#   * ANSSI control ids follow the convention 'vuln<level>_<slug>' where
#     <level> is the ANSSI maturity level (1 = most critical hygiene gap,
#     5 = advanced). Maturity is derived from this prefix, so the prefix is
#     load-bearing - keep it as the first characters of every AnssiControl.
#
# DETECTION ONLY: nothing here performs exploitation. Scoring reads finding
# metadata that was produced by read-only configuration/attribute checks.
#
# Mapping note: MITRE technique ids are authoritative. The ANSSI control ids
# follow ANSSI's Active Directory point-of-control conventions and a
# maturity structure comparable to PingCastle's; review against the current
# official ANSSI control catalogue before relying on them for formal
# compliance reporting.

# Fallback weights by SeverityLevel (Critical=4 .. Info=0), used only when an
# Issue is not present in the mapping table.
$Script:ADScoreSeverityWeights = @{
    4 = 40   # Critical
    3 = 20   # High
    2 = 10   # Medium
    1 = 4    # Low
    0 = 1    # Info
}

# Fallback ANSSI level by SeverityLevel (used only for unmapped issues).
$Script:ADScoreSeverityAnssiLevel = @{
    4 = 1
    3 = 2
    2 = 3
    1 = 4
    0 = 5
}

# MITRE ATT&CK technique id -> display name (rendering only).
$Script:MitreTechniqueNames = @{
    'T1003'      = 'OS Credential Dumping'
    'T1003.006'  = 'OS Credential Dumping: DCSync'
    'T1037'      = 'Boot or Logon Initialization Scripts'
    'T1068'      = 'Exploitation for Privilege Escalation'
    'T1078.002'  = 'Valid Accounts: Domain Accounts'
    'T1078.003'  = 'Valid Accounts: Local Accounts'
    'T1087.002'  = 'Account Discovery: Domain Account'
    'T1098'      = 'Account Manipulation'
    'T1110'      = 'Brute Force'
    'T1134.005'  = 'Access Token Manipulation: SID-History Injection'
    'T1135'      = 'Network Share Discovery'
    'T1136.002'  = 'Create Account: Domain Account'
    'T1187'      = 'Forced Authentication'
    'T1207'      = 'Rogue Domain Controller'
    'T1210'      = 'Exploitation of Remote Services'
    'T1482'      = 'Domain Trust Discovery'
    'T1484.001'  = 'Domain or Tenant Policy Modification: Group Policy Modification'
    'T1485'      = 'Data Destruction'
    'T1552.001'  = 'Unsecured Credentials: Credentials In Files'
    'T1552.006'  = 'Unsecured Credentials: Group Policy Preferences'
    'T1556'      = 'Modify Authentication Process'
    'T1557'      = 'Adversary-in-the-Middle'
    'T1557.001'  = 'Adversary-in-the-Middle: Name Resolution Poisoning and SMB Relay'
    'T1558'      = 'Steal or Forge Kerberos Tickets'
    'T1558.001'  = 'Steal or Forge Kerberos Tickets: Golden Ticket'
    'T1558.002'  = 'Steal or Forge Kerberos Tickets: Silver Ticket'
    'T1558.003'  = 'Steal or Forge Kerberos Tickets: Kerberoasting'
    'T1558.004'  = 'Steal or Forge Kerberos Tickets: AS-REP Roasting'
    'T1574.002'  = 'Hijack Execution Flow: DLL Side-Loading'
    'T1590.002'  = 'Gather Victim Network Information: DNS'
    'T1649'      = 'Steal or Forge Authentication Certificates'
    'T1685.001'  = 'Disable or Modify Tools: Disable or Modify Windows Event Log'
    'T1078'      = 'Valid Accounts'
    'T1098.007'  = 'Account Manipulation: Additional Local or Domain Groups'
    'T1547.005'  = 'Boot or Logon Autostart Execution: Security Support Provider'
    'T1552.005'  = 'Unsecured Credentials: Cloud Instance Metadata API'
}

# -----------------------------------------------------------------------------
# THE central mapping table. Issue string -> @{ Mitre; Anssi; Weight }.
# Seeded for every Issue string emitted by the existing audit modules.
# To add a new check: add ONE entry here keyed by its exact Issue string.
# -----------------------------------------------------------------------------
$Script:ADFindingMetadataMap = @{

    # --- User Account ---
    'Kerberos Pre-Authentication Disabled'                  = @{ Mitre = 'T1558.004'; Anssi = 'vuln2_asrep_roastable';        Weight = 20 }
    'DES Encryption Enabled'                                = @{ Mitre = 'T1558.003'; Anssi = 'vuln2_des_enabled';            Weight = 20 }
    'Reversible Password Encryption'                        = @{ Mitre = 'T1003';     Anssi = 'vuln1_reversible_password';     Weight = 40 }
    'Password Never Expires'                                = @{ Mitre = 'T1078.002'; Anssi = 'vuln3_password_never_expires';  Weight = 10 }
    'Unconstrained Delegation Enabled'                      = @{ Mitre = 'T1558';     Anssi = 'vuln1_unconstrained_delegation';Weight = 40 }
    'Computer Account with Unconstrained Delegation'        = @{ Mitre = 'T1558';     Anssi = 'vuln1_unconstrained_delegation_computer'; Weight = 40 }
    'Inactive Enabled Account'                              = @{ Mitre = 'T1078.002'; Anssi = 'vuln4_inactive_account';        Weight = 4  }
    'Old Password'                                          = @{ Mitre = 'T1110';     Anssi = 'vuln4_old_password';            Weight = 4  }
    'Privileged Account with SPN (Kerberoasting Risk)'     = @{ Mitre = 'T1558.003'; Anssi = 'vuln1_priv_spn_kerberoast';     Weight = 40 }
    'User Account with SPN (Kerberoasting Risk)'           = @{ Mitre = 'T1558.003'; Anssi = 'vuln3_spn_kerberoast';          Weight = 10 }
    'Privileged Account Not in Protected Users Group'      = @{ Mitre = 'T1003';     Anssi = 'vuln3_protected_users';         Weight = 10 }
    'Privileged Account Not Configured as Sensitive and Cannot Be Delegated' = @{ Mitre = 'T1558'; Anssi = 'vuln2_priv_account_delegatable'; Weight = 20 }
    'Built-in Administrator Account Enabled and Not Recently Rotated' = @{ Mitre = 'T1110'; Anssi = 'vuln2_builtin_admin_stale_password'; Weight = 20 }
    'Built-in Guest Account Enabled'                       = @{ Mitre = 'T1078';     Anssi = 'vuln3_guest_account_enabled';  Weight = 10 }

    # --- Privileged Groups ---
    'Excessive Privileged Group Membership'                = @{ Mitre = 'T1078.002'; Anssi = 'vuln2_privileged_members';      Weight = 20 }
    'Nested Groups in Critical Privileged Group'           = @{ Mitre = 'T1078.002'; Anssi = 'vuln2_nested_privileged_group'; Weight = 20 }
    'Disabled User in Privileged Group'                    = @{ Mitre = 'T1078.002'; Anssi = 'vuln4_disabled_in_privileged';  Weight = 4  }

    # --- AdminSDHolder ---
    'Non-Standard Permissions on AdminSDHolder'            = @{ Mitre = 'T1098';     Anssi = 'vuln1_adminsdholder_acl';       Weight = 40 }
    'Deny ACE on AdminSDHolder'                            = @{ Mitre = 'T1098';     Anssi = 'vuln3_adminsdholder_deny_ace';  Weight = 10 }
    'Orphaned adminCount Attribute'                        = @{ Mitre = 'T1078.002'; Anssi = 'vuln4_orphaned_admincount';     Weight = 4  }
    'AdminSDHolder Ghost Account'                          = @{ Mitre = 'T1098';     Anssi = 'vuln2_adminsdholder_ghost';     Weight = 20 }
    'AdminSDHolder ACL Compromise'                         = @{ Mitre = 'T1098';     Anssi = 'vuln1_adminsdholder_compromise';Weight = 40 }
    'AdminSDHolder Inheritance Re-Enabled'                 = @{ Mitre = 'T1098';     Anssi = 'vuln1_adminsdholder_inheritance'; Weight = 40 }
    'No Auditing on AdminSDHolder Object'                  = @{ Mitre = 'T1685.001'; Anssi = 'vuln3_no_audit_adminsdholder';  Weight = 10 }

    # --- Group Policy ---
    'Over-Permissioned GPO'                                = @{ Mitre = 'T1484.001'; Anssi = 'vuln2_gpo_overpermissioned';    Weight = 20 }
    'GPO Linked to Domain Controllers with Weak Permissions' = @{ Mitre = 'T1484.001'; Anssi = 'vuln1_gpo_dc_weak_perms';    Weight = 40 }
    'Unlinked GPO'                                         = @{ Mitre = 'T1484.001'; Anssi = 'vuln5_unlinked_gpo';            Weight = 1  }
    'Insecure SYSVOL Permissions'                          = @{ Mitre = 'T1484.001'; Anssi = 'vuln2_sysvol_permissions';      Weight = 20 }

    # --- Replication Security ---
    'Unauthorized DCSync Permissions'                      = @{ Mitre = 'T1003.006'; Anssi = 'vuln1_dcsync';                  Weight = 40 }
    'SPN-Holding Account Also Has DCSync Rights'           = @{ Mitre = 'T1003.006'; Anssi = 'vuln1_spn_dcsync_chain';        Weight = 40 }
    'Membership in Privileged Operations Group'            = @{ Mitre = 'T1078.002'; Anssi = 'vuln3_privileged_ops_group';    Weight = 10 }

    # --- Domain Security ---
    'Weak Minimum Password Length'                         = @{ Mitre = 'T1110';     Anssi = 'vuln2_weak_min_pwd_length';     Weight = 20 }
    'Password Complexity Disabled'                         = @{ Mitre = 'T1110';     Anssi = 'vuln2_pwd_complexity_disabled'; Weight = 20 }
    'Reversible Encryption Enabled Domain-Wide'            = @{ Mitre = 'T1003';     Anssi = 'vuln1_reversible_domain_wide';  Weight = 40 }
    'Account Lockout Disabled'                             = @{ Mitre = 'T1110';     Anssi = 'vuln1_lockout_disabled';        Weight = 40 }
    'Account Lockout Threshold Above Recommended Maximum'  = @{ Mitre = 'T1110';     Anssi = 'vuln3_lockout_threshold_high';  Weight = 10 }
    'Outdated Domain Functional Level'                     = @{ Mitre = 'T1078.002'; Anssi = 'vuln4_outdated_dfl';            Weight = 4  }
    'Outdated Forest Functional Level'                     = @{ Mitre = 'T1078.002'; Anssi = 'vuln4_outdated_ffl';            Weight = 4  }
    # Lower weight than the "Outdated" pair above (4): Windows2016 is fully
    # supported and not itself insecure - this is an opportunity/roadmap
    # item (Windows Server 2025 introduced the first new functional level
    # since 2016), not a vulnerability, so it scores like the other Low-
    # severity hygiene items (AD Recycle Bin Not Enabled, Short Tombstone
    # Lifetime) rather than the security-relevant "actually deprecated"
    # levels.
    'Domain Functional Level Could Be Raised'              = @{ Mitre = '';          Anssi = 'vuln4_upgradable_dfl';          Weight = 1  }
    'Forest Functional Level Could Be Raised'               = @{ Mitre = '';          Anssi = 'vuln4_upgradable_ffl';          Weight = 1  }
    'AD Recycle Bin Not Enabled'                           = @{ Mitre = 'T1485';     Anssi = 'vuln5_recycle_bin_disabled';    Weight = 1  }
    'Legacy Operating Systems in Domain'                   = @{ Mitre = 'T1210';     Anssi = 'vuln3_legacy_os';               Weight = 10 }
    'Stale AzureADSSOACC Kerberos Key'                     = @{ Mitre = 'T1558.002'; Anssi = 'vuln2_azuread_sso_key';         Weight = 20 }
    'Short Tombstone Lifetime'                             = @{ Mitre = '';          Anssi = 'vuln5_short_tombstone_lifetime'; Weight = 1  }

    # --- Domain Trusts ---
    'Bidirectional Domain Trust'                           = @{ Mitre = 'T1482';     Anssi = 'vuln4_bidirectional_trust';     Weight = 4  }
    'SID Filtering Disabled on External Trust'             = @{ Mitre = 'T1134.005'; Anssi = 'vuln1_sid_filtering_disabled';  Weight = 40 }
    'Forest Trust Without Selective Authentication'        = @{ Mitre = 'T1482';     Anssi = 'vuln3_no_selective_auth';       Weight = 10 }
    'Trust Password Not Recently Rotated'                  = @{ Mitre = 'T1558';     Anssi = 'vuln3_trust_pwd_rotation';      Weight = 10 }

    # --- Certificate Services (AD CS / ESC) ---
    'Certificate Template Allows Subject Alternative Name (ESC1)'        = @{ Mitre = 'T1649'; Anssi = 'vuln1_adcs_esc1';        Weight = 40 }
    'Certificate Template Allows Subject Alternative Name (Restricted)'  = @{ Mitre = 'T1649'; Anssi = 'vuln2_adcs_esc1_restricted'; Weight = 20 }
    'Certificate Template with No EKU Restrictions (ESC2)'              = @{ Mitre = 'T1649'; Anssi = 'vuln1_adcs_esc2';        Weight = 40 }
    'Enrollment Agent Template with Low-Privilege Enrollment (ESC3)'    = @{ Mitre = 'T1649'; Anssi = 'vuln1_adcs_esc3';        Weight = 40 }
    'Certificate Template Does Not Require RA Signatures'               = @{ Mitre = 'T1649'; Anssi = 'vuln2_adcs_ra_signature'; Weight = 20 }
    'Overly Permissive CA Permissions (ESC7)'                          = @{ Mitre = 'T1649'; Anssi = 'vuln1_adcs_esc7';        Weight = 40 }
    'Low-Privilege CA Management Rights'                               = @{ Mitre = 'T1649'; Anssi = 'vuln2_adcs_ca_mgmt';     Weight = 20 }
    'Certificate Template with Weak ACL (ESC4)'                        = @{ Mitre = 'T1649'; Anssi = 'vuln2_adcs_esc4';        Weight = 20 }
    'Certificate Template Allows High-Risk Enrollment Without Manager Approval' = @{ Mitre = 'T1649'; Anssi = 'vuln2_adcs_no_approval'; Weight = 20 }
    'CA Web Enrollment over HTTP (ESC8)'                               = @{ Mitre = 'T1649'; Anssi = 'vuln1_adcs_esc8';        Weight = 40 }
    'ROCA-Vulnerable Certificate Key'                                  = @{ Mitre = 'T1649'; Anssi = 'vuln2_adcs_roca';        Weight = 20 }
    'Weak Signature Algorithm in PKI Trust Store'                      = @{ Mitre = 'T1649'; Anssi = 'vuln3_adcs_weak_signature'; Weight = 10 }
    'CA Chase-Fallback Enabled (CVE-2026-54121 / Certighost Exposure)' = @{ Mitre = 'T1649'; Anssi = 'vuln1_adcs_certighost_chase'; Weight = 40 }
    'CA-Wide SAN Attribute Flag Enabled (ESC6)'            = @{ Mitre = 'T1649';     Anssi = 'vuln1_adcs_esc6_san_flag';       Weight = 40 }
    'Certificate Template Allows Arbitrary Server Certificate (ESC17)' = @{ Mitre = 'T1649'; Anssi = 'vuln1_adcs_esc17';       Weight = 40 }
    'Weak ACL on PKI Container Object (ESC5)'              = @{ Mitre = 'T1649';     Anssi = 'vuln1_adcs_esc5';                Weight = 40 }
    'Certificate Template Missing Security Extension (ESC9)' = @{ Mitre = 'T1649';   Anssi = 'vuln2_adcs_esc9';                Weight = 20 }
    'Weak Certificate Binding Compensation Enabled (ESC10)' = @{ Mitre = 'T1649';    Anssi = 'vuln2_adcs_esc10';               Weight = 20 }
    'CA RPC Enrollment Encryption Not Enforced (ESC11)'    = @{ Mitre = 'T1649';     Anssi = 'vuln1_adcs_esc11';               Weight = 40 }
    'Certificate Template Issuance Policy Linked to Privileged Group (ESC13)' = @{ Mitre = 'T1649'; Anssi = 'vuln1_adcs_esc13'; Weight = 40 }
    'Certificate Template Vulnerable to Schema V1 EKU Injection (ESC15)' = @{ Mitre = 'T1649'; Anssi = 'vuln1_adcs_esc15'; Weight = 40 }
    'Weak Explicit Certificate Mapping on Privileged Account (ESC14)' = @{ Mitre = 'T1649'; Anssi = 'vuln2_adcs_esc14';        Weight = 20 }
    'CA-Wide Security Extension Disabled (ESC16)'          = @{ Mitre = 'T1649';     Anssi = 'vuln1_adcs_esc16';               Weight = 40 }

    # --- Kerberos Security (KRBTGT) ---
    'KRBTGT Password Age Exceeds Recommended Threshold'   = @{ Mitre = 'T1558.001'; Anssi = 'vuln1_krbtgt_age';              Weight = 40 }
    'KRBTGT Password Approaching Rotation Threshold'      = @{ Mitre = 'T1558.001'; Anssi = 'vuln3_krbtgt_approaching';      Weight = 10 }
    'KRBTGT Password Last Set Date Unknown'               = @{ Mitre = 'T1558.001'; Anssi = 'vuln3_krbtgt_unknown';          Weight = 10 }

    # --- LAPS Deployment ---
    'LAPS Not Deployed'                                    = @{ Mitre = 'T1078.003'; Anssi = 'vuln2_laps_not_deployed';       Weight = 20 }
    'Incomplete LAPS Coverage'                            = @{ Mitre = 'T1078.003'; Anssi = 'vuln3_laps_incomplete';         Weight = 10 }
    'Expired LAPS Passwords'                              = @{ Mitre = 'T1078.003'; Anssi = 'vuln3_laps_expired';            Weight = 10 }

    # --- Audit Policy ---
    'Insufficient Audit Policy Configuration'             = @{ Mitre = 'T1685.001'; Anssi = 'vuln3_audit_insufficient';      Weight = 10 }
    'Advanced Audit Policy Verification Required'         = @{ Mitre = 'T1685.001'; Anssi = 'vuln4_audit_verify';            Weight = 4  }
    'No Auditing on Domain Root Object'                   = @{ Mitre = 'T1685.001'; Anssi = 'vuln3_no_audit_domain_root';    Weight = 10 }

    # --- Kerberos Delegation ---
    'User Account with Protocol Transition (T2A4D)'      = @{ Mitre = 'T1558';     Anssi = 'vuln1_user_protocol_transition'; Weight = 40 }
    'User Account with Constrained Delegation'           = @{ Mitre = 'T1558';     Anssi = 'vuln2_user_constrained_deleg';   Weight = 20 }
    'Computer Account with Protocol Transition (T2A4D)'  = @{ Mitre = 'T1558';     Anssi = 'vuln2_computer_protocol_transition'; Weight = 20 }
    'Resource-Based Constrained Delegation Configured'   = @{ Mitre = 'T1558';     Anssi = 'vuln2_rbcd';                     Weight = 20 }

    # --- Dangerous Permissions ---
    'Enterprise Key Admins Over-Privileged (Misconfiguration Bug)'              = @{ Mitre = 'T1556'; Anssi = 'vuln2_enterprise_key_admins'; Weight = 20 }
    'Enterprise Key Admins Permissions Not Scoped to msDS-KeyCredentialLink'    = @{ Mitre = 'T1556'; Anssi = 'vuln3_enterprise_key_admins_scope'; Weight = 10 }
    'Dangerous Rights on Critical OU'                    = @{ Mitre = 'T1098';     Anssi = 'vuln1_dangerous_ou_rights';      Weight = 40 }
    'Non-Standard Permissions on Schema Naming Context'         = @{ Mitre = 'T1098'; Anssi = 'vuln1_schema_nc_acl'; Weight = 40 }
    'Non-Standard Permissions on Configuration Naming Context'  = @{ Mitre = 'T1098'; Anssi = 'vuln1_config_nc_acl'; Weight = 40 }
    'Vulnerable Schema Class Allows Arbitrary Object Creation'   = @{ Mitre = 'T1098'; Anssi = 'vuln1_schema_class_vulnerable'; Weight = 40 }
    'Schema defaultSecurityDescriptor Modified'                  = @{ Mitre = 'T1098'; Anssi = 'vuln1_schema_default_sd';       Weight = 40 }
    'AD Display Specifier Tampered'                              = @{ Mitre = 'T1098'; Anssi = 'vuln2_display_specifier_tampered'; Weight = 20 }

    # --- Legacy Attack Vector / Admin Equivalence ---
    'Shadow Credentials Detected'                        = @{ Mitre = 'T1556';     Anssi = 'vuln1_shadow_credentials';       Weight = 40 }
    'SID History Injection (Same Domain)'                = @{ Mitre = 'T1134.005'; Anssi = 'vuln1_sid_history_injection';     Weight = 40 }
    'Privileged SID in History'                          = @{ Mitre = 'T1134.005'; Anssi = 'vuln1_privileged_sid_history';    Weight = 40 }
    'SID History Attribute Populated'                    = @{ Mitre = 'T1134.005'; Anssi = 'vuln5_sid_history_populated';     Weight = 1  }
    'Cross-Domain Privileged Group Membership'           = @{ Mitre = '';          Anssi = 'vuln5_cross_domain_group_membership'; Weight = 1  }
    'Legacy Logon Script Defined'                        = @{ Mitre = 'T1037';     Anssi = 'vuln4_legacy_logon_script';      Weight = 4  }
    'Domain Admin Equivalent Access Detected'            = @{ Mitre = 'T1078.002'; Anssi = 'vuln2_da_equivalent_access';      Weight = 20 }

    # --- Machine Account Quota ---
    'Default Machine Account Quota Not Restricted'       = @{ Mitre = 'T1136.002'; Anssi = 'vuln2_maq_default';              Weight = 20 }
    'Non-Zero Machine Account Quota'                     = @{ Mitre = 'T1136.002'; Anssi = 'vuln3_maq_nonzero';              Weight = 10 }

    # --- Domain Hardening (dsHeuristics, Pre-Win2000, anonymous binding) ---
    'Dangerous dsHeuristics Flag Set'                    = @{ Mitre = 'T1556';     Anssi = 'vuln2_dsheuristics_dangerous';  Weight = 20 }
    'Broad Membership in Pre-Windows 2000 Compatible Access' = @{ Mitre = 'T1078.002'; Anssi = 'vuln2_prewin2000_broad';    Weight = 20 }
    'Anonymous LDAP / RootDSE Binding Permitted'         = @{ Mitre = 'T1087.002'; Anssi = 'vuln3_anonymous_bind';          Weight = 10 }
    'Null-Session Pipe/Share Access Permitted'           = @{ Mitre = 'T1135';     Anssi = 'vuln3_null_session_access';     Weight = 10 }

    # --- Coercion & NTLM Relay Exposure ---
    'Print Spooler Running on Domain Controller'         = @{ Mitre = 'T1187';     Anssi = 'vuln1_dc_spooler_running';      Weight = 40 }
    'WebClient Service Enabled on Domain Controller'     = @{ Mitre = 'T1187';     Anssi = 'vuln1_dc_webclient_running';    Weight = 40 }
    'LDAP Signing Not Enforced on Domain Controller'     = @{ Mitre = 'T1557.001'; Anssi = 'vuln1_ldap_signing_not_enforced'; Weight = 40 }
    'LDAP Channel Binding Not Enforced'                  = @{ Mitre = 'T1557.001'; Anssi = 'vuln1_ldap_channel_binding_not_enforced'; Weight = 40 }

    # --- LSA Protection (Skeleton Key mitigation) ---
    'LSA Protection (RunAsPPL) Not Enabled on Domain Controller' = @{ Mitre = 'T1547.005'; Anssi = 'vuln2_lsa_protection_disabled'; Weight = 20 }

    # --- DNS Security (AD-integrated DNS) ---
    'Non-Default Members in DnsAdmins'                        = @{ Mitre = 'T1574.002'; Anssi = 'vuln1_dnsadmins_members';        Weight = 40 }
    'DNS Zone Transfer Allowed'                               = @{ Mitre = 'T1590.002'; Anssi = 'vuln3_dns_zone_transfer';        Weight = 10 }
    'Insecure Dynamic DNS Updates Enabled'                    = @{ Mitre = 'T1557';     Anssi = 'vuln3_dns_insecure_updates';     Weight = 10 }
    'Authenticated Users Can Create Child Objects in DNS Zone' = @{ Mitre = 'T1557';    Anssi = 'vuln2_dns_adidns_createchild';   Weight = 20 }
    'Stale/Dangling DNS Zone Delegation'                      = @{ Mitre = 'T1590.002'; Anssi = 'vuln2_dns_stale_delegation';     Weight = 20 }

    # --- Legacy Auth & Name Poisoning (SMBv1, signing, LM/NTLMv1, LLMNR, WSUS-HTTP) ---
    'SMBv1 Enabled / Not Disabled by Policy'              = @{ Mitre = 'T1210';     Anssi = 'vuln1_smbv1_enabled';          Weight = 40 }
    'SMB Signing Not Required'                            = @{ Mitre = 'T1557.001'; Anssi = 'vuln1_smb_signing_not_required'; Weight = 40 }
    'LM/NTLMv1 Authentication Permitted'                  = @{ Mitre = 'T1557.001'; Anssi = 'vuln1_lm_ntlmv1_permitted';     Weight = 40 }
    'GPO Permits LM Hash Storage'                         = @{ Mitre = 'T1557.001'; Anssi = 'vuln1_lm_hash_storage';        Weight = 40 }
    'LLMNR Not Disabled by Policy'                        = @{ Mitre = 'T1557.001'; Anssi = 'vuln3_llmnr_not_disabled';     Weight = 10 }
    'WSUS Delivered over HTTP'                            = @{ Mitre = 'T1210';     Anssi = 'vuln1_wsus_http';              Weight = 40 }
    'NTLM Authentication Not Restricted in Domain'         = @{ Mitre = 'T1557.001'; Anssi = 'vuln3_ntlm_not_restricted';     Weight = 10 }

    # --- Kerberos Hardening Depth (AES enforcement, FAST/armoring, cross-trust TGT delegation) ---
    'RC4 Kerberos Encryption Still Permitted'             = @{ Mitre = 'T1558.003'; Anssi = 'vuln2_rc4_kerberos_permitted'; Weight = 20 }
    'Kerberos Armoring (FAST) Not Enabled'                = @{ Mitre = 'T1558';     Anssi = 'vuln2_kerberos_armoring_not_enabled'; Weight = 20 }
    'Cross-Trust TGT Delegation Enabled'                  = @{ Mitre = 'T1558';     Anssi = 'vuln1_cross_trust_tgt_delegation'; Weight = 40 }
    'Trust Configured for Privileged Identity Management (PIM_TRUST)' = @{ Mitre = 'T1558'; Anssi = 'vuln1_pim_trust';       Weight = 40 }

    # --- Stale-Object & Hygiene Depth (PASSWD_NOTREQD, primaryGroupID, duplicate SPNs, DC registration) ---
    'Accounts with PASSWD_NOTREQD Set'                    = @{ Mitre = 'T1110';     Anssi = 'vuln2_passwd_notreqd';         Weight = 20 }
    'Non-Default primaryGroupID (Membership Hiding)'      = @{ Mitre = 'T1098';     Anssi = 'vuln2_primary_group_id';       Weight = 20 }
    'Computer Account Never Joined with No Password Set'  = @{ Mitre = 'T1078.002'; Anssi = 'vuln2_never_joined_computer';  Weight = 20 }
    'Constrained Delegation Configured to Decommissioned SPN' = @{ Mitre = 'T1187'; Anssi = 'vuln2_ghost_spn_delegation';    Weight = 20 }
    'Broad Membership in Distributed COM Users or Performance Log Users' = @{ Mitre = 'T1098'; Anssi = 'vuln2_underaudited_group_membership'; Weight = 20 }
    'Duplicate Service Principal Names'                   = @{ Mitre = 'T1098';     Anssi = 'vuln3_duplicate_spn';          Weight = 10 }
    'DC Subnet/Site Registration Gap'                     = @{ Mitre = 'T1590.002'; Anssi = 'vuln4_dc_subnet_missing';      Weight = 4  }
    'Legacy FRS-Based SYSVOL Replication In Use'          = @{ Mitre = 'T1210';     Anssi = 'vuln2_legacy_frs_sysvol';      Weight = 20 }
    'Insufficient Domain Controller Count'                = @{ Mitre = 'T1485';     Anssi = 'vuln3_insufficient_dc_count';  Weight = 10 }
    'Domain Controller Registration Inconsistent'         = @{ Mitre = 'T1207';     Anssi = 'vuln1_dc_registration_inconsistent'; Weight = 40 }
    'Rogue NTDS Settings Object Detected'                 = @{ Mitre = 'T1207';     Anssi = 'vuln1_rogue_ntds_object';      Weight = 40 }

    # --- GPO-Deployed Secrets & Insecure Settings (GPP cpassword, script credentials) ---
    'GPP cpassword Found in SYSVOL'                       = @{ Mitre = 'T1552.006'; Anssi = 'vuln1_gpp_cpassword';          Weight = 40 }
    'Credentials Referenced in Logon/Startup Script'      = @{ Mitre = 'T1552.001'; Anssi = 'vuln2_script_credentials';     Weight = 20 }
    'Insecure Setting Deployed via GPO'                   = @{ Mitre = 'T1484.001'; Anssi = 'vuln3_gpo_insecure_setting';   Weight = 10 }
    'GPO Grants Sensitive Logon Right to Broad Principal'  = @{ Mitre = 'T1078';     Anssi = 'vuln1_gpo_anonymous_logon_right'; Weight = 40 }

    # --- Known DC Vulnerabilities by Patch/Build (MS14-068, MS17-010, ZeroLogon, PrintNightmare, CVE-2026-41089 Netlogon RCE, BadSuccessor) ---
    'DC Missing ZeroLogon Patch'                          = @{ Mitre = 'T1068';     Anssi = 'vuln1_zerologon_unpatched';    Weight = 40 }
    'DC Vulnerable to MS17-010'                           = @{ Mitre = 'T1210';     Anssi = 'vuln1_ms17010_unpatched';      Weight = 40 }
    'DC Vulnerable to MS14-068'                           = @{ Mitre = 'T1558.001'; Anssi = 'vuln1_ms14068_unpatched';      Weight = 40 }
    'PrintNightmare Exposure on DC'                       = @{ Mitre = 'T1068';     Anssi = 'vuln2_printnightmare_exposed'; Weight = 20 }
    'DC Missing CVE-2026-41089 Patch (Netlogon RCE)'      = @{ Mitre = 'T1210';     Anssi = 'vuln1_netlogon_cve2026_41089_unpatched'; Weight = 40 }
    'DC Missing CVE-2026-72982 Patch (Netlogon RCE)'      = @{ Mitre = 'T1210';     Anssi = 'vuln1_netlogon_cve2026_72982_unpatched'; Weight = 40 }
    'BadSuccessor / dMSA Escalation Exposure'             = @{ Mitre = 'T1098';     Anssi = 'vuln2_badsuccessor_dmsa';      Weight = 20 }

    # --- Exchange-in-AD Privilege Escalation (Exchange Windows Permissions / WriteDACL) ---
    'Exchange Group Holds WriteDACL on Domain Object'     = @{ Mitre = 'T1098';     Anssi = 'vuln1_exchange_domain_writedacl'; Weight = 40 }
    'Exchange-Related AdminSDHolder ACE'                  = @{ Mitre = 'T1098';     Anssi = 'vuln2_exchange_adminsdholder_ace'; Weight = 20 }

    # --- Read-Only Domain Controller Security Posture ---
    'Privileged Account Revealed to RODC'                 = @{ Mitre = 'T1003';     Anssi = 'vuln1_rodc_privileged_revealed'; Weight = 40 }
    'RODC Password Replication Policy Misconfigured'      = @{ Mitre = 'T1078.002'; Anssi = 'vuln2_rodc_prp_misconfigured';   Weight = 20 }
    'Orphaned RODC krbtgt Account'                        = @{ Mitre = 'T1078.002'; Anssi = 'vuln3_rodc_krbtgt_orphan';       Weight = 10 }

    # --- Attack-Path Graph & Indirect-Privilege (Control-Path) Findings ---
    'Indirect Control Path to Tier-0 Object'               = @{ Mitre = 'T1098'; Anssi = 'vuln2_control_path_indirect';        Weight = 20 }
    'Everyone/Authenticated Users on a Control Path to Tier-0' = @{ Mitre = 'T1098'; Anssi = 'vuln1_control_path_broad';       Weight = 40 }
    'Owner of Tier-0 Object is Non-Privileged'             = @{ Mitre = 'T1098'; Anssi = 'vuln2_control_path_owner';           Weight = 20 }

    # --- Managed Service Accounts (gMSA password-retrieval rights) ---
    'gMSA Password Retrievable by Broad Principal'         = @{ Mitre = 'T1552.005'; Anssi = 'vuln1_gmsa_broad_retrieval';    Weight = 40 }
    'Privileged gMSA Password Retrieval Not Tightly Scoped' = @{ Mitre = 'T1552.005'; Anssi = 'vuln2_gmsa_tier0_retrieval';   Weight = 20 }
    'Non-Default Access to gMSA KDS Root Key'              = @{ Mitre = 'T1552.005'; Anssi = 'vuln1_gmsa_kds_root_key';      Weight = 40 }
    'Non-Default Access to Domain DPAPI Backup Key'        = @{ Mitre = 'T1552.001'; Anssi = 'vuln1_dpapi_backup_key';       Weight = 40 }
    'Legacy LAPS SearchFlags Exposes Password'             = @{ Mitre = 'T1552.001'; Anssi = 'vuln2_laps_searchflags';       Weight = 20 }

    # --- Group Policy (Restricted Groups / GPO ownership additions) ---
    'GPO Deploys Restricted Groups Membership'             = @{ Mitre = 'T1098.007'; Anssi = 'vuln1_gpo_restricted_groups';   Weight = 40 }
    'Non-Standard GPO Owner'                               = @{ Mitre = 'T1484.001'; Anssi = 'vuln2_gpo_non_admin_owner';     Weight = 20 }
}

function Get-ADFindingMetadataMap {
    <#
    .SYNOPSIS
        Returns the central Issue -> {Mitre, Anssi, Weight} mapping table.
    .DESCRIPTION
        Exposes the single source of truth so callers/tests can inspect or
        validate coverage. Returns a clone so the live table is not mutated.
    #>
    [CmdletBinding()]
    param()
    return $Script:ADFindingMetadataMap.Clone()
}

function Set-ADFindingMetadata {
    <#
    .SYNOPSIS
        Tags a finding with MITRE / ANSSI / Weight from the central map.
    .DESCRIPTION
        Looks the finding's Issue string up in $Script:ADFindingMetadataMap and
        populates MitreTechnique, AnssiControl, and Weight. Idempotent. For
        issues not yet in the table, falls back to severity-derived defaults so
        scoring still degrades gracefully (and emits a verbose warning so the
        gap can be closed by adding a table entry).

        FIXED (reported): -Finding used to be typed [ADSecurityFinding].
        That's correct for a live run (Main.ps1 passes genuine
        [ADSecurityFinding] instances, a reference type, so mutations
        inside this function correctly persisted back to the caller's
        object) - but Export-ADSecurityReportHTMLFromJson and
        Get-ADRetestComparison instead pass PSCustomObjects deserialized
        from a findings JSON export. Passing a PSCustomObject to a
        parameter typed as a specific class forces PowerShell to
        implicitly CONSTRUCT A NEW, SEPARATE [ADSecurityFinding] instance
        at the call boundary (a copy), tag THAT copy, and then discard it
        when the function returns - the caller's original PSCustomObject
        was never touched. The bug was invisible for a live run (already
        the right type, no conversion happens) and invisible for a
        recent-enough JSON export (Main.ps1 already tags every finding
        with real Weight/AnssiControl before ConvertTo-Json, so the
        IsNullOrEmpty/-le 0 guard in Get-ADRiskScore's caller skips
        re-tagging entirely) - but for any finding whose JSON export
        genuinely lacks this metadata (an old export from before v1.2.0
        added tagging, or any Issue not yet in the map at export time),
        Get-ADRiskScore's rescore call silently computed a correct-looking
        score against a copy that was thrown away, then read Weight back
        off the STILL-UNTAGGED original as 0 - understating (sometimes to
        literally zero) that finding's contribution to the recomputed
        risk score, maturity level, and MITRE summary, with no error or
        warning of any kind.

        -Finding is now untyped, so PowerShell passes the actual object
        reference through unchanged - whatever its shape (a live
        [ADSecurityFinding], or a JSON-deserialized PSCustomObject) - and
        mutations below persist to the caller's own object. Property
        writes go through Set-ADFindingProperty (not plain dot-assignment)
        because a PSCustomObject from a JSON export that predates a given
        property (e.g. Weight didn't exist in the schema yet) doesn't
        have that property to assign to at all; plain "$Finding.Weight =
        4" throws "the property 'Weight' cannot be found" in that case,
        where a live [ADSecurityFinding] (which always has every property
        the class declares) would not.
    .PARAMETER Finding
        The finding to tag. Mutated in place and also returned for
        pipelining. Deliberately untyped - see FIXED note above.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $Finding
    )

    process {
        $meta = $Script:ADFindingMetadataMap[$Finding.Issue]

        if ($null -ne $meta) {
            Set-ADFindingProperty -Object $Finding -Name 'MitreTechnique' -Value $meta.Mitre
            Set-ADFindingProperty -Object $Finding -Name 'AnssiControl'   -Value $meta.Anssi
            Set-ADFindingProperty -Object $Finding -Name 'Weight'         -Value $meta.Weight
        }
        else {
            Write-Verbose "Set-ADFindingMetadata: no mapping for Issue '$($Finding.Issue)'; using severity-derived defaults."
            $sev = $Finding.SeverityLevel
            if (-not $Script:ADScoreSeverityWeights.ContainsKey($sev)) { $sev = 0 }

            if (-not ($Finding.Weight -gt 0)) {
                Set-ADFindingProperty -Object $Finding -Name 'Weight' -Value $Script:ADScoreSeverityWeights[$sev]
            }
            if ([string]::IsNullOrEmpty($Finding.AnssiControl)) {
                $lvl = $Script:ADScoreSeverityAnssiLevel[$sev]
                Set-ADFindingProperty -Object $Finding -Name 'AnssiControl' -Value "vuln${lvl}_unmapped"
            }
        }

        return $Finding
    }
}

function Get-ADRiskScore {
    <#
    .SYNOPSIS
        Computes a 0-100 risk score (higher = worse), per-category sub-scores,
        and a 1-5 ANSSI-style maturity level for a set of findings.
    .DESCRIPTION
        Scoring model (comparable in spirit to PingCastle's, but not identical):
          * Each finding contributes its Weight (set from the central map).
            Findings without metadata are tagged on the fly.
          * Each category's sub-score uses diminishing returns: the category
            starts "clean" (factor 1.0) and every finding multiplies that
            factor by (1 - Weight/100); Score = 100 * (1 - factor). This
            approaches 100 smoothly as findings accumulate instead of a flat
            weight sum hard-capped at 100, so a couple of Critical findings
            no longer saturate a category to the maximum outright.
          * The TotalScore is the MAX of the category sub-scores - i.e. an
            environment is rated by its worst risk area (the same
            weakest-link philosophy used by PingCastle for its global score).
        Maturity (ANSSI-style 1..5, higher = better):
          * Derived from the 'vuln<level>_' prefix of each AnssiControl.
          * Maturity = the lowest level present among findings (a single
            level-1 gap caps maturity at 1). With no findings, maturity = 5.
        Detection only - this function reads finding metadata; it performs no
        queries against any host.
    .PARAMETER Findings
        Array of ADSecurityFinding objects.
    .OUTPUTS
        PSCustomObject with TotalScore, MaturityLevel, MaturityLabel,
        CategoryScores (array), MitreSummary (array), and counts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Findings
    )

    # Defensive guard: flatten in case $Findings is jagged (an element that
    # is itself a sub-array of several findings rather than one) - e.g. from
    # a findings JSON re-read offline by Get-ADRetestComparison. Without
    # this, a jagged element makes every property read below return an
    # array instead of a scalar (PowerShell member-enumeration), producing a
    # confusing "cannot convert System.Object[] to Int32" deep in the loop
    # rather than working findings data. A no-op when $Findings is already
    # flat (the normal case for a live audit run). @() wrap is load-bearing
    # for a genuinely empty (zero-finding) call - see
    # ConvertTo-ADFlatFindingsArray's own docs: without it, a clean run
    # would silently reassign this already-validated parameter to a real
    # $null mid-function, rather than keeping it a valid empty array.
    $Findings = @(ConvertTo-ADFlatFindingsArray -Findings $Findings)

    $maturityLabels = @{
        1 = 'Level 1 - Critical gaps (basic hygiene not met)'
        2 = 'Level 2 - Partial hygiene'
        3 = 'Level 3 - Standard hardening'
        4 = 'Level 4 - Advanced hardening'
        5 = 'Level 5 - Optimal'
    }

    # Empty environment => best possible posture.
    if (-not $Findings -or $Findings.Count -eq 0) {
        return [PSCustomObject]@{
            TotalScore     = 0
            MaturityLevel  = 5
            MaturityLabel  = $maturityLabels[5]
            CategoryScores = @()
            MitreSummary   = @()
            FindingCount   = 0
            WeightedPoints = 0
            SeverityCounts = [PSCustomObject]@{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
            # Stored as an ISO-8601 STRING, not a raw [datetime]. ConvertTo-Json
            # expands a raw [datetime] using its own DisplayHint/DateTime/value
            # note properties rather than a plain string, so anything that
            # later reads this back with ConvertFrom-Json (e.g.
            # Get-ADRetestComparison's score-sidecar metadata) would otherwise
            # get "@{value=...; DisplayHint=2; DateTime=...}" instead of a date.
            GeneratedDate  = (Get-Date).ToString('o')
            ModuleVersion  = $script:ModuleVersion
        }
    }

    $categoryPoints  = @{}   # raw weighted-points sum, kept for the report's informational total
    $categoryFactors = @{}   # diminishing-returns "clean" factor per category, starts at 1.0
    $categoryCounts  = @{}
    $mitreCounts    = @{}
    $totalPoints    = 0
    $minLevel       = 5
    $sevCounts      = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }

    foreach ($finding in $Findings) {
        # Ensure metadata is present (idempotent; tags raw findings).
        if ([string]::IsNullOrEmpty($finding.AnssiControl) -or $finding.Weight -le 0) {
            [void](Set-ADFindingMetadata -Finding $finding)
        }

        $cat = if ([string]::IsNullOrEmpty($finding.Category)) { 'Uncategorized' } else { $finding.Category }
        $w   = [int]$finding.Weight

        if (-not $categoryPoints.ContainsKey($cat)) {
            $categoryPoints[$cat]  = 0
            $categoryFactors[$cat] = 1.0
            $categoryCounts[$cat]  = 0
        }
        $categoryPoints[$cat] += $w
        $categoryCounts[$cat]++
        $totalPoints += $w

        # Diminishing-returns accumulation: each finding "cleans away" a
        # fraction of the category's remaining headroom rather than adding
        # a flat number of points that can blow straight through the 0-100
        # ceiling. A finding's weight (0-100+, clamped here to 0-100) is
        # treated as the probability that this single finding alone would
        # justify a fully-saturated (100) category score; combining n
        # independent findings multiplies their "not-fully-bad" complements
        # together (categoryFactor), so the category score is
        # 100 * (1 - categoryFactor). This grows smoothly toward 100 as
        # findings accumulate instead of hard-capping the instant a
        # category's raw point sum crosses 100 - e.g. three Critical
        # (weight 40) findings in one category previously saturated it to
        # 100/100 outright; under this model they land at ~78/100, with the
        # remaining headroom closed out by further findings.
        $clampedWeight = [math]::Max(0, [math]::Min(100, $w))
        $categoryFactors[$cat] = $categoryFactors[$cat] * (1 - ($clampedWeight / 100.0))

        # MITRE technique tally
        if (-not [string]::IsNullOrEmpty($finding.MitreTechnique)) {
            if (-not $mitreCounts.ContainsKey($finding.MitreTechnique)) {
                $mitreCounts[$finding.MitreTechnique] = 0
            }
            $mitreCounts[$finding.MitreTechnique]++
        }

        # ANSSI level from the 'vuln<level>_' prefix -> maturity.
        if ($finding.AnssiControl -match '^vuln([1-5])_') {
            $lvl = [int]$Matches[1]
            if ($lvl -lt $minLevel) { $minLevel = $lvl }
        }

        switch ($finding.Severity) {
            'Critical' { $sevCounts.Critical++ }
            'High'     { $sevCounts.High++ }
            'Medium'   { $sevCounts.Medium++ }
            'Low'      { $sevCounts.Low++ }
            default    { $sevCounts.Info++ }
        }
    }

    # Per-category sub-scores via diminishing returns: Score = 100 * (1 - factor),
    # where factor is the product of (1 - weight/100) across every finding in
    # the category. Naturally bounded to (0, 100) with no explicit cap needed;
    # RawPoints is retained for transparency/debugging but no longer drives
    # the score directly.
    $categoryScores = foreach ($cat in $categoryFactors.Keys) {
        [PSCustomObject]@{
            Category   = $cat
            Score      = [int][math]::Round(100 * (1 - $categoryFactors[$cat]))
            Findings   = $categoryCounts[$cat]
            RawPoints  = $categoryPoints[$cat]
        }
    }
    $categoryScores = @($categoryScores | Sort-Object -Property Score, Findings -Descending)

    # Global score = worst category (an environment is only as strong as its
    # weakest risk area - the same worst-category philosophy as before, just
    # applied to the new diminishing-returns per-category score).
    $totalScore = 0
    if ($categoryScores.Count -gt 0) {
        $totalScore = ($categoryScores | Measure-Object -Property Score -Maximum).Maximum
    }

    # MITRE summary (technique id + name + count), most-frequent first.
    $mitreSummary = foreach ($id in $mitreCounts.Keys) {
        $name = if ($Script:MitreTechniqueNames.ContainsKey($id)) { $Script:MitreTechniqueNames[$id] } else { 'Unknown technique' }
        [PSCustomObject]@{
            Technique = $id
            Name      = $name
            Count     = $mitreCounts[$id]
        }
    }
    $mitreSummary = @($mitreSummary | Sort-Object -Property Count, Technique -Descending)

    return [PSCustomObject]@{
        TotalScore     = [int]$totalScore
        MaturityLevel  = [int]$minLevel
        MaturityLabel  = $maturityLabels[[int]$minLevel]
        CategoryScores = $categoryScores
        MitreSummary   = $mitreSummary
        FindingCount   = $Findings.Count
        WeightedPoints = $totalPoints
        SeverityCounts = [PSCustomObject]$sevCounts
        # See the empty-environment branch above for why this is a string,
        # not a raw [datetime].
        GeneratedDate  = (Get-Date).ToString('o')
        ModuleVersion  = $script:ModuleVersion
    }
}

#endregion
