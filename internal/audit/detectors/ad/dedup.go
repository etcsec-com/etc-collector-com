package ad

// ─────────────────────────────────────────────────────────────────────────────
// INTER-TYPE DE-DUPLICATION RULE (T_036)
//
// Read this before adding a detector whose findings could overlap an existing
// one. It is a rule, not a list of past fixes: the next detector must comply.
//
//	R1. One real defect is COUNTED once, at one granularity.
//
// Two findings are DUPLICATES when their predicates select the same population
// by construction — same condition, same object set, same granularity. Only the
// wording, the Type or the severity differ. One of them must go.
//
// Two findings are NOT duplicates when their predicates differ, even if their
// entity sets happen to coincide on a given domain. The test is the PREDICATE,
// never the observed set: a coincidence on one domain is not a duplication.
//
//	R2. When two detectors legitimately describe the same defect from different
//	    heights, they must differ in GRANULARITY, and only one carries the
//	    per-object list.
//
// The LAPS family is the reference implementation of R2:
//
//	COMPUTER_NO_LAPS          per-machine list   ← the only one carrying entities
//	LAPS_NOT_DEPLOYED         domain-level, binary: LAPS is absent domain-wide
//	LAPS_DOMAIN_COVERAGE_LOW  domain-level, metric: coverage percentage
//
// Before T_036 all three carried the same 72 machines, so a customer saw three
// problems where there is one. Now the 72 machines are counted once, and the
// two domain-level findings state something the per-machine list cannot.
//
//	R3. Multi-lens overlap is legitimate when one predicate is a strict subset
//	    of the other AND the narrower lens adds a decision the broader one does
//	    not support.
//
// Example (B_011): ADMIN_ASREP_ROASTABLE ⊂ ASREP_ROASTING_RISK. The narrower
// lens says "this one is privileged, treat it first". That is a priority
// signal, not a second copy of the defect. Kept deliberately.
//
//	R4. Deleting a detector requires proving nobody depended on it ALONE:
//	    - no true positive it reported is invisible elsewhere, and
//	    - every compliance control it mapped keeps another evidence source
//	      (internal/audit/compliance/mappings.go is keyed by detector ID; a
//	      deleted Type silently stops feeding its controls).
//
// R4 is why LAPS_NOT_DEPLOYED was repurposed rather than deleted: it is the
// only detector mapping ANSSI BP-039 R12 and PA-099 R30-, so removing it would
// have taken two controls out of the compliance score without saying so.
//
// Applied in T_036 — duplicates removed (predicate identical by construction):
//
//	REPLICATION_RIGHTS        ≡ ADMIN_COUNT_ORPHANED           (adminCount check)
//	SMARTCARD_NOT_REQUIRED    ≡ ADMIN_NO_SMARTCARD             (adminCount + UAC 0x40000)
//	UNIX_USER_PASSWORD        ≡ PASSWORD_CLEARTEXT_STORAGE     (UnixUserPassword || UserPassword)
//	ACL_FORCECHANGEPASSWORD   ≡ ACL_USER_FORCE_CHANGE_PASSWORD (same extended-right GUID)
//
// Applied in T_075 — B_032/B_011 (see accounts/privileged/not-in-protected-users.go
// and computers/other/pre-windows-2000.go for the full evidence):
//
//	NO_PROTECTED_USERS_MONITORING ≡ NOT_IN_PROTECTED_USERS (removed; the survivor's
//	    exclusions — built-in Administrator, SPN-bearing service accounts — make it
//	    the strictly more accurate implementation of the identical claim, and the
//	    removed one carried no compliance mapping, R4)
//	COMPUTER_PRE_WINDOWS_2000 ⊃ COMPUTER_OS_OBSOLETE_NT (repurposed, not removed:
//	    its "Windows NT|Windows 2000" branch was byte-identical to
//	    COMPUTER_OS_OBSOLETE_NT's whole predicate — verified live, both matched
//	    exactly one machine, LEGACY-NT4-SRV$ — narrowed to the Windows 95/98
//	    strings COMPUTER_OS_OBSOLETE_NT never covered, R4)
//
// REPLICATION_RIGHTS's own compliance-mapping entry (internal/audit/compliance/
// mappings.go, keyed by the now-dead detector ID) was left behind by T_036 and
// stayed orphaned through T_075 while that file sat outside ad's files_owned.
// Removed in T_108 once mappings.go was opened: DCSYNC_CAPABLE already carried
// the identical {R6, R12, R22, R23, M9} set, so no coverage was lost.
//
// Kept as distinct defects despite identical or near-identical entity sets on
// DC01 (different predicates — R1 second paragraph):
//
//	ADMIN_AUDIT_BYPASS vs ADMIN_NO_SMARTCARD vs NOT_IN_PROTECTED_USERS
//	    "privileged, unprotected AND password 6+ months old" vs "privileged
//	    without smartcard" vs "privileged and not in Protected Users" — three
//	    different conditions (T_075: the first adds a password-age test the
//	    other two don't have) that happened to select the same 7 (or, for the
//	    narrower one, 4) accounts on this lab. Different remediations.
//	ANSSI_R6_INACTIVE_ACCOUNTS vs STALE_ACCOUNT (T_075)
//	    90-day vs 180-day inactivity threshold, on slightly different fields
//	    (max(LastLogonTimestamp, LastLogon) vs LastLogon alone) — genuinely
//	    different conditions that landed on the same 15 accounts only because
//	    this domain has nobody inactive 90-179 days. R6 also feeds the ANSSI
//	    compliance score; STALE_ACCOUNT does not.
//	KERBEROS_AES_DISABLED vs WEAK_ENCRYPTION_RC4 vs SERVICE_ACCOUNT_WEAK_ENCRYPTION (T_075)
//	    all-users/no-AES-at-all vs all-users/RC4-specifically vs
//	    service-accounts-only/DES-or-RC4 — different population scope (all
//	    users vs service accounts) and different bit coverage; only 2 accounts
//	    coincided on this lab.
//	ANSSI_R36_CA_RISKS vs ANSSI_R37_WEAK_CERT_TEMPLATES
//	    two distinct ANSSI controls; a compliance report must answer both
//	    questions separately even when the same object triggers them.
//
// ─────────────────────────────────────────────────────────────────────────────
