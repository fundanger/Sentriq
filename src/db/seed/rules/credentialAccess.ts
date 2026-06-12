import type { RuleSeed } from "../types";

export const credentialAccessRules: RuleSeed[] = [
  // --- Kerberoasting family (KQL + Sigma) ---
  {
    family: {
      id: "fam-kerberoasting",
      name: "Kerberoasting - Suspicious Kerberos Service Ticket Requests",
      slug: "kerberoasting-service-ticket-requests",
      categoryId: "cat-credential-access",
      conceptDescription:
        "Kerberoasting is a credential access technique that targets Active Directory service accounts. Any authenticated domain user can request a Kerberos Ticket Granting Service (TGS) ticket for any service principal name (SPN) registered in the domain. The TGS ticket is encrypted using a hash derived from the service account's password. Because the requesting user can obtain this ticket without triggering any privileged operation, an attacker can request tickets for high-value service accounts (which often have weak, never-rotated passwords and elevated privileges) and then crack the ticket's encryption offline at unlimited speed using tools like Hashcat.\n\nWhat makes this technique attractive to attackers is that it requires no malware, no elevated access, and blends in with normal Kerberos traffic - a single Event ID 4769 (Kerberos Service Ticket was Requested) is generated whether the request is legitimate or malicious. Detection therefore focuses on the *pattern* of requests rather than a single event: a single user account requesting TGS tickets for an unusually large number of distinct SPNs in a short time window, especially when those tickets use the weaker RC4 (etype 0x17) encryption instead of AES, is a strong indicator of an automated Kerberoasting tool such as Rubeus or Impacket's GetUserSPNs.py.\n\nLegitimate activity that can resemble this includes administrative tools that enumerate SPNs for inventory purposes, and certain backup/monitoring software that authenticates to many services. Tuning should focus on excluding known service accounts used by legitimate scanning tools and on correlating ticket requests with subsequent offline cracking indicators (e.g., a spike in failed logons for the targeted service account shortly after).",
    },
    variants: [
      {
        id: "rule-kerberoasting-kql",
        language: "kql",
        platformVariant: "Microsoft Sentinel",
        title: "Kerberoasting: Multiple RC4 TGS Requests from a Single Account",
        slug: "kerberoasting-multiple-rc4-tgs-requests-kql",
        descriptionSummary:
          "Flags a single user account requesting an unusually high number of Kerberos service tickets using RC4 encryption within a short window, a hallmark of automated Kerberoasting tools.",
        ruleBody: `// Kerberoasting: Multiple RC4-encrypted TGS requests from a single account
// Data source: SecurityEvent (Windows Security Event Log forwarded to Sentinel)
// Requires Event ID 4769 auditing enabled on Domain Controllers
let lookback = 1h;
let ticketThreshold = 10;
SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID == 4769
| where TicketEncryptionType == "0x17" // RC4-HMAC, the weakest commonly issued type
| where ServiceName !endswith "$"      // exclude machine account requests
| summarize
    DistinctServicesRequested = dcount(ServiceName),
    ServiceNames = make_set(ServiceName, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by TargetUserName, IpAddress, Computer
| where DistinctServicesRequested >= ticketThreshold
| extend
    AccountCustomEntity = TargetUserName,
    IPCustomEntity = IpAddress
| project FirstSeen, LastSeen, TargetUserName, IpAddress, Computer, DistinctServicesRequested, ServiceNames
| order by DistinctServicesRequested desc`,
        ruleFormatVersion: "Sentinel Analytics Rule (Scheduled)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.2",
        falsePositiveNotes:
          "Service account inventory tools, SPN audit scripts, and some backup software (e.g., Veeam, Commvault agents performing pre-flight checks) can request many service tickets in a short window. Maintain an allow-list of known scanner/service accounts in a watchlist and exclude them with `| where TargetUserName !in (ServiceAccountAllowlist)`. If the threshold generates excessive noise in large environments, raise `ticketThreshold` to 15-20 and add a check for AES-only environments where RC4 should not appear at all - in that case, ANY RC4 TGS request is suspicious regardless of count.",
        dataSourceRequirements:
          "Requires the SecurityEvent table populated via Azure Monitor Agent or Microsoft Defender for Identity, with 'Audit Kerberos Service Ticket Operations' success auditing enabled on all Domain Controllers (Event ID 4769).",
        mitreTechniqueIds: ["T1558.003"],
        cveIds: [],
        tags: ["Active Directory", "Kerberos", "Service Accounts"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1558/003/",
            title: "MITRE ATT&CK - Kerberoasting",
            referenceType: "mitre_page",
          },
          {
            url: "https://www.thehacker.recipes/ad/movement/kerberos/kerberoast",
            title: "The Hacker Recipes - Kerberoasting",
            referenceType: "documentation",
          },
        ],
      },
      {
        id: "rule-kerberoasting-sigma",
        language: "sigma",
        title: "Kerberoasting: Suspicious Service Ticket Request Pattern",
        slug: "kerberoasting-suspicious-ticket-pattern-sigma",
        descriptionSummary:
          "Sigma rule detecting RC4-encrypted Kerberos TGS requests, which are anomalous in modern AES-enforced environments and commonly associated with Kerberoasting tools.",
        ruleBody: `title: Kerberoasting - RC4 Encrypted TGS Request
id: 8f7a2e1c-3b4d-4f6a-9c2e-1a2b3c4d5e6f
status: stable
description: |
    Detects Kerberos TGS requests (Event ID 4769) that use RC4 encryption (etype 0x17).
    In environments where AES is enforced via Kerberos encryption type policy, an RC4
    ticket request for a service account is a strong indicator of a Kerberoasting attempt
    using tools such as Rubeus, Impacket GetUserSPNs.py, or PowerView's Invoke-Kerberoast.
references:
    - https://attack.mitre.org/techniques/T1558/003/
    - https://github.com/GhostPack/Rubeus
author: Sentriq Detection Engineering
date: 2024-01-15
modified: 2024-06-02
tags:
    - attack.credential_access
    - attack.t1558.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
    filter_machine_accounts:
        TargetUserName|endswith: '$'
    filter_anonymous:
        TargetUserName: 'ANONYMOUS LOGON'
    condition: selection and not filter_machine_accounts and not filter_anonymous
falsepositives:
    - Legacy applications or devices that only support RC4 (rare in modern environments)
    - Environments that have not enforced AES-only Kerberos policy (msDS-SupportedEncryptionTypes)
level: medium`,
        ruleFormatVersion: "Sigma Schema 2.0",
        severity: "medium",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.1",
        falsePositiveNotes:
          "If your domain has not enforced AES Kerberos encryption (via Default Domain Policy 'Network security: Configure encryption types allowed for Kerberos'), RC4 tickets may be issued routinely for legacy systems, resulting in high false-positive volume. Before deploying at 'medium' severity, audit `msDS-SupportedEncryptionTypes` across service accounts; once AES is enforced domain-wide, raise this rule's severity to 'high' since RC4 requests become a true anomaly.",
        dataSourceRequirements:
          "Windows Security Event Log, Event ID 4769, forwarded via Sigma-compatible backend (Sentinel, Splunk, Elastic).",
        mitreTechniqueIds: ["T1558.003"],
        cveIds: [],
        tags: ["Active Directory", "Kerberos", "Service Accounts"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1558/003/",
            title: "MITRE ATT&CK - Kerberoasting",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },

  // --- AS-REP Roasting (KQL) ---
  {
    family: {
      id: "fam-asrep-roasting",
      name: "AS-REP Roasting - Accounts Without Kerberos Pre-Authentication",
      slug: "as-rep-roasting",
      categoryId: "cat-credential-access",
      conceptDescription:
        "AS-REP Roasting targets user accounts that have the 'Do not require Kerberos preauthentication' setting enabled (UF_DONT_REQUIRE_PREAUTH flag). For these accounts, an attacker can request an AS-REP (Authentication Server Response) message without supplying any credentials. The response contains a portion encrypted with a key derived from the target user's password, which the attacker can then crack offline.\n\nUnlike Kerberoasting, AS-REP Roasting doesn't even require the attacker to authenticate first - they only need to know (or guess) a valid username. This makes it especially dangerous against accounts with weak passwords. The technique is detectable because Event ID 4768 (a Kerberos authentication ticket was requested) will show `PreAuthType` as 0 or absent for these accounts, which is unusual for normally-configured accounts that require a pre-authentication timestamp.\n\nIn most well-managed environments, very few or zero accounts should have pre-authentication disabled, so any AS-REQ without pre-authentication - especially in volume or against multiple distinct usernames from a single source - warrants investigation.",
    },
    variants: [
      {
        id: "rule-asrep-roasting-kql",
        language: "kql",
        platformVariant: "Microsoft Sentinel",
        title: "AS-REP Roasting: Kerberos Pre-Authentication Disabled Abuse",
        slug: "as-rep-roasting-preauth-disabled-kql",
        descriptionSummary:
          "Detects AS-REQ requests without Kerberos pre-authentication, which can indicate AS-REP Roasting against accounts with 'Do not require Kerberos preauthentication' enabled.",
        ruleBody: `// AS-REP Roasting detection: AS-REQ without pre-authentication (PreAuthType absent/0)
// Data source: SecurityEvent, Event ID 4768
let lookback = 1h;
SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID == 4768
| where PreAuthType == "0" or isempty(PreAuthType)
| where TicketEncryptionType in ("0x17", "0x18") // RC4 or DES - typical for crackable AS-REP responses
| summarize
    DistinctAccountsTargeted = dcount(TargetUserName),
    Accounts = make_set(TargetUserName, 25),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by IpAddress
| where DistinctAccountsTargeted >= 1
| extend IPCustomEntity = IpAddress
| order by DistinctAccountsTargeted desc`,
        ruleFormatVersion: "Sentinel Analytics Rule (Scheduled)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "Some legacy applications and certain Linux Kerberos clients (older MIT krb5 configurations) may not send pre-authentication by default. Cross-reference any alerting accounts against the `Do not require Kerberos preauthentication` flag in their userAccountControl attribute - if the flag is set, this is expected behavior for that account and should be remediated (disable the flag) rather than continually tuned around. If the flag is NOT set but PreAuthType is still 0, investigate as a potential AS-REP roasting tool probing for vulnerable accounts.",
        dataSourceRequirements:
          "SecurityEvent table with Event ID 4768 auditing enabled ('Audit Kerberos Authentication Service' success/failure) on Domain Controllers.",
        mitreTechniqueIds: ["T1558.004"],
        cveIds: [],
        tags: ["Active Directory", "Kerberos", "Weak Configuration"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1558/004/",
            title: "MITRE ATT&CK - AS-REP Roasting",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },

  // --- LSASS Memory Dumping (Sigma + SentinelOne) ---
  {
    family: {
      id: "fam-lsass-dumping",
      name: "LSASS Memory Access for Credential Dumping",
      slug: "lsass-memory-credential-dumping",
      categoryId: "cat-credential-access",
      conceptDescription:
        "The Local Security Authority Subsystem Service (LSASS) process on Windows holds credential material in memory, including NTLM password hashes, Kerberos tickets, and in some configurations plaintext passwords (via WDigest or Credential Guard misconfigurations). Tools like Mimikatz, ProcDump (abused as a LOLBin), and Task Manager's 'Create dump file' feature can be used to read this memory and extract credentials for offline cracking or direct pass-the-hash attacks.\n\nThe detection approach centers on monitoring for processes that open a handle to lsass.exe with access rights that include memory-read permissions (PROCESS_VM_READ, PROCESS_QUERY_INFORMATION), particularly from processes that are not part of the expected set of system processes (which is essentially just other Windows components and approved EDR/AV agents). A second, complementary signal is monitoring for the creation of files with extensions or naming patterns consistent with memory dump output (.dmp) in combination with a handle being opened to lsass.exe.\n\nFalse positives primarily come from legitimate EDR, antivirus, and system diagnostic tools that routinely inspect LSASS for their own protective purposes - these need explicit exclusions based on signed, known-good binary paths and certificates.",
    },
    variants: [
      {
        id: "rule-lsass-dumping-sigma",
        language: "sigma",
        title: "Credential Dumping via LSASS Process Memory Access",
        slug: "lsass-process-memory-access-sigma",
        descriptionSummary:
          "Detects processes requesting high-privilege access to lsass.exe (PROCESS_VM_READ), a common precursor to credential dumping via Mimikatz or ProcDump.",
        ruleBody: `title: LSASS Memory Dump via Process Access
id: 4c6f3d2a-1e5b-4a8c-9f7d-2b3c4d5e6f7a
status: stable
description: |
    Detects access to the LSASS process with GrantedAccess rights that allow reading
    process memory (0x1010 or 0x1438 and similar masks), which is required to extract
    credential material using tools such as Mimikatz, ProcDump, or comsvcs.dll MiniDump.
references:
    - https://attack.mitre.org/techniques/T1003/001/
    - https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_lsass_dump.yml
author: Sentriq Detection Engineering
date: 2024-02-10
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    product: windows
    category: process_access
detection:
    selection_target:
        TargetImage|endswith: '\\lsass.exe'
    selection_access:
        GrantedAccess|endswith:
            - '0x1010'
            - '0x1410'
            - '0x1438'
            - '0x143a'
            - '0x1fffff'
    filter_known_tools:
        SourceImage|startswith:
            - 'C:\\Program Files\\Windows Defender\\'
            - 'C:\\ProgramData\\Microsoft\\Windows Defender\\'
            - 'C:\\Program Files\\CrowdStrike\\'
            - 'C:\\Program Files\\SentinelOne\\'
    condition: selection_target and selection_access and not filter_known_tools
falsepositives:
    - Endpoint protection products performing legitimate memory scans (add to filter_known_tools by install path)
    - Windows Error Reporting (WerFault.exe) during a genuine LSASS crash
level: high`,
        ruleFormatVersion: "Sigma Schema 2.0",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.3",
        falsePositiveNotes:
          "EDR and AV agents legitimately open high-privilege handles to LSASS. Build the `filter_known_tools` list from your actual deployed security stack's installation paths and code-signing certificate thumbprints rather than path alone, since path-based exclusions can be spoofed by an attacker placing a malicious binary in the same directory. WerFault.exe handling a real LSASS crash is rare but possible - correlate with EventID 1000 application error events for lsass.exe before dismissing as benign.",
        dataSourceRequirements:
          "Requires Sysmon Event ID 10 (ProcessAccess) with appropriate filtering rules to capture lsass.exe access, or equivalent EDR telemetry mapped to the 'process_access' Sigma category.",
        mitreTechniqueIds: ["T1003.001"],
        cveIds: [],
        tags: ["Credential Dumping", "LSASS", "Mimikatz"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1003/001/",
            title: "MITRE ATT&CK - OS Credential Dumping: LSASS Memory",
            referenceType: "mitre_page",
          },
        ],
      },
      {
        id: "rule-lsass-dumping-s1",
        language: "sentinelone",
        platformVariant: "STAR Rule / Deep Visibility",
        title: "Suspicious LSASS Access by Non-Standard Process",
        slug: "lsass-suspicious-process-access-s1",
        descriptionSummary:
          "SentinelOne Deep Visibility query identifying non-allow-listed processes opening handles to lsass.exe with memory-read access, indicative of credential dumping tools.",
        ruleBody: `// SentinelOne Deep Visibility Query (STAR Rule)
// Detects processes opening LSASS with memory-read access rights,
// excluding known-good security agents by signer.

event.type = "Process Access"
AND tgt.process.name = "lsass.exe"
AND src.process.image.path != "*\\\\Program Files\\\\SentinelOne\\\\*"
AND src.process.image.path != "*\\\\Windows\\\\System32\\\\svchost.exe"
AND src.process.publisher != "Microsoft Windows"
AND (
    ProcessAccess.AccessMask = "0x1010"
    OR ProcessAccess.AccessMask = "0x1410"
    OR ProcessAccess.AccessMask = "0x1438"
    OR ProcessAccess.AccessMask = "0x1fffff"
)

| group count() by src.process.name, src.process.image.path, src.process.user, endpoint.name
| having count() > 0`,
        ruleFormatVersion: "STAR Rule (Deep Visibility Query Language)",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "Tune the signer exclusion list (`src.process.publisher`) to include your organization's approved EDR/AV vendors beyond Microsoft. Some backup agents (e.g., Veeam Agent) that perform VSS-based snapshots may briefly touch LSASS - verify against your backup software's documented behavior and add a path-based exclusion for the specific backup binary if confirmed benign.",
        dataSourceRequirements:
          "SentinelOne agent with Deep Visibility enabled; STAR rules require an Enterprise/Complete tier license for custom detection rule creation.",
        mitreTechniqueIds: ["T1003.001"],
        cveIds: [],
        tags: ["Credential Dumping", "LSASS", "EDR"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1003/001/",
            title: "MITRE ATT&CK - OS Credential Dumping: LSASS Memory",
            referenceType: "mitre_page",
          },
          {
            url: "https://www.sentinelone.com/blog/deep-visibility-and-the-need-for-speed/",
            title: "SentinelOne - Deep Visibility Overview",
            referenceType: "vendor_advisory",
          },
        ],
      },
    ],
  },

  // --- Password Spraying (Sigma + Splunk) ---
  {
    family: {
      id: "fam-password-spraying",
      name: "Password Spraying Against Authentication Endpoints",
      slug: "password-spraying",
      categoryId: "cat-credential-access",
      conceptDescription:
        "Password spraying is a low-and-slow brute-force technique where an attacker attempts a small number of commonly used passwords (e.g., 'Summer2024!', 'Password123') against a large number of usernames, rather than many passwords against a single account. This approach is designed specifically to evade account lockout policies, which typically trigger only after several failed attempts against the *same* account within a time window - by spreading attempts across many accounts, the attacker stays under the per-account threshold while still achieving a meaningful overall success rate, since some fraction of users in any large organization will have chosen one of the sprayed passwords.\n\nThe detection signature is therefore at the aggregate level: a single source IP address (or small set of IPs, in the case of distributed spraying via botnets or residential proxies) generating authentication failures against an unusually large number of distinct usernames within a short window, typically followed by one or more successes. This is fundamentally different from a traditional brute-force signature (many failures against one account) and requires aggregation/grouping logic rather than simple threshold-per-account rules.\n\nCommon false positives include: misconfigured applications or scripts using stale/incorrect service account credentials against many resources, shared NAT egress IPs (e.g., corporate VPN exits, cloud NAT gateways) where many legitimate users' failed logins appear to originate from one IP, and password rotation events where many users are prompted to re-authenticate simultaneously.",
    },
    variants: [
      {
        id: "rule-password-spray-sigma",
        language: "sigma",
        title: "Password Spraying - High Volume of Failed Logons Across Distinct Accounts",
        slug: "password-spraying-distinct-accounts-sigma",
        descriptionSummary:
          "Detects a single source generating failed authentication attempts against many distinct user accounts within a short window - the signature of password spraying.",
        ruleBody: `title: Potential Password Spraying Attack
id: 9b1d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f
status: stable
description: |
    Detects an authentication source generating failed logon attempts (Event ID 4625)
    against an unusually high number of distinct target accounts within a short window,
    consistent with a password spraying attack designed to evade per-account lockout
    thresholds.
references:
    - https://attack.mitre.org/techniques/T1110/003/
author: Sentriq Detection Engineering
date: 2024-01-20
tags:
    - attack.credential_access
    - attack.t1110.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        LogonType:
            - 3   # Network
            - 8   # NetworkCleartext
    timeframe: 30m
    condition: selection | count(TargetUserName) by IpAddress > 15
falsepositives:
    - Shared corporate VPN/NAT egress IPs aggregating many users' legitimate auth attempts
    - Misconfigured service accounts retrying stale credentials against multiple resources
level: high`,
        ruleFormatVersion: "Sigma Schema 2.0 (Correlation)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.1",
        falsePositiveNotes:
          "Identify and allow-list known shared egress points (corporate VPN concentrators, cloud NAT gateway IPs) since these will naturally aggregate many users' legitimate failed logons (e.g., users who fat-finger their password). For these IPs, consider a much higher threshold (50+) or switch to per-user-agent or per-session correlation instead of pure IP-based grouping. Also monitor for a successful logon (Event ID 4624) from the same source shortly after the failure spike - this combination significantly increases confidence of a successful spray.",
        dataSourceRequirements:
          "Windows Security Event Log Event ID 4625 (An account failed to log on), aggregated across domain controllers. For cloud identity, use the equivalent Azure AD / Entra ID sign-in logs.",
        mitreTechniqueIds: ["T1110.003"],
        cveIds: [],
        tags: ["Brute Force", "Authentication", "Active Directory"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1110/003/",
            title: "MITRE ATT&CK - Password Spraying",
            referenceType: "mitre_page",
          },
        ],
      },
      {
        id: "rule-password-spray-splunk",
        language: "splunk",
        title: "Password Spray Detection - Windows Authentication Logs",
        slug: "password-spray-detection-splunk",
        descriptionSummary:
          "SPL search aggregating Windows EventCode=4625 failures by source address to surface password spraying activity against many distinct accounts.",
        ruleBody: `\`# Password Spraying Detection - Splunk SPL\`
\`# Searches Windows Security logs for EventCode=4625 (failed logon)\`
\`# and aggregates by source IP to find sprays against many distinct accounts\`

index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
    Logon_Type IN (3, 8)
| bucket _time span=30m
| stats
    dc(Account_Name) as distinct_accounts,
    values(Account_Name) as targeted_accounts,
    count as total_failures
    by _time, Source_Network_Address
| where distinct_accounts > 15
| eval risk_score = case(
    distinct_accounts > 50, "critical",
    distinct_accounts > 30, "high",
    true(), "medium"
)
| sort - distinct_accounts
| table _time, Source_Network_Address, distinct_accounts, total_failures, risk_score, targeted_accounts`,
        ruleFormatVersion: "SPL (Search Processing Language)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "As with the Sigma variant, shared NAT/VPN egress points are the primary false-positive source. Maintain a Splunk lookup table of known shared-egress IPs and use `NOT [| inputlookup known_shared_egress.csv]` to exclude them, or apply a higher threshold specifically for those IPs via a conditional eval.",
        dataSourceRequirements:
          "Windows Security Event Log (EventCode=4625) ingested into Splunk via Universal Forwarder or equivalent, indexed with sourcetype WinEventLog:Security.",
        mitreTechniqueIds: ["T1110.003"],
        cveIds: [],
        tags: ["Brute Force", "Authentication", "Active Directory"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1110/003/",
            title: "MITRE ATT&CK - Password Spraying",
            referenceType: "mitre_page",
          },
        ],
      },
      {
        id: "rule-password-spray-s1",
        language: "sentinelone",
        platformVariant: "STAR Rule / Singularity Identity",
        title: "Password Spray Pattern Against Many Distinct Accounts from Single Source",
        slug: "password-spraying-distinct-accounts-s1",
        descriptionSummary:
          "STAR rule over SentinelOne Singularity Identity / cloud-IdP login event data, flagging a single source IP generating failed authentications against an unusually high number of distinct usernames within a 30-minute window.",
        ruleBody: `// SentinelOne STAR Rule - Singularity Identity / IdP Login Events
// Detects a single source IP failing authentication against many distinct
// user accounts within a 30-minute window (password spraying).
//
// Source: identity provider login events ingested via SentinelOne's
// Identity connector (e.g., Okta, Entra ID, Active Directory) or the
// equivalent Deep Visibility "Login" event class for domain-joined endpoints.

event.category = "Login"
AND event.type = "Login Failure"

| group
    distinct_accounts = count_distinct(user.name),
    total_failures = count(),
    targeted_accounts = values(user.name)
    by src.ip.address, timeperiod(30m)

| filter distinct_accounts > 15

| eval severity = case(
    distinct_accounts > 50, "critical",
    distinct_accounts > 30, "high",
    true(), "medium"
)`,
        ruleFormatVersion: "STAR Rule (Deep Visibility Query Language)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "As with the Sigma/SPL variants, shared corporate VPN/NAT egress IPs are the dominant false-positive source for IP-based grouping - maintain an allow-list of known shared-egress addresses and either exclude them or apply a substantially higher threshold. If your IdP integration provides a `client.geo.asn` or similar field, consider grouping by ASN in addition to IP to catch distributed spraying from a single hosting provider's IP range. A successful login (`event.type = \"Login Success\"`) from the same source shortly after the failure spike should be correlated separately and treated as a high-confidence compromise indicator.",
        dataSourceRequirements:
          "SentinelOne Singularity Identity with a configured IdP connector (Okta, Entra ID, AD FS), or Deep Visibility Login events for domain-joined endpoints. STAR rules require an Enterprise/Complete tier license.",
        mitreTechniqueIds: ["T1110.003"],
        cveIds: [],
        tags: ["Brute Force", "Authentication", "Identity", "EDR"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1110/003/",
            title: "MITRE ATT&CK - Password Spraying",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },

  // --- Browser Credential Theft (SentinelOne) ---
  {
    family: {
      id: "fam-browser-cred-theft",
      name: "Browser-Stored Credential Theft",
      slug: "browser-credential-theft",
      categoryId: "cat-credential-access",
      conceptDescription:
        "Modern browsers (Chrome, Edge, Firefox) store saved passwords, cookies, and autofill data in local SQLite database files (e.g., `Login Data` for Chrome/Edge), encrypted using a key protected by the operating system's data protection APIs (DPAPI on Windows). Malware families such as RedLine Stealer, Vidar, and various commodity infostealers specifically target these files, often combined with a call to DPAPI functions (`CryptUnprotectData`) to decrypt the stored secrets using the logged-on user's context - no separate exploit is needed since the malware runs as the user.\n\nThe detection pattern focuses on process behavior: a non-browser process directly accessing browser profile directories (particularly files named 'Login Data', 'Cookies', or 'Web Data') combined with command-line indicators of staging or archiving (e.g., copying to a temp directory, creating a zip archive) is highly suspicious. Additionally, processes making DPAPI calls shortly after accessing these files strengthens the signal.\n\nLegitimate false positives include browser sync/backup utilities, enterprise password managers that import existing browser-saved credentials, and IT migration tools (e.g., profile migration during device refreshes).",
    },
    variants: [
      {
        id: "rule-browser-cred-theft-s1",
        language: "sentinelone",
        platformVariant: "STAR Rule / Deep Visibility",
        title: "Non-Browser Process Accessing Browser Credential Stores",
        slug: "non-browser-process-credential-store-access-s1",
        descriptionSummary:
          "Detects processes other than the browser itself reading 'Login Data', 'Cookies', or 'Web Data' files from Chrome/Edge profile directories, a common infostealer behavior.",
        ruleBody: `// SentinelOne Deep Visibility Query (STAR Rule)
// Detects non-browser processes reading browser credential store files

event.type = "File Open"
AND (
    tgt.file.path Contains "\\\\User Data\\\\Default\\\\Login Data"
    OR tgt.file.path Contains "\\\\User Data\\\\Default\\\\Cookies"
    OR tgt.file.path Contains "\\\\User Data\\\\Default\\\\Web Data"
)
AND NOT (
    src.process.name In ("chrome.exe", "msedge.exe", "brave.exe", "opera.exe")
)
AND NOT (
    src.process.image.path Contains "\\\\Program Files\\\\"
    AND src.process.publisher Matches "*Google*|*Microsoft*"
)

| group count() by src.process.name, src.process.image.path, src.process.cmdline, endpoint.name, tgt.file.path
| having count() > 0`,
        ruleFormatVersion: "STAR Rule (Deep Visibility Query Language)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "Enterprise password managers (1Password, Bitwarden, LastPass) with browser-import features will trigger this rule once during migration. Backup/sync agents (e.g., browser profile sync tools used in VDI environments) are a recurring source - add their signed binary paths to the exclusion list. Consider raising severity to critical only when combined with a subsequent network connection to a non-corporate destination or an archive-creation event (zip/rar) involving the same file.",
        dataSourceRequirements:
          "SentinelOne agent with Deep Visibility file activity monitoring enabled.",
        mitreTechniqueIds: ["T1555.003"],
        cveIds: [],
        tags: ["Infostealer", "Browser", "DPAPI"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1555/003/",
            title: "MITRE ATT&CK - Credentials from Web Browsers",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },
];
