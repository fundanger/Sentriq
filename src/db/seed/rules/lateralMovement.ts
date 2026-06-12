import type { RuleSeed } from "../types";

export const lateralMovementRules: RuleSeed[] = [
  // --- Pass-the-Hash (KQL) ---
  {
    family: {
      id: "fam-pass-the-hash",
      name: "Pass-the-Hash Lateral Movement",
      slug: "pass-the-hash-lateral-movement",
      categoryId: "cat-lateral-movement",
      conceptDescription:
        "Pass-the-Hash (PtH) is a lateral movement technique where an attacker who has obtained an NTLM password hash (via LSASS dumping, SAM database extraction, or similar credential-access techniques) uses that hash directly to authenticate to other systems, without ever needing to know or crack the underlying plaintext password. NTLM authentication is fundamentally challenge-response based on the hash itself, so possessing the hash is functionally equivalent to possessing the password for authentication purposes.\n\nIn practice, an attacker uses tools like Mimikatz's `sekurlsa::pth` module, Impacket's `psexec.py`/`wmiexec.py` with the `-hashes` flag, or CrackMapExec to inject the stolen hash into a new logon session and then connect to a remote host via SMB, WMI, or RDP (in restricted-admin mode). The resulting authentication on the target system shows up as a Logon Type 3 (Network) or Logon Type 9 (NewCredentials) event using NTLM rather than Kerberos - which is itself anomalous in a well-configured Active Directory environment where Kerberos is the default and expected authentication protocol for domain-joined systems.\n\nThe most reliable detection signal is the combination of: (1) NTLM authentication (rather than Kerberos) for a logon from one workstation/server to another, (2) the authenticating account being a privileged account (Domain Admin, Server Admin) that would not normally interactively log onto end-user workstations, and (3) the logon occurring without a corresponding interactive session (no console logon, just network-type authentication). Microsoft's Local Administrator Password Solution (LAPS) and Protected Users security group are the primary mitigations, but detection remains important for environments mid-way through hardening or for catching PtH against service accounts that can't use LAPS.",
    },
    variants: [
      {
        id: "rule-pass-the-hash-kql",
        language: "kql",
        platformVariant: "Microsoft Sentinel",
        title: "Pass-the-Hash: NTLM Authentication from Privileged Account to Multiple Hosts",
        slug: "pass-the-hash-ntlm-privileged-kql",
        descriptionSummary:
          "Detects NTLM (not Kerberos) network logons by privileged accounts to multiple distinct hosts within a short time window, indicating possible Pass-the-Hash lateral movement.",
        ruleBody: `// Pass-the-Hash detection: NTLM network logons by privileged accounts
// to multiple hosts in a short window
// Data source: SecurityEvent (Windows Security Event Log, forwarded to Sentinel)
let PrivilegedGroups = dynamic(["Domain Admins", "Enterprise Admins", "Server Operators"]);
let lookback = 1h;
SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID == 4624  // Successful logon
| where LogonType in (3, 9)  // Network or NewCredentials
| where AuthenticationPackageName =~ "NTLM"
| where isnotempty(TargetUserName)
| where TargetUserName !endswith "$"  // exclude machine accounts
// Join against a privileged-account reference list maintained separately
// (e.g., from IdentityInfo table or a watchlist)
| join kind=inner (
    IdentityInfo
    | where AssignedRoles has_any (PrivilegedGroups) or GroupMembership has_any (PrivilegedGroups)
    | project AccountUPN = tolower(AccountUPN)
  ) on $left.TargetUserName == $right.AccountUPN
| summarize
    DistinctHosts = dcount(Computer),
    Hosts = make_set(Computer),
    SourceIPs = make_set(IpAddress),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by TargetUserName
| where DistinctHosts >= 3
| extend AccountCustomEntity = TargetUserName
| project FirstSeen, LastSeen, TargetUserName, DistinctHosts, Hosts, SourceIPs`,
        ruleFormatVersion: "Sentinel Analytics Rule (KQL)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.1",
        falsePositiveNotes:
          "Legitimate administrative tools that don't support Kerberos delegation (some older remote management software, certain backup agents running under service accounts) can produce NTLM network logons from privileged accounts to many hosts - particularly vulnerability scanners authenticating with domain admin credentials for credentialed scans. Maintain an exclusion list of known-good source IPs for scanner/management infrastructure, and consider raising the `DistinctHosts` threshold in environments with such tooling. A genuine PtH attack typically shows logons originating from a single non-standard source IP/host (the attacker's pivot point) rather than from the expected management server - cross-reference `SourceIPs` against your asset inventory of authorized admin jump hosts.",
        dataSourceRequirements:
          "Windows Security Event Log forwarded to Sentinel (SecurityEvent table, Event ID 4624), with Logon Type and Authentication Package fields populated. IdentityInfo table populated via Microsoft Defender for Identity or Entra ID for privileged-group membership lookups.",
        mitreTechniqueIds: ["T1550.002", "T1021.002"],
        cveIds: [],
        tags: ["Pass-the-Hash", "NTLM", "Active Directory", "Lateral Movement"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1550/002/",
            title: "MITRE ATT&CK - Pass the Hash",
            referenceType: "mitre_page",
          },
          {
            url: "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory",
            title: "Microsoft - Protected Accounts and Groups in Active Directory",
            referenceType: "documentation",
          },
        ],
      },
    ],
  },

  // --- PsExec Lateral Movement (Sigma + Elastic) ---
  {
    family: {
      id: "fam-psexec-lateral-movement",
      name: "PsExec-Style Remote Service Execution",
      slug: "psexec-remote-service-execution",
      categoryId: "cat-lateral-movement",
      conceptDescription:
        "PsExec (a legitimate Sysinternals tool) and its open-source equivalents (Impacket's psexec.py, CrackMapExec, etc.) enable remote command execution by connecting to a target's SMB/admin shares (`\\\\target\\C$\\` or `\\\\target\\ADMIN$\\`), copying over a service executable, registering it as a Windows service via the Service Control Manager (SCM), starting the service to execute the attacker's payload, and then cleaning up by stopping and deleting the service. This is one of the oldest and still most common lateral movement techniques because it works on stock Windows with valid administrative credentials - no exploit required.\n\nThe technique leaves a very consistent forensic signature on the target host: (1) a new file is written to `\\Windows\\` (the default PsExec service binary, often named `PSEXESVC.exe` for genuine PsExec but can be renamed for impacket/CME variants), (2) a new service is created in the registry (`HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>`) and logged as Event ID 7045 (Service Installed), (3) the service process spawns with a parent of `services.exe`, and (4) shortly afterward the service and its binary are often deleted.\n\nDetection focuses on Event ID 7045 (a new service was installed on the system) combined with characteristics suggesting a remote, non-standard service: a binary path pointing to a temporary or unusual directory, a service name that is a random string or matches known tool defaults (PSEXESVC, RemComSvc), or the source being a remote SMB session rather than local installation via an MSI/installer.",
    },
    variants: [
      {
        id: "rule-psexec-sigma",
        language: "sigma",
        title: "PsExec-Style Lateral Movement - Suspicious Service Installation",
        slug: "psexec-suspicious-service-install-sigma",
        descriptionSummary:
          "Detects Windows Event ID 7045 (service installed) with characteristics typical of PsExec, Impacket psexec.py, or similar remote-service-based lateral movement tools.",
        ruleBody: `title: PsExec-Style Remote Service Installation
id: 1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e
status: stable
description: |
    Detects the installation of a new Windows service (Event ID 7045) with a name or
    binary path commonly associated with PsExec and its open-source equivalents
    (Impacket psexec.py, CrackMapExec, RemCom), used for remote command execution
    as part of lateral movement.
references:
    - https://attack.mitre.org/techniques/T1021/002/
    - https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec
author: Sentriq Detection Engineering
date: 2022-02-14
tags:
    - attack.lateral_movement
    - attack.execution
    - attack.t1021.002
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName|contains:
            - 'PSEXESVC'
            - 'PAExec'
            - 'RemComSvc'
    selection_generic_path:
        EventID: 7045
        ImagePath|contains:
            - '\\Windows\\Temp\\'
            - '\\ADMIN$\\'
            - '\\\\\\\\'   # UNC path in image path - unusual for legitimate services
    selection_random_name:
        EventID: 7045
        ServiceName|re: '^[A-Za-z0-9]{8,16}$'
        ServiceFileName|endswith: '.exe'
    condition: selection or (selection_generic_path) or (selection_random_name)
falsepositives:
    - Legitimate use of PsExec by IT administrators for remote troubleshooting
    - Software deployment tools (SCCM, etc.) that install services with randomized temporary names
level: high`,
        ruleFormatVersion: "Sigma Schema 2.0",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.2",
        falsePositiveNotes:
          "Legitimate IT administration via genuine PsExec is common in many environments - the `PSEXESVC` name match alone will fire on authorized use. To reduce noise, correlate the source IP/account against a list of authorized admin workstations and helpdesk jump hosts; an alert where the source account is NOT a member of the helpdesk/IT admin group, or the source host is not a known admin workstation, should be prioritized. The `selection_random_name` sub-rule is the noisiest - software deployment tools (SCCM, Intune, PDQ Deploy) frequently install short-lived services with randomized names during package installation; tune by excluding `ImagePath` prefixes matching your software deployment tool's working directories (e.g., `C:\\Windows\\ccmcache\\`).",
        dataSourceRequirements:
          "Windows System Event Log (Event ID 7045 - Service Control Manager), forwarded to the SIEM.",
        mitreTechniqueIds: ["T1021.002", "T1569.002"],
        cveIds: [],
        tags: ["PsExec", "Lateral Movement", "Service Creation"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1021/002/",
            title: "MITRE ATT&CK - SMB/Windows Admin Shares",
            referenceType: "mitre_page",
          },
          {
            url: "https://attack.mitre.org/techniques/T1569/002/",
            title: "MITRE ATT&CK - Service Execution",
            referenceType: "mitre_page",
          },
        ],
      },
      {
        id: "rule-psexec-elastic",
        language: "elastic",
        platformVariant: "ES|QL / EQL",
        title: "PsExec-Style Lateral Movement - services.exe Spawning Suspicious Child Process",
        slug: "psexec-services-exe-child-process-elastic",
        descriptionSummary:
          "EQL rule detecting services.exe spawning a process from an admin-share or temp path immediately after a remote SMB logon, indicating PsExec-style remote service execution.",
        ruleBody: `// Elastic Security - EQL rule
// Detects services.exe spawning an executable from a path consistent with
// PsExec/Impacket-style remote service execution, combined with a recent
// Type 3 (network) logon on the host.

sequence by host.id with maxspan=2m
  [authentication where event.action == "logged-in" and winlog.logon.type == "Network" and event.outcome == "success"]
  [process where event.type == "start" and process.parent.name : "services.exe" and (
      process.executable : "*\\\\Windows\\\\*.exe" and
      process.executable : ("*PSEXESVC*", "*PAExec*", "*RemCom*")
    ) or (
      process.executable : "*\\\\ADMIN$\\\\*"
    )
  ]

// --- Companion KQL-style query for Kibana Discover / detection rule ---
// process.parent.name : "services.exe" and
//   (process.name : "PSEXESVC.exe" or process.name : "PAExec*.exe" or process.name : "RemCom*.exe")`,
        ruleFormatVersion: "Elastic Security Detection Rule (EQL)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "As with the Sigma variant, genuine administrative PsExec use will match this sequence. The sequence requirement (a network logon followed within 2 minutes by services.exe spawning a matching process) reduces false positives compared to matching on process creation alone, since it ties the service execution to a remote authentication event rather than a locally-installed service. Tune the `maxspan` window based on observed latency between authentication and service start in your environment (typically a few seconds, but can be longer on loaded systems).",
        dataSourceRequirements:
          "Elastic Agent / Winlogbeat collecting both Security event log authentication events (winlog.logon.type) and Sysmon/process-creation events (process.parent.name).",
        mitreTechniqueIds: ["T1021.002", "T1569.002"],
        cveIds: [],
        tags: ["PsExec", "Lateral Movement", "Service Creation"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1021/002/",
            title: "MITRE ATT&CK - SMB/Windows Admin Shares",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },

  // --- RDP Brute Force (KQL) ---
  {
    family: {
      id: "fam-rdp-bruteforce",
      name: "RDP Brute Force and Spray Against Internet-Facing Hosts",
      slug: "rdp-brute-force-spray",
      categoryId: "cat-lateral-movement",
      conceptDescription:
        "Remote Desktop Protocol (RDP, TCP port 3389) is one of the most frequently targeted services for brute-force and credential-spraying attacks, particularly against internet-exposed servers (a persistent problem in cloud environments where security groups are misconfigured to allow 0.0.0.0/0 on port 3389). Attackers use tools like Hydra, NLBrute, or custom scripts to attempt logins against common usernames (administrator, admin, user) with large password lists, or to spray a small number of passwords across many discovered usernames.\n\nA successful RDP brute-force compromise is frequently the entry point for ransomware deployment - once an attacker has valid credentials for an RDP-exposed server, they gain an interactive graphical session with the privileges of the compromised account, from which they can disable security tooling, move laterally, and stage ransomware deployment.\n\nDetection relies on Windows Security Event Log Event ID 4625 (failed logon) with Logon Type 3 (Network) or Logon Type 10 (RemoteInteractive) from external IP addresses, looking for a high volume of failures against one or more accounts from the same or related source IPs in a short window, optionally followed by a successful Event ID 4624 from the same source IP - which would indicate the brute force succeeded. Network-layer detection (NSG flow logs, firewall logs) can also identify the connection volume pattern independent of authentication outcome.",
    },
    variants: [
      {
        id: "rule-rdp-bruteforce-kql",
        language: "kql",
        platformVariant: "Microsoft Sentinel",
        title: "RDP Brute Force - High-Volume Failed Logons Followed by Success",
        slug: "rdp-bruteforce-failed-then-success-kql",
        descriptionSummary:
          "Detects a high volume of failed RDP (RemoteInteractive/Network logon) attempts from a single external source IP, followed by a successful logon - indicating a successful RDP brute-force compromise.",
        ruleBody: `// RDP Brute Force detection: high-volume failures from external IP
// followed by a successful logon (Logon Type 10 = RemoteInteractive)
// Data source: SecurityEvent (Windows Security Event Log)
let FailureThreshold = 10;
let TimeWindow = 30m;
let FailedLogons =
    SecurityEvent
    | where TimeGenerated >= ago(1d)
    | where EventID == 4625
    | where LogonType in (3, 10)
    | where ipv4_is_match(IpAddress, "0.0.0.0/0") // external; refine with private-range exclusion below
    | where not(ipv4_is_in_any_range(IpAddress, dynamic(["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"])))
    | summarize
        FailureCount = count(),
        TargetAccounts = make_set(TargetUserName),
        FirstFailure = min(TimeGenerated),
        LastFailure = max(TimeGenerated)
        by IpAddress, Computer, bin(TimeGenerated, TimeWindow)
    | where FailureCount >= FailureThreshold;
let SuccessfulLogons =
    SecurityEvent
    | where TimeGenerated >= ago(1d)
    | where EventID == 4624
    | where LogonType in (3, 10)
    | project SuccessTime = TimeGenerated, SuccessAccount = TargetUserName, IpAddress, Computer;
FailedLogons
| join kind=inner SuccessfulLogons on IpAddress, Computer
| where SuccessTime between (FirstFailure .. (LastFailure + 1h))
| extend
    AccountCustomEntity = SuccessAccount,
    IPCustomEntity = IpAddress,
    HostCustomEntity = Computer
| project FirstFailure, LastFailure, SuccessTime, IpAddress, Computer, FailureCount, TargetAccounts, SuccessAccount
| order by FailureCount desc`,
        ruleFormatVersion: "Sentinel Analytics Rule (KQL)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.2",
        falsePositiveNotes:
          "Users who repeatedly mistype their own password before eventually succeeding (e.g., after a recent password change before muscle memory adjusts) can trigger this if the failure count crosses the threshold within the window - however, this scenario almost always originates from an internal/known IP rather than an external one, which this rule already filters for. Corporate VPN exit nodes or NAT gateways shared by many users can produce a 'single source IP, many accounts, eventually one succeeds' pattern that resembles password spraying but is benign; if your organization's remote users connect to RDP via a VPN concentrator, exclude that concentrator's egress IP range explicitly rather than relying on the private-range exclusion (which won't catch a public-IP VPN gateway).",
        dataSourceRequirements:
          "Windows Security Event Log (Event IDs 4624, 4625) forwarded to Sentinel from RDP-accessible hosts. For cloud-hosted VMs, ensure NSG flow logs are also available for a network-layer corroborating view.",
        mitreTechniqueIds: ["T1110.001", "T1021.001"],
        cveIds: [],
        tags: ["RDP", "Brute Force", "Ransomware Precursor"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1110/001/",
            title: "MITRE ATT&CK - Password Guessing",
            referenceType: "mitre_page",
          },
          {
            url: "https://attack.mitre.org/techniques/T1021/001/",
            title: "MITRE ATT&CK - Remote Desktop Protocol",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },
];
