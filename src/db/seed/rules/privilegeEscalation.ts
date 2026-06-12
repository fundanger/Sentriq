import type { RuleSeed } from "../types";

export const privilegeEscalationRules: RuleSeed[] = [
  // --- PrintNightmare (Sigma + KQL) ---
  {
    family: {
      id: "fam-printnightmare",
      name: "PrintNightmare Print Spooler Privilege Escalation (CVE-2021-34527)",
      slug: "printnightmare-print-spooler-privesc",
      categoryId: "cat-privilege-escalation",
      conceptDescription:
        "PrintNightmare (CVE-2021-34527, closely related to CVE-2021-1675) is a vulnerability in the Windows Print Spooler service that allows a low-privileged authenticated user - or, in the remote variant, an unauthenticated attacker with access to the spooler's RPC interface - to install a malicious printer driver that executes code with SYSTEM privileges. The Print Spooler service runs as SYSTEM and is enabled by default on virtually all Windows systems including domain controllers, making this vulnerability particularly severe: a foothold on any domain-joined machine could be escalated directly to SYSTEM, and on a domain controller, to full domain compromise.\n\nThe exploit works by calling the `RpcAddPrinterDriverEx` (or `RpcAsyncAddPrinterDriver`) RPC function exposed by the spooler service, pointing it at a malicious driver DLL staged on an accessible share (often via the attacker's own SMB server, or a world-writable network path). The spooler service, running as SYSTEM, loads and executes this DLL - granting the attacker a SYSTEM-level process.\n\nThe most reliable detection artifact is the Print Spooler service (`spoolsv.exe`) loading a DLL from a non-standard driver directory or spawning a child process - normal printer driver installation loads drivers from `%SystemRoot%\\System32\\spool\\drivers\\` via legitimate, signed driver packages installed through the Add Printer wizard or Group Policy, and `spoolsv.exe` does not normally spawn child processes at all. Microsoft's PrintNightmare-specific patches also added Event ID 808 (driver load blocked due to not meeting signature requirements) and enhanced Event ID 316 logging in the PrintService operational log, which provide direct signals when 'RestrictDriverInstallationToAdministrators' policies block an exploitation attempt.",
    },
    variants: [
      {
        id: "rule-printnightmare-sigma",
        language: "sigma",
        title: "PrintNightmare - Print Spooler Spawning Child Process or Loading Driver from Unusual Path",
        slug: "printnightmare-spoolsv-child-process-sigma",
        descriptionSummary:
          "Detects spoolsv.exe (Print Spooler service) spawning a child process, or loading a printer driver DLL from a path outside the standard driver store - the core indicator of PrintNightmare exploitation.",
        ruleBody: `title: PrintNightmare - Print Spooler Service Spawning Child Process
id: 7b8c9d0e-1f2a-4b3c-9d4e-5f6a7b8c9d0e
status: stable
description: |
    Detects the Print Spooler service (spoolsv.exe) spawning any child process, or
    loading a DLL/driver from a path outside the standard driver store
    (%SystemRoot%\\System32\\spool\\drivers\\). spoolsv.exe does not legitimately spawn
    child processes during normal printer driver installation or print job processing.
    This behavior is the primary indicator of PrintNightmare (CVE-2021-34527) exploitation.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-34527
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
author: Sentriq Detection Engineering
date: 2021-07-02
tags:
    - attack.privilege_escalation
    - attack.t1068
    - cve.2021.34527
logsource:
    category: process_creation
    product: windows
detection:
    selection_child_process:
        ParentImage|endswith: '\\spoolsv.exe'
    filter_legit_drivers:
        Image|startswith: 'C:\\Windows\\System32\\spool\\drivers\\'
    condition: selection_child_process and not filter_legit_drivers
falsepositives:
    - Extremely rare; some third-party print management software has been known to interact with spoolsv.exe in non-standard ways - verify against an inventory of installed print management products before excluding
level: critical
---
title: PrintNightmare - Driver Load from Non-Standard Path via Spooler
id: 8c9d0e1f-2a3b-4c4d-8e5f-6a7b8c9d0e1f
status: stable
description: |
    Detects DLL/image load events by spoolsv.exe from paths outside the standard
    driver store directory, indicating a malicious printer driver was loaded as
    part of PrintNightmare exploitation.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-34527
author: Sentriq Detection Engineering
date: 2021-07-02
tags:
    - attack.privilege_escalation
    - attack.t1068
    - cve.2021.34527
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\\spoolsv.exe'
    filter:
        ImageLoaded|startswith: 'C:\\Windows\\System32\\spool\\drivers\\'
    filter_system:
        ImageLoaded|startswith: 'C:\\Windows\\System32\\'
    condition: selection and not (filter or filter_system)
falsepositives:
    - None known when properly scoped to spoolsv.exe image-load events outside both the driver store and core System32
level: critical`,
        ruleFormatVersion: "Sigma Schema 2.0 (multi-document)",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.1",
        falsePositiveNotes:
          "These rules have an extremely low false-positive rate by design - `spoolsv.exe` spawning any child process or loading any DLL outside `System32` and the driver store is abnormal in virtually all environments. The rare exception is specialized enterprise print-management suites (PaperCut, PrinterLogic) that sometimes install helper components interacting closely with the spooler; if deployed, baseline these specific products' behavior during a pilot period and add narrow exclusions for their specific signed binaries/paths. Any hit on a domain controller should be treated as a Sev1 incident regardless of any pending exclusions, given the domain-compromise blast radius.",
        dataSourceRequirements:
          "Sysmon Event ID 1 (Process Create) and Event ID 7 (Image Load - note: Sysmon image-load logging can be high-volume; scope this specific rule's image-load collection to spoolsv.exe via Sysmon config ProcessImage filtering to control volume).",
        mitreTechniqueIds: ["T1068"],
        cveIds: ["CVE-2021-34527"],
        tags: ["PrintNightmare", "Print Spooler", "Privilege Escalation"],
        references: [
          {
            url: "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
            title: "NVD - CVE-2021-34527",
            referenceType: "cve_record",
          },
          {
            url: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
            title: "Microsoft Security Response Center - CVE-2021-34527",
            referenceType: "vendor_advisory",
          },
        ],
      },
      {
        id: "rule-printnightmare-kql",
        language: "kql",
        platformVariant: "Microsoft Sentinel / Defender for Endpoint",
        title: "PrintNightmare - New Printer Driver Installed via RPC Followed by SYSTEM Process Creation",
        slug: "printnightmare-driver-install-system-process-kql",
        descriptionSummary:
          "Detects new printer driver installation events (Event ID 808/Operational PrintService log) on domain controllers and servers, correlated with spoolsv.exe spawning a SYSTEM-level process shortly after.",
        ruleBody: `// PrintNightmare detection: driver installation correlated with spoolsv.exe child process
// Data sources: DeviceProcessEvents (Defender for Endpoint), Event (PrintService Operational log)
let SpoolerChildProcesses =
    DeviceProcessEvents
    | where Timestamp >= ago(1d)
    | where InitiatingProcessFileName =~ "spoolsv.exe"
    | where FileName !~ "spoolsv.exe"
    | project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName=InitiatingProcessAccountName;
let DriverInstallEvents =
    Event
    | where Source == "Microsoft-Windows-PrintService"
    | where EventID in (808, 316)
    | project InstallTime = TimeGenerated, Computer, EventID, RenderedDescription;
SpoolerChildProcesses
| extend Computer = DeviceName
| join kind=leftouter DriverInstallEvents on Computer
| where InstallTime between ((Timestamp - 5m) .. Timestamp) or isempty(InstallTime)
| extend
    HostCustomEntity = DeviceName,
    AccountCustomEntity = AccountName,
    IsDomainController = DeviceName has_any (dynamic(["DC01","DC02","-DC-"])), // adjust to your DC naming convention
    Verdict = "Print Spooler spawned unexpected child process - confirmed PrintNightmare exploitation pattern"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, EventID, RenderedDescription, IsDomainController, Verdict
| order by Timestamp desc`,
        ruleFormatVersion: "Sentinel Analytics Rule / Defender Advanced Hunting",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "Same considerations as the Sigma variant apply - the `SpoolerChildProcesses` portion alone is already extremely high-fidelity. The driver-install-event join is a corroborating signal but uses `leftouter` specifically because PrintNightmare exploitation does not always generate the PrintService operational log events depending on patch level and policy configuration - absence of a matching driver-install event should NOT be treated as reducing confidence; the spooler child-process event alone is sufficient for escalation. The `IsDomainController` flag should be customized to match your actual DC naming convention or, better, joined against an asset-inventory table with a `Role` field rather than a name-substring match.",
        dataSourceRequirements:
          "Microsoft Defender for Endpoint DeviceProcessEvents table; Windows Event Log Microsoft-Windows-PrintService/Operational (Event IDs 808, 316) forwarded to the same workspace.",
        mitreTechniqueIds: ["T1068"],
        cveIds: ["CVE-2021-34527"],
        tags: ["PrintNightmare", "Print Spooler", "Domain Controller"],
        references: [
          {
            url: "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
            title: "NVD - CVE-2021-34527",
            referenceType: "cve_record",
          },
        ],
      },
    ],
  },

  // --- Zerologon (Sigma) ---
  {
    family: {
      id: "fam-zerologon",
      name: "Zerologon Netlogon Privilege Escalation (CVE-2020-1472)",
      slug: "zerologon-netlogon-privesc",
      categoryId: "cat-privilege-escalation",
      conceptDescription:
        "Zerologon (CVE-2020-1472) is a critical vulnerability in the Netlogon Remote Protocol (MS-NRPC) caused by a cryptographic flaw in the AES-CFB8 implementation used for the Netlogon authentication handshake. The flaw allows an attacker with network access to a domain controller to bypass authentication entirely by sending a sequence of `NetrServerAuthenticate3` RPC calls with an all-zero client challenge and credential - due to the cryptographic weakness, this combination has roughly a 1-in-256 chance of producing a valid authentication, and the attacker simply retries until it succeeds (typically within seconds).\n\nOnce authenticated as the domain controller's own computer account (or any computer account), the attacker can call `NetrServerPasswordSet2` to reset the domain controller's machine account password to an empty/known value - effectively taking control of the domain controller's own AD identity. From there, the attacker can perform a DCSync attack to extract all domain credential hashes (including krbtgt, enabling Golden Ticket attacks), making this one of the most severe vulnerabilities ever assigned a CVSS score of 10.0.\n\nDetection focuses on the highly anomalous authentication pattern: a high volume of `NetrServerReqChallenge`/`NetrServerAuthenticate3` Netlogon RPC calls in rapid succession from a single source within a very short time window (the brute-force nature of the exploit requires many attempts), combined with Event ID 5829 (logged by patched/mitigation-mode DCs when a vulnerable Netlogon connection is attempted) or, on unpatched systems, network-layer detection of the characteristic all-zero authenticator pattern in Netlogon RPC traffic (RPC port 135 + dynamic high ports, or named pipe `\\\\<DC>\\netlogon`).",
    },
    variants: [
      {
        id: "rule-zerologon-sigma",
        language: "sigma",
        title: "Zerologon - High-Volume Netlogon Authentication Attempts from Single Source",
        slug: "zerologon-netlogon-bruteforce-sigma",
        descriptionSummary:
          "Detects Event ID 5829 (vulnerable Netlogon authentication attempt logged by mitigation-enforcing DCs) or an abnormally high volume of Netlogon session events from a single non-DC source in a short window.",
        ruleBody: `title: Zerologon - Vulnerable Netlogon Authentication Attempt
id: 9d0e1f2a-3b4c-4d5e-9f6a-7b8c9d0e1f2a
status: stable
description: |
    Detects Event ID 5829, logged on domain controllers running in Netlogon
    "Enforcement mode" (post-August 2020 patch) whenever a client attempts a
    vulnerable Netlogon secure channel connection - i.e., an active Zerologon
    (CVE-2020-1472) exploitation attempt. Also detects an abnormally high rate
    of Netlogon authentication events (Event ID 4742 - computer account changed,
    often following successful exploitation) from non-domain-controller sources.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2020-1472
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472
author: Sentriq Detection Engineering
date: 2020-09-15
tags:
    - attack.privilege_escalation
    - attack.t1068
    - cve.2020.1472
logsource:
    product: windows
    service: system
detection:
    selection_enforcement_mode:
        EventID: 5829
        Channel: 'System'
    selection_computer_account_change:
        EventID: 4742
        Channel: 'Security'
    condition: selection_enforcement_mode or selection_computer_account_change
falsepositives:
    - selection_computer_account_change can occur during legitimate domain-join operations, computer account password rotations (default 30-day machine account password change), or re-imaging - high volume from a SINGLE source IP in a short window is the key differentiator, not the event alone
level: critical`,
        ruleFormatVersion: "Sigma Schema 2.0",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.1",
        falsePositiveNotes:
          "Event ID 5829 has essentially zero false-positive rate - it is ONLY logged when a client attempts a connection that would be vulnerable under the pre-patch Netlogon implementation, which legitimate, fully-patched Windows clients never do. Event ID 4742 (computer account changed) is common in normal AD operations (machine account password rotation every 30 days by default) - this sub-selection should be tuned with a volume threshold (e.g., more than 3 occurrences from the same source within 5 minutes) before alerting at critical severity, since the raw event alone is too common. Any organization still running domain controllers without the August 2020 + enforcement-mode update is at active risk and should prioritize patching over relying solely on detection.",
        dataSourceRequirements:
          "Windows System and Security Event Logs from domain controllers (Event IDs 5829, 4742), forwarded to the SIEM. Requires DCs to be running with Netlogon enforcement mode enabled (default since the February 2021 update) to generate Event ID 5829.",
        mitreTechniqueIds: ["T1068", "T1003"],
        cveIds: ["CVE-2020-1472"],
        tags: ["Zerologon", "Netlogon", "Domain Controller", "DCSync"],
        references: [
          {
            url: "https://nvd.nist.gov/vuln/detail/CVE-2020-1472",
            title: "NVD - CVE-2020-1472",
            referenceType: "cve_record",
          },
          {
            url: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472",
            title: "Microsoft Security Response Center - CVE-2020-1472",
            referenceType: "vendor_advisory",
          },
        ],
      },
    ],
  },
];
