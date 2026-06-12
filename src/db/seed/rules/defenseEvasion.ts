import type { RuleSeed } from "../types";

export const defenseEvasionRules: RuleSeed[] = [
  // --- Clear Event Logs (Sigma + KQL) ---
  {
    family: {
      id: "fam-clear-event-logs",
      name: "Windows Event Log Clearing",
      slug: "windows-event-log-clearing",
      categoryId: "cat-defense-evasion",
      conceptDescription:
        "Clearing Windows Event Logs is one of the clearest signals of malicious activity available to defenders, precisely because it has almost no legitimate use case in a managed enterprise environment. Attackers clear logs - via `wevtutil cl <logname>`, PowerShell's `Clear-EventLog`/`Remove-EventLog`, or directly through the Event Viewer GUI - to destroy the forensic record of their actions: failed and successful logons, process creations, scheduled task installations, and the log-clearing event itself (which is, ironically, also logged).\n\nThe self-referential nature of this technique is what makes it detectable: the act of clearing the Security event log generates Event ID 1102 ('The audit log was cleared'), and clearing the System log generates Event ID 104 ('The System log file was cleared') in that same log (or, since the System log was just cleared, in whatever log captured the clearing tool's execution). Because the clearing action itself is logged, and because this event is exceptionally rare in normal operations (perhaps occurring during legitimate log-rotation automation in some environments, but almost never via interactive `wevtutil` or PowerShell invocation), Event ID 1102/104 should be treated as a near-certain indicator of an attacker covering their tracks - typically occurring late in an intrusion, after the attacker has achieved their objectives (data theft, ransomware deployment) and is attempting to delay detection and complicate incident response.\n\nA sophisticated attacker who clears logs has usually already completed significant malicious activity; the detection therefore often serves less to 'catch the attack in progress' and more to trigger an immediate, high-priority incident response investigation into everything that happened on that host in the preceding hours/days, using whatever telemetry sources (EDR, network logs, other hosts' logs referencing this host) survived the clearing.",
    },
    variants: [
      {
        id: "rule-clear-event-logs-sigma",
        language: "sigma",
        title: "Windows Security or System Event Log Cleared",
        slug: "windows-event-log-cleared-sigma",
        descriptionSummary:
          "Detects Event ID 1102 (Security log cleared) or Event ID 104 (System log cleared) - both rare events with an extremely high correlation to anti-forensic activity by an active intruder.",
        ruleBody: `title: Windows Event Log Cleared
id: 5f6a7b8c-9d0e-4f1a-8b2c-3d4e5f6a7b8c
status: stable
description: |
    Detects the clearing of the Windows Security event log (Event ID 1102) or System
    event log (Event ID 104). Both events have an extremely low false-positive rate
    in managed enterprise environments and strongly indicate an attacker attempting
    to remove evidence of prior activity (anti-forensics). This event should trigger
    immediate, high-priority investigation of all activity on the host.
references:
    - https://attack.mitre.org/techniques/T1070/001/
author: Sentriq Detection Engineering
date: 2021-11-02
tags:
    - attack.defense_evasion
    - attack.t1070.001
logsource:
    product: windows
    service: security
detection:
    selection_security_log_cleared:
        EventID: 1102
    selection_system_log_cleared:
        EventID: 104
        Channel: 'System'
    condition: selection_security_log_cleared or selection_system_log_cleared
falsepositives:
    - Automated log-archival/rotation tooling that clears logs after successful export (should be a known, documented exception tied to a specific service account)
level: critical`,
        ruleFormatVersion: "Sigma Schema 2.0",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.1",
        falsePositiveNotes:
          "If your organization uses an automated log-management tool that clears local event logs after successfully shipping them to a central SIEM (some legacy log-forwarding agents do this to manage disk space), this WILL trigger the rule. The fix is not to suppress the rule but to document the exact service account/process responsible, and create a narrow exception for events where `SubjectUserName` matches that specific service account AND the action occurs on a predictable schedule. Any occurrence where the actor is an interactive user account, or where `wevtutil.exe`/`powershell.exe` is the process responsible (visible via the companion Sysmon process-creation event for the clearing command itself), should never be suppressed.",
        dataSourceRequirements:
          "Windows Security and System Event Logs forwarded to the SIEM. Note: because this event represents the log being cleared, ensure log forwarding is near-real-time (not batch-on-schedule) so the 1102/104 event itself is captured before any subsequent clearing.",
        mitreTechniqueIds: ["T1070.001"],
        cveIds: [],
        tags: ["Anti-Forensics", "Log Clearing", "Defense Evasion"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1070/001/",
            title: "MITRE ATT&CK - Clear Windows Event Logs",
            referenceType: "mitre_page",
          },
        ],
      },
      {
        id: "rule-clear-event-logs-kql",
        language: "kql",
        platformVariant: "Microsoft Sentinel",
        title: "Event Log Cleared - Correlation with Preceding Suspicious Activity",
        slug: "event-log-cleared-correlation-kql",
        descriptionSummary:
          "Detects Event ID 1102/104 and surfaces a summary of all Security and Sysmon events recorded on the same host in the 24 hours prior to the log being cleared, to accelerate incident response.",
        ruleBody: `// Event log clearing detection + pre-clearing activity summary
// Data source: SecurityEvent (Windows Security Event Log)
let ClearingEvents =
    SecurityEvent
    | where EventID in (1102, 104)
    | project ClearTime = TimeGenerated, Computer, ClearingActor = SubjectUserName, EventID;
ClearingEvents
| join kind=leftouter (
    SecurityEvent
    | where EventID in (4624, 4625, 4672, 4720, 4728, 4732, 7045, 4698)
    | project ActivityTime = TimeGenerated, Computer, ActivityEventID = EventID, ActivityAccount = TargetUserName
  ) on Computer
| where ActivityTime between ((ClearTime - 24h) .. ClearTime)
| summarize
    PriorActivityCount = count(),
    PriorEventTypes = make_set(ActivityEventID),
    AffectedAccounts = make_set(ActivityAccount)
    by ClearTime, Computer, ClearingActor, EventID
| extend
    HostCustomEntity = Computer,
    AccountCustomEntity = ClearingActor,
    Verdict = "Event log cleared - review PriorEventTypes and AffectedAccounts for the preceding 24h on this host immediately"
| order by ClearTime desc`,
        ruleFormatVersion: "Sentinel Analytics Rule (KQL)",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "Same caveats as the Sigma variant regarding automated log-management tooling. The additional value of this KQL version is the automatic 24-hour activity summary, which helps an analyst immediately triage whether the clearing followed suspicious privileged-group changes (4728/4732), new service installs (7045), or scheduled task creation (4698) versus occurring with no other notable activity (which could indicate the clearing tool itself was the only thing logged before the attacker pivoted to a less-monitored host).",
        dataSourceRequirements:
          "Windows Security Event Log forwarded to Sentinel with at least Event IDs 1102, 104, 4624, 4625, 4672, 4720, 4728, 4732, 7045, 4698 enabled via audit policy.",
        mitreTechniqueIds: ["T1070.001"],
        cveIds: [],
        tags: ["Anti-Forensics", "Log Clearing", "Incident Response"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1070/001/",
            title: "MITRE ATT&CK - Clear Windows Event Logs",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },

  // --- AMSI Bypass (Sigma) ---
  {
    family: {
      id: "fam-amsi-bypass",
      name: "AMSI Bypass via PowerShell Reflection",
      slug: "amsi-bypass-powershell-reflection",
      categoryId: "cat-defense-evasion",
      conceptDescription:
        "The Antimalware Scan Interface (AMSI) is a Windows component that allows applications - most notably PowerShell, but also VBA, WSH, and .NET - to submit content (scripts, command lines) to the installed antivirus engine for scanning before execution. AMSI is a critical control because it provides visibility into obfuscated/in-memory scripts at the moment they're about to run, after any decoding/deobfuscation has occurred, defeating obfuscation techniques that would otherwise hide malicious code from static, on-disk scanning.\n\nAMSI bypass techniques aim to prevent malicious PowerShell from ever reaching the AMSI scan. The most well-known and widely-reused technique uses .NET reflection to directly patch the in-memory AMSI provider: the script obtains a reference to the `System.Management.Automation.AmsiUtils` class (an internal PowerShell class responsible for calling into AMSI), uses reflection (`[Ref].Assembly.GetType(...)`, `GetField(...)`, `SetValue(...)`) to access its private `amsiInitFailed` field, and sets it to `$true` - which tricks the PowerShell engine into believing AMSI initialization failed, causing it to skip all subsequent AMSI scans for that session.\n\nBecause this technique requires a very specific sequence of reflection API calls referencing the exact internal class and field names (`AmsiUtils`, `amsiInitFailed`, `System.Management.Automation.Internal`), and because legitimate PowerShell scripts have essentially no reason to perform reflection against PowerShell's own internal AMSI implementation, this is one of the highest-fidelity command-line detections available - the presence of these specific strings together in a PowerShell command line is overwhelmingly likely to be malicious, regardless of obfuscation applied to the rest of the script.",
    },
    variants: [
      {
        id: "rule-amsi-bypass-sigma",
        language: "sigma",
        title: "PowerShell AMSI Bypass via AmsiUtils Reflection",
        slug: "powershell-amsi-bypass-amsiutils-sigma",
        descriptionSummary:
          "Detects PowerShell command lines or script-block-logging events referencing AmsiUtils, amsiInitFailed, or similar reflection-based AMSI bypass indicators.",
        ruleBody: `title: PowerShell AMSI Bypass via AmsiUtils Reflection
id: 6a7b8c9d-0e1f-4a2b-9c3d-4e5f6a7b8c9d
status: stable
description: |
    Detects PowerShell execution containing references to the internal AmsiUtils class
    and its amsiInitFailed/amsiSession/amsiContext fields via .NET reflection - the
    signature of widely-reused AMSI bypass one-liners (e.g., the "matt graeber" style
    bypass and its many derivatives). This combination of strings has no legitimate
    use outside of security research/testing.
references:
    - https://attack.mitre.org/techniques/T1562/001/
    - https://research.checkpoint.com/2021/amsi-bypass-redux/
author: Sentriq Detection Engineering
date: 2022-06-01
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: ps_script  # PowerShell Script Block Logging (Event ID 4104)
    product: windows
detection:
    selection:
        ScriptBlockText|contains:
            - 'AmsiUtils'
            - 'amsiInitFailed'
            - 'amsiSession'
            - 'amsiContext'
    selection_reflection:
        ScriptBlockText|contains|all:
            - 'GetField'
            - 'SetValue'
    condition: selection or (selection_reflection and selection)
falsepositives:
    - Authorized red team / penetration testing using public AMSI bypass scripts
    - Security research or AMSI-testing tooling run by the security team itself
level: critical`,
        ruleFormatVersion: "Sigma Schema 2.0",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "The only realistic source of false positives is authorized security testing - red team engagements, AMSI bypass research by the security team, or training/demo environments. Maintain an exception for specific, time-boxed testing windows tied to known source hosts/accounts rather than disabling the rule, since this is one of the most reliable single-event indicators of malicious PowerShell available. Note that newer bypass variants obfuscate the string `AmsiUtils` itself (e.g., via string concatenation or character-code construction); this rule catches the common/published variants but should be paired with a more general PowerShell obfuscation-scoring rule (e.g., flagging scripts with high entropy + reflection API usage regardless of specific strings) for defense in depth.",
        dataSourceRequirements:
          "PowerShell Script Block Logging enabled (Event ID 4104 in Microsoft-Windows-PowerShell/Operational), forwarded to the SIEM.",
        mitreTechniqueIds: ["T1562.001", "T1059.001"],
        cveIds: [],
        tags: ["AMSI Bypass", "PowerShell", "Defense Evasion"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1562/001/",
            title: "MITRE ATT&CK - Disable or Modify Tools",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },

  // --- Disable Defender (KQL + Elastic) ---
  {
    family: {
      id: "fam-disable-defender",
      name: "Microsoft Defender Tampering or Disablement",
      slug: "defender-tampering-disablement",
      categoryId: "cat-defense-evasion",
      conceptDescription:
        "Before deploying ransomware, credential-theft tools, or other malware likely to be flagged by endpoint protection, attackers commonly attempt to disable or weaken Microsoft Defender (or other EDR/AV products) using a small set of well-known techniques: setting `DisableRealtimeMonitoring`, `DisableBehaviorMonitoring`, `DisableScanOnRealtimeEnable`, or `DisableIOAVProtection` to `1` via the registry or `Set-MpPreference` PowerShell cmdlet; adding broad exclusion paths (`Add-MpPreference -ExclusionPath C:\\`) that effectively whitelist the attacker's working directory or the entire C: drive; stopping the `WinDefend` service (though this is increasingly prevented by Defender's self-protection on modern Windows); or uninstalling/disabling Defender entirely via Group Policy manipulation or the `MpCmdRun.exe -RemoveDefinitions` command in combination with tamper-protection bypass tools.\n\nThis technique is extremely high-signal: in a properly managed enterprise, changes to endpoint protection configuration go through change management and are made via centralized policy (Intune, Group Policy, or a security platform's management console) - not via local `Set-MpPreference` commands run interactively on individual endpoints. Any local modification to these settings via PowerShell or registry edit by a non-administrative deployment process should be treated as a strong indicator of an imminent malware deployment, particularly ransomware, where defender-tampering is consistently observed as one of the final preparatory steps before encryption begins.",
    },
    variants: [
      {
        id: "rule-disable-defender-kql",
        language: "kql",
        platformVariant: "Microsoft Sentinel / Defender for Endpoint",
        title: "Microsoft Defender Real-Time Protection Disabled or Broad Exclusion Added",
        slug: "defender-realtime-protection-disabled-kql",
        descriptionSummary:
          "Detects PowerShell Set-MpPreference/Add-MpPreference commands disabling real-time protection, behavior monitoring, or adding overly broad exclusion paths - a common precursor to ransomware deployment.",
        ruleBody: `// Microsoft Defender tampering detection via command-line and registry telemetry
// Data source: DeviceProcessEvents (Microsoft Defender for Endpoint)
DeviceProcessEvents
| where Timestamp >= ago(1d)
| where FileName in~ ("powershell.exe", "powershell_ise.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "Set-MpPreference",
    "Add-MpPreference",
    "DisableRealtimeMonitoring",
    "DisableBehaviorMonitoring",
    "DisableIOAVProtection",
    "DisableScanOnRealtimeEnable"
)
| extend
    SuspiciousExclusion = ProcessCommandLine has "ExclusionPath" and (
        ProcessCommandLine has "C:\\\\" or ProcessCommandLine has "C:\\\\\\\\"
    ),
    DisablesRealtime = ProcessCommandLine has "DisableRealtimeMonitoring" and ProcessCommandLine has "\$true"
| extend
    AccountCustomEntity = InitiatingProcessAccountName,
    HostCustomEntity = DeviceName,
    Verdict = case(
        DisablesRealtime, "CRITICAL: Real-time protection disabled",
        SuspiciousExclusion, "HIGH: Broad exclusion path added",
        "Defender configuration modified via PowerShell"
    )
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, Verdict
| order by Timestamp desc`,
        ruleFormatVersion: "Sentinel Analytics Rule / Defender Advanced Hunting",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.2",
        falsePositiveNotes:
          "Legitimate software deployment tools occasionally add narrow, justified Defender exclusions during installation (e.g., a backup product excluding its own staging directory, or a developer tool excluding a build output folder) - these should be made via centralized policy (Intune/GPO) rather than interactive PowerShell, but if your organization does use interactive scripts for this, build an allowlist of the *specific* exclusion paths used by approved software and flag only exclusions outside that list. `DisableRealtimeMonitoring=$true` has essentially no legitimate interactive use case in a managed environment and should always be treated as critical; if a help-desk workflow legitimately needs to do this for troubleshooting, it should be a documented, audited, time-boxed exception tied to a specific ticket.",
        dataSourceRequirements:
          "Microsoft Defender for Endpoint DeviceProcessEvents table (command-line logging), or equivalent EDR process telemetry with full command-line capture.",
        mitreTechniqueIds: ["T1562.001"],
        cveIds: [],
        tags: ["Defender", "Tamper Protection", "Ransomware Precursor"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1562/001/",
            title: "MITRE ATT&CK - Disable or Modify Tools",
            referenceType: "mitre_page",
          },
          {
            url: "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection",
            title: "Microsoft - Tamper Protection in Microsoft Defender",
            referenceType: "documentation",
          },
        ],
      },
      {
        id: "rule-disable-defender-elastic",
        language: "elastic",
        platformVariant: "EQL / KQL (Detection Rule)",
        title: "Defender Service Stop or Tamper Protection Registry Modification",
        slug: "defender-service-stop-tamper-elastic",
        descriptionSummary:
          "Detects attempts to stop the WinDefend service via sc.exe/net.exe, or registry modifications to Defender's tamper-protection and policy-management keys.",
        ruleBody: `// Elastic Security Detection Rule - KQL query
// Index pattern: winlogbeat-*, logs-windows.*, logs-endpoint.events.*

(
  (process.name : ("sc.exe", "net.exe", "net1.exe") and
   process.args : ("stop", "config") and
   process.args : ("WinDefend", "wdnissvc", "WdNisSvc", "SecurityHealthService"))
  or
  (event.category : "registry" and
   registry.path : (
     "*\\\\SOFTWARE\\\\Microsoft\\\\Windows Defender\\\\DisableAntiSpyware*",
     "*\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\\\\DisableAntiSpyware*",
     "*\\\\SOFTWARE\\\\Microsoft\\\\Windows Defender\\\\Features\\\\TamperProtection*"
   ) and
   registry.data.strings : "1")
)

// --- Companion: detect MpCmdRun.exe used to remove definitions (signature wipe) ---
// process.name : "MpCmdRun.exe" and process.args : "-RemoveDefinitions"`,
        ruleFormatVersion: "Elastic Security Detection Rule (KQL)",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "On endpoints where a third-party AV product is the primary endpoint protection and Defender is intentionally disabled via supported policy mechanisms (Defender automatically passively disables itself when a third-party AV with appropriate registration is present), the `DisableAntiSpyware` registry path may be set by Windows itself rather than an attacker - scope this rule to exclude hosts where a registered third-party AV product is confirmed present, or correlate with EDR telemetry showing the change was made by `MsMpEng.exe`/the OS itself rather than an interactive user process. The `sc.exe stop WinDefend` pattern has very low false-positive potential on modern Windows since Tamper Protection normally prevents this entirely - a successful stop is high-confidence evidence that Tamper Protection itself has also been compromised or was never enabled.",
        dataSourceRequirements:
          "Elastic Agent / Winlogbeat with Sysmon process-creation (Event ID 1) and registry (Event ID 12/13/14) events.",
        mitreTechniqueIds: ["T1562.001"],
        cveIds: [],
        tags: ["Defender", "Tamper Protection", "Ransomware Precursor"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1562/001/",
            title: "MITRE ATT&CK - Disable or Modify Tools",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },
];
