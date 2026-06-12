import type { RuleSeed } from "../types";

export const ransomwareRules: RuleSeed[] = [
  // --- Ransomware Mass File Rename (Sigma + SentinelOne) ---
  {
    family: {
      id: "fam-ransomware-mass-rename",
      name: "Ransomware Mass File Extension Rename / Encryption Activity",
      slug: "ransomware-mass-file-rename",
      categoryId: "cat-ransomware",
      conceptDescription:
        "The defining behavioral characteristic of ransomware is mass file modification: a process rapidly opens, reads, encrypts, and rewrites (or renames with a new extension) a very large number of files across user directories, network shares, and mapped drives in a short time period. Unlike legitimate software - even backup or sync tools, which typically operate on a more limited file set or work incrementally - ransomware encryptors are optimized for speed and will touch thousands of files per minute across many different directories and file extensions, since the goal is to encrypt as much data as possible before detection and response.\n\nMost ransomware families append a distinctive new extension to encrypted files (`.locked`, `.encrypted`, `.lockbit`, `.conti`, or family-specific random extensions) and/or drop a ransom note file (commonly named `README.txt`, `HOW_TO_DECRYPT.txt`, `RECOVER-FILES.txt`, or similar) in every directory they touch - the presence of an identically-named new text file appearing simultaneously across dozens or hundreds of directories is itself a strong behavioral indicator independent of the specific encryption activity.\n\nDetection approaches fall into two categories: (1) EDR/behavioral detection that counts file-modify/rename operations by a single process within a time window and alerts when the rate exceeds a threshold far beyond normal application behavior (this is the approach taken by SentinelOne's ransomware-specific behavioral AI and similar EDR 'ransomware kill switches'), and (2) SIEM-based detection using file-system audit events (Sysmon Event ID 11 for file creation, or Windows Object Access auditing) to detect a high rate of file creates with new/unusual extensions, or the appearance of ransom-note-like filenames across many directories in a short window. Because by the time mass encryption is detected significant damage may already be done, these detections are typically wired to automated response actions (process kill, network isolation) rather than analyst-reviewed alerts alone.",
    },
    variants: [
      {
        id: "rule-ransomware-rename-sigma",
        language: "sigma",
        title: "High-Rate File Renames to Unknown Extension Across Multiple Directories",
        slug: "high-rate-file-rename-unknown-extension-sigma",
        descriptionSummary:
          "Detects a single process performing a high volume of file rename/creation operations to an unrecognized extension across multiple distinct directories within a short window - the core ransomware encryption signature.",
        ruleBody: `title: Ransomware-Like Mass File Rename Activity
id: 0e1f2a3b-4c5d-4e6f-9a7b-8c9d0e1f2a3b
status: stable
description: |
    Detects a single process creating/renaming a high volume of files with unfamiliar
    extensions across multiple distinct directories within a short time window - the
    behavioral signature of ransomware encryption activity. This rule is intended for
    correlation/aggregation backends that support count() over a sliding window
    (e.g., Sigma correlation rules, or translated to a SIEM-native scheduled query).
references:
    - https://attack.mitre.org/techniques/T1486/
author: Sentriq Detection Engineering
date: 2023-01-10
tags:
    - attack.impact
    - attack.t1486
logsource:
    category: file_event
    product: windows
detection:
    selection:
        EventID: 11  # Sysmon FileCreate
        TargetFilename|re: '\\.(locked|encrypted|enc|crypt|lock|locky|cerber|zzz|micro|[a-z0-9]{4,8})$'
    filter_known_extensions:
        TargetFilename|endswith:
            - '.tmp'
            - '.log'
            - '.bak'
            - '.config'
    timeframe: 1m
    condition: selection and not filter_known_extensions | count(TargetFilename) by Image > 50
falsepositives:
    - File compression/archival tools producing many output files with new extensions in a short period (e.g., bulk re-encoding, format conversion batch jobs)
    - Legitimate full-disk encryption software (BitLocker, etc.) during initial encryption rollout - should be a known, scheduled, documented event
level: critical`,
        ruleFormatVersion: "Sigma Schema 2.0 (Correlation)",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "Bulk media transcoding tools, backup software performing full-disk imaging with compression, and (rarely) legitimate disk-encryption rollouts (BitLocker enabling on a large file server) can produce similar volume patterns. The key differentiators for true ransomware are: (1) the extension is novel/random rather than a well-known format (.mp4, .zip), (2) the activity spans many user-data directories (Documents, Desktop, network shares) rather than a single application's working directory, and (3) it's frequently accompanied by ransom-note files appearing in the same directories. Tune the extension regex and the count threshold (50/minute is conservative) based on your environment's normal peak file-write rates from legitimate bulk-processing applications - establish this baseline during initial deployment.",
        dataSourceRequirements:
          "Sysmon Event ID 11 (FileCreate) with file-system audit scope covering user profile directories and mapped network shares. Requires a correlation-capable backend (Sigma correlation rules, Splunk `transaction`/`stats`, or Sentinel KQL `summarize` with time bins).",
        mitreTechniqueIds: ["T1486"],
        cveIds: [],
        tags: ["Ransomware", "File Encryption", "Behavioral Detection"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1486/",
            title: "MITRE ATT&CK - Data Encrypted for Impact",
            referenceType: "mitre_page",
          },
        ],
      },
      {
        id: "rule-ransomware-rename-s1",
        language: "sentinelone",
        platformVariant: "STAR Rule",
        title: "Ransom Note File Created Across Multiple Sibling Directories",
        slug: "ransom-note-multiple-directories-s1",
        descriptionSummary:
          "SentinelOne STAR rule detecting identically-named ransom-note-style files (README, DECRYPT, RECOVER) created in rapid succession across multiple distinct parent directories by the same process.",
        ruleBody: `// SentinelOne STAR Rule (Deep Visibility Query Language)
// Detects ransom-note file creation pattern across multiple directories

event.type == "File Creation" AND
(
  tgt.file.path Matches "(?i).*\\\\(README|DECRYPT[_-]?ME|HOW[_-]TO[_-]DECRYPT|RECOVER[_-]?FILES|RESTORE[_-]?FILES)[^\\\\\\\\]*\\\\.(txt|html|hta)$"
)
AND src.process.name NOT IN ("explorer.exe", "notepad.exe")

| group by src.process.uid, src.process.name
| having count(DISTINCT tgt.file.path) > 5 within 2m

// Companion query: combine with high file-modification rate from the same process
// event.type == "File Modification" AND src.process.uid == <flagged_uid>
// | group by src.process.uid having count(*) > 100 within 1m`,
        ruleFormatVersion: "SentinelOne STAR Rule / Deep Visibility Query",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "False positives are very rare for this specific pattern - legitimate software essentially never creates multiple identically-purposed 'instruction' files with these exact naming conventions across many directories in a short window. The narrow exclusion for `explorer.exe`/`notepad.exe` covers a user manually creating/copying a single text file with a similar name (e.g., a user's own 'readme.txt' notes) - if such manual activity somehow spans more than 5 directories within 2 minutes, it would still be unusual enough to warrant review. This rule is designed to be paired with an automated response action (SentinelOne 'Kill' + 'Quarantine' on the offending process) given the time-critical nature of ransomware encryption - by the time an analyst reviews the alert, significant encryption may have already occurred.",
        dataSourceRequirements:
          "SentinelOne Deep Visibility / Singularity Data Lake with file-system event collection enabled on the endpoint.",
        mitreTechniqueIds: ["T1486", "T1490"],
        cveIds: [],
        tags: ["Ransomware", "Ransom Note", "SentinelOne"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1486/",
            title: "MITRE ATT&CK - Data Encrypted for Impact",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },

  // --- Shadow Copy Deletion (KQL) ---
  {
    family: {
      id: "fam-shadow-copy-deletion",
      name: "Volume Shadow Copy Deletion - Recovery Inhibition",
      slug: "shadow-copy-deletion-recovery-inhibition",
      categoryId: "cat-ransomware",
      conceptDescription:
        "Windows Volume Shadow Copy Service (VSS) maintains point-in-time snapshots of files that allow recovery without restoring from external backups. Virtually all major ransomware families include a step to delete these shadow copies before or during encryption, specifically to prevent victims from simply rolling back to a pre-encryption snapshot rather than paying the ransom. This is typically done via `vssadmin.exe delete shadows /all /quiet`, `wmic shadowcopy delete`, or PowerShell's `Get-WmiObject Win32_ShadowCopy | Remove-WmiObject`.\n\nBeyond shadow copies, ransomware often also disables the Windows Recovery Environment boot option (`bcdedit /set {default} bootstatuspolicy ignoreallfailures` and `bcdedit /set {default} recoveryenabled no`) and clears Windows Server Backup catalogs, as part of a comprehensive 'inhibit system recovery' step.\n\nLike Defender-tampering and event-log-clearing, this is a high-signal, low-false-positive technique because there is essentially no legitimate business reason for an end-user workstation or server to delete all of its own shadow copies via command-line tools during normal operation - shadow copy management is typically automated via scheduled VSS tasks or storage-management tooling, not ad-hoc `vssadmin` invocations. When observed, this should be treated as a near-certain precursor to imminent ransomware deployment and should trigger immediate isolation of the affected host, since encryption frequently follows within minutes.",
    },
    variants: [
      {
        id: "rule-shadow-copy-deletion-kql",
        language: "kql",
        platformVariant: "Microsoft Sentinel / Defender for Endpoint",
        title: "Shadow Copy Deletion and Recovery Inhibition Commands",
        slug: "shadow-copy-deletion-recovery-inhibition-kql",
        descriptionSummary:
          "Detects vssadmin, wmic, and PowerShell commands that delete volume shadow copies, plus bcdedit commands that disable Windows recovery options - a near-certain ransomware precursor.",
        ruleBody: `// Shadow copy deletion / recovery inhibition - ransomware precursor detection
// Data source: DeviceProcessEvents (Microsoft Defender for Endpoint)
DeviceProcessEvents
| where Timestamp >= ago(1d)
| where (
    (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete" and ProcessCommandLine has "shadows")
    or
    (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
    or
    (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Win32_ShadowCopy" and ProcessCommandLine has "Remove")
    or
    (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled no", "ignoreallfailures"))
    or
    (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete" and ProcessCommandLine has "catalog")
)
| extend
    AccountCustomEntity = InitiatingProcessAccountName,
    HostCustomEntity = DeviceName,
    TechniqueObserved = case(
        FileName =~ "vssadmin.exe" or FileName =~ "wmic.exe" or ProcessCommandLine has "Win32_ShadowCopy", "Shadow Copy Deletion",
        FileName =~ "bcdedit.exe", "Recovery Environment Disabled",
        FileName =~ "wbadmin.exe", "Backup Catalog Deletion",
        "Unknown"
    )
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, TechniqueObserved
| order by Timestamp desc`,
        ruleFormatVersion: "Sentinel Analytics Rule / Defender Advanced Hunting",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.1",
        falsePositiveNotes:
          "Storage administrators occasionally run `vssadmin delete shadows` manually to free disk space when shadow-copy storage fills a volume - this is the primary legitimate use case. Such activity should originate from a known storage-admin account on a server (not a workstation), during a documented maintenance window, and typically targets a specific volume (`/for=`) rather than `/all`. The `/all /quiet` combination specifically is heavily favored by ransomware (the `/quiet` flag suppresses confirmation prompts for unattended execution) and should be weighted higher than a narrowly-scoped manual deletion. Any occurrence on more than one host within a short time period strongly suggests automated/scripted execution (ransomware) rather than manual admin activity and should bypass normal triage queues for immediate response.",
        dataSourceRequirements:
          "Microsoft Defender for Endpoint DeviceProcessEvents table with command-line logging enabled, or equivalent EDR process telemetry.",
        mitreTechniqueIds: ["T1490", "T1486"],
        cveIds: [],
        tags: ["Ransomware", "Shadow Copy", "Recovery Inhibition"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1490/",
            title: "MITRE ATT&CK - Inhibit System Recovery",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },

  // --- YARA Malware Signatures (x2) ---
  {
    family: {
      id: "fam-cobalt-strike-beacon",
      name: "Cobalt Strike Beacon Memory/Binary Indicators",
      slug: "cobalt-strike-beacon-indicators",
      categoryId: "cat-c2",
      conceptDescription:
        "Cobalt Strike is a commercial adversary-simulation/red-team tool that has been extensively repurposed by real-world threat actors (including ransomware affiliates like Conti, Ryuk, and many others) as a post-exploitation command-and-control framework. Its 'Beacon' payload - the implant that runs on compromised hosts and communicates back to the attacker's team server - has several characteristics that, despite the tool's configurability, remain detectable in its default or lightly-modified configurations.\n\nBeacon payloads (whether delivered as raw shellcode, a reflectively-loaded DLL, or a PE executable) contain a configuration block that, in default/common configurations, includes recognizable byte patterns: the XOR key `0x2e` is commonly used to obfuscate the config block in older versions, certain default named pipe formats (`\\\\.\\pipe\\MSSE-<random>-server` or similar patterns used for SMB Beacon peer-to-peer communication), and characteristic strings related to its sleep/jitter configuration and HTTP GET/POST profile structure. Additionally, Beacon's in-memory artifacts include recognizable patterns in its reflective DLL loader stub.\n\nBecause Cobalt Strike is also used legitimately by authorized red teams and penetration testers, a YARA match on these indicators should be correlated with deployment context: is this an authorized assessment (check with the red team / track via a known engagement calendar), or does it correspond to unexpected process injection into a legitimate process (a common Beacon deployment pattern is injection into `rundll32.exe`, `svchost.exe`, or browser processes)? The combination of a YARA match with anomalous process ancestry (the host process for the match having no legitimate reason to contain this code) is the highest-confidence indicator.",
    },
    variants: [
      {
        id: "rule-cobalt-strike-yara",
        language: "yara",
        title: "Cobalt Strike Beacon Configuration and Loader Patterns",
        slug: "cobalt-strike-beacon-config-loader-yara",
        descriptionSummary:
          "YARA rule matching common Cobalt Strike Beacon configuration block patterns, default named-pipe naming conventions, and reflective loader stub signatures in process memory or on-disk binaries.",
        ruleBody: `import "pe"

rule CobaltStrike_Beacon_Config_XOR_2E
{
    meta:
        description = "Detects Cobalt Strike Beacon config block obfuscated with the common 0x2e XOR key"
        author = "Sentriq Detection Engineering"
        date = "2023-08-01"
        reference = "https://attack.mitre.org/software/S0154/"
        severity = "critical"

    strings:
        // 0x2e-XOR'd "%02d/%02d/%02d %02d:%02d:%02d" timestamp format string,
        // commonly present in Beacon config blocks
        $xor_timestamp = { 0E 0C 1F 1E 0E 1A 1E 0C 1F 1E 0E 1A 1E 0C 1F 1E 0E 1A 1E 0C 1F 1E 0E 1A }

        // Beacon's "beacon.dll" / "beacon.x64.dll" PDB remnants seen in unstripped builds
        $pdb1 = "beacon.dll" nocase
        $pdb2 = "beacon.x64.dll" nocase

    condition:
        any of them
}

rule CobaltStrike_Default_Named_Pipe
{
    meta:
        description = "Detects default/common Cobalt Strike SMB Beacon named pipe naming patterns"
        author = "Sentriq Detection Engineering"
        date = "2023-08-01"
        reference = "https://attack.mitre.org/software/S0154/"
        severity = "high"

    strings:
        $pipe1 = "\\\\\\\\.\\\\pipe\\\\MSSE-" wide ascii
        $pipe2 = "\\\\\\\\.\\\\pipe\\\\status_" wide ascii
        $pipe3 = "\\\\\\\\.\\\\pipe\\\\postex_" wide ascii

    condition:
        any of them
}

rule CobaltStrike_Reflective_Loader_Stub
{
    meta:
        description = "Detects byte patterns characteristic of Cobalt Strike's reflective DLL loader stub"
        author = "Sentriq Detection Engineering"
        date = "2023-08-01"
        severity = "critical"

    strings:
        // Common reflective loader prologue pattern (searches for PE header walk + GetProcAddress resolution stub)
        $loader_stub = { 4D 5A 41 52 55 48 89 E5 } // 'MZARUH..' - common stub prefix in CS reflective loaders

    condition:
        $loader_stub at 0
}`,
        ruleFormatVersion: "YARA 4.x",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.2",
        falsePositiveNotes:
          "Authorized red team engagements using Cobalt Strike will trigger these rules - maintain a calendar of approved engagements and correlate matches against it before escalating to incident response. The PDB-string rules (`pdb1`/`pdb2`) only match unstripped or debug builds and are increasingly rare against professionally-operated intrusions that use stripped/obfuscated loaders (malleable C2 profiles routinely change these). The named-pipe rule is scanning for *strings* (e.g., in memory dumps or unpacked binaries) - matching against live named-pipe enumeration on a host (via Sysmon Event ID 17/18 PipeEvent) is a complementary, often higher-fidelity detection that should be run alongside this YARA-based file/memory scan.",
        dataSourceRequirements:
          "YARA scanning capability against process memory (e.g., via EDR memory-scan integration, Velociraptor, or manual memory dumps) and/or on-disk file scanning.",
        mitreTechniqueIds: ["T1071.001", "T1055", "T1105"],
        cveIds: [],
        tags: ["Cobalt Strike", "C2", "Beacon"],
        references: [
          {
            url: "https://attack.mitre.org/software/S0154/",
            title: "MITRE ATT&CK - Cobalt Strike (Software)",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },
  {
    family: {
      id: "fam-lockbit-ransomware-binary",
      name: "LockBit Ransomware Binary Indicators",
      slug: "lockbit-ransomware-binary-indicators",
      categoryId: "cat-ransomware",
      conceptDescription:
        "LockBit is one of the most prolific ransomware-as-a-service (RaaS) operations, with multiple major versions (LockBit 2.0, 3.0/Black, and leaked builder-based variants following the 3.0 builder leak in 2022) widely deployed by numerous affiliates. Despite operating as a RaaS with many independent affiliates customizing ransom notes and contact details, the core encryptor binaries share recognizable characteristics across versions: distinctive wallpaper-change routines that set a LockBit-branded desktop background on encrypted systems, a consistent icon-changing mechanism for encrypted files (LockBit assigns a custom icon resource to encrypted files via registry association), specific mutex names used to prevent multiple simultaneous executions on the same host, and characteristic strings related to its self-deletion routine and anti-analysis checks (checking for specific language/locale settings to avoid encrypting systems in certain CIS countries - a common feature across many Russia-linked ransomware families).\n\nBecause the LockBit 3.0 builder was leaked publicly, there is also a large population of 'LockBit-based' ransomware from unrelated actors using the same builder with different branding - YARA signatures targeting the underlying encryptor code (rather than branding strings, which are easily changed via the builder's configuration) provide broader coverage across both 'authentic' LockBit affiliate deployments and builder-derived variants from unrelated groups.\n\nDetection via YARA is most effective as a post-incident/forensic tool (scanning quarantined samples or disk images to confirm/attribute a ransomware incident) and as a complement to behavioral detection (the mass-file-rename and shadow-copy-deletion rules in this library) - by the time a YARA file-scan identifies a LockBit binary on disk, behavioral detections should ideally have already fired. Its primary value is in threat intelligence and incident scoping: confirming which ransomware family is involved informs decryptor availability research, negotiation posture, and IOC sharing with the broader community.",
    },
    variants: [
      {
        id: "rule-lockbit-yara",
        language: "yara",
        title: "LockBit 3.0/Black Ransomware Encryptor Indicators",
        slug: "lockbit-3-encryptor-indicators-yara",
        descriptionSummary:
          "YARA rule matching mutex names, anti-analysis locale checks, and string indicators characteristic of LockBit 3.0/Black ransomware encryptor binaries and builder-derived variants.",
        ruleBody: `rule LockBit3_Mutex_And_Locale_Check
{
    meta:
        description = "Detects LockBit 3.0/Black encryptor mutex naming and CIS-locale anti-analysis checks"
        author = "Sentriq Detection Engineering"
        date = "2023-04-12"
        reference = "https://attack.mitre.org/software/S1124/"
        severity = "critical"

    strings:
        // LockBit 3.0 commonly uses a hardcoded GUID-format mutex
        $mutex = /Global\\\\\{[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}/ ascii wide

        // Locale IDs for CIS countries checked and excluded by many Russia-linked
        // ransomware families including LockBit (Russian, Ukrainian, Belarusian, etc.)
        $locale_ru = { 19 04 00 00 } // LCID 0x0419 (Russian) as raw bytes
        $locale_uk = { 22 04 00 00 } // LCID 0x0422 (Ukrainian)

        // Common LockBit ransom note filename pattern across versions
        $note_pattern = /[A-Za-z0-9]{5,10}\\.README\\.txt/ ascii wide

        // LockBit 3.0 icon resource swap registry path artifact
        $icon_regkey = "\\\\DefaultIcon" wide ascii

    condition:
        $mutex and 1 of ($locale_ru, $locale_uk) and ($note_pattern or $icon_regkey)
}

rule LockBit3_Wallpaper_Change_Routine
{
    meta:
        description = "Detects strings associated with LockBit's desktop wallpaper replacement routine post-encryption"
        author = "Sentriq Detection Engineering"
        date = "2023-04-12"
        severity = "high"

    strings:
        $wallpaper_api1 = "SystemParametersInfoW" ascii wide
        $wallpaper_api2 = "SPI_SETDESKWALLPAPER" ascii wide
        $wallpaper_reg = "Control Panel\\\\Desktop" ascii wide
        $ransom_ext_marker = ".lockbit" nocase ascii wide

    condition:
        2 of ($wallpaper_api1, $wallpaper_api2, $wallpaper_reg) and $ransom_ext_marker
}`,
        ruleFormatVersion: "YARA 4.x",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "The mutex-pattern rule (`LockBit3_Mutex_And_Locale_Check`) uses a generic GUID-format mutex regex combined with locale-check byte patterns and ransom-note naming - the GUID pattern alone is far too generic and WILL match many legitimate applications that use GUID-format mutexes (extremely common in Windows software); it is only meaningful in combination with the other conditions, which is why the rule requires all three categories. The `.lockbit` extension marker in the second rule is specific to affiliates who haven't customized the extension via the builder (a configurable option) - builder-derived variants with custom extensions will not match this specific string and require updating the `$ransom_ext_marker` string per observed campaign. As with all ransomware family-specific YARA rules, treat this as a confirmation/attribution tool rather than a primary detection layer - the behavioral rules (mass file rename, shadow copy deletion) in this library should fire first and faster.",
        dataSourceRequirements:
          "YARA file-scanning capability (on-disk scanning of suspected samples, or EDR-integrated YARA scanning of quarantined files).",
        mitreTechniqueIds: ["T1486", "T1490"],
        cveIds: [],
        tags: ["LockBit", "Ransomware", "YARA"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1486/",
            title: "MITRE ATT&CK - Data Encrypted for Impact",
            referenceType: "mitre_page",
          },
          {
            url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a",
            title: "CISA Advisory AA23-165A - LockBit 3.0 Ransomware",
            referenceType: "vendor_advisory",
          },
        ],
      },
    ],
  },
];
