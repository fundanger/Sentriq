import type { RuleSeed } from "../types";

export const persistenceRules: RuleSeed[] = [
  // --- Generic Web Shell (YARA + Sigma multi-doc Win+Linux) ---
  {
    family: {
      id: "fam-webshell-generic",
      name: "Generic Web Shell Deployment",
      slug: "generic-web-shell-deployment",
      categoryId: "cat-persistence",
      conceptDescription:
        "A web shell is a small script (commonly written in PHP, JSP, ASPX, or as a Python/Perl CGI) that an attacker uploads to a compromised web server to provide persistent, remote command-execution access through the web server's own HTTP interface. Web shells are typically dropped as the final step of exploiting a vulnerability that allows arbitrary file write (an unrestricted file upload form, a path-traversal bug, a vulnerable plugin's update mechanism, or post-exploitation following RCE chains like ProxyShell or MOVEit) - once written, the attacker simply requests the shell's URL with command parameters to execute arbitrary code as the web server's service account, without needing to maintain any other foothold.\n\nWeb shells range from extremely simple one-liners (`<?php system($_GET['c']); ?>`) to fully-featured management interfaces (China Chopper, ASPXSpy, WSO, b374k) offering file browsers, database clients, and reverse-shell launchers, often with obfuscation (base64-encoded payloads, dynamic function construction via `create_function`/`call_user_func`, string concatenation to avoid signature matches) to evade static scanning.\n\nDetection takes two complementary approaches: (1) static/content-based scanning for known web shell signatures and suspicious code patterns (dangerous function calls combined with user-input sources, encoded payloads, known-malicious file hashes) via YARA across the web root, and (2) behavioral/runtime detection of the web server process spawning unexpected child processes (cmd.exe, powershell.exe, /bin/sh, /bin/bash) - since a legitimate web application almost never needs its web server process to spawn a shell interpreter, this is one of the highest-fidelity signals for web shell activity regardless of the specific shell's code.",
    },
    variants: [
      {
        id: "rule-webshell-yara",
        language: "yara",
        title: "Generic PHP/JSP/ASPX Web Shell Indicators",
        slug: "generic-web-shell-yara",
        descriptionSummary:
          "YARA rule matching common web shell code patterns across PHP, JSP, and ASPX - dangerous function calls fed by user-controlled HTTP parameters, common obfuscation idioms, and known web shell family strings (China Chopper, WSO, b374k).",
        ruleBody: `rule Generic_PHP_Webshell_Dangerous_Functions
{
    meta:
        description = "Detects PHP files calling code-execution functions with direct $_GET/$_POST/$_REQUEST input - classic minimal web shell pattern"
        author = "Sentriq Detection Engineering"
        date = "2024-01-10"
        severity = "high"

    strings:
        $func1 = "system($_"
        $func2 = "exec($_"
        $func3 = "shell_exec($_"
        $func4 = "passthru($_"
        $func5 = "eval($_"
        $func6 = "assert($_"
        $func7 = /(system|exec|shell_exec|passthru|eval)\\s*\\(\\s*\\$_(GET|POST|REQUEST|COOKIE)\\s*\\[/

    condition:
        any of them
}

rule Generic_Webshell_China_Chopper
{
    meta:
        description = "Detects the China Chopper web shell - a near-ubiquitous, extremely compact ASPX/PHP/JSP shell consisting of a single eval/exec line"
        author = "Sentriq Detection Engineering"
        date = "2024-01-10"
        severity = "critical"

    strings:
        $aspx = "<%@ Page Language=\\"Jscript\\"%><%eval(Request.Item[" ascii
        $php = "<?php @eval($_POST[" ascii
        $jsp = "<%if(request.getParameter(" ascii

    condition:
        any of them
}

rule Generic_Webshell_Known_Families
{
    meta:
        description = "Detects string artifacts associated with widely-used web shell toolkits (WSO, b374k, ASPXSpy, r57)"
        author = "Sentriq Detection Engineering"
        date = "2024-01-10"
        severity = "high"

    strings:
        $wso1 = "WSO 2.5" ascii nocase
        $wso2 = "wso_version" ascii
        $b374k1 = "b374k" ascii nocase
        $aspxspy1 = "ASPXSpy" ascii
        $r57_1 = "r57shell" ascii nocase
        $generic_obfuscated = /\\$[a-zA-Z_][a-zA-Z0-9_]{0,15}\\s*=\\s*str_rot13\\s*\\(/

    condition:
        any of them
}`,
        ruleFormatVersion: "YARA 4.x",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.1",
        falsePositiveNotes:
          "The `Generic_PHP_Webshell_Dangerous_Functions` rule will match legitimate administrative tools and frameworks that intentionally expose code-execution for authenticated admin users (some CMS plugin managers, server control panels, CI/CD webhook handlers that shell out based on request parameters) - when scanning a web root, expect matches in known admin-panel files and maintain a path-based allowlist for those specific files after verifying their access controls. The China Chopper and known-family signatures have a very low false-positive rate - these exact byte sequences have essentially no legitimate use case, and any match should be treated as a confirmed compromise indicator warranting immediate isolation of the host and forensic review of how the file was written (check web server access logs for the upload/write request).",
        dataSourceRequirements:
          "File system access to the web root for YARA scanning (scheduled scan via EDR file-scanning capability, or a dedicated integrity-monitoring/YARA-scanning agent such as Wazuh, Velociraptor, or THOR).",
        mitreTechniqueIds: ["T1505.003"],
        cveIds: [],
        tags: ["Web Shell", "Persistence", "PHP", "Web Application"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1505/003/",
            title: "MITRE ATT&CK - Server Software Component: Web Shell",
            referenceType: "mitre_page",
          },
          {
            url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-120a",
            title: "CISA - Detect and Prevent Web Shell Malware",
            referenceType: "vendor_advisory",
          },
        ],
      },
      {
        id: "rule-webshell-sigma",
        language: "sigma",
        title: "Web Server Process Spawning Command Interpreter (Web Shell Behavior)",
        slug: "webserver-spawns-shell-sigma",
        descriptionSummary:
          "Multi-platform Sigma rule (Windows IIS/w3wp.exe and Linux Apache/Nginx/PHP-FPM) detecting a web server worker process spawning a command-line interpreter - the highest-fidelity behavioral signal for active web shell usage regardless of the shell's specific code.",
        ruleBody: `title: Web Server Process Spawning Command Shell (Windows)
id: 4c5d6e7f-8a9b-4c0d-1e2f-3a4b5c6d7e8f
status: stable
description: |
    Detects IIS worker processes (w3wp.exe) or other common Windows web server
    processes spawning cmd.exe, powershell.exe, or other command interpreters as
    a child process - a strong indicator of an active web shell being used to
    execute commands via an HTTP request.
references:
    - https://attack.mitre.org/techniques/T1505/003/
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-120a
author: Sentriq Detection Engineering
date: 2023-06-01
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\\w3wp.exe'
            - '\\httpd.exe'
            - '\\nginx.exe'
            - '\\php-cgi.exe'
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\pwsh.exe'
            - '\\cscript.exe'
            - '\\wscript.exe'
    condition: selection
falsepositives:
    - Web application health-check or maintenance scripts that legitimately invoke command-line utilities (rare; should be allowlisted by exact CommandLine and scheduled-task correlation)
level: high
---
title: Web Server Process Spawning Command Shell (Linux)
id: 5d6e7f8a-9b0c-4d1e-2f3a-4b5c6d7e8f9a
status: stable
description: |
    Detects Linux web server worker processes (apache2, httpd, nginx, php-fpm)
    spawning /bin/sh, /bin/bash, or other shell interpreters as a child process -
    the equivalent Linux behavioral signal for active web shell usage.
references:
    - https://attack.mitre.org/techniques/T1505/003/
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-120a
author: Sentriq Detection Engineering
date: 2023-06-01
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        ParentProcess|endswith:
            - '/apache2'
            - '/httpd'
            - '/nginx'
            - '/php-fpm'
        Process|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
            - '/python3'
            - '/perl'
    filter_known_cgi:
        Process|endswith: '/python3'
        CommandLine|contains: '/usr/lib/cgi-bin/'
    condition: selection and not filter_known_cgi
falsepositives:
    - CGI scripts written in Python/Perl that are an intentional part of the application (excluded above when located under the standard cgi-bin path; broaden the filter for non-standard CGI directories in your environment)
level: high`,
        ruleFormatVersion: "Sigma Schema 2.0 (multi-document)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.1",
        falsePositiveNotes:
          "This rule has a low false-positive rate in most production web environments, since a properly configured web application should never need its web server worker process to directly invoke a shell interpreter - any match warrants investigation. The main source of noise is legitimate CGI scripts (especially older Perl/Python CGI applications) and certain web-based admin panels (phpMyAdmin, cPanel plugins) that intentionally shell out for specific administrative functions; the Linux variant includes a filter for the standard `cgi-bin` path as a starting point, but environments with custom CGI directories should extend this filter accordingly. Once tuned for a given environment's known-legitimate CGI paths, remaining matches should be treated as high-confidence web shell activity.",
        dataSourceRequirements:
          "Process creation telemetry with parent-child relationships: Sysmon Event ID 1 (Windows) or auditd/EDR process events (Linux), forwarded to the SIEM.",
        mitreTechniqueIds: ["T1505.003"],
        cveIds: [],
        tags: ["Web Shell", "Persistence", "Process Execution"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1505/003/",
            title: "MITRE ATT&CK - Server Software Component: Web Shell",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },

  // --- Registry Run Key Persistence (Sigma) ---
  {
    family: {
      id: "fam-registry-run-key",
      name: "Registry Run Key / Startup Folder Persistence",
      slug: "registry-run-key-persistence",
      categoryId: "cat-persistence",
      conceptDescription:
        "One of the oldest and still most commonly used persistence mechanisms on Windows is registering a program to run automatically at user logon or system startup via the registry's \"Run\" and \"RunOnce\" keys (`HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`, and the `HKLM` equivalent for all users), or by dropping a shortcut/script into a user's Startup folder (`%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup`). Any value written to these registry keys, or any file placed in the Startup folder, is automatically executed the next time the relevant user logs on (or the system boots, for the `HKLM` keys and All Users Startup folder).\n\nMalware and post-exploitation frameworks favor Run keys because they require no special privileges (the `HKCU` keys are writable by the logged-on user), survive reboots, and - critically - because there are dozens of legitimate applications that also use Run keys for things like update checkers, cloud-sync clients, and hardware utilities, making the technique blend into a noisy baseline.\n\nDetection focuses on registry value-set events (Sysmon Event ID 13, or Event ID 12/14 for key creation/deletion) targeting the known Run/RunOnce key paths, with particular attention to: values pointing to executables in unusual locations (`%TEMP%`, `%APPDATA%\\Roaming\\<random>`, `C:\\Users\\Public\\`), values containing encoded PowerShell commands or `rundll32`/`regsvr32` invocations, and the process making the registry modification being something other than a recognized installer (msiexec.exe) or the application's own setup process.",
    },
    variants: [
      {
        id: "rule-registry-run-key-sigma",
        language: "sigma",
        title: "Suspicious Registry Run Key or Startup Folder Persistence",
        slug: "suspicious-run-key-startup-persistence-sigma",
        descriptionSummary:
          "Detects new values written to Run/RunOnce registry keys or files dropped into Startup folders that point to executables in temporary/user-writable directories or invoke script interpreters, indicating malware persistence.",
        ruleBody: `title: Suspicious Registry Run Key / Startup Folder Persistence
id: 6e7f8a9b-0c1d-4e2f-3a4b-5c6d7e8f9a0b
status: stable
description: |
    Detects creation of new values under the Run/RunOnce registry keys or new
    files in user/global Startup folders where the referenced command points
    to a binary in a temporary or user-writable directory, or invokes a script
    interpreter (powershell.exe, wscript.exe, mshta.exe, rundll32.exe) - common
    patterns for malware establishing automatic-startup persistence.
references:
    - https://attack.mitre.org/techniques/T1547/001/
    - https://redcanary.com/threat-detection-report/techniques/registry-run-keys-startup-folder/
author: Sentriq Detection Engineering
date: 2023-02-20
modified: 2024-05-10
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection_run_keys:
        TargetObject|contains:
            - '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
            - '\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
    selection_suspicious_path:
        Details|contains:
            - '\\AppData\\Roaming\\'
            - '\\AppData\\Local\\Temp\\'
            - '\\Users\\Public\\'
            - '\\ProgramData\\'
    selection_suspicious_interpreter:
        Details|contains:
            - 'powershell'
            - 'wscript'
            - 'mshta'
            - 'rundll32'
            - 'regsvr32'
            - '-enc '
            - '-EncodedCommand'
    condition: selection_run_keys and (selection_suspicious_path or selection_suspicious_interpreter)
falsepositives:
    - Legitimate software updaters and cloud-sync clients (OneDrive, Dropbox, Slack, Zoom, Teams) commonly register Run key entries pointing to AppData\\Local paths
    - Some enterprise software deployment tools stage installers under AppData/ProgramData and register temporary Run entries during multi-stage installs
level: high`,
        ruleFormatVersion: "Sigma Schema 2.0",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.2",
        falsePositiveNotes:
          "This is a moderately noisy rule in environments with many consumer-style applications (chat clients, cloud storage sync agents, browser updaters) that legitimately self-register Run key entries under `AppData\\Local` or `AppData\\Roaming` - build an allowlist of known-good `Details` value patterns (full path + binary name) for your standard software image and exclude those exact matches rather than excluding the entire `AppData` path, which would blind the rule to malware staged in the same location (a very common technique specifically because it blends with legitimate software). The `selection_suspicious_interpreter` branch (PowerShell, mshta, rundll32 references in the Run value) is higher-fidelity and rarely matches legitimate software - prioritize alerts matching this branch over the path-based branch alone.",
        dataSourceRequirements:
          "Sysmon Event ID 13 (RegistryEvent - Value Set) with registry auditing enabled for the relevant Run/RunOnce key paths, forwarded to the SIEM. Optionally Sysmon Event ID 11 (FileCreate) scoped to Startup folder paths for the file-drop variant of this technique.",
        mitreTechniqueIds: ["T1547.001"],
        cveIds: [],
        tags: ["Persistence", "Registry", "Autorun"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1547/001/",
            title: "MITRE ATT&CK - Registry Run Keys / Startup Folder",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },

  // --- Scheduled Task Persistence (Elastic KQL + EQL) ---
  {
    family: {
      id: "fam-scheduled-task-persistence",
      name: "Malicious Scheduled Task Creation",
      slug: "malicious-scheduled-task-creation",
      categoryId: "cat-persistence",
      conceptDescription:
        "Windows Scheduled Tasks (managed via `schtasks.exe`, the Task Scheduler COM API, or the `Register-ScheduledTask` PowerShell cmdlet) provide a flexible persistence mechanism: a task can be configured to run at logon, at boot, on a recurring interval, or in response to specific event-log triggers, and - depending on how it's configured - can run with SYSTEM privileges regardless of which user is logged in, making it attractive for both persistence and privilege escalation.\n\nAttackers and post-exploitation frameworks (Cobalt Strike's `schtasksrun` Beacon command, Empire, many ransomware loaders) commonly create scheduled tasks that execute PowerShell with encoded commands, run a dropped binary from a temp/user-writable directory, or re-establish a C2 beacon if the primary process is killed. Task creation is logged as Event ID 4698 (A scheduled task was created) in the Security event log (if the relevant audit policy is enabled) and Event ID 106 in the Task Scheduler operational log, both of which include the full task XML definition - making the task's action (command + arguments) directly visible to detection logic.\n\nDetection focuses on newly-created scheduled tasks whose action invokes a script interpreter with suspicious arguments, references an executable in a non-standard location, or whose task name/author mimics a legitimate Windows component (e.g., \"MicrosoftEdgeUpdateTaskMachineUA\" with a different binary path than the genuine Edge updater) - a common attacker technique to blend into the long list of legitimate scheduled tasks present on most Windows systems.",
    },
    variants: [
      {
        id: "rule-scheduled-task-elastic",
        language: "elastic",
        platformVariant: "ES|QL / EQL",
        title: "Scheduled Task Created to Run PowerShell or Binary from Suspicious Path",
        slug: "scheduled-task-suspicious-action-elastic",
        descriptionSummary:
          "EQL/ES|QL rule pair detecting new scheduled task registration (Event ID 4698 / 106) where the task action invokes PowerShell with encoded commands or runs an executable from a temporary or user-writable directory.",
        ruleBody: `// Elastic Security - EQL rule
// Detects scheduled task registration events where the registered action
// (TaskContent / Command) references PowerShell with encoded/hidden execution
// flags, or an executable located outside standard installation directories.

any where event.code in ("4698", "106") and (
  (process.command_line : "*schtasks*" and process.command_line : ("*-enc*", "*-EncodedCommand*", "*-WindowStyle Hidden*", "*-nop*")) or
  (winlog.event_data.TaskContent : ("*\\\\Users\\\\*\\\\AppData\\\\*", "*\\\\Temp\\\\*", "*\\\\ProgramData\\\\*") and
   winlog.event_data.TaskContent : ("*powershell*", "*cmd.exe*", "*.vbs*", "*.hta*"))
)

// --- Companion ES|QL query for Kibana detection rule / dashboard ---
// FROM logs-windows.*
// | WHERE event.code IN ("4698", "106")
// | WHERE winlog.event_data.TaskContent LIKE "*powershell*"
//     AND (winlog.event_data.TaskContent LIKE "*-enc*" OR winlog.event_data.TaskContent LIKE "*AppData*")
// | KEEP @timestamp, host.name, user.name, winlog.event_data.TaskName, winlog.event_data.TaskContent
// | SORT @timestamp DESC`,
        ruleFormatVersion: "Elastic Security Detection Rule (EQL / ES|QL)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "Software installers and update mechanisms (Google Chrome's update task, Adobe's scheduled updaters, enterprise patch-management agents) legitimately register scheduled tasks that run executables from `ProgramData` or vendor-specific AppData subdirectories - build an allowlist of known-good `TaskName` and `TaskContent` binary-path combinations for your standard software image. The PowerShell-encoded-command branch is significantly higher-fidelity: legitimate scheduled tasks rarely invoke PowerShell with `-enc`/`-EncodedCommand`/`-WindowStyle Hidden` together, and this combination should be treated as a strong persistence indicator warranting investigation of the task's creator (`user.name` / `Subject` fields) and the encoded command's decoded content.",
        dataSourceRequirements:
          "Windows Security Event Log Event ID 4698 (requires 'Audit Other Object Access Events' to be enabled) and/or Task Scheduler operational log Event ID 106, forwarded via Winlogbeat/Elastic Agent.",
        mitreTechniqueIds: ["T1053.005"],
        cveIds: [],
        tags: ["Scheduled Task", "Persistence", "PowerShell"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1053/005/",
            title: "MITRE ATT&CK - Scheduled Task",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },

  // --- New Administrative Account Creation (KQL) ---
  {
    family: {
      id: "fam-new-admin-account",
      name: "Unauthorized Administrative Account Creation",
      slug: "unauthorized-admin-account-creation",
      categoryId: "cat-persistence",
      conceptDescription:
        "Creating a new local or domain administrative account is one of the most durable persistence techniques available to an attacker who has already achieved privileged access: unlike a malware implant, a legitimate-looking user account does not trigger antivirus/EDR signatures, survives patching and reimaging of the original compromised host (for domain accounts), and provides the attacker with standard, fully-functional credentials for re-entry via RDP, VPN, or any other authentication-gated service.\n\nOn a local Windows system, this manifests as Event ID 4720 (a user account was created) immediately followed by Event ID 4732 (a member was added to a security-enabled local group) adding the new account to the local Administrators group. On a domain controller, the equivalent is Event ID 4720 plus Event ID 4728/4732/4756 for addition to privileged domain groups (Domain Admins, Enterprise Admins, Account Operators). Attackers often choose account names designed to blend in - names similar to existing service accounts, generic names like \"svc_backup\" or \"sqladmin\", or names differing from a legitimate account by a single character.\n\nDetection focuses on the temporal correlation of account creation followed quickly by privileged group membership changes, especially when performed by an account that does not normally perform user-provisioning tasks (i.e., not a member of the Helpdesk/IT provisioning group, or an account that itself was only recently granted elevated privileges - suggesting a privilege-escalation-then-persist chain).",
    },
    variants: [
      {
        id: "rule-new-admin-account-kql",
        language: "kql",
        platformVariant: "Microsoft Sentinel",
        title: "New User Account Created and Immediately Added to Administrators Group",
        slug: "new-admin-account-created-kql",
        descriptionSummary:
          "Detects a new local or domain user account being created and added to a privileged administrative group within a short time window, especially when performed by an account outside the normal IT provisioning group.",
        ruleBody: `// New administrative account persistence detection
// Correlates account creation (4720) with privileged group membership
// addition (4728/4732/4756) for the same account within 10 minutes
// Data source: SecurityEvent (Windows Security Event Log)
let TimeWindow = 10m;
let ProvisioningGroup = dynamic(["HelpDesk Admins", "IT Provisioning", "Account Operators"]);
let AccountsCreated =
    SecurityEvent
    | where TimeGenerated >= ago(1d)
    | where EventID == 4720
    | project CreatedTime = TimeGenerated, NewAccount = TargetUserName, CreatedBy = SubjectUserName, Computer;
let PrivilegedGroupAdds =
    SecurityEvent
    | where TimeGenerated >= ago(1d)
    | where EventID in (4728, 4732, 4756)
    | where TargetUserName has_any ("Administrators", "Domain Admins", "Enterprise Admins", "Account Operators", "Remote Desktop Users")
    | project AddTime = TimeGenerated, AddedAccount = MemberName, GroupName = TargetUserName, AddedBy = SubjectUserName, Computer;
AccountsCreated
| join kind=inner PrivilegedGroupAdds on Computer
| where AddedAccount has NewAccount
| where AddTime between (CreatedTime .. (CreatedTime + TimeWindow))
| join kind=leftanti (
    IdentityInfo
    | where AssignedRoles has_any (ProvisioningGroup) or GroupMembership has_any (ProvisioningGroup)
    | project CreatedBy = tolower(AccountUPN)
  ) on $left.CreatedBy == $right.CreatedBy
| extend AccountCustomEntity = NewAccount, ActorCustomEntity = CreatedBy
| project CreatedTime, AddTime, NewAccount, GroupName, CreatedBy, AddedBy, Computer
| order by CreatedTime desc`,
        ruleFormatVersion: "Sentinel Analytics Rule (KQL)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.1",
        falsePositiveNotes:
          "Legitimate IT onboarding processes for new administrators or contractors will match this pattern exactly - a new account created and added to an admin group within minutes is the expected workflow for provisioning a new privileged user. The `leftanti` join against `IdentityInfo` is intended to suppress these cases by excluding actions performed by members of the designated provisioning/helpdesk group; keep this group membership list accurate and up to date, as stale group membership is the most common cause of both false positives (provisioning staff who left the group still appearing as exceptions) and false negatives (new provisioning staff not yet added). When a true positive fires, prioritize investigation based on `CreatedBy`: if the creating account itself was only recently granted elevated privileges, this likely represents a privilege-escalation-then-persistence chain rather than a single compromised admin account.",
        dataSourceRequirements:
          "Windows Security Event Log (Event IDs 4720, 4728, 4732, 4756) forwarded to Sentinel from domain controllers and/or member servers, with audit policy 'Audit User Account Management' and 'Audit Security Group Management' enabled. IdentityInfo table populated via Microsoft Defender for Identity or Entra ID for provisioning-group membership lookups.",
        mitreTechniqueIds: ["T1098", "T1136"],
        cveIds: [],
        tags: ["Account Manipulation", "Persistence", "Active Directory"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1098/",
            title: "MITRE ATT&CK - Account Manipulation",
            referenceType: "mitre_page",
          },
          {
            url: "https://attack.mitre.org/techniques/T1136/",
            title: "MITRE ATT&CK - Create Account",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },
];
