export const categorySeeds = [
  {
    id: "cat-recon",
    name: "Reconnaissance & Scanning",
    slug: "reconnaissance-scanning",
    description:
      "Detections for active and passive reconnaissance against your environment: port scans, directory brute-forcing, credential stuffing probes, and enumeration of users, groups, or cloud resources that typically precede a targeted attack.",
    sortOrder: "1",
  },
  {
    id: "cat-initial-access",
    name: "Initial Access",
    slug: "initial-access",
    description:
      "Detections for the techniques adversaries use to gain an initial foothold: phishing payloads, exploitation of public-facing applications, malicious OAuth consent grants, and abuse of valid accounts.",
    sortOrder: "2",
  },
  {
    id: "cat-web-attacks",
    name: "Web Application Attacks",
    slug: "web-application-attacks",
    description:
      "Detections for attacks against web applications and APIs: SQL injection, cross-site scripting, server-side request forgery, path traversal, deserialization attacks, and exploitation of known web framework vulnerabilities.",
    sortOrder: "3",
  },
  {
    id: "cat-credential-access",
    name: "Credential Access",
    slug: "credential-access",
    description:
      "Detections for techniques used to steal credentials: password spraying, brute forcing, Kerberoasting, AS-REP roasting, credential dumping from memory (LSASS), and theft of browser-stored or cached secrets.",
    sortOrder: "4",
  },
  {
    id: "cat-privilege-escalation",
    name: "Privilege Escalation",
    slug: "privilege-escalation",
    description:
      "Detections for attempts to gain higher-level permissions: token manipulation, exploitation of vulnerable services, UAC bypass, scheduled task abuse, and misuse of privilege escalation primitives in cloud IAM.",
    sortOrder: "5",
  },
  {
    id: "cat-persistence",
    name: "Persistence",
    slug: "persistence",
    description:
      "Detections for mechanisms adversaries use to maintain access across reboots and credential changes: registry run keys, scheduled tasks, new service creation, startup folder modifications, and web shells.",
    sortOrder: "6",
  },
  {
    id: "cat-defense-evasion",
    name: "Defense Evasion",
    slug: "defense-evasion",
    description:
      "Detections for attempts to avoid detection or disable security controls: clearing event logs, disabling Microsoft Defender, AMSI bypass, process injection, masquerading, and obfuscated/encoded command execution.",
    sortOrder: "7",
  },
  {
    id: "cat-lateral-movement",
    name: "Lateral Movement",
    slug: "lateral-movement",
    description:
      "Detections for movement between systems within a network: pass-the-hash, pass-the-ticket, remote service creation, RDP and SMB abuse, and use of administrative tools like PsExec or WMI for remote execution.",
    sortOrder: "8",
  },
  {
    id: "cat-c2",
    name: "Command & Control",
    slug: "command-and-control",
    description:
      "Detections for adversary command-and-control channels: DNS tunneling, beaconing over HTTP/HTTPS, abuse of legitimate cloud services for C2, and anomalous outbound connection patterns.",
    sortOrder: "9",
  },
  {
    id: "cat-exfiltration",
    name: "Exfiltration & Data Loss",
    slug: "exfiltration-data-loss",
    description:
      "Detections for unauthorized movement of data out of the environment: large or unusual data transfers, uploads to personal cloud storage, email exfiltration, and abuse of cloud storage sharing features.",
    sortOrder: "10",
  },
  {
    id: "cat-ransomware",
    name: "Ransomware & Malware Execution",
    slug: "ransomware-malware-execution",
    description:
      "Detections for malware execution and ransomware behaviors: mass file encryption, shadow copy deletion, known malware families and packers, suspicious binary characteristics, and living-off-the-land binary abuse.",
    sortOrder: "11",
  },
  {
    id: "cat-cloud-saas",
    name: "Cloud & SaaS Threats",
    slug: "cloud-saas-threats",
    description:
      "Detections for threats specific to cloud and SaaS platforms: impossible travel sign-ins, MFA fatigue attacks, suspicious OAuth application consent, anomalous Azure AD/Entra ID changes, and AWS IAM abuse.",
    sortOrder: "12",
  },
  {
    id: "cat-insider-threat",
    name: "Insider Threat & Anomalous Behavior",
    slug: "insider-threat-anomalous-behavior",
    description:
      "Detections for behavioral anomalies that may indicate insider threats or compromised accounts: after-hours access, mass file downloads, unusual privilege use, and deviations from established user baselines.",
    sortOrder: "13",
  },
  {
    id: "cat-cve-exploitation",
    name: "Vulnerability Exploitation (CVE-Specific)",
    slug: "vulnerability-exploitation-cve",
    description:
      "Detections tied to specific, named CVEs with published CVSS scores: exploitation attempts for high-profile vulnerabilities such as Log4Shell, ProxyShell, EternalBlue, and PrintNightmare. Cross-cutting category - rules here are also tagged with their primary tactic category.",
    sortOrder: "14",
  },
] as const;
