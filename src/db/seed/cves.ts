export const cveSeeds = [
  {
    id: "CVE-2021-44228",
    cvssScore: 10.0,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    cvssVersion: "3.1" as const,
    description:
      "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled (Log4Shell).",
    referenceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
  },
  {
    id: "CVE-2017-0144",
    cvssScore: 8.1,
    cvssVector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvssVersion: "3.0" as const,
    description:
      "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets, exploited by the EternalBlue tool and used to propagate the WannaCry and NotPetya ransomware worms.",
    referenceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
  },
  {
    id: "CVE-2021-34527",
    cvssScore: 8.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    cvssVersion: "3.1" as const,
    description:
      "Windows Print Spooler Remote Code Execution Vulnerability (PrintNightmare). An attacker who successfully exploits this vulnerability could run arbitrary code with SYSTEM privileges via the Print Spooler service performing privileged file operations.",
    referenceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
  },
  {
    id: "CVE-2021-34473",
    cvssScore: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvssVersion: "3.1" as const,
    description:
      "Microsoft Exchange Server Remote Code Execution Vulnerability, part of the ProxyShell exploit chain. Allows pre-authentication remote code execution when combined with CVE-2021-34523 and CVE-2021-31207.",
    referenceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2021-34473",
  },
  {
    id: "CVE-2021-34523",
    cvssScore: 9.0,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    cvssVersion: "3.1" as const,
    description:
      "Microsoft Exchange Server Elevation of Privilege Vulnerability, part of the ProxyShell exploit chain. An authenticated attacker can exploit a flaw in the Exchange PowerShell backend to gain elevated privileges, used in combination with CVE-2021-34473 and CVE-2021-31207 to achieve unauthenticated remote code execution.",
    referenceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2021-34523",
  },
  {
    id: "CVE-2021-26855",
    cvssScore: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvssVersion: "3.1" as const,
    description:
      "Microsoft Exchange Server Remote Code Execution Vulnerability (ProxyLogon). A server-side request forgery (SSRF) vulnerability allows an unauthenticated attacker to send arbitrary HTTP requests and authenticate as the Exchange server.",
    referenceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2021-26855",
  },
  {
    id: "CVE-2023-23397",
    cvssScore: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvssVersion: "3.1" as const,
    description:
      "Microsoft Outlook Elevation of Privilege Vulnerability. A specially crafted email with an extended MAPI property containing a UNC path to an attacker-controlled SMB share triggers an NTLM authentication leak as soon as the email is retrieved/processed by the Outlook client, without user interaction.",
    referenceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2023-23397",
  },
  {
    id: "CVE-2023-34362",
    cvssScore: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvssVersion: "3.1" as const,
    description:
      "Progress MOVEit Transfer SQL Injection Vulnerability that allows an unauthenticated attacker to gain unauthorized access to the MOVEit Transfer database, exploited at scale by the Cl0p ransomware group for mass data theft.",
    referenceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2023-34362",
  },
  {
    id: "CVE-2024-3094",
    cvssScore: 10.0,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    cvssVersion: "3.1" as const,
    description:
      "Malicious code was discovered in the upstream tarballs of xz-utils versions 5.6.0 and 5.6.1, introducing a backdoor into liblzma that allows an attacker with a specific Ed448 private key to execute arbitrary code via sshd on affected Linux systems.",
    referenceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
  },
  {
    id: "CVE-2022-30190",
    cvssScore: 7.8,
    cvssVector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    cvssVersion: "3.1" as const,
    description:
      "A remote code execution vulnerability in the Microsoft Windows Support Diagnostic Tool (MSDT), known as Follina, exploited via malicious Office documents that invoke MSDT through the ms-msdt URI scheme even when macros are disabled.",
    referenceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2022-30190",
  },
  {
    id: "CVE-2020-1472",
    cvssScore: 10.0,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    cvssVersion: "3.1" as const,
    description:
      "An elevation of privilege vulnerability (Zerologon) exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller using the Netlogon Remote Protocol (MS-NRPC), allowing impersonation of any computer account including the domain controller itself.",
    referenceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2020-1472",
  },
  {
    id: "CVE-2023-22515",
    cvssScore: 10.0,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    cvssVersion: "3.1" as const,
    description:
      "A broken access control vulnerability in Atlassian Confluence Data Center and Server allows an unauthenticated attacker to create unauthorized Confluence administrator accounts and access Confluence instances, observed exploited in the wild as a zero-day.",
    referenceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2023-22515",
  },
  {
    id: "CVE-2024-21887",
    cvssScore: 9.1,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
    cvssVersion: "3.1" as const,
    description:
      "A command injection vulnerability in Ivanti Connect Secure and Policy Secure web components allows an authenticated administrator to send specially crafted requests and execute arbitrary commands on the appliance, frequently chained with CVE-2023-46805 for unauthenticated exploitation.",
    referenceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2024-21887",
  },
] as const;
