const ATTACK_BASE = "https://attack.mitre.org/techniques";

export const mitreTechniqueSeeds = [
  // Reconnaissance
  { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance", parentTechniqueId: null },
  { id: "T1595.001", name: "Active Scanning: Scanning IP Blocks", tactic: "Reconnaissance", parentTechniqueId: "T1595" },
  { id: "T1589", name: "Gather Victim Identity Information", tactic: "Reconnaissance", parentTechniqueId: null },
  { id: "T1590", name: "Gather Victim Network Information", tactic: "Reconnaissance", parentTechniqueId: null },

  // Initial Access
  { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access", parentTechniqueId: null },
  { id: "T1566", name: "Phishing", tactic: "Initial Access", parentTechniqueId: null },
  { id: "T1566.001", name: "Phishing: Spearphishing Attachment", tactic: "Initial Access", parentTechniqueId: "T1566" },
  { id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "Initial Access", parentTechniqueId: "T1566" },
  { id: "T1078", name: "Valid Accounts", tactic: "Initial Access", parentTechniqueId: null },
  { id: "T1133", name: "External Remote Services", tactic: "Initial Access", parentTechniqueId: null },
  { id: "T1199", name: "Trusted Relationship", tactic: "Initial Access", parentTechniqueId: null },
  { id: "T1195", name: "Supply Chain Compromise", tactic: "Initial Access", parentTechniqueId: null },

  // Execution
  { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution", parentTechniqueId: null },
  { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution", parentTechniqueId: "T1059" },
  { id: "T1059.003", name: "Command and Scripting Interpreter: Windows Command Shell", tactic: "Execution", parentTechniqueId: "T1059" },
  { id: "T1203", name: "Exploitation for Client Execution", tactic: "Execution", parentTechniqueId: null },
  { id: "T1047", name: "Windows Management Instrumentation", tactic: "Execution", parentTechniqueId: null },
  { id: "T1204", name: "User Execution", tactic: "Execution", parentTechniqueId: null },
  { id: "T1204.002", name: "User Execution: Malicious File", tactic: "Execution", parentTechniqueId: "T1204" },
  { id: "T1569", name: "System Services", tactic: "Execution", parentTechniqueId: null },
  { id: "T1569.002", name: "System Services: Service Execution", tactic: "Execution", parentTechniqueId: "T1569" },

  // Persistence
  { id: "T1098", name: "Account Manipulation", tactic: "Persistence", parentTechniqueId: null },
  { id: "T1098.001", name: "Account Manipulation: Additional Cloud Credentials", tactic: "Persistence", parentTechniqueId: "T1098" },
  { id: "T1098.003", name: "Account Manipulation: Additional Cloud Roles", tactic: "Persistence", parentTechniqueId: "T1098" },
  { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "Persistence", parentTechniqueId: null },
  { id: "T1547.001", name: "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", tactic: "Persistence", parentTechniqueId: "T1547" },
  { id: "T1053", name: "Scheduled Task/Job", tactic: "Persistence", parentTechniqueId: null },
  { id: "T1053.005", name: "Scheduled Task/Job: Scheduled Task", tactic: "Persistence", parentTechniqueId: "T1053" },
  { id: "T1505", name: "Server Software Component", tactic: "Persistence", parentTechniqueId: null },
  { id: "T1505.003", name: "Server Software Component: Web Shell", tactic: "Persistence", parentTechniqueId: "T1505" },
  { id: "T1136", name: "Create Account", tactic: "Persistence", parentTechniqueId: null },
  { id: "T1136.003", name: "Create Account: Cloud Account", tactic: "Persistence", parentTechniqueId: "T1136" },
  { id: "T1543", name: "Create or Modify System Process", tactic: "Persistence", parentTechniqueId: null },
  { id: "T1543.003", name: "Create or Modify System Process: Windows Service", tactic: "Persistence", parentTechniqueId: "T1543" },

  // Privilege Escalation
  { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation", parentTechniqueId: null },
  { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation", parentTechniqueId: null },
  { id: "T1548.002", name: "Abuse Elevation Control Mechanism: Bypass User Account Control", tactic: "Privilege Escalation", parentTechniqueId: "T1548" },
  { id: "T1134", name: "Access Token Manipulation", tactic: "Privilege Escalation", parentTechniqueId: null },
  { id: "T1055", name: "Process Injection", tactic: "Privilege Escalation", parentTechniqueId: null },
  { id: "T1611", name: "Escape to Host", tactic: "Privilege Escalation", parentTechniqueId: null },

  // Defense Evasion
  { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion", parentTechniqueId: null },
  { id: "T1070.001", name: "Indicator Removal: Clear Windows Event Logs", tactic: "Defense Evasion", parentTechniqueId: "T1070" },
  { id: "T1562", name: "Impair Defenses", tactic: "Defense Evasion", parentTechniqueId: null },
  { id: "T1562.001", name: "Impair Defenses: Disable or Modify Tools", tactic: "Defense Evasion", parentTechniqueId: "T1562" },
  { id: "T1562.004", name: "Impair Defenses: Disable or Modify System Firewall", tactic: "Defense Evasion", parentTechniqueId: "T1562" },
  { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion", parentTechniqueId: null },
  { id: "T1027.010", name: "Obfuscated Files or Information: Command Obfuscation", tactic: "Defense Evasion", parentTechniqueId: "T1027" },
  { id: "T1036", name: "Masquerading", tactic: "Defense Evasion", parentTechniqueId: null },
  { id: "T1036.005", name: "Masquerading: Match Legitimate Name or Location", tactic: "Defense Evasion", parentTechniqueId: "T1036" },
  { id: "T1218", name: "System Binary Proxy Execution", tactic: "Defense Evasion", parentTechniqueId: null },
  { id: "T1218.011", name: "System Binary Proxy Execution: Rundll32", tactic: "Defense Evasion", parentTechniqueId: "T1218" },
  { id: "T1140", name: "Deobfuscate/Decode Files or Information", tactic: "Defense Evasion", parentTechniqueId: null },
  { id: "T1620", name: "Reflective Code Loading", tactic: "Defense Evasion", parentTechniqueId: null },
  { id: "T1556", name: "Modify Authentication Process", tactic: "Defense Evasion", parentTechniqueId: null },

  // Credential Access
  { id: "T1110", name: "Brute Force", tactic: "Credential Access", parentTechniqueId: null },
  { id: "T1110.001", name: "Brute Force: Password Guessing", tactic: "Credential Access", parentTechniqueId: "T1110" },
  { id: "T1110.003", name: "Brute Force: Password Spraying", tactic: "Credential Access", parentTechniqueId: "T1110" },
  { id: "T1110.004", name: "Brute Force: Credential Stuffing", tactic: "Credential Access", parentTechniqueId: "T1110" },
  { id: "T1558", name: "Steal or Forge Kerberos Tickets", tactic: "Credential Access", parentTechniqueId: null },
  { id: "T1558.003", name: "Steal or Forge Kerberos Tickets: Kerberoasting", tactic: "Credential Access", parentTechniqueId: "T1558" },
  { id: "T1558.004", name: "Steal or Forge Kerberos Tickets: AS-REP Roasting", tactic: "Credential Access", parentTechniqueId: "T1558" },
  { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access", parentTechniqueId: null },
  { id: "T1003.001", name: "OS Credential Dumping: LSASS Memory", tactic: "Credential Access", parentTechniqueId: "T1003" },
  { id: "T1003.002", name: "OS Credential Dumping: Security Account Manager", tactic: "Credential Access", parentTechniqueId: "T1003" },
  { id: "T1555", name: "Credentials from Password Stores", tactic: "Credential Access", parentTechniqueId: null },
  { id: "T1555.003", name: "Credentials from Password Stores: Credentials from Web Browsers", tactic: "Credential Access", parentTechniqueId: "T1555" },
  { id: "T1621", name: "Multi-Factor Authentication Request Generation", tactic: "Credential Access", parentTechniqueId: null },
  { id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access", parentTechniqueId: null },
  { id: "T1552.001", name: "Unsecured Credentials: Credentials In Files", tactic: "Credential Access", parentTechniqueId: "T1552" },
  { id: "T1187", name: "Forced Authentication", tactic: "Credential Access", parentTechniqueId: null },

  // Discovery
  { id: "T1087", name: "Account Discovery", tactic: "Discovery", parentTechniqueId: null },
  { id: "T1087.002", name: "Account Discovery: Domain Account", tactic: "Discovery", parentTechniqueId: "T1087" },
  { id: "T1018", name: "Remote System Discovery", tactic: "Discovery", parentTechniqueId: null },
  { id: "T1046", name: "Network Service Discovery", tactic: "Discovery", parentTechniqueId: null },
  { id: "T1518", name: "Software Discovery", tactic: "Discovery", parentTechniqueId: null },
  { id: "T1518.001", name: "Software Discovery: Security Software Discovery", tactic: "Discovery", parentTechniqueId: "T1518" },

  // Lateral Movement
  { id: "T1021", name: "Remote Services", tactic: "Lateral Movement", parentTechniqueId: null },
  { id: "T1021.001", name: "Remote Services: Remote Desktop Protocol", tactic: "Lateral Movement", parentTechniqueId: "T1021" },
  { id: "T1021.002", name: "Remote Services: SMB/Windows Admin Shares", tactic: "Lateral Movement", parentTechniqueId: "T1021" },
  { id: "T1021.006", name: "Remote Services: Windows Remote Management", tactic: "Lateral Movement", parentTechniqueId: "T1021" },
  { id: "T1570", name: "Lateral Tool Transfer", tactic: "Lateral Movement", parentTechniqueId: null },
  { id: "T1550", name: "Use Alternate Authentication Material", tactic: "Lateral Movement", parentTechniqueId: null },
  { id: "T1550.002", name: "Use Alternate Authentication Material: Pass the Hash", tactic: "Lateral Movement", parentTechniqueId: "T1550" },
  { id: "T1550.003", name: "Use Alternate Authentication Material: Pass the Ticket", tactic: "Lateral Movement", parentTechniqueId: "T1550" },

  // Collection
  { id: "T1119", name: "Automated Collection", tactic: "Collection", parentTechniqueId: null },
  { id: "T1114", name: "Email Collection", tactic: "Collection", parentTechniqueId: null },
  { id: "T1530", name: "Data from Cloud Storage", tactic: "Collection", parentTechniqueId: null },

  // Command and Control
  { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control", parentTechniqueId: null },
  { id: "T1071.001", name: "Application Layer Protocol: Web Protocols", tactic: "Command and Control", parentTechniqueId: "T1071" },
  { id: "T1071.004", name: "Application Layer Protocol: DNS", tactic: "Command and Control", parentTechniqueId: "T1071" },
  { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control", parentTechniqueId: null },
  { id: "T1572", name: "Protocol Tunneling", tactic: "Command and Control", parentTechniqueId: null },
  { id: "T1090", name: "Proxy", tactic: "Command and Control", parentTechniqueId: null },
  { id: "T1102", name: "Web Service", tactic: "Command and Control", parentTechniqueId: null },
  { id: "T1528", name: "Steal Application Access Token", tactic: "Credential Access", parentTechniqueId: null },

  // Exfiltration
  { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration", parentTechniqueId: null },
  { id: "T1567", name: "Exfiltration Over Web Service", tactic: "Exfiltration", parentTechniqueId: null },
  { id: "T1567.002", name: "Exfiltration Over Web Service: Exfiltration to Cloud Storage", tactic: "Exfiltration", parentTechniqueId: "T1567" },
  { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration", parentTechniqueId: null },
  { id: "T1029", name: "Scheduled Transfer", tactic: "Exfiltration", parentTechniqueId: null },

  // Impact
  { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", parentTechniqueId: null },
  { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact", parentTechniqueId: null },
  { id: "T1485", name: "Data Destruction", tactic: "Impact", parentTechniqueId: null },
  { id: "T1489", name: "Service Stop", tactic: "Impact", parentTechniqueId: null },
] as const;

export function mitreReferenceUrl(id: string): string {
  const parts = id.split(".");
  if (parts.length === 2) {
    return `${ATTACK_BASE}/${parts[0]}/${parts[1]}/`;
  }
  return `${ATTACK_BASE}/${id}/`;
}
