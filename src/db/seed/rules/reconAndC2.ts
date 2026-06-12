import type { RuleSeed } from "../types";

export const reconAndC2Rules: RuleSeed[] = [
  // --- Port Scan Detection (Cloudflare + Splunk) ---
  {
    family: {
      id: "fam-port-scan",
      name: "Port Scanning Against Internet-Facing Infrastructure",
      slug: "port-scanning-internet-facing",
      categoryId: "cat-recon",
      conceptDescription:
        "Port scanning is the reconnaissance technique of systematically probing a range of network ports on a target host or range of hosts to identify open services, often as a precursor to more targeted exploitation attempts against whatever services are discovered. Tools like Nmap, Masscan, and Zmap can scan large IP ranges and full port ranges (1-65535) extremely quickly - Masscan in particular can scan the entire IPv4 address space for a single port in under an hour from a well-resourced host.\n\nFrom the perspective of a single organization's internet-facing infrastructure, port scanning manifests as connection attempts to many different destination ports (or many different destination IPs on the same port, for horizontal scans across a CIDR range) from the same source IP within a short time window, with most connections receiving no response, a RST (closed port), or - for the smaller subset of open ports - a SYN-ACK followed by the scanner immediately closing the connection without sending application-layer data (since the scanner is just enumerating, not interacting).\n\nWhile port scanning itself is extremely common - the modern internet is continuously scanned by research projects (Shodan, Censys), security vendors, and malicious actors alike, such that any internet-facing IP will see scan traffic essentially constantly - the value of detecting it lies in: (1) identifying scans that are unusually targeted or thorough (suggesting a more motivated actor doing reconnaissance specifically against your organization, vs. opportunistic internet-wide background noise), (2) correlating scan activity with subsequent exploitation attempts against the specific services discovered as open, and (3) at the WAF/application layer, detecting scans for specific sensitive paths/endpoints (admin panels, API documentation, common CMS paths) which indicate targeted reconnaissance of the web application itself rather than generic port-level scanning.",
    },
    variants: [
      {
        id: "rule-port-scan-cloudflare",
        language: "cloudflare",
        platformVariant: "WAF Custom Rule / Rate Limiting",
        title: "Block Sources Requesting Many Distinct Sensitive Paths in Short Window",
        slug: "sensitive-path-enumeration-cloudflare",
        descriptionSummary:
          "Cloudflare rate-limiting rule that challenges/blocks source IPs requesting a high number of distinct sensitive paths (admin panels, config files, common CMS endpoints) in a short time window - indicating application-layer reconnaissance.",
        ruleBody: `# Cloudflare Rate Limiting Rule (configured via Cloudflare dashboard / API)
# Matches requests to commonly-probed sensitive paths, rate-limits by source IP

# --- Rule expression (which requests count toward the rate limit) ---
(
  http.request.uri.path matches "(?i)^/(wp-admin|wp-login\\\\.php|administrator|phpmyadmin|\\\\.env|\\\\.git/config|config\\\\.php|actuator|admin/config|\\\\.aws/credentials|server-status|debug/default/view)" or
  http.request.uri.path matches "(?i)\\\\.(bak|old|sql|swp|zip)$"
)

# --- Rate limiting configuration ---
# Characteristic to count: cf.colo.region or ip.src (per source IP)
# Period: 60 seconds
# Requests threshold: 10
# Mitigation action: Managed Challenge for first breach, Block for repeat offenders (escalation via separate rule + WAF custom list)

# --- Companion: add offending IPs to a temporary blocklist for 1 hour ---
# Action: "Block" with a 1-hour rate-limit duration once threshold exceeded`,
        ruleFormatVersion: "Cloudflare Rate Limiting Rules + WAF Custom Rules",
        severity: "medium",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.1",
        falsePositiveNotes:
          "Legitimate security scanning (your own vulnerability scanners, bug bounty researchers operating within program scope) will trigger this rule - maintain an allowlist of authorized scanner source IPs/ASNs. Some legitimate monitoring/uptime services occasionally probe `/server-status` or similar endpoints if misconfigured to do so by the customer; if you intentionally expose any of these paths for legitimate purposes (rare, but e.g., an `/actuator/health` endpoint intentionally exposed for a load balancer health check), exclude that specific path from the rule rather than disabling it entirely. The threshold (10 requests/60s) is intentionally low since legitimate users never request these paths at all - any single hit on `.env` or `.git/config` is worth investigating even below the rate-limit threshold, via a separate informational/log-only rule.",
        dataSourceRequirements:
          "Cloudflare zone with WAF and Rate Limiting Rules enabled (available on Pro plan and above for custom rate limiting).",
        mitreTechniqueIds: ["T1595.001", "T1190"],
        cveIds: [],
        tags: ["Reconnaissance", "Scanning", "WAF"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1595/001/",
            title: "MITRE ATT&CK - Scanning IP Blocks",
            referenceType: "mitre_page",
          },
        ],
      },
      {
        id: "rule-port-scan-splunk",
        language: "splunk",
        title: "Horizontal/Vertical Port Scan Detection from Firewall Logs",
        slug: "port-scan-detection-firewall-logs-splunk",
        descriptionSummary:
          "SPL search identifying source IPs that attempt connections to many distinct destination ports (vertical scan) or many distinct destination hosts on the same port (horizontal scan) within a short window.",
        ruleBody: `\`# Port Scan Detection - Splunk SPL\`
\`# Identifies vertical scans (many ports, one host) and horizontal scans (one port, many hosts)\`

index=firewall sourcetype IN ("cisco:asa", "paloalto:firewall", "fortinet:firewall")
action IN ("deny", "drop", "reset")
| bin _time span=5m
| stats
    dc(dest_port) as distinct_ports,
    dc(dest_ip) as distinct_hosts,
    values(dest_port) as ports_attempted,
    count as total_attempts
    by _time, src_ip
| eval scan_type=case(
    distinct_ports >= 20 AND distinct_hosts <= 3, "vertical_scan",
    distinct_hosts >= 20 AND distinct_ports <= 3, "horizontal_scan",
    distinct_ports >= 20 AND distinct_hosts >= 20, "block_scan",
    1=1, "none"
  )
| where scan_type != "none"
| eval severity=case(
    scan_type="block_scan", "high",
    1=1, "medium"
  )
| table _time, src_ip, scan_type, distinct_ports, distinct_hosts, total_attempts, severity
| sort - total_attempts`,
        ruleFormatVersion: "SPL (Search Processing Language)",
        severity: "medium",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "Internal vulnerability scanners (Nessus, Qualys, Rapid7) performing scheduled scans will match this pattern exactly and at high volume - exclude known scanner IPs via a lookup table (`| lookup authorized_scanners.csv src_ip OUTPUT is_authorized | where isnull(is_authorized)`). Network monitoring/discovery tools (Lansweeper, SolarWinds) that perform periodic asset discovery via port probing will also match `horizontal_scan` - these typically run on a predictable schedule from a fixed management host, making them straightforward to allowlist. The `block_scan` classification (both high port-count and high host-count) is the least likely to have benign explanations and should be prioritized.",
        dataSourceRequirements:
          "Firewall deny/drop logs (Cisco ASA, Palo Alto, Fortinet, or equivalent) ingested into Splunk with normalized `src_ip`, `dest_ip`, `dest_port`, `action` fields (CIM-compliant Network Traffic data model recommended).",
        mitreTechniqueIds: ["T1595.001", "T1046"],
        cveIds: [],
        tags: ["Reconnaissance", "Port Scan", "Firewall"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1595/001/",
            title: "MITRE ATT&CK - Scanning IP Blocks",
            referenceType: "mitre_page",
          },
          {
            url: "https://attack.mitre.org/techniques/T1046/",
            title: "MITRE ATT&CK - Network Service Discovery",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },

  // --- DNS Tunneling (Sigma + Splunk) ---
  {
    family: {
      id: "fam-dns-tunneling",
      name: "DNS Tunneling for Command-and-Control or Exfiltration",
      slug: "dns-tunneling-c2-exfiltration",
      categoryId: "cat-c2",
      conceptDescription:
        "DNS tunneling encodes data within DNS queries and responses to establish a covert communication channel, exploiting the fact that DNS traffic is almost universally permitted outbound through firewalls (since virtually all applications depend on DNS resolution) and is often subject to less scrutiny than HTTP/HTTPS traffic. Attackers use DNS tunneling for both command-and-control (receiving commands embedded in DNS responses, typically in TXT or CNAME records) and data exfiltration (encoding stolen data into the subdomain labels of outbound DNS queries, e.g., `<base32-encoded-data-chunk>.exfil.attacker-domain.com`).\n\nTools like `dnscat2`, `iodine`, and custom malware DNS-tunneling implementations (used by APT groups including OilRig/APT34 and many others) share detectable characteristics: an abnormally high volume of DNS queries to a single domain (since data must be chunked into many small DNS messages due to the size limits of DNS labels - 63 characters per label, 255 total), queries with unusually long or high-entropy subdomain labels (encoded data looks random compared to typical hostnames), queries for record types rarely used by normal applications (TXT, NULL records used for tunneling payloads), and queries to domains with very low overall popularity/reputation that nonetheless receive sustained query volume from internal hosts.\n\nDetection approaches include: (1) volumetric - counting distinct subdomains queried per parent domain per host within a time window, flagging domains receiving an abnormally high count of unique subdomains (legitimate domains rarely have more than a handful of distinct subdomains queried by a single host), (2) entropy-based - calculating Shannon entropy of query labels and flagging high-entropy labels inconsistent with human-readable hostnames, and (3) record-type-based - flagging TXT/NULL queries to non-standard domains, since these record types are used by mail (SPF/DKIM, which queries known domains) and DNSSEC but rarely by general client traffic to arbitrary external domains.",
    },
    variants: [
      {
        id: "rule-dns-tunneling-sigma",
        language: "sigma",
        title: "DNS Tunneling - High Volume of Distinct Subdomain Queries to Single Domain",
        slug: "dns-tunneling-high-subdomain-volume-sigma",
        descriptionSummary:
          "Sigma correlation rule detecting a single host issuing an abnormally high number of distinct subdomain DNS queries to the same parent domain within a short window - the volumetric signature of DNS tunneling.",
        ruleBody: `title: DNS Tunneling - High Volume of Unique Subdomains Queried
id: 1f2a3b4c-5d6e-4f7a-8b9c-0d1e2f3a4b5c
status: stable
description: |
    Detects a single host issuing DNS queries for an abnormally high number of
    distinct subdomains under the same parent (registrable) domain within a short
    time window. Legitimate domains are queried for a small, stable set of
    hostnames; a high volume of distinct, often high-entropy subdomains is the
    primary volumetric signature of DNS tunneling tools (dnscat2, iodine, custom
    C2 implants).
references:
    - https://attack.mitre.org/techniques/T1071/004/
    - https://unit42.paloaltonetworks.com/dns-tunneling-in-the-wild-overview-of-oilrigs-dns-tunneling/
author: Sentriq Detection Engineering
date: 2023-05-18
tags:
    - attack.command_and_control
    - attack.exfiltration
    - attack.t1071.004
    - attack.t1048
logsource:
    category: dns
detection:
    selection:
        record_type:
            - 'A'
            - 'TXT'
            - 'CNAME'
            - 'NULL'
    timeframe: 10m
    condition: selection | count(distinct query_subdomain) by src_ip, query_registrable_domain > 50
falsepositives:
    - Content Delivery Networks (CDNs) and cloud services that legitimately use many distinct, randomly-generated subdomains for routing/load-balancing (e.g., some CDN edge node addressing schemes)
    - Telemetry/analytics SDKs that generate unique per-session subdomains for cache-busting
level: high`,
        ruleFormatVersion: "Sigma Schema 2.0 (Correlation)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "Some CDNs and SaaS platforms (notably certain configurations of Akamai, CloudFront, or analytics/telemetry vendors) legitimately generate large numbers of distinct subdomains under a shared parent domain as part of their normal operation - these should be identified during a baseline period and added to a domain allowlist (`query_registrable_domain` exclusion list). The 50-subdomains-per-10-minutes threshold is a starting point; environments with heavy use of such legitimate high-cardinality-subdomain services may need a higher threshold or a per-domain allowlist rather than a global one. High-entropy label scoring (a secondary signal not encoded in this base rule) can help distinguish 'many subdomains that look like CDN routing hashes' from 'many subdomains that look like base32/base64-encoded exfiltrated data' - both can be high-cardinality, but the latter has higher character-distribution entropy.",
        dataSourceRequirements:
          "DNS query logs from an internal DNS resolver (Windows DNS analytical logging, BIND query logs, or a DNS security product like Cisco Umbrella/Infoblox) with source host IP, queried name, and record type fields. Requires a correlation-capable backend.",
        mitreTechniqueIds: ["T1071.004", "T1048"],
        cveIds: [],
        tags: ["DNS Tunneling", "C2", "Exfiltration"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1071/004/",
            title: "MITRE ATT&CK - DNS",
            referenceType: "mitre_page",
          },
        ],
      },
      {
        id: "rule-dns-tunneling-splunk",
        language: "splunk",
        title: "DNS Tunneling - High-Entropy Subdomain Labels with TXT Record Queries",
        slug: "dns-tunneling-high-entropy-txt-splunk",
        descriptionSummary:
          "SPL search calculating Shannon entropy of queried subdomain labels and flagging hosts issuing high-entropy TXT/NULL record queries to non-allowlisted domains - a complementary entropy-based DNS tunneling detection.",
        ruleBody: `\`# DNS Tunneling Detection - High Entropy Subdomain Labels (Splunk SPL)\`
\`# Requires a custom entropy-calculation macro or use of the | eval with mvmap for char-frequency analysis\`
\`# This example assumes a pre-computed 'label_entropy' field from a DNS log enrichment pipeline\`
\`# (e.g., via a Splunk lookup/eval that runs Shannon entropy over the leftmost label)\`

index=dns sourcetype="dns:query"
record_type IN ("TXT", "NULL", "A")
| eval leftmost_label=mvindex(split(query, "."), 0)
| eval label_length=len(leftmost_label)
\`# Shannon entropy approximation via character frequency - simplified inline calc\`
| eval char_list=split(leftmost_label, "")
| eval total_chars=mvcount(char_list)
| eventstats count as char_count by char_list
| eval entropy=if(total_chars>0, round(log(total_chars,2) * (1 - (1/total_chars)), 2), 0)
| where label_length > 20 AND entropy > 3.5
| lookup allowlisted_domains.csv query_registrable_domain OUTPUT is_allowlisted
| where isnull(is_allowlisted)
| stats
    count as query_count,
    dc(leftmost_label) as distinct_labels,
    values(record_type) as record_types,
    avg(entropy) as avg_entropy
    by src_ip, query_registrable_domain
| where query_count > 10
| sort - query_count`,
        ruleFormatVersion: "SPL (Search Processing Language)",
        severity: "high",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "The entropy calculation in this example is simplified for illustration; production deployments should use a proper Shannon entropy implementation (via a custom Splunk command, a lookup-based n-gram model, or pre-computed during log ingestion). High-entropy labels also occur legitimately for: container/pod-name-based DNS in Kubernetes clusters (pod IPs/hashes as hostnames), some load-balancer health-check subdomains, and certain ad-tech/tracking pixels that encode session IDs in subdomains. The `allowlisted_domains.csv` lookup is essential - without it, this rule will be extremely noisy in any environment with significant cloud-native or ad-tech traffic. TXT record queries specifically are rare for general workstation traffic outside of mail server infrastructure (which queries TXT for SPF/DKIM/DMARC against known mail-related domains) - TXT queries from end-user workstations to arbitrary external domains are a stronger signal than the A-record volumetric pattern alone.",
        dataSourceRequirements:
          "DNS query logs with record type and full query name, ingested into Splunk. A maintained `allowlisted_domains.csv` lookup of known-legitimate high-cardinality-subdomain services.",
        mitreTechniqueIds: ["T1071.004", "T1048"],
        cveIds: [],
        tags: ["DNS Tunneling", "C2", "Entropy Analysis"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1071/004/",
            title: "MITRE ATT&CK - DNS",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },

  // --- Cloud Storage Exfiltration (Cloudflare) ---
  {
    family: {
      id: "fam-cloud-storage-exfil",
      name: "Data Exfiltration to Unsanctioned Cloud Storage Services",
      slug: "cloud-storage-exfiltration",
      categoryId: "cat-exfiltration",
      conceptDescription:
        "Exfiltration to cloud storage services abuses the fact that domains like `*.s3.amazonaws.com`, `drive.google.com`, `*.dropbox.com`, `transfer.sh`, `*.blob.core.windows.net`, and similar are typically allowed through corporate web proxies/firewalls by default (since they're widely used for legitimate business purposes), making them attractive destinations for attackers to upload stolen data without triggering network-layer blocks that would catch traffic to less-reputable destinations.\n\nThis technique is used both by sophisticated threat actors during multi-stage intrusions (after achieving access and collection, data is staged and uploaded to an attacker-controlled cloud storage bucket or a temporary file-sharing service before the attacker's session ends) and by insiders exfiltrating data to personal cloud storage accounts (a common insider-threat pattern: an employee planning to leave uploads large volumes of company files to their personal Google Drive or Dropbox shortly before resignation).\n\nAt the network egress layer (proxy logs, Cloudflare Gateway/CASB-style controls), detection focuses on: (1) large outbound POST/PUT request volumes (by byte count) to cloud storage domains, especially from hosts/users that don't normally interact with that service, (2) uploads to *personal* instances of sanctioned services (e.g., the corporate Google Workspace is sanctioned, but a user's personal `@gmail.com`-associated Drive is not - distinguishable via the destination account/tenant ID in the request where visible), and (3) uploads to file-sharing services with no business justification at all (`transfer.sh`, `anonfiles`, `mega.nz`) which should arguably be blocked outright rather than merely monitored. Cloudflare's Zero Trust/Gateway product (DLP + CASB policies) is increasingly used to enforce these controls at the DNS/HTTP layer for all egress traffic, not just traffic to the organization's own web properties.",
    },
    variants: [
      {
        id: "rule-cloud-storage-exfil-cloudflare",
        language: "cloudflare",
        platformVariant: "Cloudflare Gateway (Zero Trust) HTTP Policy",
        title: "Block Uploads to Unsanctioned File-Sharing Services and Flag Large Uploads to Personal Cloud Storage",
        slug: "cloud-storage-exfil-gateway-policy-cloudflare",
        descriptionSummary:
          "Cloudflare Gateway HTTP policy blocking uploads to known unsanctioned file-sharing domains outright, and flagging/logging large POST/PUT requests to sanctioned cloud storage providers for DLP review.",
        ruleBody: `# Cloudflare Gateway (Zero Trust) HTTP Policies
# Configured via Gateway > Firewall Policies > HTTP

# --- Policy 1: Block unsanctioned file-sharing/transfer services outright ---
# Action: Block
# Expression:
any(dns.fqdn in {
  "transfer.sh"
  "anonfiles.com"
  "mega.nz"
  "wetransfer.com"
  "send.firefox.com"
  "file.io"
})

# --- Policy 2: Flag large uploads to sanctioned cloud storage from non-corporate accounts ---
# Action: Block (or "Isolate" for browser-isolation review)
# Expression (requires HTTP body/header inspection - Gateway with DLP add-on):
(
  any(dns.fqdn in {"drive.google.com" "docs.google.com" "*.dropbox.com" "*.box.com"}) and
  http.request.method in {"POST" "PUT"} and
  http.request.body.size > 26214400  \`# 25 MB\`
)
and not (
  \`# Exclude requests where the destination account matches the corporate tenant\`
  \`# (requires Gateway DLP / CASB API-based posture integration for account-level visibility)\`
  http.request.headers["X-Goog-AuthUser"][0] == "corporate-tenant-id"
)

# --- Policy 3: Log (do not block) all traffic to *.s3.amazonaws.com and *.blob.core.windows.net
#     for separate DLP/anomaly analysis - too broad to block given legitimate enterprise SaaS usage ---
# Action: Allow + Log
any(dns.fqdn in {"*.s3.amazonaws.com" "*.blob.core.windows.net" "*.storage.googleapis.com"})`,
        ruleFormatVersion: "Cloudflare Zero Trust Gateway HTTP Policies",
        severity: "medium",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "Policy 1 (blocking transfer.sh/mega.nz/etc.) is low-risk to deploy as a hard block in most enterprises since these services rarely have legitimate business use - if a team does have a legitimate need (e.g., sending large files to an external partner), provide a sanctioned alternative (corporate-managed secure file transfer) rather than excepting these domains. Policy 2's account-based exclusion (`X-Goog-AuthUser` header matching) requires the corporate Google Workspace tenant ID and only works for Google services with this header pattern - equivalent account-scoping for Dropbox/Box requires their respective API-based CASB integrations rather than header inspection alone, since not all services expose tenant identity in a simple header. The 25 MB threshold in Policy 2 should be tuned based on typical legitimate file sizes in your environment (e.g., design teams routinely working with large media files will need either a higher threshold or an exception for verified corporate-tenant destinations). Policy 3 is intentionally log-only given how broadly `*.s3.amazonaws.com` is used by legitimate enterprise SaaS products (effectively unblockable without breaking many integrations) - its value is for retrospective DLP analysis, not real-time blocking.",
        dataSourceRequirements:
          "Cloudflare Zero Trust (Gateway) deployed as the organization's secure web gateway / DNS filtering layer, with HTTP policy inspection enabled (requires routing traffic through Cloudflare's proxy, e.g., via WARP client or PAC file).",
        mitreTechniqueIds: ["T1567.002", "T1048"],
        cveIds: [],
        tags: ["Exfiltration", "Cloud Storage", "DLP", "Insider Threat"],
        references: [
          {
            url: "https://attack.mitre.org/techniques/T1567/002/",
            title: "MITRE ATT&CK - Exfiltration to Cloud Storage",
            referenceType: "mitre_page",
          },
        ],
      },
    ],
  },
];
