import type { RuleSeed } from "../types";

export const supplyChainRules: RuleSeed[] = [
  // --- XZ Utils Backdoor (YARA + Sigma) ---
  {
    family: {
      id: "fam-xz-backdoor",
      name: "XZ Utils Supply Chain Backdoor (CVE-2024-3094)",
      slug: "xz-utils-supply-chain-backdoor",
      categoryId: "cat-cve-exploitation",
      conceptDescription:
        "CVE-2024-3094 is a backdoor deliberately introduced into the xz-utils compression library (versions 5.6.0 and 5.6.1) by a long-term contributor to the project who had gradually gained maintainer trust over roughly two years - one of the most sophisticated supply-chain attacks ever discovered, and notable for being caught before widespread deployment to production systems (discovered by a Microsoft engineer investigating unrelated SSH performance anomalies in Debian unstable).\n\nThe backdoor was hidden with extraordinary care: the malicious code was NOT in the project's git repository in readable form, but was instead injected via the release tarballs' build process - a malicious `build-to-host.m4` file in the autotools build chain, combined with deliberately corrupted/disabled test files (`bad-3-corrupt_lzma2.xz`, `good-large_compressed.lzma2.xz` and others, which appeared to be test fixtures but actually contained the staged backdoor payload in obfuscated form), extracted and assembled the backdoor only during the `./configure` && `make` build process - meaning the backdoor was essentially invisible to anyone reviewing the source repository directly, only manifesting in compiled binaries built from the official release tarballs.\n\nThe payload hooks into `liblzma`, which is a dependency of `libsystemd`, which in turn is linked by `sshd` on systems using systemd's notification socket integration for SSH (common on Debian/RPM-based distributions with patches integrating sshd with systemd). The backdoor intercepts RSA/Ed448 key-related operations during SSH authentication, allowing an attacker possessing a specific private key to bypass authentication and achieve remote code execution via `sshd` - effectively a universal SSH master-key backdoor on any affected system.\n\nBecause this was caught extremely early (affected versions were only in Linux distribution 'unstable'/'testing' branches like Debian Sid and Fedora 40/41 Rawhide, not stable releases), detection focuses primarily on identifying whether the vulnerable library versions are present at all (version/file-hash scanning) rather than detecting active exploitation (for which no widespread evidence was found). The detection rules here serve both as a historical/educational example of supply-chain compromise detection and as a template for similar future incidents - checking installed package versions against known-bad version strings, and YARA scanning for the specific obfuscated test-file signatures used to smuggle the payload.",
    },
    variants: [
      {
        id: "rule-xz-backdoor-yara",
        language: "yara",
        title: "XZ Utils 5.6.0/5.6.1 Backdoor Test File Signatures",
        slug: "xz-backdoor-test-file-signatures-yara",
        descriptionSummary:
          "YARA rule matching the specific obfuscated test-fixture files used to smuggle the CVE-2024-3094 backdoor payload into compiled xz-utils 5.6.0/5.6.1 binaries.",
        ruleBody: `rule XZ_Utils_CVE_2024_3094_Backdoor_Test_Files
{
    meta:
        description = "Detects the specific corrupted/obfuscated .xz test fixture files used to smuggle the XZ backdoor payload (CVE-2024-3094)"
        author = "Sentriq Detection Engineering"
        date = "2024-04-01"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"
        severity = "critical"

    strings:
        // Filenames of the specific test fixtures identified as carrying the
        // obfuscated backdoor payload within the xz-utils 5.6.0/5.6.1 source tarballs
        $fname1 = "bad-3-corrupt_lzma2.xz"
        $fname2 = "good-large_compressed.lzma2.xz"
        $fname3 = "tests/files/bad-3-corrupt_lzma2.xz"

        // The malicious build-to-host.m4 macro injected into the build chain
        $m4_marker1 = "build-to-host.m4"
        $m4_marker2 = "GL_GCC_VERSION_IFELSE"

    condition:
        any of ($fname*) or all of ($m4_marker*)
}

rule XZ_Utils_Backdoored_Version_String
{
    meta:
        description = "Detects xz/liblzma version strings matching the known-backdoored 5.6.0 and 5.6.1 releases"
        author = "Sentriq Detection Engineering"
        date = "2024-04-01"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"
        severity = "critical"

    strings:
        $ver_560 = "xz (XZ Utils) 5.6.0" ascii
        $ver_561 = "xz (XZ Utils) 5.6.1" ascii
        $liblzma_560 = "liblzma.so.5.6.0" ascii
        $liblzma_561 = "liblzma.so.5.6.1" ascii

    condition:
        any of them
}`,
        ruleFormatVersion: "YARA 4.x",
        severity: "critical",
        status: "stable",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "The version-string rule (`XZ_Utils_Backdoored_Version_String`) will only match systems that have the literal backdoored versions (5.6.0/5.6.1) installed - these versions were only ever distributed in Linux 'unstable'/'testing'/'rawhide' branches (Debian Sid, Fedora 41/Rawhide, openSUSE Tumbleweed, Kali rolling during the affected window) and a small number of container images built from those bases; if a match occurs on a production system, it should be treated as critical regardless of whether active exploitation is confirmed, since the mere presence of the backdoored library on an SSH-accessible host represents the vulnerability. The test-file-signature rule has effectively zero false-positive rate when scanning source tarballs/build artifacts - these exact filenames with this exact content have no legitimate purpose outside the compromised xz-utils releases. This rule set is primarily a software-composition/asset-inventory check (have we ever built or deployed anything from the affected tarballs) rather than a runtime intrusion detection - run it against package manifests, container image layers, and build artifact caches.",
        dataSourceRequirements:
          "File system / package-manager scanning capability (dpkg/rpm database queries for installed package versions, or YARA scanning of container image layers and build caches for the test-file signatures).",
        mitreTechniqueIds: ["T1195"],
        cveIds: ["CVE-2024-3094"],
        tags: ["Supply Chain", "XZ Utils", "Backdoor", "SSH"],
        references: [
          {
            url: "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
            title: "NVD - CVE-2024-3094",
            referenceType: "cve_record",
          },
          {
            url: "https://www.openwall.com/lists/oss-security/2024/03/29/4",
            title: "Openwall oss-security - backdoor in upstream xz/liblzma leading to ssh server compromise",
            referenceType: "blog_post",
          },
        ],
      },
      {
        id: "rule-xz-backdoor-sigma",
        language: "sigma",
        title: "SSH Authentication via Backdoored liblzma on Affected Linux Hosts",
        slug: "xz-backdoor-sshd-anomaly-sigma",
        descriptionSummary:
          "Detects sshd process behavior anomalies consistent with the XZ backdoor's authentication-bypass code path - unexpected sshd crashes or unusual CPU usage patterns during authentication on hosts running affected liblzma versions.",
        ruleBody: `title: Potential XZ Backdoor Exploitation - Anomalous sshd Behavior
id: 2a3b4c5d-6e7f-4a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: |
    Detects anomalous sshd process behavior on Linux hosts confirmed to have the
    backdoored liblzma 5.6.0/5.6.1 installed (see companion YARA rule for version
    detection). Because the backdoor intercepts RSA_public_decrypt (or similar
    cryptographic operations) during SSH authentication via an IFUNC hook in
    liblzma, exploitation attempts may manifest as sshd crashes (SIGSEGV) during
    authentication, or as authentication taking measurably longer than baseline
    due to the additional backdoor code path executing.

    NOTE: This rule is marked experimental - at the time of writing, no confirmed
    in-the-wild exploitation of this backdoor was observed (it was caught before
    widespread deployment). This rule serves as a template should similar future
    supply-chain backdoors in widely-linked libraries require runtime detection.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-3094
    - https://www.openwall.com/lists/oss-security/2024/03/29/4
author: Sentriq Detection Engineering
date: 2024-04-02
tags:
    - attack.initial_access
    - attack.t1195
    - cve.2024.3094
logsource:
    product: linux
    service: auth
detection:
    selection_sshd_crash:
        process: 'sshd'
        signal: 'SIGSEGV'
    selection_sshd_aborted_auth:
        message|contains:
            - 'sshd[*]: error: kex_exchange_identification'
            - 'sshd[*]: Connection closed by'
    condition: selection_sshd_crash or selection_sshd_aborted_auth
falsepositives:
    - sshd crashes/connection resets have many benign causes (network instability, client incompatibility, fail2ban interactions) - this rule should ONLY be enabled on hosts confirmed to have the backdoored liblzma version present (see companion YARA/version-check rule), where it serves as a secondary monitoring layer while the host is being remediated/rebuilt
level: medium
---
title: Host Running Backdoored liblzma Version (Asset Inventory Check)
id: 3b4c5d6e-7f8a-4b9c-0d1e-2f3a4b5c6d7e
status: stable
description: |
    Identifies hosts with liblzma 5.6.0 or 5.6.1 installed via package inventory
    logs - the primary, highest-confidence detection for CVE-2024-3094, since the
    correct remediation is to remove/downgrade the package on any host where it's
    found, regardless of whether exploitation is observed.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-3094
author: Sentriq Detection Engineering
date: 2024-04-02
tags:
    - attack.initial_access
    - attack.t1195
    - cve.2024.3094
logsource:
    product: linux
    category: package_inventory
detection:
    selection:
        package_name: 'xz-utils'
        package_version:
            - '5.6.0'
            - '5.6.1'
    selection_lib:
        package_name: 'liblzma5'
        package_version:
            - '5.6.0'
            - '5.6.1'
    condition: selection or selection_lib
falsepositives:
    - None - presence of these exact versions is the vulnerability itself
level: critical`,
        ruleFormatVersion: "Sigma Schema 2.0 (multi-document)",
        severity: "critical",
        status: "experimental",
        author: "Sentriq Detection Engineering",
        ruleVersion: "1.0",
        falsePositiveNotes:
          "The first sub-rule (anomalous sshd behavior) is marked experimental and has a HIGH false-positive rate if deployed broadly - sshd crashes and connection resets are common for many benign reasons. It should only be enabled, scoped, or weighted as part of an alert on hosts that the second sub-rule (package inventory check) has already flagged as running the backdoored version - at which point ANY sshd anomaly becomes worth a closer look while remediation is in progress. The package-inventory check itself has zero false positives: these exact version strings should not exist on any system following remediation (downgrade to 5.4.x or a patched 5.6.x+ release), and any detection should trigger immediate package removal/downgrade and host investigation (was SSH accessible from untrusted networks while the backdoored version was installed?) rather than waiting for exploitation evidence.",
        dataSourceRequirements:
          "Linux package manager inventory data (dpkg/rpm query results) collected via configuration-management/asset-inventory tooling (Osquery, Wazuh, Ansible facts) and forwarded to the SIEM; auth.log/journald sshd logs for the experimental behavioral sub-rule.",
        mitreTechniqueIds: ["T1195"],
        cveIds: ["CVE-2024-3094"],
        tags: ["Supply Chain", "XZ Utils", "Backdoor", "SSH"],
        references: [
          {
            url: "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
            title: "NVD - CVE-2024-3094",
            referenceType: "cve_record",
          },
        ],
      },
    ],
  },
];
