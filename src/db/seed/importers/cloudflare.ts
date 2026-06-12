import fs from "node:fs";
import path from "node:path";
import type { ImportedRuleRecord, ImporterOptions, RuleImporter } from "./types";
import type { RuleSeverity } from "../types";

const REPO = "mintyYuki/cf-waf-ruleset";
const BRANCH = "main";
const RAW_BASE = `https://raw.githubusercontent.com/${REPO}/${BRANCH}`;
const REPO_BLOB_BASE = `https://github.com/${REPO}/blob/${BRANCH}`;
const LICENSE_URL = `https://github.com/${REPO}/blob/${BRANCH}/LICENSE`;

interface CloudflareRuleDef {
  file: string;
  title: string;
  description: string;
  action: string;
  severity: RuleSeverity;
  categoryId: string;
  tags: string[];
}

const RULE_DEFS: CloudflareRuleDef[] = [
  {
    file: "BasicSecurity.txt",
    title: "Cloudflare WAF: Basic Security Block List",
    description:
      "Blocks requests matching common low-sophistication abuse signals: known-bad ASNs, malformed/blank user agents, anomalous HTTP versions, and suspicious characters in request URIs. Intended as a baseline Layer 7 filter for Cloudflare-fronted applications.",
    action: "Block",
    severity: "medium",
    categoryId: "cat-web-attacks",
    tags: ["cloudflare-waf", "layer7", "ddos"],
  },
  {
    file: "AntiExploit.txt",
    title: "Cloudflare WAF: Anti-Exploit Query String Patterns",
    description:
      "Blocks requests whose query string contains common SQL injection, XSS, and PHP code-injection patterns (SQL comment sequences, `benchmark()`, `<script>`, `<?php`, encoded null bytes/control characters, etc.).",
    action: "Block",
    severity: "high",
    categoryId: "cat-web-attacks",
    tags: ["cloudflare-waf", "sql-injection", "xss"],
  },
  {
    file: "AdvancedSecurity-1.txt",
    title: "Cloudflare WAF: Advanced Security — Anomalous Request Signals (1)",
    description:
      "Issues a Managed Challenge for requests exhibiting anomalous HTTP methods (PUT/PATCH/DELETE/PURGE), suspicious/blank user agents, requests from high-risk ASNs and country codes, and SQL-comment-style query strings.",
    action: "Managed Challenge",
    severity: "low",
    categoryId: "cat-recon",
    tags: ["cloudflare-waf", "layer7", "ddos"],
  },
  {
    file: "AdvancedSecurity-2.txt",
    title: "Cloudflare WAF: Advanced Security — Anomalous Request Signals (2)",
    description:
      "Issues a Managed Challenge for requests originating from a curated list of high-risk ASNs and clients presenting unusual or outdated user-agent strings (old mobile OS builds, game console UAs, etc.) commonly associated with bot traffic.",
    action: "Managed Challenge",
    severity: "low",
    categoryId: "cat-recon",
    tags: ["cloudflare-waf", "layer7", "ddos"],
  },
];

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export const cloudflareImporter: RuleImporter = {
  id: "cloudflare",
  name: "mintyYuki/cf-waf-ruleset",

  async fetch(_options: ImporterOptions): Promise<string> {
    const workDir = path.join("tmp", "cloudflare");
    fs.mkdirSync(workDir, { recursive: true });

    for (const def of RULE_DEFS) {
      const localPath = path.join(workDir, def.file);
      if (fs.existsSync(localPath)) continue;

      const url = `${RAW_BASE}/${def.file}`;
      const res = await fetch(url, { headers: { "User-Agent": "Sentriq-Importer" } });
      if (!res.ok) {
        throw new Error(`GET ${url} -> ${res.status}`);
      }
      const content = await res.text();
      fs.writeFileSync(localPath, content, "utf-8");
    }

    return workDir;
  },

  async *parse(workDir: string, _options: ImporterOptions): AsyncIterable<ImportedRuleRecord> {
    for (const def of RULE_DEFS) {
      const localPath = path.join(workDir, def.file);
      if (!fs.existsSync(localPath)) continue;

      const expression = fs.readFileSync(localPath, "utf-8").trim();
      if (!expression) continue;

      const idSeed = slugify(def.title);
      const ruleId = `cloudflare-${idSeed}`;
      const slug = `cloudflare-${idSeed}`;
      const familySlug = `cloudflare-fam-${idSeed}`;

      const ruleBody = `# Action: ${def.action}\n# Cloudflare WAF custom rule expression\n\n${expression}\n`;

      yield {
        familyId: familySlug,
        familyName: def.title,
        familySlug,
        conceptDescription: def.description,
        categoryId: def.categoryId,
        source: {
          sourceProject: "mintyYuki/cf-waf-ruleset",
          sourceUrl: `${REPO_BLOB_BASE}/${def.file}`,
          sourceAuthor: "yuki (mintyYuki)",
          licenseName: "MIT",
          licenseUrl: LICENSE_URL,
        },
        variant: {
          id: ruleId,
          language: "cloudflare",
          title: def.title,
          slug,
          descriptionSummary: def.description.slice(0, 300),
          descriptionFull: def.description,
          ruleBody,
          ruleFormatVersion: undefined,
          severity: def.severity,
          status: "stable",
          author: "yuki (mintyYuki)",
          ruleVersion: "1.0",
          falsePositiveNotes:
            "Broad ASN- and user-agent-based blocks can false-positive on legitimate users behind shared hosting providers, VPNs, or older/uncommon devices. Review the Cloudflare Security Events log before enabling in Block mode; consider starting with Managed Challenge or Log.",
          dataSourceRequirements: "Cloudflare WAF custom rules (Ruleset Engine) on a proxied (orange-cloud) zone",
          mitreTechniqueIds: [],
          cveIds: [],
          tags: def.tags,
          references: [],
        },
      };
    }
  },
};
