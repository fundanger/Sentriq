import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import type { ImportedRuleRecord, ImporterOptions, RuleImporter } from "./types";
import type { RuleSeverity, RuleStatus } from "../types";

const REPO = "falcosecurity/rules";
const BRANCH = "main";
const RAW_BASE = `https://raw.githubusercontent.com/${REPO}/${BRANCH}`;
const REPO_BLOB_BASE = `https://github.com/${REPO}/blob/${BRANCH}`;
const LICENSE_URL = `https://github.com/${REPO}/blob/${BRANCH}/LICENSE`;

const RULE_FILES = ["rules/falco_rules.yaml", "rules/falco-incubating_rules.yaml", "rules/falco-sandbox_rules.yaml"];

/** Maps Falco `mitre_<tactic>` tag suffixes to Sentriq category IDs. */
const MITRE_TAG_TO_CATEGORY: Record<string, string> = {
  reconnaissance: "cat-recon",
  resource_development: "cat-recon",
  initial_access: "cat-initial-access",
  execution: "cat-ransomware",
  persistence: "cat-persistence",
  privilege_escalation: "cat-privilege-escalation",
  defense_evasion: "cat-defense-evasion",
  credential_access: "cat-credential-access",
  discovery: "cat-recon",
  lateral_movement: "cat-lateral-movement",
  collection: "cat-insider-threat",
  command_and_control: "cat-c2",
  exfiltration: "cat-exfiltration",
  impact: "cat-ransomware",
};

/** Fallback mapping from Falco context tags to Sentriq category IDs when no mitre_* tag is present. */
const CONTEXT_TAG_TO_CATEGORY: Record<string, string> = {
  network: "cat-c2",
  filesystem: "cat-defense-evasion",
  container: "cat-cloud-saas",
  k8s: "cat-cloud-saas",
  process: "cat-ransomware",
};

const DEFAULT_CATEGORY = "cat-insider-threat";

const PRIORITY_TO_SEVERITY: Record<string, RuleSeverity> = {
  emergency: "critical",
  alert: "critical",
  critical: "critical",
  error: "high",
  warning: "medium",
  notice: "low",
  informational: "informational",
  info: "informational",
  debug: "informational",
};

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

interface FalcoRule {
  rule?: string;
  desc?: string;
  condition?: string;
  enabled?: boolean;
  output?: string;
  priority?: string;
  tags?: string[];
  source?: string;
}

function mitreTechniqueIdsFromTags(tags: string[]): string[] {
  const ids: string[] = [];
  for (const tag of tags) {
    const match = tag.match(/^T(\d{4,5})(\.(\d{3}))?$/);
    if (!match) continue;
    const id = match[3] ? `T${match[1]}.${match[3]}` : `T${match[1]}`;
    ids.push(id);
  }
  return [...new Set(ids)];
}

function categoryForTags(tags: string[]): string {
  for (const tag of tags) {
    if (tag.startsWith("mitre_")) {
      const mapped = MITRE_TAG_TO_CATEGORY[tag.slice("mitre_".length)];
      if (mapped) return mapped;
    }
  }
  for (const tag of tags) {
    const mapped = CONTEXT_TAG_TO_CATEGORY[tag];
    if (mapped) return mapped;
  }
  return DEFAULT_CATEGORY;
}

/** Renders a Falco rule as a standalone YAML document (rule + condition + output, etc). */
function renderRuleBody(rule: FalcoRule): string {
  const { rule: name, desc, condition, enabled, output, priority, tags, source } = rule;
  return YAML.stringify([{ rule: name, desc, condition, enabled, output, priority, source, tags }]);
}

export const falcoImporter: RuleImporter = {
  id: "falco",
  name: "falcosecurity/rules",

  async fetch(_options: ImporterOptions): Promise<string> {
    const workDir = path.join("tmp", "falco");
    fs.mkdirSync(workDir, { recursive: true });

    for (const relPath of RULE_FILES) {
      const localPath = path.join(workDir, path.basename(relPath));
      if (fs.existsSync(localPath)) continue;

      const url = `${RAW_BASE}/${relPath}`;
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
    for (const relPath of RULE_FILES) {
      const localPath = path.join(workDir, path.basename(relPath));
      if (!fs.existsSync(localPath)) continue;

      let raw: string;
      try {
        raw = fs.readFileSync(localPath, "utf-8");
      } catch {
        continue;
      }

      let docs: unknown;
      try {
        docs = YAML.parse(raw);
      } catch {
        continue;
      }

      if (!Array.isArray(docs)) continue;

      for (const item of docs as FalcoRule[]) {
        if (!item?.rule || !item.condition) continue;

        const tags = item.tags ?? [];
        const mitreIds = mitreTechniqueIdsFromTags(tags);
        const categoryId = categoryForTags(tags);
        const idSeed = slugify(item.rule);
        const ruleId = `falco-${idSeed}`;
        const slug = `falco-${idSeed}`;
        const familySlug = `falco-fam-${idSeed}`;

        const descriptionSummary = (item.desc ?? item.rule).split("\n")[0].trim().slice(0, 300);
        const conceptDescription = (item.desc ?? item.rule).trim();

        const priorityKey = (item.priority ?? "warning").toLowerCase();
        const status: RuleStatus = item.enabled === false ? "experimental" : "stable";

        yield {
          familyId: familySlug,
          familyName: item.rule,
          familySlug,
          conceptDescription,
          categoryId,
          source: {
            sourceProject: "falcosecurity/rules",
            sourceUrl: `${REPO_BLOB_BASE}/${relPath}`,
            sourceAuthor: "The Falco Authors",
            licenseName: "Apache-2.0",
            licenseUrl: LICENSE_URL,
          },
          variant: {
            id: ruleId,
            language: "falco",
            title: item.rule,
            slug,
            descriptionSummary,
            descriptionFull: conceptDescription,
            ruleBody: renderRuleBody(item),
            ruleFormatVersion: undefined,
            severity: PRIORITY_TO_SEVERITY[priorityKey] ?? "medium",
            status,
            author: "The Falco Authors",
            ruleVersion: "1.0",
            falsePositiveNotes: undefined,
            dataSourceRequirements: "Falco runtime security agent (syscall events, container/k8s metadata)",
            mitreTechniqueIds: mitreIds,
            cveIds: [],
            tags: tags.filter((t) => !t.startsWith("mitre_") && !/^T\d{4,5}(\.\d{3})?$/.test(t)),
            references: [],
          },
        };
      }
    }
  },
};
