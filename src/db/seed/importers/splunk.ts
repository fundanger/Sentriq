import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import YAML from "yaml";
import { db } from "../../index";
import type { ImportedRuleRecord, ImporterOptions, RuleImporter } from "./types";
import type { RuleSeverity, RuleStatus } from "../types";

const REPO_URL = "https://github.com/splunk/security_content.git";
const BRANCH = "develop";
const LICENSE_URL = "https://github.com/splunk/security_content/blob/develop/LICENSE";
const REPO_BLOB_BASE = `https://github.com/splunk/security_content/blob/${BRANCH}`;

const DETECTIONS_DIR = "detections";

/** Maps MITRE ATT&CK tactic names (matching mitre_techniques.tactic) to Sentriq category IDs. */
const TACTIC_NAME_TO_CATEGORY: Record<string, string> = {
  Reconnaissance: "cat-recon",
  "Resource Development": "cat-recon",
  "Initial Access": "cat-initial-access",
  Execution: "cat-ransomware",
  Persistence: "cat-persistence",
  "Privilege Escalation": "cat-privilege-escalation",
  "Defense Evasion": "cat-defense-evasion",
  "Credential Access": "cat-credential-access",
  Discovery: "cat-recon",
  "Lateral Movement": "cat-lateral-movement",
  Collection: "cat-insider-threat",
  "Command and Control": "cat-c2",
  Exfiltration: "cat-exfiltration",
  Impact: "cat-ransomware",
};

/** Fallback mapping from Splunk `category`/`security_domain` to Sentriq category IDs. */
const DOMAIN_TO_CATEGORY: Record<string, string> = {
  endpoint: "cat-ransomware",
  cloud: "cat-cloud-saas",
  network: "cat-c2",
  web: "cat-web-attacks",
  application: "cat-web-attacks",
};

const DEFAULT_CATEGORY = "cat-insider-threat";

const STATUS_MAP: Record<string, RuleStatus> = {
  production: "stable",
  validated: "stable",
  experimental: "experimental",
  deprecated: "deprecated",
};

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

interface SplunkDetection {
  name?: string;
  id?: string;
  version?: number | string;
  date?: string;
  modification_date?: string;
  author?: string;
  status?: string;
  type?: string;
  description?: string;
  data_source?: string[];
  search?: string;
  how_to_implement?: string;
  known_false_positives?: string;
  references?: string[];
  category?: string;
  security_domain?: string;
  mitre_attack_id?: string[];
}

async function* walkYamlFiles(dir: string): AsyncIterable<string> {
  if (!fs.existsSync(dir)) return;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkYamlFiles(full);
    } else if (entry.isFile() && (entry.name.endsWith(".yml") || entry.name.endsWith(".yaml"))) {
      yield full;
    }
  }
}

function falsePositiveNotes(notes?: string): string | undefined {
  if (!notes) return undefined;
  const trimmed = notes.trim();
  if (!trimmed || trimmed.toLowerCase() === "none identified.") return undefined;
  return trimmed;
}

function dataSourceRequirements(dataSource?: string[], howToImplement?: string): string | undefined {
  const parts: string[] = [];
  if (dataSource && dataSource.length > 0) {
    parts.push(`Data sources: ${dataSource.join(", ")}`);
  }
  if (howToImplement) {
    parts.push(howToImplement.trim());
  }
  return parts.length > 0 ? parts.join("\n\n") : undefined;
}

async function categoryForDetection(
  mitreIds: string[],
  fallbackDomain?: string,
  fallbackCategory?: string
): Promise<string> {
  for (const techniqueId of mitreIds) {
    const technique = await db.query.mitreTechniques.findFirst({
      where: (t, { eq }) => eq(t.id, techniqueId),
      columns: { tactic: true },
    });
    if (technique?.tactic) {
      const mapped = TACTIC_NAME_TO_CATEGORY[technique.tactic];
      if (mapped) return mapped;
    }
  }

  const domain = (fallbackDomain ?? fallbackCategory)?.toLowerCase();
  if (domain) {
    const mapped = DOMAIN_TO_CATEGORY[domain];
    if (mapped) return mapped;
  }

  return DEFAULT_CATEGORY;
}

export const splunkImporter: RuleImporter = {
  id: "splunk",
  name: "splunk/security_content",

  async fetch(_options: ImporterOptions): Promise<string> {
    const workDir = path.join("tmp", "splunk");

    if (fs.existsSync(workDir)) {
      console.log(`  Reusing existing checkout at ${workDir} (delete it to force a fresh clone).`);
      return workDir;
    }

    console.log(`  Cloning ${REPO_URL} (branch: ${BRANCH}, sparse: ${DETECTIONS_DIR})...`);
    fs.mkdirSync(workDir, { recursive: true });

    execFileSync(
      "git",
      ["clone", "--depth", "1", "--branch", BRANCH, "--filter=blob:none", "--sparse", REPO_URL, "."],
      { cwd: workDir, stdio: "inherit" }
    );
    execFileSync("git", ["sparse-checkout", "set", DETECTIONS_DIR], { cwd: workDir, stdio: "inherit" });

    return workDir;
  },

  async *parse(workDir: string, _options: ImporterOptions): AsyncIterable<ImportedRuleRecord> {
    const absDir = path.join(workDir, DETECTIONS_DIR);

    for await (const filePath of walkYamlFiles(absDir)) {
      let raw: string;
      try {
        raw = fs.readFileSync(filePath, "utf-8");
      } catch {
        continue;
      }

      let parsed: SplunkDetection;
      try {
        parsed = YAML.parse(raw) as SplunkDetection;
      } catch {
        continue;
      }

      if (!parsed?.id || !parsed.name || !parsed.search) continue;
      if (parsed.status === "deprecated") continue;

      const mitreIds = [...new Set(parsed.mitre_attack_id ?? [])];
      const idPrefix = parsed.id.slice(0, 8);
      const ruleId = `splunk-${idPrefix}`;
      const slug = `splunk-${slugify(parsed.name)}-${idPrefix}`;
      const familySlug = `splunk-fam-${slugify(parsed.name)}-${idPrefix}`;
      const categoryId = await categoryForDetection(mitreIds, parsed.security_domain, parsed.category);
      const relPath = path.relative(workDir, filePath).replace(/\\/g, "/");

      const descriptionSummary = (parsed.description ?? parsed.name)
        .split("\n")[0]
        .slice(0, 300);

      const references = (parsed.references ?? []).map((url) => ({
        url,
        title: url,
        referenceType: "other" as const,
      }));

      const severity: RuleSeverity = "medium";

      yield {
        familyId: familySlug,
        familyName: parsed.name,
        familySlug,
        conceptDescription: parsed.description ?? parsed.name,
        categoryId,
        source: {
          sourceProject: "splunk/security_content",
          sourceUrl: `${REPO_BLOB_BASE}/${relPath}`,
          sourceAuthor: parsed.author,
          licenseName: "Apache-2.0",
          licenseUrl: LICENSE_URL,
        },
        variant: {
          id: ruleId,
          language: "splunk",
          title: parsed.name,
          slug,
          descriptionSummary,
          descriptionFull: parsed.description,
          ruleBody: parsed.search,
          ruleFormatVersion: undefined,
          severity,
          status: STATUS_MAP[parsed.status ?? "experimental"] ?? "experimental",
          author: parsed.author ?? "Splunk Threat Research Team",
          ruleVersion: String(parsed.version ?? parsed.modification_date ?? parsed.date ?? "1"),
          falsePositiveNotes: falsePositiveNotes(parsed.known_false_positives),
          dataSourceRequirements: dataSourceRequirements(parsed.data_source, parsed.how_to_implement),
          mitreTechniqueIds: mitreIds,
          cveIds: [],
          tags: parsed.type ? [parsed.type] : [],
          references,
        },
      };
    }
  },
};
