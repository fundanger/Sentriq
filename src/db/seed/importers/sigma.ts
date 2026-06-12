import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import YAML from "yaml";
import type { ImportedRuleRecord, ImporterOptions, RuleImporter } from "./types";
import type { RuleSeverity, RuleStatus } from "../types";

const REPO_URL = "https://github.com/SigmaHQ/sigma.git";
const LICENSE_URL =
  "https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md";
const REPO_BLOB_BASE = "https://github.com/SigmaHQ/sigma/blob/master";

const BASE_DIRS = ["rules", "rules-threat-hunting"];
const EMERGING_DIRS = ["rules-emerging-threats", "rules-compliance"];

/**
 * Maps Sigma `attack.<tactic>` tags to Sentriq category IDs (src/db/seed/categories.ts).
 * Sigma tactic tags use hyphens (e.g. `attack.credential-access`, `attack.command-and-control`),
 * not the underscored ATT&CK tactic names. Also includes a couple of non-standard tags Sigma
 * itself uses in place of (or alongside) tactic tags.
 */
const TACTIC_TO_CATEGORY: Record<string, string> = {
  reconnaissance: "cat-recon",
  "resource-development": "cat-recon",
  "initial-access": "cat-initial-access",
  execution: "cat-ransomware",
  persistence: "cat-persistence",
  "privilege-escalation": "cat-privilege-escalation",
  "defense-evasion": "cat-defense-evasion",
  "defense-impairment": "cat-defense-evasion",
  stealth: "cat-defense-evasion",
  "credential-access": "cat-credential-access",
  discovery: "cat-recon",
  "lateral-movement": "cat-lateral-movement",
  collection: "cat-insider-threat",
  "command-and-control": "cat-c2",
  exfiltration: "cat-exfiltration",
  impact: "cat-ransomware",
};

/** Fallback mapping from Sigma `logsource.category` to Sentriq category IDs when no attack.* tag is present. */
const LOGSOURCE_TO_CATEGORY: Record<string, string> = {
  firewall: "cat-recon",
  proxy: "cat-c2",
  webserver: "cat-web-attacks",
  antivirus: "cat-ransomware",
  dns: "cat-c2",
  cloud: "cat-cloud-saas",
};

const DEFAULT_CATEGORY = "cat-insider-threat";

const LEVEL_TO_SEVERITY: Record<string, RuleSeverity> = {
  informational: "informational",
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
};

const STATUS_MAP: Record<string, RuleStatus> = {
  stable: "stable",
  test: "experimental",
  experimental: "experimental",
  deprecated: "deprecated",
  unsupported: "deprecated",
};

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export interface SigmaRule {
  id?: string;
  title?: string;
  description?: string;
  status?: string;
  level?: string;
  author?: string;
  date?: string;
  modified?: string;
  tags?: string[];
  falsepositives?: string[] | string;
  references?: string[];
  logsource?: Record<string, string>;
  detection?: unknown;
}

export function categoryForTags(tags: string[], logsource?: Record<string, string>): string {
  for (const tag of tags) {
    const t = tag.toLowerCase();
    if (t.startsWith("attack.")) {
      const key = t.slice("attack.".length);
      const mapped = TACTIC_TO_CATEGORY[key];
      if (mapped) return mapped;
    }
  }
  if (logsource?.category) {
    const mapped = LOGSOURCE_TO_CATEGORY[logsource.category.toLowerCase()];
    if (mapped) return mapped;
  }
  return DEFAULT_CATEGORY;
}

function mitreTechniqueIdsFromTags(tags: string[]): string[] {
  const ids: string[] = [];
  for (const tag of tags) {
    const t = tag.toLowerCase();
    if (!t.startsWith("attack.t")) continue;
    const raw = t.slice("attack.".length); // e.g. "t1110.003"
    const match = raw.match(/^t(\d{4,5})(\.(\d{3}))?$/);
    if (!match) continue;
    const id = match[3] ? `T${match[1]}.${match[3]}` : `T${match[1]}`;
    ids.push(id);
  }
  return [...new Set(ids)];
}

function dataSourceRequirements(logsource?: Record<string, string>): string | undefined {
  if (!logsource) return undefined;
  const parts = Object.entries(logsource).map(([k, v]) => `${k}: ${v}`);
  return parts.length > 0 ? `Sigma logsource — ${parts.join(", ")}` : undefined;
}

function falsePositiveNotes(fp?: string[] | string): string | undefined {
  if (!fp) return undefined;
  const list = Array.isArray(fp) ? fp : [fp];
  const filtered = list.filter((f) => f && f.toLowerCase() !== "unknown");
  if (filtered.length === 0) return undefined;
  return filtered.map((f) => `- ${f}`).join("\n");
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

export const sigmaImporter: RuleImporter = {
  id: "sigma",
  name: "SigmaHQ/sigma",

  async fetch(options: ImporterOptions): Promise<string> {
    const workDir = path.join("tmp", "sigma");
    const dirs = options.flags.has("--include-emerging")
      ? [...BASE_DIRS, ...EMERGING_DIRS]
      : BASE_DIRS;

    if (fs.existsSync(workDir)) {
      console.log(`  Reusing existing checkout at ${workDir} (delete it to force a fresh clone).`);
      return workDir;
    }

    console.log(`  Cloning ${REPO_URL} (sparse: ${dirs.join(", ")})...`);
    fs.mkdirSync(workDir, { recursive: true });

    execFileSync("git", ["clone", "--depth", "1", "--filter=blob:none", "--sparse", REPO_URL, "."], {
      cwd: workDir,
      stdio: "inherit",
    });
    execFileSync("git", ["sparse-checkout", "set", ...dirs], { cwd: workDir, stdio: "inherit" });

    return workDir;
  },

  async *parse(workDir: string, options: ImporterOptions): AsyncIterable<ImportedRuleRecord> {
    const dirs = options.flags.has("--include-emerging")
      ? [...BASE_DIRS, ...EMERGING_DIRS]
      : BASE_DIRS;

    for (const dir of dirs) {
      const absDir = path.join(workDir, dir);
      for await (const filePath of walkYamlFiles(absDir)) {
        let raw: string;
        try {
          raw = fs.readFileSync(filePath, "utf-8");
        } catch {
          continue;
        }

        // Sigma "collection" files contain multiple `---`-separated documents
        // (action + filter rules); we only import standalone detection rules.
        const docs = raw
          .split(/^---$/m)
          .map((d) => d.trim())
          .filter(Boolean);

        for (const doc of docs) {
          let parsed: SigmaRule;
          try {
            parsed = YAML.parse(doc) as SigmaRule;
          } catch {
            continue;
          }

          if (!parsed?.id || !parsed.title || !parsed.detection) continue;
          if (parsed.status === "deprecated" || parsed.status === "unsupported") continue;

          const tags = parsed.tags ?? [];
          const idPrefix = parsed.id.slice(0, 8);
          const ruleId = `sigma-${idPrefix}`;
          const slug = `sigma-${slugify(parsed.title)}-${idPrefix}`;
          const familySlug = `sigma-fam-${slugify(parsed.title)}-${idPrefix}`;
          const categoryId = categoryForTags(tags, parsed.logsource);
          const relPath = path.relative(workDir, filePath).replace(/\\/g, "/");

          const descriptionSummary = (parsed.description ?? parsed.title)
            .split("\n")[0]
            .slice(0, 300);

          const references = (parsed.references ?? []).map((url) => ({
            url,
            title: url,
            referenceType: "other" as const,
          }));

          yield {
            familyId: familySlug,
            familyName: parsed.title,
            familySlug,
            conceptDescription: parsed.description ?? parsed.title,
            categoryId,
            source: {
              sourceProject: "SigmaHQ/sigma",
              sourceUrl: `${REPO_BLOB_BASE}/${relPath}`,
              sourceAuthor: parsed.author,
              licenseName: "DRL-1.1",
              licenseUrl: LICENSE_URL,
            },
            variant: {
              id: ruleId,
              language: "sigma",
              title: parsed.title,
              slug,
              descriptionSummary,
              descriptionFull: parsed.description,
              ruleBody: raw,
              ruleFormatVersion: undefined,
              severity: LEVEL_TO_SEVERITY[parsed.level ?? "medium"] ?? "medium",
              status: STATUS_MAP[parsed.status ?? "experimental"] ?? "experimental",
              author: parsed.author ?? "SigmaHQ",
              ruleVersion: parsed.modified ?? parsed.date ?? "1.0",
              falsePositiveNotes: falsePositiveNotes(parsed.falsepositives),
              dataSourceRequirements: dataSourceRequirements(parsed.logsource),
              mitreTechniqueIds: mitreTechniqueIdsFromTags(tags),
              cveIds: [],
              tags: tags.filter((t) => !t.toLowerCase().startsWith("attack.")),
              references,
            },
          };
        }
      }
    }
  },
};
