import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import type { ImportedRuleRecord, ImporterOptions, RuleImporter } from "./types";
import type { RuleSeverity, RuleStatus } from "../types";

const REPO = "Azure/Azure-Sentinel";
const BRANCH = "master";
const TREE_API_URL = `https://api.github.com/repos/${REPO}/git/trees/${BRANCH}?recursive=1`;
const RAW_BASE = `https://raw.githubusercontent.com/${REPO}/${BRANCH}`;
const REPO_BLOB_BASE = `https://github.com/${REPO}/blob/${BRANCH}`;
const LICENSE_URL = `https://github.com/${REPO}/blob/${BRANCH}/LICENSE`;

const ANALYTIC_RULE_PATH_RE = /Analytic Rules\/.*\.ya?ml$/i;
const CONCURRENCY = 12;

/** Maps Azure Sentinel `tactics` entries (PascalCase, no spaces) to MITRE tactic names (matching mitre_techniques.tactic). */
const AZ_TACTIC_TO_MITRE_TACTIC: Record<string, string> = {
  Reconnaissance: "Reconnaissance",
  ResourceDevelopment: "Resource Development",
  InitialAccess: "Initial Access",
  Execution: "Execution",
  Persistence: "Persistence",
  PrivilegeEscalation: "Privilege Escalation",
  DefenseEvasion: "Defense Evasion",
  CredentialAccess: "Credential Access",
  Discovery: "Discovery",
  LateralMovement: "Lateral Movement",
  Collection: "Collection",
  CommandAndControl: "Command and Control",
  Exfiltration: "Exfiltration",
  Impact: "Impact",
};

/** Maps MITRE tactic names to Sentriq category IDs. */
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

const DEFAULT_CATEGORY = "cat-insider-threat";

const SEVERITY_MAP: Record<string, RuleSeverity> = {
  informational: "informational",
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
};

const STATUS_MAP: Record<string, RuleStatus> = {
  available: "stable",
  deprecated: "deprecated",
};

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

interface AzureAnalyticRule {
  id?: string;
  name?: string;
  description?: string;
  severity?: string;
  status?: string;
  requiredDataConnectors?: Array<{ connectorId?: string; dataTypes?: string[] }>;
  tactics?: string[];
  relevantTechniques?: string[];
  query?: string;
  version?: string;
  techniques?: string[];
}

interface TreeEntry {
  path: string;
  type: string;
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url, {
    headers: { "User-Agent": "Sentriq-Importer", Accept: "application/vnd.github+json" },
  });
  if (!res.ok) {
    throw new Error(`GET ${url} -> ${res.status}`);
  }
  return (await res.json()) as T;
}

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, { headers: { "User-Agent": "Sentriq-Importer" } });
  if (!res.ok) {
    throw new Error(`GET ${url} -> ${res.status}`);
  }
  return await res.text();
}

async function runWithConcurrency<T>(items: T[], limit: number, worker: (item: T) => Promise<void>) {
  let index = 0;
  async function next(): Promise<void> {
    const i = index++;
    if (i >= items.length) return;
    await worker(items[i]);
    return next();
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => next()));
}

function dataSourceRequirements(connectors?: Array<{ connectorId?: string; dataTypes?: string[] }>): string | undefined {
  if (!connectors || connectors.length === 0) return undefined;
  const parts = connectors
    .map((c) => {
      const types = c.dataTypes?.join(", ") ?? "";
      return c.connectorId ? `${c.connectorId}${types ? ` (${types})` : ""}` : types;
    })
    .filter(Boolean);
  return parts.length > 0 ? `Required data connectors: ${parts.join("; ")}` : undefined;
}

function categoryForTactics(tactics: string[]): string {
  for (const tactic of tactics) {
    const mitreTactic = AZ_TACTIC_TO_MITRE_TACTIC[tactic];
    if (mitreTactic) {
      const mapped = TACTIC_NAME_TO_CATEGORY[mitreTactic];
      if (mapped) return mapped;
    }
  }
  return DEFAULT_CATEGORY;
}

function cleanDescription(description?: string): string | undefined {
  if (!description) return undefined;
  let text = description.trim();
  // Some files wrap the description in a stray pair of single quotes due to upstream YAML quirks.
  if (text.startsWith("'") && text.endsWith("'") && text.length > 1) {
    text = text.slice(1, -1).trim();
  }
  return text || undefined;
}

export const azureSentinelImporter: RuleImporter = {
  id: "azure-sentinel",
  name: "Azure/Azure-Sentinel",

  async fetch(_options: ImporterOptions): Promise<string> {
    const workDir = path.join("tmp", "azure-sentinel");
    fs.mkdirSync(workDir, { recursive: true });

    const manifestPath = path.join(workDir, "manifest.json");
    let paths: string[];

    if (fs.existsSync(manifestPath)) {
      paths = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
      console.log(`  Reusing existing manifest (${paths.length} files). Delete ${manifestPath} to re-discover.`);
    } else {
      console.log(`  Discovering Analytic Rules via GitHub git-trees API...`);
      const tree = await fetchJson<{ tree: TreeEntry[]; truncated: boolean }>(TREE_API_URL);
      if (tree.truncated) {
        throw new Error("Azure-Sentinel git tree response was truncated; cannot enumerate all files.");
      }
      paths = tree.tree.filter((t) => t.type === "blob" && ANALYTIC_RULE_PATH_RE.test(t.path)).map((t) => t.path);
      fs.writeFileSync(manifestPath, JSON.stringify(paths, null, 2));
      console.log(`  Found ${paths.length} Analytic Rule files.`);
    }

    const filesDir = path.join(workDir, "files");
    fs.mkdirSync(filesDir, { recursive: true });

    const toFetch = paths.filter((p) => !fs.existsSync(path.join(filesDir, `${slugify(p)}.yaml`)));
    if (toFetch.length > 0) {
      console.log(`  Fetching ${toFetch.length} of ${paths.length} files (concurrency ${CONCURRENCY})...`);
      let done = 0;
      await runWithConcurrency(toFetch, CONCURRENCY, async (relPath) => {
        const url = `${RAW_BASE}/${encodeURI(relPath)}`;
        try {
          const content = await fetchText(url);
          fs.writeFileSync(path.join(filesDir, `${slugify(relPath)}.yaml`), content, "utf-8");
        } catch {
          // Leave missing; parse step will simply not find this file.
        }
        done += 1;
        if (done % 250 === 0) {
          console.log(`    ...fetched ${done}/${toFetch.length}`);
        }
      });
    } else {
      console.log(`  All ${paths.length} files already cached locally.`);
    }

    return workDir;
  },

  async *parse(workDir: string, _options: ImporterOptions): AsyncIterable<ImportedRuleRecord> {
    const manifestPath = path.join(workDir, "manifest.json");
    const filesDir = path.join(workDir, "files");
    if (!fs.existsSync(manifestPath)) return;

    const paths: string[] = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));

    for (const relPath of paths) {
      const localPath = path.join(filesDir, `${slugify(relPath)}.yaml`);
      if (!fs.existsSync(localPath)) continue;

      let raw: string;
      try {
        raw = fs.readFileSync(localPath, "utf-8");
      } catch {
        continue;
      }
      if (!raw.trim()) continue;

      let parsed: AzureAnalyticRule;
      try {
        parsed = YAML.parse(raw) as AzureAnalyticRule;
      } catch {
        continue;
      }

      if (!parsed?.id || !parsed.name || !parsed.query) continue;
      if (parsed.status?.toLowerCase() === "deprecated") continue;

      const tactics = parsed.tactics ?? [];
      const mitreIds = [...new Set(parsed.relevantTechniques ?? [])];
      const idPrefix = parsed.id.slice(0, 8);
      const ruleId = `azsentinel-${idPrefix}`;
      const slug = `azsentinel-${slugify(parsed.name)}-${idPrefix}`;
      const familySlug = `azsentinel-fam-${slugify(parsed.name)}-${idPrefix}`;
      const categoryId = categoryForTactics(tactics);

      const description = cleanDescription(parsed.description);
      const descriptionSummary = (description ?? parsed.name).split("\n")[0].slice(0, 300);

      const severityKey = (parsed.severity ?? "medium").toLowerCase();
      const statusKey = (parsed.status ?? "available").toLowerCase();

      yield {
        familyId: familySlug,
        familyName: parsed.name,
        familySlug,
        conceptDescription: description ?? parsed.name,
        categoryId,
        source: {
          sourceProject: "Azure/Azure-Sentinel",
          sourceUrl: `${REPO_BLOB_BASE}/${relPath.split("/").map(encodeURIComponent).join("/")}`,
          sourceAuthor: undefined,
          licenseName: "MIT",
          licenseUrl: LICENSE_URL,
        },
        variant: {
          id: ruleId,
          language: "kql",
          platformVariant: "Microsoft Sentinel",
          title: parsed.name,
          slug,
          descriptionSummary,
          descriptionFull: description,
          ruleBody: parsed.query,
          ruleFormatVersion: undefined,
          severity: SEVERITY_MAP[severityKey] ?? "medium",
          status: STATUS_MAP[statusKey] ?? "stable",
          author: "Microsoft",
          ruleVersion: parsed.version ?? "1.0",
          falsePositiveNotes: undefined,
          dataSourceRequirements: dataSourceRequirements(parsed.requiredDataConnectors),
          mitreTechniqueIds: mitreIds,
          cveIds: [],
          tags: tactics,
          references: [],
        },
      };
    }
  },
};
