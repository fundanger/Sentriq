import fs from "node:fs";
import path from "node:path";
import type { ImportedRuleRecord, ImporterOptions, RuleImporter } from "./types";
import type { RuleSeverity } from "../types";

const REPO = "0xN0n4m3d3v/kit-shell";
const BRANCH = "main";
const RAW_BASE = `https://raw.githubusercontent.com/${REPO}/${BRANCH}`;
const REPO_BLOB_BASE = `https://github.com/${REPO}/blob/${BRANCH}`;
const LICENSE_URL = `https://github.com/${REPO}/blob/${BRANCH}/LICENSE`;

/** Maps kit-shell YARA file basenames to Sentriq category IDs. */
const FILE_TO_CATEGORY: Record<string, string> = {
  hacktool: "cat-defense-evasion",
  infostealers: "cat-credential-access",
  malware_generic: "cat-ransomware",
  ransomware: "cat-ransomware",
  webshells: "cat-persistence",
};

const RULE_FILES = [
  "knowledge/yara/core/hacktool.yar",
  "knowledge/yara/core/infostealers.yar",
  "knowledge/yara/core/malware_generic.yar",
  "knowledge/yara/core/ransomware.yar",
  "knowledge/yara/core/webshells.yar",
];

const SEVERITY_MAP: Record<string, RuleSeverity> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  informational: "informational",
};

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

interface ParsedYaraRule {
  name: string;
  body: string;
  description?: string;
  severity?: string;
  mitreId?: string;
}

/** Splits a YARA source file into individual top-level `rule NAME { ... }` blocks via brace matching. */
function splitYaraRules(source: string): ParsedYaraRule[] {
  const rules: ParsedYaraRule[] = [];
  const ruleStart = /rule\s+([A-Za-z0-9_]+)\s*(:[^{]*)?\{/g;

  let match: RegExpExecArray | null;
  while ((match = ruleStart.exec(source)) !== null) {
    const name = match[1];
    const braceOpenIndex = match.index + match[0].length - 1;

    let depth = 1;
    let i = braceOpenIndex + 1;
    for (; i < source.length && depth > 0; i++) {
      if (source[i] === "{") depth += 1;
      else if (source[i] === "}") depth -= 1;
    }

    const body = source.slice(match.index, i).trimEnd();

    const descriptionMatch = body.match(/description\s*=\s*"((?:[^"\\]|\\.)*)"/);
    const severityMatch = body.match(/severity\s*=\s*"((?:[^"\\]|\\.)*)"/);
    const mitreMatch = body.match(/mitre\s*=\s*"((?:[^"\\]|\\.)*)"/);

    rules.push({
      name,
      body,
      description: descriptionMatch?.[1],
      severity: severityMatch?.[1],
      mitreId: mitreMatch?.[1],
    });

    ruleStart.lastIndex = i;
  }

  return rules;
}

export const yaraImporter: RuleImporter = {
  id: "yara",
  name: "0xN0n4m3d3v/kit-shell (YARA core rules)",

  async fetch(_options: ImporterOptions): Promise<string> {
    const workDir = path.join("tmp", "yara");
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
      const basename = path.basename(relPath, ".yar");
      const localPath = path.join(workDir, path.basename(relPath));
      if (!fs.existsSync(localPath)) continue;

      let raw: string;
      try {
        raw = fs.readFileSync(localPath, "utf-8");
      } catch {
        continue;
      }

      const categoryId = FILE_TO_CATEGORY[basename] ?? "cat-ransomware";

      for (const rule of splitYaraRules(raw)) {
        const idSeed = slugify(rule.name);
        const ruleId = `yara-${idSeed}`;
        const slug = `yara-${idSeed}`;
        const familySlug = `yara-fam-${idSeed}`;

        const description = rule.description ?? rule.name.replace(/_/g, " ");
        const severityKey = (rule.severity ?? "medium").toLowerCase();
        const mitreIds = rule.mitreId ? [rule.mitreId] : [];

        yield {
          familyId: familySlug,
          familyName: rule.name.replace(/_/g, " "),
          familySlug,
          conceptDescription: description,
          categoryId,
          source: {
            sourceProject: "0xN0n4m3d3v/kit-shell",
            sourceUrl: `${REPO_BLOB_BASE}/${relPath}`,
            sourceAuthor: "0xN0n4m3d3v",
            licenseName: "CC0-1.0",
            licenseUrl: LICENSE_URL,
          },
          variant: {
            id: ruleId,
            language: "yara",
            title: rule.name.replace(/_/g, " "),
            slug,
            descriptionSummary: description.slice(0, 300),
            descriptionFull: description,
            ruleBody: rule.body,
            ruleFormatVersion: undefined,
            severity: SEVERITY_MAP[severityKey] ?? "medium",
            status: "stable",
            author: "0xN0n4m3d3v",
            ruleVersion: "1.0",
            falsePositiveNotes: undefined,
            dataSourceRequirements: "YARA scanner (file/memory scanning, e.g. via EDR, sandbox, or yara-python)",
            mitreTechniqueIds: mitreIds,
            cveIds: [],
            tags: [basename.replace(/_/g, "-")],
            references: [],
          },
        };
      }
    }
  },
};
