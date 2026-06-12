import type { RuleVariantSeed } from "../types";

/** Attribution metadata written to the `rule_sources` table for an imported rule. */
export interface ImportedRuleSource {
  sourceProject: string;
  sourceUrl: string;
  sourceAuthor?: string;
  licenseName: string;
  licenseUrl: string;
}

/**
 * A single rule produced by an importer, ready for the shared runner to insert.
 *
 * `variant` mirrors `RuleVariantSeed` but omits `id`/`slug` derivation concerns —
 * importers should still provide deterministic, idempotent `id`/`slug` values so
 * re-running an import is a no-op for unchanged rules.
 */
export interface ImportedRuleRecord {
  /** Deterministic family id (e.g. `"sigma-fam-<slug>"`). Reused across variants that represent the same concept. */
  familyId: string;
  familyName: string;
  familySlug: string;
  /** Markdown concept description for the rule family. */
  conceptDescription: string;
  /** Category id from `categorySeeds` (src/db/seed/categories.ts). */
  categoryId: string;
  variant: RuleVariantSeed;
  source: ImportedRuleSource;
}

export interface ImporterOptions {
  /** Importer-specific CLI flags, e.g. `--include-emerging`. */
  flags: Set<string>;
}

/**
 * A pluggable rule source. Implementations fetch upstream content into a local
 * working directory, then yield `ImportedRuleRecord`s for the shared runner to persist.
 */
export interface RuleImporter {
  /** Registry id, used as the CLI argument: `npm run db:import -- <id>`. */
  id: string;
  /** Human-readable name for logging. */
  name: string;
  /** Fetches upstream content (clone/download), returns the local working directory. */
  fetch(options: ImporterOptions): Promise<string>;
  /** Parses the working directory into importable rule records. */
  parse(workDir: string, options: ImporterOptions): AsyncIterable<ImportedRuleRecord>;
}
