import fs from "node:fs";
import path from "node:path";
import { db } from "../../index";
import {
  ruleFamilies,
  detectionRules,
  ruleTags,
  tags,
  ruleMitreMappings,
  mitreTechniques,
  ruleCveMappings,
  ruleReferences,
  ruleSources,
} from "../../schema";
import { mitreReferenceUrl } from "../mitre";
import { mitreExtraTechniques } from "../mitre-extra";
import type { ImporterOptions, RuleImporter } from "./types";

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * Inserts any MITRE technique IDs referenced by an import that aren't already
 * seeded, so `rule_mitre_mappings` FK inserts don't fail. Looks up the real
 * ATT&CK name/tactic from `mitreExtraTechniques` (sourced from the official
 * STIX data); falls back to an "Unmapped" placeholder for IDs not found there.
 */
async function ensureMitreTechniques(techniqueIds: Set<string>) {
  if (techniqueIds.size === 0) return;

  const existing = await db.query.mitreTechniques.findMany({
    columns: { id: true },
  });
  const existingIds = new Set(existing.map((t) => t.id));

  const missing = [...techniqueIds].filter((id) => !existingIds.has(id));
  if (missing.length === 0) return;

  console.log(`  Pre-seeding ${missing.length} new MITRE technique(s) referenced by import...`);
  for (const id of missing) {
    const parentTechniqueId = id.includes(".") ? id.split(".")[0] : null;
    const extra = mitreExtraTechniques[id];
    await db
      .insert(mitreTechniques)
      .values({
        id,
        name: extra?.name ?? id,
        tactic: extra?.tactic ?? "Unmapped",
        parentTechniqueId,
        url: mitreReferenceUrl(id),
      })
      .onConflictDoNothing();
    existingIds.add(id);
  }
}

interface RunImportResult {
  totalSeen: number;
  totalInserted: number;
  totalSkipped: number;
}

/**
 * Runs a `RuleImporter` end-to-end: fetch -> parse -> idempotent insert of
 * rule families, detection rules, tags, MITRE/CVE mappings, references, and
 * rule_sources attribution. Safe to re-run; existing rows are left untouched
 * via `onConflictDoNothing()`.
 */
export async function runImporter(
  importer: RuleImporter,
  options: ImporterOptions
): Promise<RunImportResult> {
  console.log(`Running importer "${importer.name}" (${importer.id})...`);

  const workDir = await importer.fetch(options);

  const tagIdByName = new Map<string, string>();
  const seenFamilyIds = new Set<string>();
  const referencedTechniqueIds = new Set<string>();

  const skippedLogPath = path.join("tmp", `${importer.id}-skipped.log`);
  fs.mkdirSync("tmp", { recursive: true });
  const skippedLog = fs.createWriteStream(skippedLogPath, { flags: "w" });

  let totalSeen = 0;
  let totalInserted = 0;
  let totalSkipped = 0;

  for await (const record of importer.parse(workDir, options)) {
    totalSeen += 1;

    try {
      for (const techniqueId of record.variant.mitreTechniqueIds) {
        referencedTechniqueIds.add(techniqueId);
      }
      await ensureMitreTechniques(new Set(record.variant.mitreTechniqueIds));

      const now = new Date();

      if (!seenFamilyIds.has(record.familyId)) {
        await db
          .insert(ruleFamilies)
          .values({
            id: record.familyId,
            name: record.familyName,
            slug: record.familySlug,
            conceptDescription: record.conceptDescription,
            primaryCategoryId: record.categoryId,
            createdAt: now,
            updatedAt: now,
          })
          .onConflictDoNothing();
        seenFamilyIds.add(record.familyId);
      }

      const variant = record.variant;

      const insertResult = await db
        .insert(detectionRules)
        .values({
          id: variant.id,
          ruleFamilyId: record.familyId,
          language: variant.language,
          platformVariant: variant.platformVariant ?? null,
          title: variant.title,
          slug: variant.slug,
          descriptionSummary: variant.descriptionSummary,
          descriptionFull: variant.descriptionFull ?? null,
          ruleBody: variant.ruleBody,
          ruleFormatVersion: variant.ruleFormatVersion ?? null,
          severity: variant.severity,
          status: variant.status,
          author: variant.author,
          ruleVersion: variant.ruleVersion,
          falsePositiveNotes: variant.falsePositiveNotes ?? null,
          dataSourceRequirements: variant.dataSourceRequirements ?? null,
          primaryCategoryId: record.categoryId,
          embedding: null,
          createdAt: now,
          updatedAt: now,
        })
        .onConflictDoNothing()
        .returning({ id: detectionRules.id });

      if (insertResult.length === 0) {
        // Rule already exists from a previous import run; skip dependent rows too.
        totalSkipped += 1;
        continue;
      }

      totalInserted += 1;

      // rule_sources attribution
      await db
        .insert(ruleSources)
        .values({
          id: `${variant.id}-source`,
          ruleId: variant.id,
          sourceProject: record.source.sourceProject,
          sourceUrl: record.source.sourceUrl,
          sourceAuthor: record.source.sourceAuthor ?? null,
          licenseName: record.source.licenseName,
          licenseUrl: record.source.licenseUrl,
          importedAt: now,
        })
        .onConflictDoNothing();

      // rule_tags
      for (const tagName of variant.tags) {
        let tagId = tagIdByName.get(tagName);
        if (!tagId) {
          const slug = slugify(tagName);
          tagId = `tag-${slug}`;
          tagIdByName.set(tagName, tagId);
          await db.insert(tags).values({ id: tagId, name: tagName, slug }).onConflictDoNothing();
        }
        await db.insert(ruleTags).values({ ruleId: variant.id, tagId }).onConflictDoNothing();
      }

      // rule_mitre_mappings
      for (const techniqueId of variant.mitreTechniqueIds) {
        await db
          .insert(ruleMitreMappings)
          .values({ ruleId: variant.id, techniqueId })
          .onConflictDoNothing();
      }

      // rule_cve_mappings (FK requires the CVE to already exist; skip silently if not seeded)
      for (const cveId of variant.cveIds) {
        await db.insert(ruleCveMappings).values({ ruleId: variant.id, cveId }).onConflictDoNothing();
      }

      // rule_references
      for (const [index, ref] of variant.references.entries()) {
        await db
          .insert(ruleReferences)
          .values({
            id: `${variant.id}-ref-${index}`,
            ruleId: variant.id,
            url: ref.url,
            title: ref.title,
            referenceType: ref.referenceType,
            sortOrder: index,
          })
          .onConflictDoNothing();
      }
    } catch (err) {
      totalSkipped += 1;
      skippedLog.write(`${record.variant.id}: ${err instanceof Error ? err.message : String(err)}\n`);
    }

    if (totalSeen % 250 === 0) {
      console.log(`  ...processed ${totalSeen} rules (${totalInserted} inserted, ${totalSkipped} skipped)`);
    }
  }

  skippedLog.end();

  console.log(
    `Importer "${importer.name}" finished: ${totalSeen} seen, ${totalInserted} inserted, ${totalSkipped} skipped.`
  );
  if (totalSkipped > 0) {
    console.log(`  Skipped records logged to ${skippedLogPath}`);
  }

  return { totalSeen, totalInserted, totalSkipped };
}
