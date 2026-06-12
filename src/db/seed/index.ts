import bcrypt from "bcryptjs";
import { db } from "../index";
import {
  categories,
  tags,
  ruleTags,
  mitreTechniques,
  ruleMitreMappings,
  cves,
  ruleCveMappings,
  ruleReferences,
  ruleFamilies,
  detectionRules,
  users,
} from "../schema";
import { categorySeeds } from "./categories";
import { mitreTechniqueSeeds, mitreReferenceUrl } from "./mitre";
import { cveSeeds } from "./cves";
import { credentialAccessRules } from "./rules/credentialAccess";
import { webAttackRules } from "./rules/webAttacks";
import { lateralMovementRules } from "./rules/lateralMovement";
import { persistenceRules } from "./rules/persistence";
import { defenseEvasionRules } from "./rules/defenseEvasion";
import { privilegeEscalationRules } from "./rules/privilegeEscalation";
import { ransomwareRules } from "./rules/ransomware";
import { cloudSaasRules } from "./rules/cloudSaas";
import { reconAndC2Rules } from "./rules/reconAndC2";
import { supplyChainRules } from "./rules/supplyChain";
import type { RuleSeed } from "./types";

const allRuleSeeds: RuleSeed[] = [
  ...credentialAccessRules,
  ...webAttackRules,
  ...lateralMovementRules,
  ...persistenceRules,
  ...defenseEvasionRules,
  ...privilegeEscalationRules,
  ...ransomwareRules,
  ...cloudSaasRules,
  ...reconAndC2Rules,
  ...supplyChainRules,
];

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

async function seedCategories() {
  console.log(`Seeding ${categorySeeds.length} categories...`);
  for (const category of categorySeeds) {
    await db.insert(categories).values(category).onConflictDoNothing();
  }
}

async function seedMitreTechniques() {
  console.log(`Seeding ${mitreTechniqueSeeds.length} MITRE ATT&CK techniques...`);
  for (const technique of mitreTechniqueSeeds) {
    await db
      .insert(mitreTechniques)
      .values({
        id: technique.id,
        name: technique.name,
        tactic: technique.tactic,
        parentTechniqueId: technique.parentTechniqueId,
        url: mitreReferenceUrl(technique.id),
      })
      .onConflictDoNothing();
  }
}

async function seedCves() {
  console.log(`Seeding ${cveSeeds.length} CVEs...`);
  for (const cve of cveSeeds) {
    await db.insert(cves).values(cve).onConflictDoNothing();
  }
}

// Collects every unique tag string across all rule variants and inserts them,
// returning a map of tag name -> tag id for use when inserting rule_tags rows.
async function seedTags(): Promise<Map<string, string>> {
  const tagNames = new Set<string>();
  for (const seed of allRuleSeeds) {
    for (const variant of seed.variants) {
      for (const tag of variant.tags) {
        tagNames.add(tag);
      }
    }
  }

  console.log(`Seeding ${tagNames.size} unique tags...`);
  const tagIdByName = new Map<string, string>();
  for (const name of tagNames) {
    const slug = slugify(name);
    const id = `tag-${slug}`;
    tagIdByName.set(name, id);
    await db.insert(tags).values({ id, name, slug }).onConflictDoNothing();
  }
  return tagIdByName;
}

async function seedRuleFamiliesAndVariants(tagIdByName: Map<string, string>) {
  console.log(`Seeding ${allRuleSeeds.length} rule families with their variants...`);

  let totalVariants = 0;

  for (const seed of allRuleSeeds) {
    const now = new Date();

    await db
      .insert(ruleFamilies)
      .values({
        id: seed.family.id,
        name: seed.family.name,
        slug: seed.family.slug,
        conceptDescription: seed.family.conceptDescription,
        primaryCategoryId: seed.family.categoryId,
        createdAt: now,
        updatedAt: now,
      })
      .onConflictDoNothing();

    for (const variant of seed.variants) {
      await db
        .insert(detectionRules)
        .values({
          id: variant.id,
          ruleFamilyId: seed.family.id,
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
          primaryCategoryId: seed.family.categoryId,
          embedding: null,
          createdAt: now,
          updatedAt: now,
        })
        .onConflictDoNothing();

      totalVariants += 1;

      // rule_tags
      for (const tagName of variant.tags) {
        const tagId = tagIdByName.get(tagName);
        if (!tagId) continue;
        await db
          .insert(ruleTags)
          .values({ ruleId: variant.id, tagId })
          .onConflictDoNothing();
      }

      // rule_mitre_mappings
      for (const techniqueId of variant.mitreTechniqueIds) {
        await db
          .insert(ruleMitreMappings)
          .values({ ruleId: variant.id, techniqueId })
          .onConflictDoNothing();
      }

      // rule_cve_mappings
      for (const cveId of variant.cveIds) {
        await db
          .insert(ruleCveMappings)
          .values({ ruleId: variant.id, cveId })
          .onConflictDoNothing();
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
    }
  }

  console.log(`Seeded ${allRuleSeeds.length} rule families / ${totalVariants} detection rule variants.`);
}

async function seedBreakGlassAdmin() {
  const email = "admin@sentriq.local";
  const existing = await db.query.users.findFirst({
    where: (u, { eq }) => eq(u.email, email),
  });
  if (existing) {
    console.log("Break-glass admin already exists, skipping.");
    return;
  }

  console.log("Seeding break-glass admin account (admin@sentriq.local / password)...");
  const passwordHash = await bcrypt.hash("password", 10);
  await db.insert(users).values({
    id: crypto.randomUUID(),
    email,
    name: "Break-Glass Admin",
    passwordHash,
    role: "admin",
    isBreakGlass: true,
    mustChangePassword: true,
    createdAt: new Date(),
  });
}

async function main() {
  console.log("Starting Sentriq database seed...");

  await seedCategories();
  await seedMitreTechniques();
  await seedCves();
  const tagIdByName = await seedTags();
  await seedRuleFamiliesAndVariants(tagIdByName);
  await seedBreakGlassAdmin();

  console.log("Seed complete.");
}

main()
  .catch((err) => {
    console.error("Seed failed:", err);
    process.exit(1);
  })
  .finally(() => {
    process.exit(0);
  });
