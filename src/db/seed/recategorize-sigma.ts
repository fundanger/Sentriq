import { eq } from "drizzle-orm";
import YAML from "yaml";
import { db } from "../index";
import { detectionRules, ruleFamilies, categories } from "../schema";
import { categoryForTags, type SigmaRule } from "./importers/sigma";

/**
 * Re-derives `primary_category_id` for already-imported Sigma rules using the
 * corrected `attack.<tactic>` tag mapping in `importers/sigma.ts`
 * (TACTIC_TO_CATEGORY previously used underscored keys that never matched the
 * hyphenated tags Sigma actually uses, so most rules fell back to the default
 * "Insider Threat & Anomalous Behavior" category). Updates both
 * `detection_rules` and the corresponding `rule_families` row.
 */
async function main() {
  const categoryRows = await db.query.categories.findMany({ columns: { id: true, name: true } });
  const categoryNameById = new Map(categoryRows.map((c) => [c.id, c.name]));

  const rules = await db.query.detectionRules.findMany({
    where: eq(detectionRules.language, "sigma"),
    columns: { id: true, ruleFamilyId: true, ruleBody: true, primaryCategoryId: true },
  });

  console.log(`Checking ${rules.length} Sigma rules for category corrections...`);

  let updated = 0;
  let unchanged = 0;
  let parseErrors = 0;
  const moveCounts = new Map<string, number>();

  for (const rule of rules) {
    let parsed: SigmaRule;
    try {
      const firstDoc = rule.ruleBody.split(/^---$/m)[0]!.trim();
      parsed = YAML.parse(firstDoc) as SigmaRule;
    } catch {
      parseErrors += 1;
      continue;
    }

    const tags = parsed?.tags ?? [];
    const newCategoryId = categoryForTags(tags, parsed?.logsource);

    if (newCategoryId === rule.primaryCategoryId) {
      unchanged += 1;
      continue;
    }

    await db
      .update(detectionRules)
      .set({ primaryCategoryId: newCategoryId })
      .where(eq(detectionRules.id, rule.id));

    if (rule.ruleFamilyId) {
      await db
        .update(ruleFamilies)
        .set({ primaryCategoryId: newCategoryId })
        .where(eq(ruleFamilies.id, rule.ruleFamilyId));
    }

    const fromName = categoryNameById.get(rule.primaryCategoryId) ?? rule.primaryCategoryId;
    const toName = categoryNameById.get(newCategoryId) ?? newCategoryId;
    const key = `${fromName} -> ${toName}`;
    moveCounts.set(key, (moveCounts.get(key) ?? 0) + 1);

    updated += 1;
  }

  console.log(`Done. ${updated} updated, ${unchanged} unchanged, ${parseErrors} parse errors.`);
  if (moveCounts.size > 0) {
    console.log("Category moves:");
    for (const [move, count] of [...moveCounts.entries()].sort((a, b) => b[1] - a[1])) {
      console.log(`  ${move}: ${count}`);
    }
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
