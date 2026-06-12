import { isNull } from "drizzle-orm";
import { db } from "../index";
import { detectionRules } from "../schema";
import { embedRule } from "@/lib/ai/rag";
import { getActiveLlmProvider } from "@/lib/ai/provider";

async function main() {
  const admin = await db.query.users.findFirst({
    where: (u, { eq }) => eq(u.email, "admin@sentriq.local"),
  });

  if (!admin) {
    console.error("No admin user found. Run `npm run db:seed` first.");
    process.exit(1);
  }

  const provider = await getActiveLlmProvider(admin.id);
  if (!provider) {
    console.error(
      "No active AI provider configured. Add one in Settings > AI Provider before embedding rules."
    );
    process.exit(1);
  }

  const rulesToEmbed = await db.query.detectionRules.findMany({
    where: isNull(detectionRules.embedding),
  });

  console.log(`Embedding ${rulesToEmbed.length} rule(s)...`);

  let succeeded = 0;
  let failed = 0;
  for (const rule of rulesToEmbed) {
    try {
      await embedRule(admin.id, rule);
      succeeded++;
      console.log(`  embedded: ${rule.slug}`);
    } catch (err) {
      failed++;
      console.error(`  failed: ${rule.slug} (${(err as Error).message})`);
    }
  }

  console.log(`Done. ${succeeded} embedded, ${failed} failed.`);
  process.exit(0);
}

main();
