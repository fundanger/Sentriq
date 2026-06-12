import { eq, isNull } from "drizzle-orm";
import { db } from "../index";
import { detectionRules } from "../schema";
import { buildEmbeddingInput } from "@/lib/ai/rag";
import { getActiveLlmProvider } from "@/lib/ai/provider";

const CONCURRENCY = 6;
const MAX_RETRIES = 3;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Returns the HTTP status code from an SDK error, if present (OpenAI/Anthropic/Gemini SDKs all expose `.status`). */
function statusOf(err: unknown): number | undefined {
  if (typeof err === "object" && err !== null && "status" in err) {
    const status = (err as { status: unknown }).status;
    return typeof status === "number" ? status : undefined;
  }
  return undefined;
}

function isRetryable(err: unknown): boolean {
  const status = statusOf(err);
  return status === 429 || (status !== undefined && status >= 500);
}

async function embedWithRetry(
  provider: { embed(text: string): Promise<number[]> },
  text: string
): Promise<number[]> {
  let lastErr: unknown;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await provider.embed(text);
    } catch (err) {
      lastErr = err;
      if (!isRetryable(err) || attempt === MAX_RETRIES) {
        throw err;
      }
      const backoffMs = 1000 * 2 ** attempt;
      await sleep(backoffMs);
    }
  }
  throw lastErr;
}

/** Runs `tasks` with at most `limit` in flight at a time. */
async function runWithConcurrency<T>(
  tasks: (() => Promise<T>)[],
  limit: number
): Promise<void> {
  let next = 0;
  async function worker() {
    while (next < tasks.length) {
      const i = next++;
      await tasks[i]();
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, () => worker()));
}

async function main() {
  const force = process.argv.includes("--force");

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

  const rulesToEmbed = force
    ? await db.query.detectionRules.findMany()
    : await db.query.detectionRules.findMany({
        where: isNull(detectionRules.embedding),
      });

  console.log(
    `Embedding ${rulesToEmbed.length} rule(s) with concurrency=${CONCURRENCY}${force ? " (--force: re-embedding all)" : ""}...`
  );

  let succeeded = 0;
  let failed = 0;
  let done = 0;

  const tasks = rulesToEmbed.map((rule) => async () => {
    try {
      const embedding = await embedWithRetry(provider, buildEmbeddingInput(rule));
      if (embedding.length > 0) {
        await db.update(detectionRules).set({ embedding }).where(eq(detectionRules.id, rule.id));
        succeeded++;
      } else {
        failed++;
      }
    } catch (err) {
      failed++;
      console.error(`  failed: ${rule.slug} (${(err as Error).message})`);
    } finally {
      done++;
      if (done % 100 === 0) {
        console.log(`  ...${done}/${rulesToEmbed.length} processed (${succeeded} ok, ${failed} failed)`);
      }
    }
  });

  await runWithConcurrency(tasks, CONCURRENCY);

  console.log(`Done. ${succeeded} embedded, ${failed} failed.`);
  process.exit(0);
}

main();
