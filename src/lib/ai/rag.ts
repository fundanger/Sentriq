import { eq, isNotNull } from "drizzle-orm";
import { db } from "@/db";
import { detectionRules } from "@/db/schema";
import { getActiveLlmProvider } from "./provider";
import type { RagMatch } from "./types";
import type { DetectionLanguage } from "@/lib/constants";

function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length || a.length === 0) {
    return 0;
  }

  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }

  if (normA === 0 || normB === 0) {
    return 0;
  }

  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

export function buildEmbeddingInput(rule: {
  title: string;
  descriptionSummary: string;
  descriptionFull?: string | null;
}): string {
  return [rule.title, rule.descriptionSummary, rule.descriptionFull ?? ""]
    .filter(Boolean)
    .join("\n\n");
}

/**
 * Embeds and stores `detection_rules.embedding` for a single rule, if the
 * active provider supports embeddings. No-ops silently if not configured.
 */
export async function embedRule(
  userId: string,
  rule: { id: string; title: string; descriptionSummary: string; descriptionFull?: string | null }
): Promise<void> {
  const provider = await getActiveLlmProvider(userId);
  if (!provider) {
    return;
  }

  try {
    const embedding = await provider.embed(buildEmbeddingInput(rule));
    if (embedding.length > 0) {
      await db
        .update(detectionRules)
        .set({ embedding })
        .where(eq(detectionRules.id, rule.id));
    }
  } catch {
    // Provider may not support embeddings (e.g. Anthropic) - skip silently.
  }
}

export async function searchSimilarRules(
  userId: string,
  query: string,
  topK = 5
): Promise<RagMatch[]> {
  const provider = await getActiveLlmProvider(userId);
  if (!provider) {
    return [];
  }

  let queryEmbedding: number[];
  try {
    queryEmbedding = await provider.embed(query);
  } catch {
    return [];
  }

  if (queryEmbedding.length === 0) {
    return [];
  }

  const rules = await db
    .select({
      title: detectionRules.title,
      slug: detectionRules.slug,
      language: detectionRules.language,
      descriptionSummary: detectionRules.descriptionSummary,
      embedding: detectionRules.embedding,
    })
    .from(detectionRules)
    .where(isNotNull(detectionRules.embedding));

  const scored = rules
    .map((rule) => ({
      title: rule.title,
      slug: rule.slug,
      language: rule.language as DetectionLanguage,
      descriptionSummary: rule.descriptionSummary,
      score: cosineSimilarity(queryEmbedding, rule.embedding ?? []),
    }))
    .sort((a, b) => b.score - a.score);

  return scored.slice(0, topK);
}
