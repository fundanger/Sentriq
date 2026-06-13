import { eq, inArray, isNotNull } from "drizzle-orm";
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

/**
 * Finds rules similar to the given rule using stored embeddings. Uses the
 * rule's own `embedding` column if present, otherwise embeds it on the fly
 * (without persisting) if a provider is configured. Returns `[]` if no
 * provider is configured or no other rules have embeddings yet.
 */
export async function findSimilarRules(
  userId: string,
  rule: {
    id: string;
    title: string;
    descriptionSummary: string;
    descriptionFull?: string | null;
    embedding?: number[] | null;
  },
  topK = 5
): Promise<RagMatch[]> {
  let queryEmbedding = rule.embedding ?? null;

  if (!queryEmbedding) {
    const provider = await getActiveLlmProvider(userId);
    if (!provider) {
      return [];
    }

    try {
      queryEmbedding = await provider.embed(buildEmbeddingInput(rule));
    } catch {
      return [];
    }
  }

  if (!queryEmbedding || queryEmbedding.length === 0) {
    return [];
  }

  const rules = await db
    .select({
      id: detectionRules.id,
      embedding: detectionRules.embedding,
    })
    .from(detectionRules)
    .where(isNotNull(detectionRules.embedding));

  const topIds = rules
    .filter((r) => r.id !== rule.id)
    .map((r) => ({
      id: r.id,
      score: cosineSimilarity(queryEmbedding!, r.embedding ?? []),
    }))
    .filter((r) => r.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, topK);

  if (topIds.length === 0) {
    return [];
  }

  const details = await db
    .select({
      id: detectionRules.id,
      title: detectionRules.title,
      slug: detectionRules.slug,
      language: detectionRules.language,
      descriptionSummary: detectionRules.descriptionSummary,
    })
    .from(detectionRules)
    .where(inArray(detectionRules.id, topIds.map((r) => r.id)));

  const detailsById = new Map(details.map((d) => [d.id, d]));

  return topIds.flatMap((r) => {
    const d = detailsById.get(r.id);
    if (!d) return [];
    return [{
      title: d.title,
      slug: d.slug,
      language: d.language as DetectionLanguage,
      descriptionSummary: d.descriptionSummary,
      score: r.score,
    }];
  });
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
      id: detectionRules.id,
      embedding: detectionRules.embedding,
    })
    .from(detectionRules)
    .where(isNotNull(detectionRules.embedding));

  const topIds = rules
    .map((rule) => ({
      id: rule.id,
      score: cosineSimilarity(queryEmbedding, rule.embedding ?? []),
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, topK);

  if (topIds.length === 0) {
    return [];
  }

  const details = await db
    .select({
      id: detectionRules.id,
      title: detectionRules.title,
      slug: detectionRules.slug,
      language: detectionRules.language,
      descriptionSummary: detectionRules.descriptionSummary,
    })
    .from(detectionRules)
    .where(inArray(detectionRules.id, topIds.map((r) => r.id)));

  const detailsById = new Map(details.map((d) => [d.id, d]));

  return topIds.flatMap((r) => {
    const d = detailsById.get(r.id);
    if (!d) return [];
    return [{
      title: d.title,
      slug: d.slug,
      language: d.language as DetectionLanguage,
      descriptionSummary: d.descriptionSummary,
      score: r.score,
    }];
  });
}
