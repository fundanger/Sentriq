"use server";

import { z } from "zod";
import { eq, inArray } from "drizzle-orm";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { categories, mitreTechniques } from "@/db/schema";
import { getActiveLlmProvider } from "@/lib/ai/provider";
import { DETECTION_LANGUAGES } from "@/lib/constants";
import type { GeneratedRuleDraft, RuleGenerationRequest } from "@/lib/ai/types";

const LANGUAGE_VALUES = DETECTION_LANGUAGES.map((l) => l.value) as [string, ...string[]];

const generateRuleSchema = z.object({
  description: z.string().min(10, "Describe the threat behavior in at least 10 characters."),
  language: z.enum(LANGUAGE_VALUES as unknown as [string, ...string[]]),
  categoryName: z.string().optional(),
});

export interface GenerateRuleDraftResult {
  error?: string;
  needsProvider?: boolean;
  draft?: GeneratedRuleDraft;
  language?: string;
  primaryCategoryId?: string;
}

export async function generateRuleDraftAction(
  _prevState: GenerateRuleDraftResult | undefined,
  formData: FormData
): Promise<GenerateRuleDraftResult> {
  const session = await auth();
  if (!session?.user?.id) {
    return { error: "You must be signed in to generate a rule." };
  }

  const parsed = generateRuleSchema.safeParse({
    description: formData.get("description")?.toString() ?? "",
    language: formData.get("language")?.toString() ?? "",
    categoryName: formData.get("categoryName")?.toString() || undefined,
  });

  if (!parsed.success) {
    return { error: parsed.error.issues[0]?.message ?? "Invalid input." };
  }

  const provider = await getActiveLlmProvider(session.user.id);
  if (!provider) {
    return { needsProvider: true };
  }

  try {
    const draft = await provider.generateRule(parsed.data as RuleGenerationRequest);

    if (draft.suggestedMitreTechniqueIds.length > 0) {
      const validTechniques = await db.query.mitreTechniques.findMany({
        where: inArray(mitreTechniques.id, draft.suggestedMitreTechniqueIds),
        columns: { id: true },
      });
      draft.suggestedMitreTechniqueIds = validTechniques.map((t) => t.id);
    }

    let primaryCategoryId: string | undefined;
    if (parsed.data.categoryName) {
      const category = await db.query.categories.findFirst({
        where: eq(categories.name, parsed.data.categoryName),
        columns: { id: true },
      });
      primaryCategoryId = category?.id;
    }

    return { draft, language: parsed.data.language, primaryCategoryId };
  } catch (err) {
    return { error: `AI rule generation failed: ${(err as Error).message}` };
  }
}
