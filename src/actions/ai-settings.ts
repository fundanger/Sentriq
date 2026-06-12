"use server";

import { z } from "zod";
import { eq, and } from "drizzle-orm";
import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { llmProviderConfigs } from "@/db/schema";
import { encrypt } from "@/lib/crypto";
import { LLM_PROVIDERS } from "@/lib/constants";

const PROVIDER_VALUES = LLM_PROVIDERS.map((p) => p.value) as [string, ...string[]];

const configSchema = z.object({
  provider: z.enum(PROVIDER_VALUES as unknown as [string, ...string[]]),
  apiKey: z.string().min(1, "API key is required."),
  model: z.string().min(1, "Model is required."),
  embeddingModel: z.string().optional(),
  baseUrl: z.string().optional(),
});

export interface AiSettingsResult {
  error?: string;
  fieldErrors?: Record<string, string>;
  success?: string;
}

export async function saveLlmProviderConfigAction(
  _prevState: AiSettingsResult | undefined,
  formData: FormData
): Promise<AiSettingsResult> {
  const session = await auth();
  if (!session?.user?.id) {
    return { error: "You must be signed in to manage AI provider settings." };
  }

  const parsed = configSchema.safeParse({
    provider: formData.get("provider")?.toString() ?? "",
    apiKey: formData.get("apiKey")?.toString() ?? "",
    model: formData.get("model")?.toString() ?? "",
    embeddingModel: formData.get("embeddingModel")?.toString() || undefined,
    baseUrl: formData.get("baseUrl")?.toString() || undefined,
  });

  if (!parsed.success) {
    const fieldErrors: Record<string, string> = {};
    for (const issue of parsed.error.issues) {
      const key = issue.path[0];
      if (typeof key === "string" && !fieldErrors[key]) {
        fieldErrors[key] = issue.message;
      }
    }
    return { error: "Please fix the errors below.", fieldErrors };
  }

  const data = parsed.data;
  const providerMeta = LLM_PROVIDERS.find((p) => p.value === data.provider);
  if (providerMeta?.requiresBaseUrl && !data.baseUrl) {
    return {
      error: "Please fix the errors below.",
      fieldErrors: { baseUrl: "Base URL is required for this provider." },
    };
  }

  const { ciphertext, iv, authTag } = encrypt(data.apiKey);
  const now = new Date();

  const existing = await db.query.llmProviderConfigs.findFirst({
    where: and(
      eq(llmProviderConfigs.userId, session.user.id),
      eq(llmProviderConfigs.provider, data.provider as (typeof LLM_PROVIDERS)[number]["value"])
    ),
  });

  await db
    .update(llmProviderConfigs)
    .set({ isActive: false })
    .where(eq(llmProviderConfigs.userId, session.user.id));

  if (existing) {
    await db
      .update(llmProviderConfigs)
      .set({
        encryptedApiKey: ciphertext,
        apiKeyIv: iv,
        apiKeyAuthTag: authTag,
        baseUrl: data.baseUrl ?? null,
        model: data.model,
        embeddingModel: data.embeddingModel ?? null,
        isActive: true,
        updatedAt: now,
      })
      .where(eq(llmProviderConfigs.id, existing.id));
  } else {
    await db.insert(llmProviderConfigs).values({
      id: crypto.randomUUID(),
      userId: session.user.id,
      provider: data.provider as (typeof LLM_PROVIDERS)[number]["value"],
      encryptedApiKey: ciphertext,
      apiKeyIv: iv,
      apiKeyAuthTag: authTag,
      baseUrl: data.baseUrl ?? null,
      model: data.model,
      embeddingModel: data.embeddingModel ?? null,
      isActive: true,
      createdAt: now,
      updatedAt: now,
    });
  }

  revalidatePath("/settings/ai");
  return { success: "AI provider configuration saved." };
}

export async function setActiveLlmProviderAction(configId: string) {
  const session = await auth();
  if (!session?.user?.id) {
    throw new Error("You must be signed in to manage AI provider settings.");
  }

  await db
    .update(llmProviderConfigs)
    .set({ isActive: false })
    .where(eq(llmProviderConfigs.userId, session.user.id));

  await db
    .update(llmProviderConfigs)
    .set({ isActive: true, updatedAt: new Date() })
    .where(
      and(
        eq(llmProviderConfigs.id, configId),
        eq(llmProviderConfigs.userId, session.user.id)
      )
    );

  revalidatePath("/settings/ai");
}

export async function deleteLlmProviderConfigAction(configId: string) {
  const session = await auth();
  if (!session?.user?.id) {
    throw new Error("You must be signed in to manage AI provider settings.");
  }

  await db
    .delete(llmProviderConfigs)
    .where(
      and(
        eq(llmProviderConfigs.id, configId),
        eq(llmProviderConfigs.userId, session.user.id)
      )
    );

  revalidatePath("/settings/ai");
}
