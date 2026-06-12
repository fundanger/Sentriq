import { and, eq } from "drizzle-orm";
import { db } from "@/db";
import { llmProviderConfigs } from "@/db/schema";
import { decrypt } from "@/lib/crypto";
import { AnthropicProvider } from "./providers/anthropic";
import { OpenAiCompatibleProvider } from "./providers/openai-compatible";
import { GeminiProvider } from "./providers/gemini";
import type { LlmProvider } from "./types";

const DEEPSEEK_BASE_URL = "https://api.deepseek.com";

export async function getActiveLlmProvider(userId: string): Promise<LlmProvider | null> {
  const config = await db.query.llmProviderConfigs.findFirst({
    where: and(eq(llmProviderConfigs.userId, userId), eq(llmProviderConfigs.isActive, true)),
  });

  if (!config) {
    return null;
  }

  const apiKey = decrypt({
    ciphertext: config.encryptedApiKey,
    iv: config.apiKeyIv,
    authTag: config.apiKeyAuthTag,
  });

  switch (config.provider) {
    case "anthropic":
      return new AnthropicProvider(apiKey, config.model);
    case "openai":
      return new OpenAiCompatibleProvider(apiKey, config.model, null, config.embeddingModel);
    case "deepseek":
      return new OpenAiCompatibleProvider(apiKey, config.model, DEEPSEEK_BASE_URL, config.embeddingModel);
    case "openai_compatible":
      return new OpenAiCompatibleProvider(apiKey, config.model, config.baseUrl, config.embeddingModel);
    case "gemini":
      return new GeminiProvider(apiKey, config.model, config.embeddingModel);
    default:
      return null;
  }
}
