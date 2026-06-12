import OpenAI from "openai";
import { z } from "zod";
import { SEVERITY_LEVELS } from "@/lib/constants";
import {
  buildChatSystemPrompt,
  buildExplainRulePrompt,
  buildGenerateRulePrompt,
  extractJsonObject,
} from "../prompts";
import type {
  ChatMessage,
  GeneratedRuleDraft,
  LlmProvider,
  PlatformContext,
  PlatformRuleContext,
  RuleGenerationRequest,
} from "../types";

const draftSchema = z.object({
  title: z.string(),
  descriptionSummary: z.string(),
  descriptionFull: z.string(),
  ruleBody: z.string(),
  severity: z.enum(SEVERITY_LEVELS),
  falsePositiveNotes: z.string(),
  suggestedMitreTechniqueIds: z.array(z.string()).default([]),
});

export class OpenAiCompatibleProvider implements LlmProvider {
  private client: OpenAI;
  private model: string;
  private embeddingModel: string | null;

  constructor(apiKey: string, model: string, baseUrl?: string | null, embeddingModel?: string | null) {
    this.client = new OpenAI({ apiKey, baseURL: baseUrl ?? undefined });
    this.model = model;
    this.embeddingModel = embeddingModel ?? null;
  }

  async *chat(messages: ChatMessage[], context: PlatformContext): AsyncIterable<string> {
    const stream = await this.client.chat.completions.create({
      model: this.model,
      stream: true,
      messages: [
        { role: "system", content: buildChatSystemPrompt(context) },
        ...messages.map((m) => ({ role: m.role, content: m.content })),
      ],
    });

    for await (const chunk of stream) {
      const delta = chunk.choices[0]?.delta?.content;
      if (delta) {
        yield delta;
      }
    }
  }

  async generateRule(spec: RuleGenerationRequest): Promise<GeneratedRuleDraft> {
    const response = await this.client.chat.completions.create({
      model: this.model,
      messages: [{ role: "user", content: buildGenerateRulePrompt(spec) }],
    });

    const text = response.choices[0]?.message?.content ?? "";
    const parsed = draftSchema.parse(JSON.parse(extractJsonObject(text)));
    return parsed;
  }

  async explainRule(rule: PlatformRuleContext): Promise<string> {
    const response = await this.client.chat.completions.create({
      model: this.model,
      messages: [{ role: "user", content: buildExplainRulePrompt(rule) }],
    });

    return response.choices[0]?.message?.content ?? "";
  }

  async embed(text: string): Promise<number[]> {
    if (!this.embeddingModel) {
      throw new Error("No embedding model configured for this provider.");
    }

    const response = await this.client.embeddings.create({
      model: this.embeddingModel,
      input: text,
    });

    return response.data[0]?.embedding ?? [];
  }
}
