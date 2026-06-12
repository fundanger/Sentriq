import Anthropic from "@anthropic-ai/sdk";
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

export class AnthropicProvider implements LlmProvider {
  private client: Anthropic;
  private model: string;

  constructor(apiKey: string, model: string) {
    this.client = new Anthropic({ apiKey });
    this.model = model;
  }

  async *chat(messages: ChatMessage[], context: PlatformContext): AsyncIterable<string> {
    const stream = this.client.messages.stream({
      model: this.model,
      max_tokens: 4096,
      system: buildChatSystemPrompt(context),
      messages: messages.map((m) => ({ role: m.role, content: m.content })),
    });

    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        yield event.delta.text;
      }
    }
  }

  async generateRule(spec: RuleGenerationRequest): Promise<GeneratedRuleDraft> {
    const response = await this.client.messages.create({
      model: this.model,
      max_tokens: 4096,
      messages: [{ role: "user", content: buildGenerateRulePrompt(spec) }],
    });

    const text = response.content
      .filter((block) => block.type === "text")
      .map((block) => block.text)
      .join("");

    const parsed = draftSchema.parse(JSON.parse(extractJsonObject(text)));
    return parsed;
  }

  async explainRule(rule: PlatformRuleContext): Promise<string> {
    const response = await this.client.messages.create({
      model: this.model,
      max_tokens: 2048,
      messages: [{ role: "user", content: buildExplainRulePrompt(rule) }],
    });

    return response.content
      .filter((block) => block.type === "text")
      .map((block) => block.text)
      .join("");
  }

  async embed(): Promise<number[]> {
    throw new Error("Anthropic does not provide an embeddings API. Configure a different provider for embeddings.");
  }
}
