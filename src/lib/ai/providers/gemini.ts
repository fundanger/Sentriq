import { GoogleGenerativeAI } from "@google/generative-ai";
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

export class GeminiProvider implements LlmProvider {
  private client: GoogleGenerativeAI;
  private model: string;
  private embeddingModel: string | null;

  constructor(apiKey: string, model: string, embeddingModel?: string | null) {
    this.client = new GoogleGenerativeAI(apiKey);
    this.model = model;
    this.embeddingModel = embeddingModel ?? null;
  }

  async *chat(messages: ChatMessage[], context: PlatformContext): AsyncIterable<string> {
    const generativeModel = this.client.getGenerativeModel({
      model: this.model,
      systemInstruction: buildChatSystemPrompt(context),
    });

    const history = messages.slice(0, -1).map((m) => ({
      role: m.role === "assistant" ? "model" : "user",
      parts: [{ text: m.content }],
    }));
    const lastMessage = messages[messages.length - 1];

    const chat = generativeModel.startChat({ history });
    const result = await chat.sendMessageStream(lastMessage?.content ?? "");

    for await (const chunk of result.stream) {
      const text = chunk.text();
      if (text) {
        yield text;
      }
    }
  }

  async generateRule(spec: RuleGenerationRequest): Promise<GeneratedRuleDraft> {
    const generativeModel = this.client.getGenerativeModel({ model: this.model });
    const result = await generativeModel.generateContent(buildGenerateRulePrompt(spec));
    const text = result.response.text();

    const parsed = draftSchema.parse(JSON.parse(extractJsonObject(text)));
    return parsed;
  }

  async explainRule(rule: PlatformRuleContext): Promise<string> {
    const generativeModel = this.client.getGenerativeModel({ model: this.model });
    const result = await generativeModel.generateContent(buildExplainRulePrompt(rule));
    return result.response.text();
  }

  async embed(text: string): Promise<number[]> {
    if (!this.embeddingModel) {
      throw new Error("No embedding model configured for this provider.");
    }

    const generativeModel = this.client.getGenerativeModel({ model: this.embeddingModel });
    const result = await generativeModel.embedContent(text);
    return result.embedding.values;
  }
}
