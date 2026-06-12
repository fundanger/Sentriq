import type { DetectionLanguage, Severity } from "@/lib/constants";

export type ChatRole = "user" | "assistant";

export interface ChatMessage {
  role: ChatRole;
  content: string;
}

export interface PlatformRuleContext {
  title: string;
  slug: string;
  language: DetectionLanguage;
  severity: Severity;
  descriptionSummary: string;
  descriptionFull: string | null;
  ruleBody: string;
  falsePositiveNotes: string | null;
  mitreTechniques: { id: string; name: string }[];
}

export interface RagMatch {
  title: string;
  slug: string;
  language: DetectionLanguage;
  descriptionSummary: string;
  score: number;
}

export interface PlatformContext {
  currentRule?: PlatformRuleContext;
  ragMatches?: RagMatch[];
}

export interface RuleGenerationRequest {
  description: string;
  language: DetectionLanguage;
  categoryName?: string;
}

export interface GeneratedRuleDraft {
  title: string;
  descriptionSummary: string;
  descriptionFull: string;
  ruleBody: string;
  severity: Severity;
  falsePositiveNotes: string;
  suggestedMitreTechniqueIds: string[];
}

export interface LlmProvider {
  chat(messages: ChatMessage[], context: PlatformContext): AsyncIterable<string>;
  generateRule(spec: RuleGenerationRequest): Promise<GeneratedRuleDraft>;
  explainRule(rule: PlatformRuleContext): Promise<string>;
  embed(text: string): Promise<number[]>;
}
