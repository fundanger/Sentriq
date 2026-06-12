import { DETECTION_LANGUAGES, SEVERITY_LEVELS } from "@/lib/constants";
import type { PlatformContext, PlatformRuleContext, RuleGenerationRequest } from "./types";

const LANGUAGE_NAMES = DETECTION_LANGUAGES.map((l) => `${l.value} (${l.fullName})`).join(", ");

export function buildChatSystemPrompt(context: PlatformContext): string {
  const lines: string[] = [
    "You are the Sentriq AI assistant, embedded in an enterprise threat detection and prevention rule library.",
    "Sentriq stores detection rules across seven languages: " + LANGUAGE_NAMES + ".",
    "Help security analysts understand attack techniques, explain and tune detection rules, map them to MITRE ATT&CK, and answer questions about the rule library.",
    "Be precise, technically accurate, and concise. Use markdown for code blocks and formatting.",
  ];

  if (context.currentRule) {
    lines.push("", "## Current rule the user is viewing", formatRuleForPrompt(context.currentRule));
  }

  if (context.ragMatches && context.ragMatches.length > 0) {
    lines.push("", "## Potentially relevant rules from the library");
    for (const match of context.ragMatches) {
      lines.push(
        `- "${match.title}" (${match.language}, slug: ${match.slug}): ${match.descriptionSummary}`
      );
    }
  }

  return lines.join("\n");
}

export function formatRuleForPrompt(rule: PlatformRuleContext): string {
  const lines = [
    `Title: ${rule.title}`,
    `Language: ${rule.language}`,
    `Severity: ${rule.severity}`,
    `Summary: ${rule.descriptionSummary}`,
  ];

  if (rule.descriptionFull) {
    lines.push(`Description: ${rule.descriptionFull}`);
  }

  if (rule.mitreTechniques.length > 0) {
    lines.push(
      `MITRE techniques: ${rule.mitreTechniques.map((t) => `${t.id} (${t.name})`).join(", ")}`
    );
  }

  if (rule.falsePositiveNotes) {
    lines.push(`False positive notes: ${rule.falsePositiveNotes}`);
  }

  lines.push("Rule body:", "```" + rule.language, rule.ruleBody, "```");

  return lines.join("\n");
}

export function buildExplainRulePrompt(rule: PlatformRuleContext): string {
  return [
    "Explain the following detection rule to a security analyst. Cover:",
    "1. What attack technique or behavior this rule detects, and why it works.",
    "2. A walkthrough of the rule logic in plain language.",
    "3. What legitimate activity could trigger false positives, and how to tune the rule.",
    "4. Suggested MITRE ATT&CK techniques if any seem missing.",
    "",
    formatRuleForPrompt(rule),
  ].join("\n");
}

export function buildGenerateRulePrompt(spec: RuleGenerationRequest): string {
  const languageMeta = DETECTION_LANGUAGES.find((l) => l.value === spec.language);

  return [
    `Draft a new detection rule for ${languageMeta?.fullName ?? spec.language} (language code: ${spec.language}).`,
    spec.categoryName ? `It belongs in the "${spec.categoryName}" category.` : "",
    "",
    "Threat behavior to detect:",
    spec.description,
    "",
    "Respond with ONLY a JSON object (no markdown fences, no commentary) matching this exact shape:",
    "{",
    '  "title": string,',
    '  "descriptionSummary": string (1-2 sentences for a list view),',
    '  "descriptionFull": string (markdown: explain the attack technique, why the rule works, normal vs malicious activity),',
    '  "ruleBody": string (the raw rule/query code in the target language, no markdown fences),',
    `  "severity": one of ${JSON.stringify(SEVERITY_LEVELS)},`,
    '  "falsePositiveNotes": string (markdown: legitimate activity that may trigger this rule and tuning guidance),',
    '  "suggestedMitreTechniqueIds": string[] (MITRE ATT&CK technique IDs like "T1110" or "T1110.003")',
    "}",
  ]
    .filter(Boolean)
    .join("\n");
}

export function extractJsonObject(text: string): string {
  const fenceMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenceMatch) {
    return fenceMatch[1].trim();
  }

  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start !== -1 && end !== -1 && end > start) {
    return text.slice(start, end + 1);
  }

  return text.trim();
}
