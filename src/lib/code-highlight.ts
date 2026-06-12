import { codeToHtml } from "shiki";
import type { DetectionLanguage } from "@/lib/constants";

const SHIKI_LANG_MAP: Record<DetectionLanguage, string> = {
  kql: "kusto",
  sigma: "yaml",
  sentinelone: "sql",
  cloudflare: "sql",
  splunk: "splunk",
  yara: "yaml",
  elastic: "sql",
};

export async function highlightRuleBody(
  code: string,
  language: DetectionLanguage
): Promise<string> {
  return codeToHtml(code, {
    lang: SHIKI_LANG_MAP[language] ?? "text",
    themes: {
      dark: "github-dark-default",
      light: "github-light-default",
    },
    defaultColor: false,
  });
}
