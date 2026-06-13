export const PLATFORM_DEFAULTS = {
  siteName: "Sentriq",
  accentColor: "#06b6d4",
  logoUrl: null as string | null,
};

export const DETECTION_LANGUAGES = [
  { value: "kql", label: "KQL", fullName: "Kusto Query Language (Microsoft Sentinel / Defender)", kind: "language" },
  { value: "sigma", label: "Sigma", fullName: "Sigma (generic SIEM rule format)", kind: "language" },
  { value: "splunk", label: "Splunk", fullName: "Splunk SPL", kind: "language" },
  { value: "yara", label: "YARA", fullName: "YARA", kind: "language" },
  { value: "elastic", label: "Elastic", fullName: "Elastic EQL / ES|QL", kind: "language" },
  { value: "sentinelone", label: "SentinelOne", fullName: "SentinelOne Deep Visibility", kind: "platform" },
  { value: "cloudflare", label: "Cloudflare", fullName: "Cloudflare WAF", kind: "platform" },
  { value: "falco", label: "Falco", fullName: "Falco (runtime container/cloud security rules)", kind: "platform" },
] as const;

export type DetectionLanguage = (typeof DETECTION_LANGUAGES)[number]["value"];

export const SEVERITY_LEVELS = [
  "informational",
  "low",
  "medium",
  "high",
  "critical",
] as const;

export type Severity = (typeof SEVERITY_LEVELS)[number];

export const SEVERITY_BADGE_VARIANTS: Record<Severity, string> = {
  informational: "bg-slate-500/15 text-slate-400 border-slate-500/30",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  medium: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
};

export const LLM_PROVIDERS = [
  {
    value: "anthropic",
    label: "Anthropic",
    description: "Claude models via the Anthropic API.",
    models: [
      "claude-opus-4-1-20250805",
      "claude-sonnet-4-5-20250929",
      "claude-haiku-4-5-20251001",
    ],
    defaultModel: "claude-sonnet-4-5-20250929",
    supportsEmbeddings: false,
    requiresBaseUrl: false,
  },
  {
    value: "openai",
    label: "OpenAI",
    description: "GPT models via the OpenAI API.",
    models: ["gpt-5", "gpt-5-mini", "gpt-4.1", "gpt-4.1-mini"],
    defaultModel: "gpt-5",
    embeddingModels: ["text-embedding-3-small", "text-embedding-3-large"],
    defaultEmbeddingModel: "text-embedding-3-small",
    supportsEmbeddings: true,
    requiresBaseUrl: false,
  },
  {
    value: "gemini",
    label: "Google Gemini",
    description: "Gemini models via the Google Generative AI API.",
    models: ["gemini-2.5-pro", "gemini-2.5-flash"],
    defaultModel: "gemini-2.5-flash",
    embeddingModels: ["text-embedding-004"],
    defaultEmbeddingModel: "text-embedding-004",
    supportsEmbeddings: true,
    requiresBaseUrl: false,
  },
  {
    value: "deepseek",
    label: "DeepSeek",
    description: "DeepSeek models via their OpenAI-compatible API.",
    models: ["deepseek-v4-flash", "deepseek-v4-pro"],
    defaultModel: "deepseek-v4-flash",
    supportsEmbeddings: false,
    requiresBaseUrl: false,
  },
  {
    value: "openai_compatible",
    label: "OpenAI-compatible",
    description: "Any self-hosted or third-party endpoint implementing the OpenAI API (e.g. Ollama, LM Studio, vLLM).",
    models: [],
    defaultModel: "",
    supportsEmbeddings: true,
    requiresBaseUrl: true,
  },
] as const;

export type LlmProviderId = (typeof LLM_PROVIDERS)[number]["value"];
