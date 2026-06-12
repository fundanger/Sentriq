export const DETECTION_LANGUAGES = [
  { value: "kql", label: "KQL", fullName: "Kusto Query Language (Microsoft Sentinel / Defender)" },
  { value: "sigma", label: "Sigma", fullName: "Sigma (generic SIEM rule format)" },
  { value: "sentinelone", label: "SentinelOne", fullName: "SentinelOne Deep Visibility" },
  { value: "cloudflare", label: "Cloudflare", fullName: "Cloudflare WAF" },
  { value: "splunk", label: "Splunk", fullName: "Splunk SPL" },
  { value: "yara", label: "YARA", fullName: "YARA" },
  { value: "elastic", label: "Elastic", fullName: "Elastic EQL / ES|QL" },
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
