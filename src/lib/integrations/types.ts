import type { DetectionLanguage, Severity } from "@/lib/constants";

export type IntegrationPlatform =
  | "sentinel"
  | "elastic"
  | "splunk"
  | "sentinelone"
  | "cloudflare";

export interface IntegrationRuleContext {
  id: string;
  title: string;
  slug: string;
  language: DetectionLanguage;
  severity: Severity;
  descriptionSummary: string;
  ruleBody: string;
}

export interface ConnectionTestResult {
  success: boolean;
  message: string;
}

export interface PushRuleResult {
  remoteRuleId: string;
  status: "deployed" | "drift";
  message?: string;
}

export interface TriggerCountResult {
  remoteRuleId: string;
  bucketStart: Date;
  count: number;
}

/**
 * Common interface implemented by each platform adapter. Adapters translate
 * a Sentriq detection rule + credentials into the target platform's rule
 * management API. Methods that a platform doesn't support (e.g. trigger
 * counts) may throw a descriptive error rather than being optional, so
 * callers can surface "not supported by this platform" to the user.
 */
export interface PlatformIntegrationAdapter {
  readonly platform: IntegrationPlatform;

  testConnection(): Promise<ConnectionTestResult>;

  pushRule(rule: IntegrationRuleContext, remoteRuleId?: string | null): Promise<PushRuleResult>;

  deleteRule(remoteRuleId: string): Promise<void>;

  getTriggerCounts(remoteRuleIds: string[], since: Date): Promise<TriggerCountResult[]>;
}

export interface IntegrationCredentials {
  [key: string]: string;
}

export interface PlatformFieldDef {
  key: string;
  label: string;
  type: "text" | "password" | "url";
  placeholder?: string;
  required: boolean;
  helpText?: string;
}

export interface PlatformMeta {
  value: IntegrationPlatform;
  label: string;
  description: string;
  /** Detection rule languages this platform can receive pushes for. */
  supportedLanguages: DetectionLanguage[];
  /** Credential/config fields rendered in the connection form. */
  fields: PlatformFieldDef[];
  supportsTriggerCounts: boolean;
}
