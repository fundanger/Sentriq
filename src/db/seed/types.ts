export type RuleLanguage =
  | "kql"
  | "sigma"
  | "sentinelone"
  | "cloudflare"
  | "splunk"
  | "yara"
  | "elastic"
  | "falco";

export type RuleSeverity = "informational" | "low" | "medium" | "high" | "critical";

export type RuleStatus = "stable" | "experimental" | "deprecated" | "draft";

export type ReferenceType =
  | "vendor_advisory"
  | "blog_post"
  | "mitre_page"
  | "cve_record"
  | "documentation"
  | "other";

export interface RuleReferenceSeed {
  url: string;
  title: string;
  referenceType: ReferenceType;
}

export interface RuleVariantSeed {
  id: string;
  language: RuleLanguage;
  platformVariant?: string;
  title: string;
  slug: string;
  descriptionSummary: string;
  descriptionFull?: string;
  ruleBody: string;
  ruleFormatVersion?: string;
  severity: RuleSeverity;
  status: RuleStatus;
  author: string;
  ruleVersion: string;
  falsePositiveNotes?: string;
  dataSourceRequirements?: string;
  mitreTechniqueIds: string[];
  cveIds: string[];
  tags: string[];
  references: RuleReferenceSeed[];
}

export interface RuleFamilySeed {
  id: string;
  name: string;
  slug: string;
  categoryId: string;
  conceptDescription: string;
}

export interface RuleSeed {
  family: RuleFamilySeed;
  variants: RuleVariantSeed[];
}
