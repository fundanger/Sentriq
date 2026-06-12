import { sqliteTable, text, integer, index } from "drizzle-orm/sqlite-core";
import { relations } from "drizzle-orm";
import { categories, ruleTags } from "./categories";
import { ruleMitreMappings } from "./mitre";
import { ruleCveMappings } from "./cves";
import { ruleReferences } from "./references";
import { ruleSources } from "./sources";

export const ruleFamilies = sqliteTable("rule_families", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  conceptDescription: text("concept_description").notNull(),
  primaryCategoryId: text("primary_category_id")
    .notNull()
    .references(() => categories.id),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

export const detectionRules = sqliteTable(
  "detection_rules",
  {
    id: text("id").primaryKey(),
    ruleFamilyId: text("rule_family_id").references(() => ruleFamilies.id, {
      onDelete: "set null",
    }),
    language: text("language", {
      enum: ["kql", "sigma", "sentinelone", "cloudflare", "splunk", "yara", "elastic", "falco"],
    }).notNull(),
    platformVariant: text("platform_variant"),
    title: text("title").notNull(),
    slug: text("slug").notNull().unique(),
    descriptionSummary: text("description_summary").notNull(),
    descriptionFull: text("description_full"),
    ruleBody: text("rule_body").notNull(),
    ruleFormatVersion: text("rule_format_version"),
    severity: text("severity", {
      enum: ["informational", "low", "medium", "high", "critical"],
    }).notNull(),
    status: text("status", {
      enum: ["stable", "experimental", "deprecated", "draft"],
    }).notNull(),
    author: text("author").notNull(),
    ruleVersion: text("rule_version").notNull(),
    falsePositiveNotes: text("false_positive_notes"),
    dataSourceRequirements: text("data_source_requirements"),
    primaryCategoryId: text("primary_category_id")
      .notNull()
      .references(() => categories.id),
    embedding: text("embedding", { mode: "json" }).$type<number[] | null>(),
    createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
    updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
  },
  (t) => [
    index("detection_rules_language_idx").on(t.language),
    index("detection_rules_severity_idx").on(t.severity),
    index("detection_rules_primary_category_idx").on(t.primaryCategoryId),
    index("detection_rules_created_at_idx").on(t.createdAt),
  ]
);

export const ruleFamiliesRelations = relations(ruleFamilies, ({ one, many }) => ({
  primaryCategory: one(categories, {
    fields: [ruleFamilies.primaryCategoryId],
    references: [categories.id],
  }),
  variants: many(detectionRules),
}));

export const detectionRulesRelations = relations(detectionRules, ({ one, many }) => ({
  family: one(ruleFamilies, {
    fields: [detectionRules.ruleFamilyId],
    references: [ruleFamilies.id],
  }),
  primaryCategory: one(categories, {
    fields: [detectionRules.primaryCategoryId],
    references: [categories.id],
  }),
  ruleTags: many(ruleTags),
  mitreMappings: many(ruleMitreMappings),
  cveMappings: many(ruleCveMappings),
  references: many(ruleReferences),
  source: one(ruleSources),
}));
