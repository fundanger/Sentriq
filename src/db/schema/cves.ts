import { sqliteTable, text, real, primaryKey } from "drizzle-orm/sqlite-core";
import { relations } from "drizzle-orm";
import { detectionRules } from "./rules";

export const cves = sqliteTable("cves", {
  id: text("id").primaryKey(), // e.g. "CVE-2021-44228"
  cvssScore: real("cvss_score").notNull(),
  cvssVector: text("cvss_vector").notNull(),
  cvssVersion: text("cvss_version", { enum: ["3.0", "3.1", "4.0"] }).notNull(),
  description: text("description").notNull(),
  referenceUrl: text("reference_url").notNull(),
});

export const ruleCveMappings = sqliteTable(
  "rule_cve_mappings",
  {
    ruleId: text("rule_id")
      .notNull()
      .references(() => detectionRules.id, { onDelete: "cascade" }),
    cveId: text("cve_id")
      .notNull()
      .references(() => cves.id, { onDelete: "cascade" }),
  },
  (t) => [primaryKey({ columns: [t.ruleId, t.cveId] })]
);

export const cvesRelations = relations(cves, ({ many }) => ({
  ruleMappings: many(ruleCveMappings),
}));

export const ruleCveMappingsRelations = relations(ruleCveMappings, ({ one }) => ({
  rule: one(detectionRules, {
    fields: [ruleCveMappings.ruleId],
    references: [detectionRules.id],
  }),
  cve: one(cves, {
    fields: [ruleCveMappings.cveId],
    references: [cves.id],
  }),
}));
