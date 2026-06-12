import { sqliteTable, text, primaryKey } from "drizzle-orm/sqlite-core";
import { relations } from "drizzle-orm";
import { detectionRules } from "./rules";

export const mitreTechniques = sqliteTable("mitre_techniques", {
  id: text("id").primaryKey(), // e.g. "T1110" or "T1110.003"
  name: text("name").notNull(),
  tactic: text("tactic").notNull(), // e.g. "Credential Access"
  parentTechniqueId: text("parent_technique_id"),
  url: text("url").notNull(),
});

export const ruleMitreMappings = sqliteTable(
  "rule_mitre_mappings",
  {
    ruleId: text("rule_id")
      .notNull()
      .references(() => detectionRules.id, { onDelete: "cascade" }),
    techniqueId: text("technique_id")
      .notNull()
      .references(() => mitreTechniques.id, { onDelete: "cascade" }),
  },
  (t) => [primaryKey({ columns: [t.ruleId, t.techniqueId] })]
);

export const mitreTechniquesRelations = relations(mitreTechniques, ({ many }) => ({
  ruleMappings: many(ruleMitreMappings),
}));

export const ruleMitreMappingsRelations = relations(ruleMitreMappings, ({ one }) => ({
  rule: one(detectionRules, {
    fields: [ruleMitreMappings.ruleId],
    references: [detectionRules.id],
  }),
  technique: one(mitreTechniques, {
    fields: [ruleMitreMappings.techniqueId],
    references: [mitreTechniques.id],
  }),
}));
