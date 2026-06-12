import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { relations } from "drizzle-orm";
import { detectionRules } from "./rules";

export const ruleReferences = sqliteTable("rule_references", {
  id: text("id").primaryKey(),
  ruleId: text("rule_id")
    .notNull()
    .references(() => detectionRules.id, { onDelete: "cascade" }),
  url: text("url").notNull(),
  title: text("title").notNull(),
  referenceType: text("reference_type", {
    enum: [
      "vendor_advisory",
      "blog_post",
      "mitre_page",
      "cve_record",
      "documentation",
      "other",
    ],
  }).notNull(),
  sortOrder: integer("sort_order").notNull().default(0),
});

export const ruleReferencesRelations = relations(ruleReferences, ({ one }) => ({
  rule: one(detectionRules, {
    fields: [ruleReferences.ruleId],
    references: [detectionRules.id],
  }),
}));
