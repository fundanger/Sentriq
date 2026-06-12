import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { relations } from "drizzle-orm";
import { detectionRules } from "./rules";

export const ruleSources = sqliteTable("rule_sources", {
  id: text("id").primaryKey(),
  ruleId: text("rule_id")
    .notNull()
    .unique()
    .references(() => detectionRules.id, { onDelete: "cascade" }),
  sourceProject: text("source_project").notNull(),
  sourceUrl: text("source_url").notNull(),
  sourceAuthor: text("source_author"),
  licenseName: text("license_name").notNull(),
  licenseUrl: text("license_url").notNull(),
  importedAt: integer("imported_at", { mode: "timestamp" }).notNull(),
});

export const ruleSourcesRelations = relations(ruleSources, ({ one }) => ({
  rule: one(detectionRules, {
    fields: [ruleSources.ruleId],
    references: [detectionRules.id],
  }),
}));
