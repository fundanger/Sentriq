import { sqliteTable, text, primaryKey } from "drizzle-orm/sqlite-core";
import { relations } from "drizzle-orm";
import { detectionRules } from "./rules";

export const categories = sqliteTable("categories", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  description: text("description").notNull(),
  sortOrder: text("sort_order").notNull().default("0"),
});

export const tags = sqliteTable("tags", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
});

export const ruleTags = sqliteTable(
  "rule_tags",
  {
    ruleId: text("rule_id")
      .notNull()
      .references(() => detectionRules.id, { onDelete: "cascade" }),
    tagId: text("tag_id")
      .notNull()
      .references(() => tags.id, { onDelete: "cascade" }),
  },
  (t) => [primaryKey({ columns: [t.ruleId, t.tagId] })]
);

export const categoriesRelations = relations(categories, ({ many }) => ({
  rules: many(detectionRules),
}));

export const tagsRelations = relations(tags, ({ many }) => ({
  ruleTags: many(ruleTags),
}));

export const ruleTagsRelations = relations(ruleTags, ({ one }) => ({
  rule: one(detectionRules, {
    fields: [ruleTags.ruleId],
    references: [detectionRules.id],
  }),
  tag: one(tags, {
    fields: [ruleTags.tagId],
    references: [tags.id],
  }),
}));
