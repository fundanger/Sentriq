import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { relations } from "drizzle-orm";
import { users } from "./auth";

export type DashboardWidgetLayout = {
  widgetId: string;
  visible: boolean;
};

export const dashboardLayouts = sqliteTable("dashboard_layouts", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .notNull()
    .unique()
    .references(() => users.id, { onDelete: "cascade" }),
  layoutJson: text("layout_json", { mode: "json" })
    .$type<DashboardWidgetLayout[]>()
    .notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

export const dashboardLayoutsRelations = relations(dashboardLayouts, ({ one }) => ({
  user: one(users, {
    fields: [dashboardLayouts.userId],
    references: [users.id],
  }),
}));
