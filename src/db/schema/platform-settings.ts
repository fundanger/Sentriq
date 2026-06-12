import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";

/**
 * Singleton table (always id = "default") holding whitelabel/branding
 * settings for this instance. Falls back to Sentriq defaults (see
 * src/lib/constants.ts) when a value is null. Editable only by super_admin
 * (Settings > Branding).
 */
export const platformSettings = sqliteTable("platform_settings", {
  id: text("id").primaryKey().default("default"),
  siteName: text("site_name"),
  accentColor: text("accent_color"),
  logoUrl: text("logo_url"),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});
