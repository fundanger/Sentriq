import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";
import { users } from "./auth";

export const llmProviderConfigs = sqliteTable("llm_provider_configs", {
  id: text("id").primaryKey(),
  userId: text("user_id").references(() => users.id, { onDelete: "cascade" }),
  provider: text("provider", {
    enum: ["anthropic", "openai", "gemini", "deepseek", "openai_compatible"],
  }).notNull(),
  encryptedApiKey: text("encrypted_api_key").notNull(),
  apiKeyIv: text("api_key_iv").notNull(),
  apiKeyAuthTag: text("api_key_auth_tag").notNull(),
  baseUrl: text("base_url"),
  model: text("model").notNull(),
  embeddingModel: text("embedding_model"),
  isActive: integer("is_active", { mode: "boolean" }).notNull().default(false),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

export const ssoConfigs = sqliteTable("sso_configs", {
  id: text("id").primaryKey(),
  providerType: text("provider_type", { enum: ["oidc", "saml"] }).notNull(),
  displayName: text("display_name").notNull(),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(false),
  issuerUrl: text("issuer_url"),
  clientId: text("client_id"),
  encryptedClientSecret: text("encrypted_client_secret"),
  clientSecretIv: text("client_secret_iv"),
  clientSecretAuthTag: text("client_secret_auth_tag"),
  groupsClaim: text("groups_claim"),
  groupRoleMappingJson: text("group_role_mapping_json", { mode: "json" }).$type<
    Record<string, "super_admin" | "admin" | "analyst" | "viewer">
  >(),
  defaultRole: text("default_role", {
    enum: ["super_admin", "admin", "analyst", "viewer"],
  })
    .notNull()
    .default("viewer"),
  configJson: text("config_json", { mode: "json" }).$type<Record<string, unknown>>(),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});
