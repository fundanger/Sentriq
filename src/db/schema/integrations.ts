import { sqliteTable, text, integer, index, primaryKey } from "drizzle-orm/sqlite-core";
import { relations } from "drizzle-orm";
import { detectionRules } from "./rules";

export const integrations = sqliteTable("integrations", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  platform: text("platform", {
    enum: ["sentinel", "elastic", "splunk", "sentinelone", "cloudflare"],
  }).notNull(),
  baseUrl: text("base_url"),
  encryptedCredentials: text("encrypted_credentials").notNull(),
  credentialsIv: text("credentials_iv").notNull(),
  credentialsAuthTag: text("credentials_auth_tag").notNull(),
  configJson: text("config_json", { mode: "json" }).$type<Record<string, string>>(),
  isActive: integer("is_active", { mode: "boolean" }).notNull().default(true),
  lastTestedAt: integer("last_tested_at", { mode: "timestamp" }),
  lastTestResult: text("last_test_result", { enum: ["success", "failure"] }),
  lastTestMessage: text("last_test_message"),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

export const deployments = sqliteTable(
  "deployments",
  {
    id: text("id").primaryKey(),
    ruleId: text("rule_id")
      .notNull()
      .references(() => detectionRules.id, { onDelete: "cascade" }),
    integrationId: text("integration_id")
      .notNull()
      .references(() => integrations.id, { onDelete: "cascade" }),
    remoteRuleId: text("remote_rule_id"),
    status: text("status", {
      enum: ["pending", "deployed", "failed", "drift", "removed"],
    })
      .notNull()
      .default("pending"),
    deployedRuleVersion: text("deployed_rule_version"),
    statusMessage: text("status_message"),
    lastSyncedAt: integer("last_synced_at", { mode: "timestamp" }),
    createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
    updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
  },
  (t) => [
    index("deployments_rule_idx").on(t.ruleId),
    index("deployments_integration_idx").on(t.integrationId),
  ]
);

export const ruleTriggerStats = sqliteTable(
  "rule_trigger_stats",
  {
    deploymentId: text("deployment_id")
      .notNull()
      .references(() => deployments.id, { onDelete: "cascade" }),
    bucketStart: integer("bucket_start", { mode: "timestamp" }).notNull(),
    triggerCount: integer("trigger_count").notNull().default(0),
    recordedAt: integer("recorded_at", { mode: "timestamp" }).notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.deploymentId, t.bucketStart] }),
    index("rule_trigger_stats_deployment_idx").on(t.deploymentId),
  ]
);

export const integrationsRelations = relations(integrations, ({ many }) => ({
  deployments: many(deployments),
}));

export const deploymentsRelations = relations(deployments, ({ one, many }) => ({
  rule: one(detectionRules, {
    fields: [deployments.ruleId],
    references: [detectionRules.id],
  }),
  integration: one(integrations, {
    fields: [deployments.integrationId],
    references: [integrations.id],
  }),
  triggerStats: many(ruleTriggerStats),
}));

export const ruleTriggerStatsRelations = relations(ruleTriggerStats, ({ one }) => ({
  deployment: one(deployments, {
    fields: [ruleTriggerStats.deploymentId],
    references: [deployments.id],
  }),
}));
