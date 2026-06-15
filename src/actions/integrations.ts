"use server";

import { z } from "zod";
import { eq, and } from "drizzle-orm";
import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { integrations, deployments, detectionRules, ruleTriggerStats } from "@/db/schema";
import { encrypt } from "@/lib/crypto";
import { isSuperAdmin, canManageRules } from "@/lib/permissions";
import { INTEGRATION_PLATFORMS } from "@/lib/constants";
import { getIntegrationAdapter } from "@/lib/integrations/registry";
import type { IntegrationCredentials } from "@/lib/integrations/types";

const PLATFORM_VALUES = INTEGRATION_PLATFORMS.map((p) => p.value) as [string, ...string[]];

const integrationSchema = z.object({
  name: z.string().trim().min(1, "Name is required.").max(100),
  platform: z.enum(PLATFORM_VALUES as unknown as [string, ...string[]]),
});

export interface IntegrationResult {
  error?: string;
  fieldErrors?: Record<string, string>;
  success?: string;
}

export async function saveIntegrationAction(
  _prevState: IntegrationResult | undefined,
  formData: FormData
): Promise<IntegrationResult> {
  const session = await auth();
  if (!isSuperAdmin(session?.user?.role)) {
    return { error: "You must be a super admin to manage integrations." };
  }

  const parsed = integrationSchema.safeParse({
    name: formData.get("name")?.toString() ?? "",
    platform: formData.get("platform")?.toString() ?? "",
  });

  if (!parsed.success) {
    const fieldErrors: Record<string, string> = {};
    for (const issue of parsed.error.issues) {
      const key = issue.path[0];
      if (typeof key === "string" && !fieldErrors[key]) {
        fieldErrors[key] = issue.message;
      }
    }
    return { error: "Please fix the errors below.", fieldErrors };
  }

  const data = parsed.data;
  const platformMeta = INTEGRATION_PLATFORMS.find((p) => p.value === data.platform);
  if (!platformMeta) {
    return { error: "Unknown platform." };
  }

  const credentials: IntegrationCredentials = {};
  const fieldErrors: Record<string, string> = {};
  for (const field of platformMeta.fields) {
    const value = formData.get(field.key)?.toString() ?? "";
    if (field.required && !value) {
      fieldErrors[field.key] = `${field.label} is required.`;
      continue;
    }
    if (value) {
      credentials[field.key] = value;
    }
  }

  if (Object.keys(fieldErrors).length > 0) {
    return { error: "Please fix the errors below.", fieldErrors };
  }

  const { ciphertext, iv, authTag } = encrypt(JSON.stringify(credentials));
  const now = new Date();

  await db.insert(integrations).values({
    id: crypto.randomUUID(),
    name: data.name,
    platform: data.platform as (typeof INTEGRATION_PLATFORMS)[number]["value"],
    encryptedCredentials: ciphertext,
    credentialsIv: iv,
    credentialsAuthTag: authTag,
    isActive: true,
    createdAt: now,
    updatedAt: now,
  });

  revalidatePath("/settings/integrations");
  return { success: "Integration saved." };
}

export async function deleteIntegrationAction(integrationId: string) {
  const session = await auth();
  if (!isSuperAdmin(session?.user?.role)) {
    throw new Error("You must be a super admin to manage integrations.");
  }

  await db.delete(integrations).where(eq(integrations.id, integrationId));
  revalidatePath("/settings/integrations");
}

export async function toggleIntegrationActiveAction(integrationId: string, isActive: boolean) {
  const session = await auth();
  if (!isSuperAdmin(session?.user?.role)) {
    throw new Error("You must be a super admin to manage integrations.");
  }

  await db
    .update(integrations)
    .set({ isActive, updatedAt: new Date() })
    .where(eq(integrations.id, integrationId));

  revalidatePath("/settings/integrations");
}

export async function testIntegrationConnectionAction(integrationId: string): Promise<IntegrationResult> {
  const session = await auth();
  if (!isSuperAdmin(session?.user?.role)) {
    return { error: "You must be a super admin to manage integrations." };
  }

  const result = await getIntegrationAdapter(integrationId);
  if (!result) {
    return { error: "Integration not found." };
  }

  const testResult = await result.adapter.testConnection();

  await db
    .update(integrations)
    .set({
      lastTestedAt: new Date(),
      lastTestResult: testResult.success ? "success" : "failure",
      lastTestMessage: testResult.message,
    })
    .where(eq(integrations.id, integrationId));

  revalidatePath("/settings/integrations");
  return testResult.success
    ? { success: testResult.message }
    : { error: testResult.message };
}

const credentialUpdateSchema = z.record(z.string(), z.string());

export async function updateIntegrationCredentialsAction(
  integrationId: string,
  formData: FormData
): Promise<IntegrationResult> {
  const session = await auth();
  if (!isSuperAdmin(session?.user?.role)) {
    return { error: "You must be a super admin to manage integrations." };
  }

  const integration = await db.query.integrations.findFirst({
    where: eq(integrations.id, integrationId),
  });
  if (!integration) {
    return { error: "Integration not found." };
  }

  const platformMeta = INTEGRATION_PLATFORMS.find((p) => p.value === integration.platform);
  if (!platformMeta) {
    return { error: "Unknown platform." };
  }

  const credentials: Record<string, string> = {};
  const fieldErrors: Record<string, string> = {};
  for (const field of platformMeta.fields) {
    const value = formData.get(field.key)?.toString() ?? "";
    if (field.required && !value) {
      fieldErrors[field.key] = `${field.label} is required.`;
      continue;
    }
    if (value) {
      credentials[field.key] = value;
    }
  }

  if (Object.keys(fieldErrors).length > 0) {
    return { error: "Please fix the errors below.", fieldErrors };
  }

  const parsed = credentialUpdateSchema.safeParse(credentials);
  if (!parsed.success) {
    return { error: "Invalid credential values." };
  }

  const { ciphertext, iv, authTag } = encrypt(JSON.stringify(parsed.data));

  await db
    .update(integrations)
    .set({
      encryptedCredentials: ciphertext,
      credentialsIv: iv,
      credentialsAuthTag: authTag,
      updatedAt: new Date(),
    })
    .where(eq(integrations.id, integrationId));

  revalidatePath("/settings/integrations");
  return { success: "Credentials updated." };
}

/** Pushes a detection rule to a configured platform integration, creating or updating the remote rule. */
export async function deployRuleAction(
  ruleId: string,
  integrationId: string
): Promise<IntegrationResult> {
  const session = await auth();
  if (!canManageRules(session?.user?.role)) {
    return { error: "You don't have permission to deploy rules." };
  }

  const rule = await db.query.detectionRules.findFirst({
    where: eq(detectionRules.id, ruleId),
  });
  if (!rule) {
    return { error: "Rule not found." };
  }

  const result = await getIntegrationAdapter(integrationId);
  if (!result) {
    return { error: "Integration not found." };
  }

  const { adapter, integration } = result;
  if (!integration.isActive) {
    return { error: "This integration is disabled." };
  }

  const existingDeployment = await db.query.deployments.findFirst({
    where: and(eq(deployments.ruleId, ruleId), eq(deployments.integrationId, integrationId)),
  });

  try {
    const pushResult = await adapter.pushRule(
      {
        id: rule.id,
        title: rule.title,
        slug: rule.slug,
        language: rule.language,
        severity: rule.severity,
        descriptionSummary: rule.descriptionSummary,
        ruleBody: rule.ruleBody,
      },
      existingDeployment?.remoteRuleId
    );

    const now = new Date();

    if (existingDeployment) {
      await db
        .update(deployments)
        .set({
          remoteRuleId: pushResult.remoteRuleId,
          status: pushResult.status,
          deployedRuleVersion: rule.ruleVersion,
          statusMessage: pushResult.message ?? null,
          lastSyncedAt: now,
          updatedAt: now,
        })
        .where(eq(deployments.id, existingDeployment.id));
    } else {
      await db.insert(deployments).values({
        id: crypto.randomUUID(),
        ruleId,
        integrationId,
        remoteRuleId: pushResult.remoteRuleId,
        status: pushResult.status,
        deployedRuleVersion: rule.ruleVersion,
        statusMessage: pushResult.message ?? null,
        lastSyncedAt: now,
        createdAt: now,
        updatedAt: now,
      });
    }

    revalidatePath(`/rules/${rule.slug}`);
    return { success: `Deployed to ${integration.name}.` };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown deployment error.";
    const now = new Date();

    if (existingDeployment) {
      await db
        .update(deployments)
        .set({ status: "failed", statusMessage: message, updatedAt: now })
        .where(eq(deployments.id, existingDeployment.id));
    } else {
      await db.insert(deployments).values({
        id: crypto.randomUUID(),
        ruleId,
        integrationId,
        remoteRuleId: null,
        status: "failed",
        deployedRuleVersion: null,
        statusMessage: message,
        lastSyncedAt: null,
        createdAt: now,
        updatedAt: now,
      });
    }

    revalidatePath(`/rules/${rule.slug}`);
    return { error: `Deployment failed: ${message}` };
  }
}

/** Fetches trigger counts from the platform for all deployed rules on this integration and records them. */
export async function syncTriggerCountsAction(integrationId: string): Promise<IntegrationResult> {
  const session = await auth();
  if (!isSuperAdmin(session?.user?.role)) {
    return { error: "You must be a super admin to sync trigger counts." };
  }

  const result = await getIntegrationAdapter(integrationId);
  if (!result) {
    return { error: "Integration not found." };
  }

  const { adapter, integration } = result;

  const deploymentRows = await db.query.deployments.findMany({
    where: and(eq(deployments.integrationId, integrationId), eq(deployments.status, "deployed")),
  });

  const deploymentsWithRemoteId = deploymentRows.filter(
    (d): d is typeof d & { remoteRuleId: string } => !!d.remoteRuleId
  );

  if (deploymentsWithRemoteId.length === 0) {
    return { error: "No deployed rules to sync for this integration." };
  }

  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const remoteIdToDeploymentId = new Map(
    deploymentsWithRemoteId.map((d) => [d.remoteRuleId, d.id])
  );

  try {
    const counts = await adapter.getTriggerCounts(
      deploymentsWithRemoteId.map((d) => d.remoteRuleId),
      since
    );

    const now = new Date();
    for (const result of counts) {
      const deploymentId = remoteIdToDeploymentId.get(result.remoteRuleId);
      if (!deploymentId) continue;

      await db
        .insert(ruleTriggerStats)
        .values({
          deploymentId,
          bucketStart: result.bucketStart,
          triggerCount: result.count,
          recordedAt: now,
        })
        .onConflictDoUpdate({
          target: [ruleTriggerStats.deploymentId, ruleTriggerStats.bucketStart],
          set: { triggerCount: result.count, recordedAt: now },
        });
    }

    revalidatePath("/settings/integrations");
    revalidatePath("/");
    return { success: `Synced trigger counts for ${counts.length} rule(s) from ${integration.name}.` };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error syncing trigger counts.";
    return { error: `Sync failed: ${message}` };
  }
}

export async function removeDeploymentAction(deploymentId: string): Promise<IntegrationResult> {
  const session = await auth();
  if (!canManageRules(session?.user?.role)) {
    return { error: "You don't have permission to manage deployments." };
  }

  const deployment = await db.query.deployments.findFirst({
    where: eq(deployments.id, deploymentId),
    with: { rule: true },
  });
  if (!deployment) {
    return { error: "Deployment not found." };
  }

  const result = await getIntegrationAdapter(deployment.integrationId);
  if (result && deployment.remoteRuleId) {
    try {
      await result.adapter.deleteRule(deployment.remoteRuleId);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error removing remote rule.";
      return { error: `Failed to remove remote rule: ${message}` };
    }
  }

  await db.delete(deployments).where(eq(deployments.id, deploymentId));

  if (deployment.rule) {
    revalidatePath(`/rules/${deployment.rule.slug}`);
  }
  return { success: "Deployment removed." };
}
