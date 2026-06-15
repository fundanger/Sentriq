"use server";

import { z } from "zod";
import { eq } from "drizzle-orm";
import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { ssoConfigs } from "@/db/schema";
import { encrypt } from "@/lib/crypto";
import { isSuperAdmin } from "@/lib/permissions";

const ROLE_VALUES = ["super_admin", "admin", "analyst", "viewer"] as const;

const ssoConfigSchema = z.object({
  displayName: z.string().trim().min(1, "Display name is required.").max(80),
  issuerUrl: z.string().trim().url("Enter a valid issuer URL."),
  clientId: z.string().trim().min(1, "Client ID is required."),
  clientSecret: z.string().trim().min(1, "Client secret is required."),
  groupsClaim: z.string().trim().optional(),
  defaultRole: z.enum(ROLE_VALUES),
  groupRoleMapping: z.string().trim().optional(),
});

export interface SsoResult {
  error?: string;
  fieldErrors?: Record<string, string>;
  success?: string;
}

function parseGroupRoleMapping(raw: string | undefined): Record<string, (typeof ROLE_VALUES)[number]> | null {
  if (!raw) return null;

  const mapping: Record<string, (typeof ROLE_VALUES)[number]> = {};
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const [group, role] = trimmed.split("=").map((part) => part.trim());
    if (!group || !role) continue;
    if (!(ROLE_VALUES as readonly string[]).includes(role)) continue;

    mapping[group] = role as (typeof ROLE_VALUES)[number];
  }

  return Object.keys(mapping).length > 0 ? mapping : null;
}

export async function saveSsoConfigAction(
  _prevState: SsoResult | undefined,
  formData: FormData
): Promise<SsoResult> {
  const session = await auth();
  if (!isSuperAdmin(session?.user?.role)) {
    return { error: "You must be a super admin to manage SSO configuration." };
  }

  const parsed = ssoConfigSchema.safeParse({
    displayName: formData.get("displayName")?.toString() ?? "",
    issuerUrl: formData.get("issuerUrl")?.toString() ?? "",
    clientId: formData.get("clientId")?.toString() ?? "",
    clientSecret: formData.get("clientSecret")?.toString() ?? "",
    groupsClaim: formData.get("groupsClaim")?.toString() || undefined,
    defaultRole: formData.get("defaultRole")?.toString() ?? "viewer",
    groupRoleMapping: formData.get("groupRoleMapping")?.toString() || undefined,
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
  const { ciphertext, iv, authTag } = encrypt(data.clientSecret);
  const now = new Date();

  await db.insert(ssoConfigs).values({
    id: crypto.randomUUID(),
    providerType: "oidc",
    displayName: data.displayName,
    enabled: false,
    issuerUrl: data.issuerUrl,
    clientId: data.clientId,
    encryptedClientSecret: ciphertext,
    clientSecretIv: iv,
    clientSecretAuthTag: authTag,
    groupsClaim: data.groupsClaim ?? null,
    groupRoleMappingJson: parseGroupRoleMapping(data.groupRoleMapping),
    defaultRole: data.defaultRole,
    createdAt: now,
    updatedAt: now,
  });

  revalidatePath("/settings/sso");
  return { success: "SSO provider added. Enable it once you've verified the callback URL with your identity provider." };
}

export async function toggleSsoConfigAction(configId: string, enabled: boolean) {
  const session = await auth();
  if (!isSuperAdmin(session?.user?.role)) {
    throw new Error("You must be a super admin to manage SSO configuration.");
  }

  await db
    .update(ssoConfigs)
    .set({ enabled, updatedAt: new Date() })
    .where(eq(ssoConfigs.id, configId));

  revalidatePath("/settings/sso");
}

export async function deleteSsoConfigAction(configId: string) {
  const session = await auth();
  if (!isSuperAdmin(session?.user?.role)) {
    throw new Error("You must be a super admin to manage SSO configuration.");
  }

  await db.delete(ssoConfigs).where(eq(ssoConfigs.id, configId));
  revalidatePath("/settings/sso");
}
