"use server";

import { z } from "zod";
import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { platformSettings } from "@/db/schema";
import { isSuperAdmin } from "@/lib/permissions";

const HEX_COLOR_REGEX = /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;

const brandingSchema = z.object({
  siteName: z.string().trim().max(60).optional(),
  accentColor: z
    .string()
    .trim()
    .regex(HEX_COLOR_REGEX, "Enter a hex color like #06b6d4.")
    .optional()
    .or(z.literal("")),
  logoUrl: z.string().trim().url("Enter a valid URL.").optional().or(z.literal("")),
});

export interface BrandingResult {
  error?: string;
  fieldErrors?: Record<string, string>;
  success?: string;
}

export async function saveBrandingAction(
  _prevState: BrandingResult | undefined,
  formData: FormData
): Promise<BrandingResult> {
  const session = await auth();
  if (!isSuperAdmin(session?.user?.role)) {
    return { error: "You must be a super admin to change branding settings." };
  }

  const parsed = brandingSchema.safeParse({
    siteName: formData.get("siteName")?.toString() ?? "",
    accentColor: formData.get("accentColor")?.toString() ?? "",
    logoUrl: formData.get("logoUrl")?.toString() ?? "",
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

  await db
    .insert(platformSettings)
    .values({
      id: "default",
      siteName: data.siteName || null,
      accentColor: data.accentColor || null,
      logoUrl: data.logoUrl || null,
      updatedAt: new Date(),
    })
    .onConflictDoUpdate({
      target: platformSettings.id,
      set: {
        siteName: data.siteName || null,
        accentColor: data.accentColor || null,
        logoUrl: data.logoUrl || null,
        updatedAt: new Date(),
      },
    });

  revalidatePath("/", "layout");
  return { success: "Branding settings saved." };
}

export async function resetBrandingAction() {
  const session = await auth();
  if (!isSuperAdmin(session?.user?.role)) {
    throw new Error("You must be a super admin to change branding settings.");
  }

  await db
    .insert(platformSettings)
    .values({
      id: "default",
      siteName: null,
      accentColor: null,
      logoUrl: null,
      updatedAt: new Date(),
    })
    .onConflictDoUpdate({
      target: platformSettings.id,
      set: {
        siteName: null,
        accentColor: null,
        logoUrl: null,
        updatedAt: new Date(),
      },
    });

  revalidatePath("/", "layout");
}
