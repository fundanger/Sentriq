"use server";

import { z } from "zod";
import { eq } from "drizzle-orm";
import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { detectionRules, ruleMitreMappings } from "@/db/schema";
import { DETECTION_LANGUAGES, SEVERITY_LEVELS } from "@/lib/constants";
import { canManageRules } from "@/lib/permissions";
import { embedRule } from "@/lib/ai/rag";

const STATUS_VALUES = ["stable", "experimental", "deprecated", "draft"] as const;
const LANGUAGE_VALUES = DETECTION_LANGUAGES.map((l) => l.value) as [string, ...string[]];

const ruleSchema = z.object({
  title: z.string().min(3, "Title must be at least 3 characters."),
  slug: z
    .string()
    .min(3, "Slug must be at least 3 characters.")
    .regex(/^[a-z0-9]+(-[a-z0-9]+)*$/, "Slug must be lowercase, alphanumeric, and hyphen-separated."),
  language: z.enum(LANGUAGE_VALUES as unknown as [string, ...string[]]),
  platformVariant: z.string().optional(),
  primaryCategoryId: z.string().min(1, "Select a category."),
  severity: z.enum(SEVERITY_LEVELS),
  status: z.enum(STATUS_VALUES),
  author: z.string().min(1, "Author is required."),
  ruleVersion: z.string().min(1, "Rule version is required."),
  ruleFormatVersion: z.string().optional(),
  descriptionSummary: z.string().min(10, "Summary must be at least 10 characters."),
  descriptionFull: z.string().optional(),
  ruleBody: z.string().min(1, "Rule body is required."),
  falsePositiveNotes: z.string().optional(),
  dataSourceRequirements: z.string().optional(),
  mitreTechniqueIds: z.array(z.string()).default([]),
});

export interface RuleFormResult {
  error?: string;
  fieldErrors?: Record<string, string>;
}

function parseFormData(formData: FormData) {
  return {
    title: formData.get("title")?.toString() ?? "",
    slug: formData.get("slug")?.toString() ?? "",
    language: formData.get("language")?.toString() ?? "",
    platformVariant: formData.get("platformVariant")?.toString() || undefined,
    primaryCategoryId: formData.get("primaryCategoryId")?.toString() ?? "",
    severity: formData.get("severity")?.toString() ?? "",
    status: formData.get("status")?.toString() ?? "",
    author: formData.get("author")?.toString() ?? "",
    ruleVersion: formData.get("ruleVersion")?.toString() ?? "",
    ruleFormatVersion: formData.get("ruleFormatVersion")?.toString() || undefined,
    descriptionSummary: formData.get("descriptionSummary")?.toString() ?? "",
    descriptionFull: formData.get("descriptionFull")?.toString() || undefined,
    ruleBody: formData.get("ruleBody")?.toString() ?? "",
    falsePositiveNotes: formData.get("falsePositiveNotes")?.toString() || undefined,
    dataSourceRequirements: formData.get("dataSourceRequirements")?.toString() || undefined,
    mitreTechniqueIds: formData.getAll("mitreTechniqueIds").map((v) => v.toString()),
  };
}

export async function createRuleAction(
  _prevState: RuleFormResult | undefined,
  formData: FormData
): Promise<RuleFormResult> {
  const session = await auth();
  if (!session?.user?.id) {
    return { error: "You must be signed in to create a rule." };
  }
  if (!canManageRules(session.user.role)) {
    return { error: "You don't have permission to create rules." };
  }

  const parsed = ruleSchema.safeParse(parseFormData(formData));
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

  const existing = await db.query.detectionRules.findFirst({
    where: eq(detectionRules.slug, data.slug),
  });
  if (existing) {
    return {
      error: "A rule with this slug already exists.",
      fieldErrors: { slug: "This slug is already in use." },
    };
  }

  const now = new Date();
  const id = crypto.randomUUID();

  await db.insert(detectionRules).values({
    id,
    language: data.language as (typeof DETECTION_LANGUAGES)[number]["value"],
    platformVariant: data.platformVariant ?? null,
    title: data.title,
    slug: data.slug,
    descriptionSummary: data.descriptionSummary,
    descriptionFull: data.descriptionFull ?? null,
    ruleBody: data.ruleBody,
    ruleFormatVersion: data.ruleFormatVersion ?? null,
    severity: data.severity,
    status: data.status,
    author: data.author,
    ruleVersion: data.ruleVersion,
    falsePositiveNotes: data.falsePositiveNotes ?? null,
    dataSourceRequirements: data.dataSourceRequirements ?? null,
    primaryCategoryId: data.primaryCategoryId,
    createdAt: now,
    updatedAt: now,
  });

  if (data.mitreTechniqueIds.length > 0) {
    await db.insert(ruleMitreMappings).values(
      data.mitreTechniqueIds.map((techniqueId) => ({
        ruleId: id,
        techniqueId,
      }))
    );
  }

  await embedRule(session.user.id, {
    id,
    title: data.title,
    descriptionSummary: data.descriptionSummary,
    descriptionFull: data.descriptionFull,
  });

  redirect(`/rules/${data.slug}`);
}

export async function updateRuleAction(
  ruleId: string,
  _prevState: RuleFormResult | undefined,
  formData: FormData
): Promise<RuleFormResult> {
  const session = await auth();
  if (!session?.user?.id) {
    return { error: "You must be signed in to edit a rule." };
  }
  if (!canManageRules(session.user.role)) {
    return { error: "You don't have permission to edit rules." };
  }

  const parsed = ruleSchema.safeParse(parseFormData(formData));
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

  const existing = await db.query.detectionRules.findFirst({
    where: eq(detectionRules.slug, data.slug),
  });
  if (existing && existing.id !== ruleId) {
    return {
      error: "A rule with this slug already exists.",
      fieldErrors: { slug: "This slug is already in use." },
    };
  }

  await db
    .update(detectionRules)
    .set({
      language: data.language as (typeof DETECTION_LANGUAGES)[number]["value"],
      platformVariant: data.platformVariant ?? null,
      title: data.title,
      slug: data.slug,
      descriptionSummary: data.descriptionSummary,
      descriptionFull: data.descriptionFull ?? null,
      ruleBody: data.ruleBody,
      ruleFormatVersion: data.ruleFormatVersion ?? null,
      severity: data.severity,
      status: data.status,
      author: data.author,
      ruleVersion: data.ruleVersion,
      falsePositiveNotes: data.falsePositiveNotes ?? null,
      dataSourceRequirements: data.dataSourceRequirements ?? null,
      primaryCategoryId: data.primaryCategoryId,
      updatedAt: new Date(),
    })
    .where(eq(detectionRules.id, ruleId));

  await db.delete(ruleMitreMappings).where(eq(ruleMitreMappings.ruleId, ruleId));
  if (data.mitreTechniqueIds.length > 0) {
    await db.insert(ruleMitreMappings).values(
      data.mitreTechniqueIds.map((techniqueId) => ({
        ruleId,
        techniqueId,
      }))
    );
  }

  await embedRule(session.user.id, {
    id: ruleId,
    title: data.title,
    descriptionSummary: data.descriptionSummary,
    descriptionFull: data.descriptionFull,
  });

  redirect(`/rules/${data.slug}`);
}

export async function deleteRuleAction(ruleId: string) {
  const session = await auth();
  if (!session?.user?.id) {
    throw new Error("You must be signed in to delete a rule.");
  }
  if (!canManageRules(session.user.role)) {
    throw new Error("You don't have permission to delete rules.");
  }

  await db.delete(detectionRules).where(eq(detectionRules.id, ruleId));
  redirect("/rules");
}
