import { sql } from "drizzle-orm";
import { db } from "@/db";
import { detectionRules, categories, mitreTechniques, ruleMitreMappings } from "@/db/schema";
import type { DetectionLanguage, Severity } from "@/lib/constants";

export interface DashboardData {
  totalRules: number;
  languageCounts: { language: DetectionLanguage; count: number }[];
  severityCounts: { severity: Severity; count: number }[];
  categoryCounts: {
    categoryId: string;
    categoryName: string;
    categorySlug: string;
    count: number;
  }[];
  tacticCounts: { tactic: string; count: number }[];
  recentRules: {
    id: string;
    slug: string;
    title: string;
    severity: Severity;
    language: DetectionLanguage;
    categoryName?: string | null;
  }[];
}

export async function getDashboardData(): Promise<DashboardData> {
  const [
    languageCounts,
    severityCounts,
    categoryCounts,
    totalRow,
    tacticCounts,
    recentRules,
  ] = await Promise.all([
    db
      .select({
        language: detectionRules.language,
        count: sql<number>`count(*)`,
      })
      .from(detectionRules)
      .groupBy(detectionRules.language),
    db
      .select({
        severity: detectionRules.severity,
        count: sql<number>`count(*)`,
      })
      .from(detectionRules)
      .groupBy(detectionRules.severity),
    db
      .select({
        categoryId: detectionRules.primaryCategoryId,
        categoryName: categories.name,
        categorySlug: categories.slug,
        count: sql<number>`count(*)`,
      })
      .from(detectionRules)
      .innerJoin(categories, sql`${detectionRules.primaryCategoryId} = ${categories.id}`)
      .groupBy(detectionRules.primaryCategoryId),
    db.select({ count: sql<number>`count(*)` }).from(detectionRules),
    db
      .select({
        tactic: mitreTechniques.tactic,
        count: sql<number>`count(distinct ${ruleMitreMappings.ruleId})`,
      })
      .from(ruleMitreMappings)
      .innerJoin(mitreTechniques, sql`${ruleMitreMappings.techniqueId} = ${mitreTechniques.id}`)
      .groupBy(mitreTechniques.tactic)
      .orderBy(sql`count(distinct ${ruleMitreMappings.ruleId}) desc`)
      .limit(8),
    db.query.detectionRules.findMany({
      orderBy: (r, { desc }) => [desc(r.createdAt)],
      limit: 6,
      with: { primaryCategory: true },
    }),
  ]);

  return {
    totalRules: totalRow[0]?.count ?? 0,
    languageCounts: languageCounts as { language: DetectionLanguage; count: number }[],
    severityCounts: severityCounts as { severity: Severity; count: number }[],
    categoryCounts,
    tacticCounts,
    recentRules: recentRules.map((rule) => ({
      id: rule.id,
      slug: rule.slug,
      title: rule.title,
      severity: rule.severity,
      language: rule.language,
      categoryName: rule.primaryCategory?.name,
    })),
  };
}
