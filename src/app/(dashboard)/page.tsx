import Link from "next/link";
import { sql } from "drizzle-orm";
import { db } from "@/db";
import { detectionRules, categories } from "@/db/schema";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LanguageCardLink } from "@/components/dashboard/language-card-link";
import { DETECTION_LANGUAGES, SEVERITY_BADGE_VARIANTS } from "@/lib/constants";
import { cn } from "@/lib/utils";

export default async function DashboardPage() {
  const [languageCounts, categoryCounts, totalRow, recentRules] =
    await Promise.all([
      db
        .select({
          language: detectionRules.language,
          count: sql<number>`count(*)`,
        })
        .from(detectionRules)
        .groupBy(detectionRules.language),
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
      db.query.detectionRules.findMany({
        orderBy: (r, { desc }) => [desc(r.createdAt)],
        limit: 6,
        with: { primaryCategory: true },
      }),
    ]);

  const countByLanguage = new Map(
    languageCounts.map((row) => [row.language, row.count])
  );
  const totalRules = totalRow[0]?.count ?? 0;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="font-heading text-2xl font-semibold tracking-tight">
          Dashboard
        </h1>
        <p className="text-sm text-muted-foreground">
          {totalRules} detection rules across {DETECTION_LANGUAGES.length}{" "}
          languages and {categoryCounts.length} categories.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-7">
        {DETECTION_LANGUAGES.map((lang) => (
          <LanguageCardLink
            key={lang.value}
            href={`/rules?language=${lang.value}`}
            count={countByLanguage.get(lang.value) ?? 0}
            label={lang.label}
          />
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Categories</CardTitle>
            <CardDescription>
              Rule counts across the 14 MITRE-aligned categories.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-1">
            {categoryCounts
              .sort((a, b) => b.count - a.count)
              .map((row) => (
                <Link
                  key={row.categoryId}
                  href={`/rules?category=${row.categorySlug}`}
                  className="flex items-center justify-between rounded-md px-2 py-1.5 text-sm transition-colors hover:bg-muted/50"
                >
                  <span>{row.categoryName}</span>
                  <span className="tabular-nums text-muted-foreground">
                    {row.count}
                  </span>
                </Link>
              ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recently added</CardTitle>
            <CardDescription>
              The latest detection rules added to the library.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-1">
            {recentRules.map((rule) => (
              <Link
                key={rule.id}
                href={`/rules/${rule.slug}`}
                className="flex items-center justify-between gap-3 rounded-md px-2 py-1.5 text-sm transition-colors hover:bg-muted/50"
              >
                <div className="flex flex-col">
                  <span className="font-medium">{rule.title}</span>
                  <span className="text-xs text-muted-foreground">
                    {rule.primaryCategory?.name}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge
                    variant="outline"
                    className={cn("capitalize", SEVERITY_BADGE_VARIANTS[rule.severity])}
                  >
                    {rule.severity}
                  </Badge>
                  <Badge variant="secondary" className="uppercase">
                    {rule.language}
                  </Badge>
                </div>
              </Link>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
