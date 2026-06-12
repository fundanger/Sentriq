import Link from "next/link";
import { and, eq, like, or, count } from "drizzle-orm";
import { db } from "@/db";
import { detectionRules, categories } from "@/db/schema";
import { Button } from "@/components/ui/button";
import { RuleFilters } from "@/components/rules/rule-filters";
import { RuleCard } from "@/components/rules/rule-card";
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination";
import { Plus } from "lucide-react";
import type { DetectionLanguage, Severity } from "@/lib/constants";

const PAGE_SIZE = 12;

interface RulesPageProps {
  searchParams: Promise<{
    language?: string;
    category?: string;
    severity?: string;
    q?: string;
    page?: string;
  }>;
}

export default async function RulesPage({ searchParams }: RulesPageProps) {
  const params = await searchParams;
  const page = Math.max(1, Number(params.page) || 1);

  const conditions = [];
  if (params.language) {
    conditions.push(eq(detectionRules.language, params.language as DetectionLanguage));
  }
  if (params.severity) {
    conditions.push(eq(detectionRules.severity, params.severity as Severity));
  }
  if (params.category) {
    const cat = await db.query.categories.findFirst({
      where: eq(categories.slug, params.category),
    });
    if (cat) {
      conditions.push(eq(detectionRules.primaryCategoryId, cat.id));
    }
  }
  if (params.q) {
    const term = `%${params.q}%`;
    conditions.push(
      or(
        like(detectionRules.title, term),
        like(detectionRules.descriptionSummary, term)
      )
    );
  }

  const where = conditions.length > 0 ? and(...conditions) : undefined;

  const [rules, allCategories, totalRow] = await Promise.all([
    db.query.detectionRules.findMany({
      where,
      orderBy: (r, { desc }) => [desc(r.createdAt)],
      limit: PAGE_SIZE,
      offset: (page - 1) * PAGE_SIZE,
      with: { primaryCategory: true },
    }),
    db.query.categories.findMany({
      orderBy: (c, { asc }) => [asc(c.sortOrder)],
    }),
    db.select({ value: count() }).from(detectionRules).where(where),
  ]);

  const total = totalRow[0]?.value ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  function pageHref(p: number) {
    const sp = new URLSearchParams();
    if (params.language) sp.set("language", params.language);
    if (params.category) sp.set("category", params.category);
    if (params.severity) sp.set("severity", params.severity);
    if (params.q) sp.set("q", params.q);
    if (p > 1) sp.set("page", String(p));
    const query = sp.toString();
    return query ? `/rules?${query}` : "/rules";
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-heading text-2xl font-semibold tracking-tight">
            Rule Library
          </h1>
          <p className="text-sm text-muted-foreground">
            {total} {total === 1 ? "rule" : "rules"} matching your filters.
          </p>
        </div>
        <Button render={<Link href="/rules/new" />}>
          <Plus />
          New rule
        </Button>
      </div>

      <RuleFilters categories={allCategories} />

      {rules.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-border py-16 text-center">
          <p className="text-sm font-medium">No rules found</p>
          <p className="text-sm text-muted-foreground">
            Try adjusting your filters or search query.
          </p>
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {rules.map((rule) => (
            <RuleCard
              key={rule.id}
              slug={rule.slug}
              title={rule.title}
              descriptionSummary={rule.descriptionSummary}
              severity={rule.severity}
              language={rule.language}
              status={rule.status}
              categoryName={rule.primaryCategory?.name}
            />
          ))}
        </div>
      )}

      {totalPages > 1 && (
        <Pagination>
          <PaginationContent>
            <PaginationItem>
              <PaginationPrevious
                href={pageHref(Math.max(1, page - 1))}
                aria-disabled={page === 1}
                className={page === 1 ? "pointer-events-none opacity-50" : ""}
              />
            </PaginationItem>
            {Array.from({ length: totalPages }, (_, i) => i + 1).map((p) => (
              <PaginationItem key={p}>
                <PaginationLink href={pageHref(p)} isActive={p === page}>
                  {p}
                </PaginationLink>
              </PaginationItem>
            ))}
            <PaginationItem>
              <PaginationNext
                href={pageHref(Math.min(totalPages, page + 1))}
                aria-disabled={page === totalPages}
                className={page === totalPages ? "pointer-events-none opacity-50" : ""}
              />
            </PaginationItem>
          </PaginationContent>
        </Pagination>
      )}
    </div>
  );
}
