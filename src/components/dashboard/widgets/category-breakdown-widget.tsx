import Link from "next/link";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import type { DashboardData } from "@/lib/dashboard-data";

export function CategoryBreakdownWidget({ data }: { data: DashboardData }) {
  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Categories</CardTitle>
        <CardDescription>
          Rule counts across the 14 MITRE-aligned categories.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-1">
        {data.categoryCounts.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No categories with rules yet.
          </p>
        )}
        {data.categoryCounts
          .slice()
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
  );
}
