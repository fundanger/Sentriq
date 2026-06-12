import Link from "next/link";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SEVERITY_BADGE_VARIANTS } from "@/lib/constants";
import { cn } from "@/lib/utils";
import type { DashboardData } from "@/lib/dashboard-data";

export function RecentRulesWidget({ data }: { data: DashboardData }) {
  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Recently added</CardTitle>
        <CardDescription>
          The latest detection rules added to the library.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-1">
        {data.recentRules.map((rule) => (
          <Link
            key={rule.id}
            href={`/rules/${rule.slug}`}
            className="flex items-center justify-between gap-3 rounded-md px-2 py-1.5 text-sm transition-colors hover:bg-muted/50"
          >
            <div className="flex flex-col">
              <span className="font-medium">{rule.title}</span>
              <span className="text-xs text-muted-foreground">
                {rule.categoryName}
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
  );
}
