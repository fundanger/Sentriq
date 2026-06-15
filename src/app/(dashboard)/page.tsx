import dynamic from "next/dynamic";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { getDashboardData } from "@/lib/dashboard-data";
import { DashboardGrid } from "@/components/dashboard/dashboard-grid";
import { normalizeDashboardLayout } from "@/components/dashboard/widget-registry";
import { QuickActionsWidget } from "@/components/dashboard/widgets/quick-actions-widget";
import { LanguageBreakdownWidget } from "@/components/dashboard/widgets/language-breakdown-widget";
import { CategoryBreakdownWidget } from "@/components/dashboard/widgets/category-breakdown-widget";
import { RecentRulesWidget } from "@/components/dashboard/widgets/recent-rules-widget";
import { RecentlyViewedWidget } from "@/components/dashboard/widgets/recently-viewed-widget";
import { TriggerActivityWidget } from "@/components/dashboard/widgets/trigger-activity-widget";
import { ChartWidgetSkeleton } from "@/components/dashboard/widgets/chart-widget-skeleton";
import { DETECTION_LANGUAGES } from "@/lib/constants";

const SeverityDistributionWidget = dynamic(() =>
  import("@/components/dashboard/widgets/severity-distribution-widget").then(
    (mod) => mod.SeverityDistributionWidget
  ),
  { loading: () => <ChartWidgetSkeleton /> }
);

const MitreCoverageWidget = dynamic(() =>
  import("@/components/dashboard/widgets/mitre-coverage-widget").then(
    (mod) => mod.MitreCoverageWidget
  ),
  { loading: () => <ChartWidgetSkeleton /> }
);

export default async function DashboardPage() {
  const session = await auth();

  const [data, savedLayout] = await Promise.all([
    getDashboardData(),
    session?.user?.id
      ? db.query.dashboardLayouts.findFirst({
          where: (l, { eq }) => eq(l.userId, session.user!.id!),
        })
      : Promise.resolve(undefined),
  ]);

  const layout = normalizeDashboardLayout(savedLayout?.layoutJson);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="font-heading text-2xl font-semibold tracking-tight">
          Dashboard
        </h1>
        <p className="text-sm text-muted-foreground">
          {data.totalRules} detection rules across {DETECTION_LANGUAGES.length}{" "}
          languages and {data.categoryCounts.length} categories.
        </p>
      </div>

      <DashboardGrid
        layout={layout}
        widgets={{
          quick_actions: <QuickActionsWidget />,
          language_breakdown: <LanguageBreakdownWidget data={data} />,
          severity_distribution: <SeverityDistributionWidget data={data} />,
          category_breakdown: <CategoryBreakdownWidget data={data} />,
          mitre_coverage: <MitreCoverageWidget data={data} />,
          recent_rules: <RecentRulesWidget data={data} />,
          recently_viewed: <RecentlyViewedWidget />,
          trigger_activity: <TriggerActivityWidget data={data} />,
        }}
      />
    </div>
  );
}
