import type { DashboardWidgetLayout } from "@/db/schema";

export const WIDGET_IDS = [
  "quick_actions",
  "language_breakdown",
  "severity_distribution",
  "category_breakdown",
  "mitre_coverage",
  "recent_rules",
] as const;

export type WidgetId = (typeof WIDGET_IDS)[number];

export const WIDGET_TITLES: Record<WidgetId, string> = {
  quick_actions: "Quick actions",
  language_breakdown: "Rules by language",
  severity_distribution: "Severity distribution",
  category_breakdown: "Categories",
  mitre_coverage: "MITRE ATT&CK coverage",
  recent_rules: "Recently added",
};

export const DEFAULT_DASHBOARD_LAYOUT: DashboardWidgetLayout[] = WIDGET_IDS.map(
  (widgetId) => ({ widgetId, visible: true })
);

/** Merges a saved layout with the current widget set: keeps saved order/visibility, appends any newly-added widgets as visible, and drops unknown widget IDs. */
export function normalizeDashboardLayout(
  saved: DashboardWidgetLayout[] | null | undefined
): DashboardWidgetLayout[] {
  if (!saved || saved.length === 0) return DEFAULT_DASHBOARD_LAYOUT;

  const known = new Set(WIDGET_IDS as readonly string[]);
  const result = saved.filter((entry) => known.has(entry.widgetId));

  const present = new Set(result.map((entry) => entry.widgetId));
  for (const widgetId of WIDGET_IDS) {
    if (!present.has(widgetId)) {
      result.push({ widgetId, visible: true });
    }
  }

  return result;
}
