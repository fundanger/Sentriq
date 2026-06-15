"use client";

import { Bar, BarChart, CartesianGrid, XAxis, YAxis, Cell } from "recharts";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { SEVERITY_LEVELS } from "@/lib/constants";
import type { DashboardData } from "@/lib/dashboard-data";

const SEVERITY_COLORS: Record<string, string> = {
  informational: "var(--color-severity-informational)",
  low: "var(--color-severity-low)",
  medium: "var(--color-severity-medium)",
  high: "var(--color-severity-high)",
  critical: "var(--color-severity-critical)",
};

const chartConfig: ChartConfig = {
  count: { label: "Rules" },
};

export function SeverityDistributionWidget({ data }: { data: DashboardData }) {
  const countBySeverity = new Map(
    data.severityCounts.map((row) => [row.severity, row.count])
  );

  const chartData = SEVERITY_LEVELS.map((severity) => ({
    severity,
    label: severity.charAt(0).toUpperCase() + severity.slice(1),
    count: countBySeverity.get(severity) ?? 0,
  }));

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Severity distribution</CardTitle>
        <CardDescription>
          Rule counts by assigned severity across the library.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col">
        <ChartContainer config={chartConfig} className="h-full min-h-48 w-full">
          <BarChart data={chartData} layout="vertical" margin={{ left: 8 }}>
            <CartesianGrid horizontal={false} strokeDasharray="3 3" />
            <XAxis type="number" allowDecimals={false} hide />
            <YAxis
              type="category"
              dataKey="label"
              tickLine={false}
              axisLine={false}
              width={88}
            />
            <ChartTooltip content={<ChartTooltipContent />} />
            <Bar dataKey="count" radius={4}>
              {chartData.map((entry) => (
                <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity]} />
              ))}
            </Bar>
          </BarChart>
        </ChartContainer>
      </CardContent>
    </Card>
  );
}
