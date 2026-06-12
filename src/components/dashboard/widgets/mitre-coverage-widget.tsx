"use client";

import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts";
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
import type { DashboardData } from "@/lib/dashboard-data";

const chartConfig: ChartConfig = {
  count: { label: "Rules", color: "var(--color-chart-1)" },
};

export function MitreCoverageWidget({ data }: { data: DashboardData }) {
  const chartData = data.tacticCounts.map((row) => ({
    tactic: row.tactic,
    count: row.count,
  }));

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>MITRE ATT&amp;CK coverage</CardTitle>
        <CardDescription>
          Top tactics by number of mapped detection rules.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {chartData.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No MITRE technique mappings yet.
          </p>
        ) : (
          <ChartContainer config={chartConfig} className="h-56 w-full">
            <BarChart data={chartData} layout="vertical" margin={{ left: 8 }}>
              <CartesianGrid horizontal={false} strokeDasharray="3 3" />
              <XAxis type="number" allowDecimals={false} hide />
              <YAxis
                type="category"
                dataKey="tactic"
                tickLine={false}
                axisLine={false}
                width={140}
                tick={{ fontSize: 12 }}
              />
              <ChartTooltip content={<ChartTooltipContent />} />
              <Bar dataKey="count" fill="var(--color-chart-1)" radius={4} />
            </BarChart>
          </ChartContainer>
        )}
      </CardContent>
    </Card>
  );
}
