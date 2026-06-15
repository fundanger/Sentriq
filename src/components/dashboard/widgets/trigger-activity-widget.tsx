"use client";

import Link from "next/link";
import { motion } from "motion/react";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { DashboardData } from "@/lib/dashboard-data";

export function TriggerActivityWidget({ data }: { data: DashboardData }) {
  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Top triggering rules</CardTitle>
        <CardDescription>
          Deployed rules with the most alerts in the last 24 hours.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-1">
        {data.topTriggeredRules.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No trigger activity recorded yet. Sync trigger counts from Settings
            &rarr; Integrations.
          </p>
        )}
        {data.topTriggeredRules.map((rule, i) => (
          <motion.div
            key={`${rule.ruleId}-${rule.integrationName}`}
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.2, delay: i * 0.04 }}
          >
            <Link
              href={`/rules/${rule.ruleSlug}`}
              className="flex items-center justify-between gap-3 rounded-md px-2 py-1.5 text-sm transition-colors hover:bg-muted/50"
            >
              <div className="flex flex-col">
                <span className="font-medium">{rule.ruleTitle}</span>
                <span className="text-xs text-muted-foreground">
                  {rule.integrationName}
                </span>
              </div>
              <Badge variant="outline">
                {rule.triggerCount.toLocaleString()} trigger{rule.triggerCount === 1 ? "" : "s"}
              </Badge>
            </Link>
          </motion.div>
        ))}
      </CardContent>
    </Card>
  );
}
