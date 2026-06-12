"use client";

import { useEffect, useState } from "react";
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
import { SEVERITY_BADGE_VARIANTS } from "@/lib/constants";
import { cn } from "@/lib/utils";
import { getRecentlyViewedRules, type RecentlyViewedRule } from "@/lib/recently-viewed";

export function RecentlyViewedWidget() {
  const [rules, setRules] = useState<RecentlyViewedRule[]>([]);

  useEffect(() => {
    setRules(getRecentlyViewedRules());
  }, []);

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Recently viewed</CardTitle>
        <CardDescription>
          Detection rules you&apos;ve looked at recently on this device.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-1">
        {rules.length === 0 && (
          <p className="text-sm text-muted-foreground">
            Rules you view will show up here.
          </p>
        )}
        {rules.map((rule, i) => (
          <motion.div
            key={rule.slug}
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.2, delay: i * 0.04 }}
          >
            <Link
              href={`/rules/${rule.slug}`}
              className="flex items-center justify-between gap-3 rounded-md px-2 py-1.5 text-sm transition-colors hover:bg-muted/50"
            >
              <div className="flex flex-col">
                <span className="font-medium">{rule.title}</span>
                {rule.categoryName && (
                  <span className="text-xs text-muted-foreground">
                    {rule.categoryName}
                  </span>
                )}
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
          </motion.div>
        ))}
      </CardContent>
    </Card>
  );
}
