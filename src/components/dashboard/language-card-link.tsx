"use client";

import Link from "next/link";
import { motion } from "motion/react";
import { Card, CardContent } from "@/components/ui/card";

export function LanguageCardLink({
  href,
  count,
  label,
}: {
  href: string;
  count: number;
  label: string;
}) {
  return (
    <motion.div whileHover={{ y: -2 }} transition={{ duration: 0.15 }}>
      <Link href={href}>
        <Card className="transition-all hover:bg-muted/50 hover:ring-primary/40">
          <CardContent className="flex flex-col gap-1">
            <span className="text-2xl font-semibold tabular-nums">
              {count}
            </span>
            <span className="text-xs text-muted-foreground">{label}</span>
          </CardContent>
        </Card>
      </Link>
    </motion.div>
  );
}
