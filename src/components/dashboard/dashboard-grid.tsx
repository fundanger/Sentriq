"use client";

import { useState, useTransition } from "react";
import dynamic from "next/dynamic";
import { motion, AnimatePresence } from "motion/react";
import { Settings2, RotateCcw, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  saveDashboardLayoutAction,
  resetDashboardLayoutAction,
} from "@/actions/dashboard";
import type { WidgetId } from "@/components/dashboard/widget-registry";
import type { DashboardWidgetLayout } from "@/db/schema";

const DashboardCustomizePanel = dynamic(() =>
  import("@/components/dashboard/dashboard-customize-panel").then(
    (mod) => mod.DashboardCustomizePanel
  )
);

const WIDGET_SPAN: Record<WidgetId, string> = {
  quick_actions: "lg:col-span-2",
  language_breakdown: "lg:col-span-4",
  severity_distribution: "lg:col-span-2",
  category_breakdown: "lg:col-span-2",
  mitre_coverage: "lg:col-span-2",
  recent_rules: "lg:col-span-2",
  recently_viewed: "lg:col-span-2",
};

interface DashboardGridProps {
  layout: DashboardWidgetLayout[];
  widgets: Record<WidgetId, React.ReactNode>;
}

export function DashboardGrid({ layout, widgets }: DashboardGridProps) {
  const [items, setItems] = useState(layout);
  const [customizing, setCustomizing] = useState(false);
  const [isPending, startTransition] = useTransition();

  function toggleVisible(widgetId: string) {
    setItems((prev) =>
      prev.map((entry) =>
        entry.widgetId === widgetId ? { ...entry, visible: !entry.visible } : entry
      )
    );
  }

  function handleSave() {
    startTransition(async () => {
      await saveDashboardLayoutAction(items);
      setCustomizing(false);
    });
  }

  function handleReset() {
    startTransition(async () => {
      await resetDashboardLayoutAction();
      setCustomizing(false);
    });
  }

  const visibleItems = items.filter((entry) => entry.visible);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-end">
        {customizing ? (
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={handleReset} disabled={isPending}>
              <RotateCcw />
              Reset to default
            </Button>
            <Button size="sm" onClick={handleSave} disabled={isPending}>
              <Check />
              Done
            </Button>
          </div>
        ) : (
          <Button variant="outline" size="sm" onClick={() => setCustomizing(true)}>
            <Settings2 />
            Customize
          </Button>
        )}
      </div>

      {customizing ? (
        <DashboardCustomizePanel
          items={items}
          onReorder={setItems}
          onToggleVisible={toggleVisible}
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
          <AnimatePresence initial={false}>
            {visibleItems.map((entry) => (
              <motion.div
                key={entry.widgetId}
                layout
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.2, ease: "easeOut" }}
                className={WIDGET_SPAN[entry.widgetId as WidgetId]}
              >
                {widgets[entry.widgetId as WidgetId]}
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      )}
    </div>
  );
}
