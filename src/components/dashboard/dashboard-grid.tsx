"use client";

import { useState, useTransition } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
} from "@dnd-kit/core";
import {
  SortableContext,
  arrayMove,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { GripVertical, Settings2, RotateCcw, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Card } from "@/components/ui/card";
import {
  saveDashboardLayoutAction,
  resetDashboardLayoutAction,
} from "@/actions/dashboard";
import {
  WIDGET_TITLES,
  type WidgetId,
} from "@/components/dashboard/widget-registry";
import type { DashboardWidgetLayout } from "@/db/schema";
import { cn } from "@/lib/utils";

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

  const sensors = useSensors(
    useSensor(PointerSensor),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  );

  function handleDragEnd(event: DragEndEvent) {
    const { active, over } = event;
    if (!over || active.id === over.id) return;

    setItems((prev) => {
      const oldIndex = prev.findIndex((i) => i.widgetId === active.id);
      const newIndex = prev.findIndex((i) => i.widgetId === over.id);
      return arrayMove(prev, oldIndex, newIndex);
    });
  }

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
        <DndContext
          sensors={sensors}
          collisionDetection={closestCenter}
          onDragEnd={handleDragEnd}
        >
          <SortableContext
            items={items.map((i) => i.widgetId)}
            strategy={verticalListSortingStrategy}
          >
            <div className="flex flex-col gap-2">
              {items.map((entry) => (
                <SortableRow
                  key={entry.widgetId}
                  id={entry.widgetId}
                  title={WIDGET_TITLES[entry.widgetId as WidgetId]}
                  visible={entry.visible}
                  onToggle={() => toggleVisible(entry.widgetId)}
                />
              ))}
            </div>
          </SortableContext>
        </DndContext>
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

function SortableRow({
  id,
  title,
  visible,
  onToggle,
}: {
  id: string;
  title: string;
  visible: boolean;
  onToggle: () => void;
}) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } =
    useSortable({ id });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
  };

  return (
    <Card
      ref={setNodeRef}
      style={style}
      className={cn(
        "flex flex-row items-center gap-3 p-3",
        isDragging && "z-10 shadow-lg"
      )}
    >
      <button
        type="button"
        className="cursor-grab touch-none text-muted-foreground active:cursor-grabbing"
        {...attributes}
        {...listeners}
      >
        <GripVertical className="size-4" />
      </button>
      <span className="flex-1 text-sm font-medium">{title}</span>
      <Switch checked={visible} onCheckedChange={onToggle} />
    </Card>
  );
}
