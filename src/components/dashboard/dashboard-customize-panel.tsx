"use client";

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
import { GripVertical } from "lucide-react";
import { Switch } from "@/components/ui/switch";
import { Card } from "@/components/ui/card";
import {
  WIDGET_TITLES,
  type WidgetId,
} from "@/components/dashboard/widget-registry";
import type { DashboardWidgetLayout } from "@/db/schema";
import { cn } from "@/lib/utils";

interface DashboardCustomizePanelProps {
  items: DashboardWidgetLayout[];
  onReorder: (items: DashboardWidgetLayout[]) => void;
  onToggleVisible: (widgetId: string) => void;
}

export function DashboardCustomizePanel({
  items,
  onReorder,
  onToggleVisible,
}: DashboardCustomizePanelProps) {
  const sensors = useSensors(
    useSensor(PointerSensor),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  );

  function handleDragEnd(event: DragEndEvent) {
    const { active, over } = event;
    if (!over || active.id === over.id) return;

    const oldIndex = items.findIndex((i) => i.widgetId === active.id);
    const newIndex = items.findIndex((i) => i.widgetId === over.id);
    onReorder(arrayMove(items, oldIndex, newIndex));
  }

  return (
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
              onToggle={() => onToggleVisible(entry.widgetId)}
            />
          ))}
        </div>
      </SortableContext>
    </DndContext>
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
