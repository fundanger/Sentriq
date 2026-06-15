"use client";

import { useTheme } from "@/components/theme-provider";
import { Monitor, Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const OPTIONS = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
  { value: "system", label: "System", icon: Monitor },
] as const;

export function ThemePicker() {
  const { theme, setTheme } = useTheme();

  return (
    <div className="flex flex-wrap gap-2">
      {OPTIONS.map((option) => {
        const Icon = option.icon;
        const isActive = theme === option.value;
        return (
          <Button
            key={option.value}
            type="button"
            variant={isActive ? "default" : "outline"}
            className={cn("gap-2")}
            onClick={() => setTheme(option.value)}
          >
            <Icon className="size-4" />
            {option.label}
          </Button>
        );
      })}
    </div>
  );
}
