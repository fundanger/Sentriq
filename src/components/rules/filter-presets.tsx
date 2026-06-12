"use client";

import { useState } from "react";
import { useRouter, usePathname, useSearchParams } from "next/navigation";
import { Bookmark, BookmarkPlus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  getFilterPresets,
  saveFilterPreset,
  deleteFilterPreset,
  type FilterPreset,
} from "@/lib/filter-presets";
import { useLocalStorageList } from "@/hooks/use-local-storage-list";

export function FilterPresets({ hasFilters }: { hasFilters: boolean }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const presets = useLocalStorageList(getFilterPresets);
  const [name, setName] = useState("");
  const [open, setOpen] = useState(false);

  function handleSave() {
    const trimmed = name.trim();
    if (!trimmed) return;
    saveFilterPreset({ name: trimmed, query: searchParams.toString() });
    setName("");
    setOpen(false);
  }

  function handleApply(preset: FilterPreset) {
    router.push(preset.query ? `${pathname}?${preset.query}` : pathname);
  }

  function handleDelete(presetName: string) {
    deleteFilterPreset(presetName);
  }

  return (
    <div className="flex items-center gap-1">
      {presets.length > 0 && (
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <Button variant="outline" size="sm">
                <Bookmark />
                Presets
              </Button>
            }
          />
          <DropdownMenuContent align="start">
            <DropdownMenuLabel>Saved filters</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {presets.map((preset) => (
              <DropdownMenuItem
                key={preset.name}
                className="justify-between gap-2"
                onClick={() => handleApply(preset)}
              >
                <span className="truncate">{preset.name}</span>
                <button
                  type="button"
                  aria-label={`Delete preset ${preset.name}`}
                  className="text-muted-foreground hover:text-destructive"
                  onClick={(e) => {
                    e.stopPropagation();
                    handleDelete(preset.name);
                  }}
                >
                  <Trash2 className="size-3.5" />
                </button>
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      )}

      {hasFilters && (
        <Popover open={open} onOpenChange={setOpen}>
          <PopoverTrigger
            render={
              <Button variant="outline" size="sm">
                <BookmarkPlus />
                Save filters
              </Button>
            }
          />
          <PopoverContent className="w-64">
            <div className="flex flex-col gap-2">
              <p className="text-sm font-medium">Save current filters</p>
              <Input
                placeholder="Preset name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleSave();
                }}
                autoFocus
              />
              <Button size="sm" onClick={handleSave} disabled={!name.trim()}>
                Save
              </Button>
            </div>
          </PopoverContent>
        </Popover>
      )}
    </div>
  );
}
