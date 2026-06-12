"use client";

import { useState } from "react";
import { Check, ChevronsUpDown, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { cn } from "@/lib/utils";

export interface MitreTechniqueOption {
  id: string;
  name: string;
  tactic: string;
}

export function MitreTechniquePicker({
  techniques,
  defaultSelected = [],
}: {
  techniques: MitreTechniqueOption[];
  defaultSelected?: string[];
}) {
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState<string[]>(defaultSelected);

  function toggle(id: string) {
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((t) => t !== id) : [...prev, id]
    );
  }

  const selectedTechniques = techniques.filter((t) => selected.includes(t.id));

  return (
    <div className="flex flex-col gap-2">
      {selected.map((id) => (
        <input key={id} type="hidden" name="mitreTechniqueIds" value={id} />
      ))}

      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger
          render={
            <Button
              type="button"
              variant="outline"
              className="w-full justify-between font-normal"
            >
              <span className="text-muted-foreground">
                {selected.length > 0
                  ? `${selected.length} technique${selected.length === 1 ? "" : "s"} selected`
                  : "Select MITRE techniques..."}
              </span>
              <ChevronsUpDown className="text-muted-foreground" />
            </Button>
          }
        />
        <PopoverContent className="w-(--anchor-width) p-0" align="start">
          <Command>
            <CommandInput placeholder="Search techniques..." />
            <CommandList>
              <CommandEmpty>No techniques found.</CommandEmpty>
              <CommandGroup>
                {techniques.map((technique) => {
                  const isSelected = selected.includes(technique.id);
                  return (
                    <CommandItem
                      key={technique.id}
                      value={`${technique.id} ${technique.name} ${technique.tactic}`}
                      onSelect={() => toggle(technique.id)}
                    >
                      <Check
                        className={cn(
                          "opacity-0",
                          isSelected && "opacity-100"
                        )}
                      />
                      <span className="font-mono text-xs font-semibold">
                        {technique.id}
                      </span>
                      <span className="flex-1">{technique.name}</span>
                      <span className="text-xs text-muted-foreground">
                        {technique.tactic}
                      </span>
                    </CommandItem>
                  );
                })}
              </CommandGroup>
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>

      {selectedTechniques.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {selectedTechniques.map((technique) => (
            <Badge key={technique.id} variant="secondary" className="gap-1">
              <span className="font-mono">{technique.id}</span>
              <button
                type="button"
                onClick={() => toggle(technique.id)}
                aria-label={`Remove ${technique.id}`}
                className="rounded-full hover:text-destructive"
              >
                <X className="size-3" />
              </button>
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}
