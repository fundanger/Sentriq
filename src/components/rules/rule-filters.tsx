"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter, usePathname, useSearchParams } from "next/navigation";
import { Search, X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { DETECTION_LANGUAGES, SEVERITY_LEVELS } from "@/lib/constants";
import { FilterPresets } from "@/components/rules/filter-presets";
import { LIBRARY_QUERY_STORAGE_KEY } from "@/components/rules/back-to-library-link";

interface Category {
  id: string;
  name: string;
  slug: string;
}

const ALL = "all";

const LANGUAGE_LABELS: Record<string, string> = {
  [ALL]: "All languages",
  ...Object.fromEntries(DETECTION_LANGUAGES.map((l) => [l.value, l.label])),
};

const SEVERITY_LABELS: Record<string, string> = {
  [ALL]: "All severities",
  ...Object.fromEntries(SEVERITY_LEVELS.map((s) => [s, s[0]!.toUpperCase() + s.slice(1)])),
};

export function RuleFilters({ categories }: { categories: Category[] }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const language = searchParams.get("language") ?? ALL;
  const category = searchParams.get("category") ?? ALL;
  const severity = searchParams.get("severity") ?? ALL;
  const search = searchParams.get("q") ?? "";

  const [searchInput, setSearchInput] = useState(search);
  const [prevSearch, setPrevSearch] = useState(search);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Keep the input in sync if the URL changes externally (e.g. "Clear").
  if (search !== prevSearch) {
    setPrevSearch(search);
    setSearchInput(search);
  }

  useEffect(() => {
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, []);

  // Remember the current filter/search/page state so "Back to library" can
  // restore it after viewing a rule's detail page.
  useEffect(() => {
    const query = searchParams.toString();
    sessionStorage.setItem(LIBRARY_QUERY_STORAGE_KEY, query);
  }, [searchParams]);

  function handleSearchChange(value: string) {
    setSearchInput(value);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      const params = new URLSearchParams(searchParams.toString());
      if (value) {
        params.set("q", value);
      } else {
        params.delete("q");
      }
      params.delete("page");
      router.push(`${pathname}?${params.toString()}`);
    }, 300);
  }

  function updateParam(key: string, value: string | null) {
    const params = new URLSearchParams(searchParams.toString());
    if (!value || value === ALL) {
      params.delete(key);
    } else {
      params.set(key, value);
    }
    params.delete("page");
    router.push(`${pathname}?${params.toString()}`);
  }

  const hasFilters = language !== ALL || category !== ALL || severity !== ALL || search !== "";

  const categoryLabels: Record<string, string> = {
    [ALL]: "All categories",
    ...Object.fromEntries(categories.map((c) => [c.slug, c.name])),
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="relative w-full max-w-xs sm:w-64">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search rules..."
          value={searchInput}
          className="pl-8"
          data-shortcut="search"
          onChange={(e) => handleSearchChange(e.target.value)}
        />
      </div>

      <Select value={language} onValueChange={(v) => updateParam("language", v)}>
        <SelectTrigger className="w-40">
          <SelectValue>{(value: string) => LANGUAGE_LABELS[value] ?? value}</SelectValue>
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>All languages</SelectItem>
          {DETECTION_LANGUAGES.map((lang) => (
            <SelectItem key={lang.value} value={lang.value}>
              {lang.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <Select value={category} onValueChange={(v) => updateParam("category", v)}>
        <SelectTrigger className="w-48">
          <SelectValue>{(value: string) => categoryLabels[value] ?? value}</SelectValue>
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>All categories</SelectItem>
          {categories.map((cat) => (
            <SelectItem key={cat.id} value={cat.slug}>
              {cat.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <Select value={severity} onValueChange={(v) => updateParam("severity", v)}>
        <SelectTrigger className="w-36">
          <SelectValue>{(value: string) => SEVERITY_LABELS[value] ?? value}</SelectValue>
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>All severities</SelectItem>
          {SEVERITY_LEVELS.map((sev) => (
            <SelectItem key={sev} value={sev} className="capitalize">
              {sev}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {hasFilters && (
        <Button variant="ghost" size="sm" onClick={() => router.push(pathname)}>
          <X />
          Clear
        </Button>
      )}

      <FilterPresets hasFilters={hasFilters} />
    </div>
  );
}
