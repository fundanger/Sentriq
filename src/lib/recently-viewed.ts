import type { DetectionLanguage, Severity } from "@/lib/constants";

export interface RecentlyViewedRule {
  slug: string;
  title: string;
  language: DetectionLanguage;
  severity: Severity;
  categoryName?: string | null;
  viewedAt: number;
}

const STORAGE_KEY = "sentriq:recently-viewed-rules";
const MAX_ENTRIES = 8;

export function getRecentlyViewedRules(): RecentlyViewedRule[] {
  if (typeof window === "undefined") return [];

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function recordRecentlyViewedRule(rule: Omit<RecentlyViewedRule, "viewedAt">): void {
  if (typeof window === "undefined") return;

  const existing = getRecentlyViewedRules().filter((r) => r.slug !== rule.slug);
  const updated = [{ ...rule, viewedAt: Date.now() }, ...existing].slice(0, MAX_ENTRIES);

  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch {
    // localStorage unavailable (e.g. private browsing quota) - skip silently.
  }
}
