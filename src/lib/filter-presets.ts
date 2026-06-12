import { notifyLocalStorageListChange } from "@/hooks/use-local-storage-list";

export interface FilterPreset {
  name: string;
  query: string;
}

const STORAGE_KEY = "sentriq:rule-filter-presets";
const MAX_PRESETS = 10;

export function getFilterPresets(): FilterPreset[] {
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

export function saveFilterPreset(preset: FilterPreset): void {
  if (typeof window === "undefined") return;

  const existing = getFilterPresets().filter((p) => p.name !== preset.name);
  const updated = [preset, ...existing].slice(0, MAX_PRESETS);

  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    notifyLocalStorageListChange();
  } catch {
    // localStorage unavailable (e.g. private browsing quota) - skip silently.
  }
}

export function deleteFilterPreset(name: string): void {
  if (typeof window === "undefined") return;

  const updated = getFilterPresets().filter((p) => p.name !== name);

  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    notifyLocalStorageListChange();
  } catch {
    // localStorage unavailable (e.g. private browsing quota) - skip silently.
  }
}
