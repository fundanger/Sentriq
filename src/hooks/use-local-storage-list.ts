import { useSyncExternalStore } from "react";

const listeners = new Set<() => void>();

function subscribe(callback: () => void) {
  listeners.add(callback);
  return () => listeners.delete(callback);
}

/** Notify all `useLocalStorageList` subscribers after writing to localStorage from the same tab. */
export function notifyLocalStorageListChange() {
  for (const listener of listeners) listener();
}

const EMPTY: never[] = [];

// Cached snapshots per `read` function, so `getSnapshot` returns a stable
// reference until `notifyLocalStorageListChange` signals a real change.
const snapshotCache = new WeakMap<() => unknown[], { json: string; value: unknown[] }>();

/** Reads a localStorage-backed list, returning `[]` during SSR/hydration and the live value after mount. */
export function useLocalStorageList<T>(read: () => T[]): T[] {
  return useSyncExternalStore(
    subscribe,
    () => {
      const value = read();
      const json = JSON.stringify(value);
      const cached = snapshotCache.get(read);
      if (cached && cached.json === json) {
        return cached.value as T[];
      }
      snapshotCache.set(read, { json, value });
      return value;
    },
    () => EMPTY as T[]
  );
}
