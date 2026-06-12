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

/** Reads a localStorage-backed list, returning `[]` during SSR/hydration and the live value after mount. */
export function useLocalStorageList<T>(read: () => T[]): T[] {
  return useSyncExternalStore(
    subscribe,
    read,
    () => EMPTY as T[]
  );
}
