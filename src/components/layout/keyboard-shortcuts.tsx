"use client";

import { useEffect, useRef } from "react";
import { useRouter, usePathname, useSearchParams } from "next/navigation";

const SEARCH_INPUT_SELECTOR = '[data-shortcut="search"]';
const CHORD_TIMEOUT_MS = 600;

function isTypingInField(target: EventTarget | null) {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return (
    tag === "INPUT" ||
    tag === "TEXTAREA" ||
    tag === "SELECT" ||
    target.isContentEditable
  );
}

export function KeyboardShortcuts() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const pendingGRef = useRef(false);
  const chordTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    function clearChord() {
      pendingGRef.current = false;
      if (chordTimeoutRef.current) {
        clearTimeout(chordTimeoutRef.current);
        chordTimeoutRef.current = null;
      }
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.metaKey || event.ctrlKey || event.altKey) return;

      const typing = isTypingInField(event.target);

      if (event.key === "Escape") {
        if (typing && event.target instanceof HTMLElement) {
          event.target.blur();
          return;
        }
        if (pathname === "/rules" && searchParams.toString()) {
          router.push("/rules");
        }
        return;
      }

      if (typing) return;

      if (event.key === "/") {
        event.preventDefault();
        const input = document.querySelector<HTMLInputElement>(SEARCH_INPUT_SELECTOR);
        if (input) {
          input.focus();
        } else {
          router.push("/rules");
        }
        return;
      }

      if (event.key === "g") {
        pendingGRef.current = true;
        if (chordTimeoutRef.current) clearTimeout(chordTimeoutRef.current);
        chordTimeoutRef.current = setTimeout(clearChord, CHORD_TIMEOUT_MS);
        return;
      }

      if (event.key === "r" && pendingGRef.current) {
        clearChord();
        router.push("/rules");
        return;
      }

      clearChord();
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      clearChord();
    };
  }, [router, pathname, searchParams]);

  return null;
}
