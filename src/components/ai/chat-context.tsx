"use client";

import { createContext, useCallback, useContext, useState, type ReactNode } from "react";

interface AiChatState {
  isOpen: boolean;
  ruleSlug?: string;
  ruleTitle?: string;
  initialPrompt?: string;
}

interface AiChatContextValue extends AiChatState {
  openChat: (options?: { ruleSlug?: string; ruleTitle?: string; initialPrompt?: string }) => void;
  closeChat: () => void;
  setOpen: (open: boolean) => void;
}

const AiChatContext = createContext<AiChatContextValue | null>(null);

export function AiChatProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AiChatState>({ isOpen: false });

  const openChat = useCallback(
    (options?: { ruleSlug?: string; ruleTitle?: string; initialPrompt?: string }) => {
      setState({ isOpen: true, ...options });
    },
    []
  );

  const closeChat = useCallback(() => {
    setState((prev) => ({ ...prev, isOpen: false }));
  }, []);

  const setOpen = useCallback((open: boolean) => {
    setState((prev) => ({ ...prev, isOpen: open }));
  }, []);

  return (
    <AiChatContext.Provider value={{ ...state, openChat, closeChat, setOpen }}>
      {children}
    </AiChatContext.Provider>
  );
}

export function useAiChat() {
  const ctx = useContext(AiChatContext);
  if (!ctx) {
    throw new Error("useAiChat must be used within an AiChatProvider");
  }
  return ctx;
}
