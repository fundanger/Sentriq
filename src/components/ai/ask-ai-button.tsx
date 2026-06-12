"use client";

import { Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAiChat } from "@/components/ai/chat-context";

export function AskAiButton() {
  const { openChat } = useAiChat();

  return (
    <Button variant="outline" size="sm" onClick={() => openChat()}>
      <Sparkles className="size-4" />
      <span>Ask AI</span>
    </Button>
  );
}
