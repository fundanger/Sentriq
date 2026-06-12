"use client";

import { Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAiChat } from "@/components/ai/chat-context";

interface AskAiAboutRuleButtonProps {
  ruleSlug: string;
  ruleTitle: string;
}

export function AskAiAboutRuleButton({ ruleSlug, ruleTitle }: AskAiAboutRuleButtonProps) {
  const { openChat } = useAiChat();

  return (
    <Button
      variant="outline"
      size="sm"
      onClick={() =>
        openChat({
          ruleSlug,
          ruleTitle,
          initialPrompt:
            "Explain this rule: what it detects, how it works, and any tuning guidance to reduce false positives.",
        })
      }
    >
      <Sparkles />
      Ask AI about this rule
    </Button>
  );
}
