"use client";

import { ChevronDown, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAiChat } from "@/components/ai/chat-context";
import { DETECTION_LANGUAGES, type DetectionLanguage } from "@/lib/constants";

interface AskAiAboutRuleButtonProps {
  ruleSlug: string;
  ruleTitle: string;
  ruleLanguage: DetectionLanguage;
}

export function AskAiAboutRuleButton({ ruleSlug, ruleTitle, ruleLanguage }: AskAiAboutRuleButtonProps) {
  const { openChat } = useAiChat();

  function ask(initialPrompt: string) {
    openChat({ ruleSlug, ruleTitle, initialPrompt });
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button variant="outline" size="sm">
            <Sparkles />
            Ask AI about this rule
            <ChevronDown />
          </Button>
        }
      />
      <DropdownMenuContent align="end">
        <DropdownMenuItem
          onClick={() =>
            ask(
              "Explain this rule: what it detects, how it works, and any tuning guidance to reduce false positives."
            )
          }
        >
          Explain this rule
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() =>
            ask(
              "Suggest tuning changes to reduce false positives for this rule, with specific edits to the rule body where possible."
            )
          }
        >
          Suggest tuning to reduce false positives
        </DropdownMenuItem>
        <DropdownMenuSub>
          <DropdownMenuSubTrigger>Convert to another language</DropdownMenuSubTrigger>
          <DropdownMenuSubContent>
            {DETECTION_LANGUAGES.filter((lang) => lang.value !== ruleLanguage).map((lang) => (
              <DropdownMenuItem
                key={lang.value}
                onClick={() =>
                  ask(
                    `Convert this rule to ${lang.fullName} (${lang.label}). Respond with the converted rule body in a code block, followed by a brief note on any logic that doesn't translate directly.`
                  )
                }
              >
                {lang.label}
              </DropdownMenuItem>
            ))}
          </DropdownMenuSubContent>
        </DropdownMenuSub>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
