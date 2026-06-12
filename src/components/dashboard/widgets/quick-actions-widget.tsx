"use client";

import Link from "next/link";
import { Plus, Sparkles, Wand2, Library } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useAiChat } from "@/components/ai/chat-context";

export function QuickActionsWidget() {
  const { openChat } = useAiChat();

  return (
    <Card className="h-full">
      <CardContent className="grid gap-2 sm:grid-cols-2">
        <Button variant="outline" className="justify-start" render={<Link href="/rules/new" />}>
          <Plus />
          New rule
        </Button>
        <Button variant="outline" className="justify-start" render={<Link href="/rules/new" />}>
          <Wand2 />
          Generate with AI
        </Button>
        <Button variant="outline" className="justify-start" render={<Link href="/rules" />}>
          <Library />
          Browse rule library
        </Button>
        <Button
          variant="outline"
          className="justify-start"
          onClick={() =>
            openChat({
              initialPrompt:
                "What's currently covered in the rule library, and where are the gaps?",
            })
          }
        >
          <Sparkles />
          Ask AI about coverage
        </Button>
      </CardContent>
    </Card>
  );
}
