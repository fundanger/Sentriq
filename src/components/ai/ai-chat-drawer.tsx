"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { motion, AnimatePresence } from "motion/react";
import { Bot, Send, Sparkles, User, Loader2 } from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
  SheetFooter,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { useAiChat } from "@/components/ai/chat-context";
import { cn } from "@/lib/utils";
import type { ChatMessage } from "@/lib/ai/types";

const NOT_CONFIGURED_STATUS = 412;

export function AiChatDrawer() {
  const { isOpen, setOpen, ruleSlug, ruleTitle, initialPrompt } = useAiChat();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [needsProvider, setNeedsProvider] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const sentInitialPrompt = useRef<string | undefined>(undefined);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  useEffect(() => {
    if (isOpen && initialPrompt && sentInitialPrompt.current !== initialPrompt) {
      sentInitialPrompt.current = initialPrompt;
      void sendMessage(initialPrompt);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen, initialPrompt]);

  async function sendMessage(content: string) {
    const trimmed = content.trim();
    if (!trimmed || isStreaming) return;

    setError(null);
    setNeedsProvider(false);

    const nextMessages: ChatMessage[] = [...messages, { role: "user", content: trimmed }];
    setMessages(nextMessages);
    setInput("");
    setIsStreaming(true);

    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: nextMessages, ruleSlug }),
      });

      if (!res.ok) {
        if (res.status === NOT_CONFIGURED_STATUS) {
          setNeedsProvider(true);
        } else {
          setError(await res.text());
        }
        setIsStreaming(false);
        return;
      }

      const reader = res.body?.getReader();
      if (!reader) {
        setIsStreaming(false);
        return;
      }

      const decoder = new TextDecoder();
      let assistantContent = "";
      setMessages((prev) => [...prev, { role: "assistant", content: "" }]);

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        assistantContent += decoder.decode(value, { stream: true });
        setMessages((prev) => {
          const updated = [...prev];
          updated[updated.length - 1] = { role: "assistant", content: assistantContent };
          return updated;
        });
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setIsStreaming(false);
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    void sendMessage(input);
  }

  return (
    <Sheet open={isOpen} onOpenChange={setOpen}>
      <SheetContent side="right" className="flex w-full flex-col sm:max-w-md">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            <Sparkles className="size-4 text-primary" />
            Sentriq AI Assistant
          </SheetTitle>
          <SheetDescription>
            {ruleTitle
              ? `Context-aware help for "${ruleTitle}".`
              : "Ask about detection rules, MITRE techniques, and tuning guidance."}
          </SheetDescription>
        </SheetHeader>

        <div ref={scrollRef} className="flex-1 overflow-y-auto px-4">
          {messages.length === 0 && !needsProvider && (
            <p className="py-8 text-center text-sm text-muted-foreground">
              Ask a question to get started, e.g. &quot;What do we have for
              ransomware detection?&quot; or &quot;Explain this rule.&quot;
            </p>
          )}

          {needsProvider && (
            <Alert className="mt-4">
              <Sparkles />
              <AlertTitle>No AI provider configured</AlertTitle>
              <AlertDescription>
                Add an API key in{" "}
                <Link href="/settings/ai" className="underline">
                  Settings &gt; AI Provider
                </Link>{" "}
                to enable the AI assistant.
              </AlertDescription>
            </Alert>
          )}

          {error && (
            <Alert variant="destructive" className="mt-4">
              <AlertTitle>Something went wrong</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <div className="flex flex-col gap-3 py-4">
            <AnimatePresence initial={false}>
              {messages.map((message, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2 }}
                  className={cn(
                    "flex gap-2 text-sm",
                    message.role === "user" ? "flex-row-reverse" : "flex-row"
                  )}
                >
                  <div
                    className={cn(
                      "flex size-7 shrink-0 items-center justify-center rounded-full",
                      message.role === "user"
                        ? "bg-primary text-primary-foreground"
                        : "bg-muted text-muted-foreground"
                    )}
                  >
                    {message.role === "user" ? <User className="size-3.5" /> : <Bot className="size-3.5" />}
                  </div>
                  <div
                    className={cn(
                      "max-w-[85%] rounded-lg px-3 py-2 whitespace-pre-wrap",
                      message.role === "user"
                        ? "bg-primary text-primary-foreground"
                        : "bg-muted"
                    )}
                  >
                    {message.content || (
                      <Loader2 className="size-3.5 animate-spin" />
                    )}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </div>

        <SheetFooter className="border-t border-border pt-4">
          <form onSubmit={handleSubmit} className="flex items-end gap-2">
            <Textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  void sendMessage(input);
                }
              }}
              placeholder="Ask the AI assistant..."
              rows={2}
              className="resize-none"
              disabled={isStreaming}
            />
            <Button
              type="submit"
              size="icon"
              disabled={isStreaming || !input.trim()}
              aria-label="Send message"
            >
              {isStreaming ? <Loader2 className="animate-spin" /> : <Send />}
            </Button>
          </form>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
