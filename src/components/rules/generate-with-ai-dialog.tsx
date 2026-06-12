"use client";

import { useState, useTransition } from "react";
import Link from "next/link";
import { Loader2, Sparkles, WandSparkles } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { DETECTION_LANGUAGES } from "@/lib/constants";
import { generateRuleDraftAction, type GenerateRuleDraftResult } from "@/actions/ai-rule-generation";

interface Category {
  id: string;
  name: string;
}

export function GenerateWithAiDialog({
  categories,
  onApply,
}: {
  categories: Category[];
  onApply: (result: GenerateRuleDraftResult) => void;
}) {
  const [open, setOpen] = useState(false);
  const [result, setResult] = useState<GenerateRuleDraftResult | undefined>(undefined);
  const [isPending, startTransition] = useTransition();

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    startTransition(async () => {
      const next = await generateRuleDraftAction(undefined, formData);
      setResult(next);
      if (next.draft) {
        onApply(next);
        setOpen(false);
      }
    });
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger
        render={
          <Button type="button" variant="outline">
            <WandSparkles />
            Generate with AI
          </Button>
        }
      />
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Sparkles className="size-4 text-primary" />
            Generate a rule draft
          </DialogTitle>
          <DialogDescription>
            Describe the threat behavior to detect. The AI will draft a title,
            description, rule body, severity, MITRE mappings, and tuning
            notes for you to review and edit.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {result?.needsProvider && (
            <Alert>
              <Sparkles />
              <AlertTitle>No AI provider configured</AlertTitle>
              <AlertDescription>
                Add an API key in{" "}
                <Link href="/settings/ai" className="underline">
                  Settings &gt; AI Provider
                </Link>{" "}
                to enable AI rule generation.
              </AlertDescription>
            </Alert>
          )}

          {result?.error && (
            <Alert variant="destructive">
              <AlertTitle>Generation failed</AlertTitle>
              <AlertDescription>{result.error}</AlertDescription>
            </Alert>
          )}

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="ai-description">Threat behavior</Label>
            <Textarea
              id="ai-description"
              name="description"
              rows={4}
              placeholder="e.g. Detect a single host authenticating to an unusually high number of distinct servers via SMB in a short time window, indicating lateral movement reconnaissance."
              required
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="ai-language">Language</Label>
              <Select name="language" defaultValue="kql">
                <SelectTrigger id="ai-language" className="w-full">
                  <SelectValue placeholder="Select a language" />
                </SelectTrigger>
                <SelectContent>
                  {DETECTION_LANGUAGES.map((lang) => (
                    <SelectItem key={lang.value} value={lang.value}>
                      {lang.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="ai-category">Category (optional)</Label>
              <Select name="categoryName">
                <SelectTrigger id="ai-category" className="w-full">
                  <SelectValue placeholder="Select a category" />
                </SelectTrigger>
                <SelectContent>
                  {categories.map((cat) => (
                    <SelectItem key={cat.id} value={cat.name}>
                      {cat.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <DialogFooter>
            <Button type="submit" disabled={isPending}>
              {isPending ? (
                <>
                  <Loader2 className="animate-spin" />
                  Generating...
                </>
              ) : (
                <>
                  <Sparkles />
                  Generate draft
                </>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
