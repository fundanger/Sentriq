"use client";

import { useActionState, useMemo, useState } from "react";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Alert, AlertTitle } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { LLM_PROVIDERS, type LlmProviderId } from "@/lib/constants";
import { saveLlmProviderConfigAction } from "@/actions/ai-settings";
import { AlertCircle, CheckCircle2 } from "lucide-react";

const PROVIDER_LABELS: Record<string, string> = Object.fromEntries(
  LLM_PROVIDERS.map((p) => [p.value, p.label])
);

export function AiProviderForm() {
  const [state, formAction, isPending] = useActionState(
    saveLlmProviderConfigAction,
    undefined
  );
  const [provider, setProvider] = useState<LlmProviderId>(LLM_PROVIDERS[0].value);

  const providerMeta = useMemo(
    () => LLM_PROVIDERS.find((p) => p.value === provider) ?? LLM_PROVIDERS[0],
    [provider]
  );

  const fieldErrors = state?.fieldErrors ?? {};

  return (
    <form action={formAction}>
      <Card>
        <CardHeader>
          <CardTitle>Add a provider</CardTitle>
          <CardDescription>
            Bring your own API key. Keys are encrypted at rest with
            AES-256-GCM and only decrypted server-side when calling the
            provider.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {state?.error && (
            <Alert variant="destructive">
              <AlertCircle />
              <AlertTitle>{state.error}</AlertTitle>
            </Alert>
          )}
          {state?.success && (
            <Alert>
              <CheckCircle2 />
              <AlertTitle>{state.success}</AlertTitle>
            </Alert>
          )}

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="provider">Provider</Label>
              <Select
                name="provider"
                value={provider}
                onValueChange={(v) => v && setProvider(v as LlmProviderId)}
              >
                <SelectTrigger id="provider" className="w-full">
                  <SelectValue>
                    {(value: string) => PROVIDER_LABELS[value] ?? value}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {LLM_PROVIDERS.map((p) => (
                    <SelectItem key={p.value} value={p.value}>
                      {p.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {providerMeta.description}
              </p>
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="model">Model</Label>
              {providerMeta.models.length > 0 ? (
                <Select key={provider} name="model" defaultValue={providerMeta.defaultModel}>
                  <SelectTrigger id="model" className="w-full" aria-invalid={!!fieldErrors.model}>
                    <SelectValue placeholder="Select a model" />
                  </SelectTrigger>
                  <SelectContent>
                    {providerMeta.models.map((m) => (
                      <SelectItem key={m} value={m}>
                        {m}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <Input
                  id="model"
                  name="model"
                  placeholder="e.g. llama-3.1-70b-instruct"
                  aria-invalid={!!fieldErrors.model}
                  required
                />
              )}
              {fieldErrors.model && (
                <p className="text-xs text-destructive">{fieldErrors.model}</p>
              )}
            </div>
          </div>

          {providerMeta.requiresBaseUrl && (
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="baseUrl">Base URL</Label>
              <Input
                id="baseUrl"
                name="baseUrl"
                placeholder="e.g. http://localhost:11434/v1"
                aria-invalid={!!fieldErrors.baseUrl}
                required
              />
              {fieldErrors.baseUrl && (
                <p className="text-xs text-destructive">{fieldErrors.baseUrl}</p>
              )}
            </div>
          )}

          {providerMeta.supportsEmbeddings &&
            "embeddingModels" in providerMeta &&
            providerMeta.embeddingModels && (
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="embeddingModel">Embedding model (optional)</Label>
                <Select
                  key={provider}
                  name="embeddingModel"
                  defaultValue={providerMeta.defaultEmbeddingModel}
                >
                  <SelectTrigger id="embeddingModel" className="w-full sm:w-1/2">
                    <SelectValue placeholder="Select an embedding model" />
                  </SelectTrigger>
                  <SelectContent>
                    {providerMeta.embeddingModels.map((m) => (
                      <SelectItem key={m} value={m}>
                        {m}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  Used for RAG-based natural-language search across the rule
                  library.
                </p>
              </div>
            )}

          {providerMeta.supportsEmbeddings &&
            providerMeta.value === "openai_compatible" && (
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="embeddingModel">Embedding model (optional)</Label>
                <Input
                  id="embeddingModel"
                  name="embeddingModel"
                  placeholder="e.g. nomic-embed-text"
                />
                <p className="text-xs text-muted-foreground">
                  Used for RAG-based natural-language search across the rule
                  library.
                </p>
              </div>
            )}

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="apiKey">API key</Label>
            <Input
              id="apiKey"
              name="apiKey"
              type="password"
              autoComplete="off"
              placeholder="sk-..."
              aria-invalid={!!fieldErrors.apiKey}
              required
            />
            {fieldErrors.apiKey && (
              <p className="text-xs text-destructive">{fieldErrors.apiKey}</p>
            )}
          </div>
        </CardContent>
        <CardFooter>
          <Button type="submit" disabled={isPending}>
            {isPending ? "Saving..." : "Save & activate"}
          </Button>
        </CardFooter>
      </Card>
    </form>
  );
}
