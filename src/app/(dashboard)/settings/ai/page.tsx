import { eq } from "drizzle-orm";
import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { llmProviderConfigs } from "@/db/schema";
import { isSuperAdmin } from "@/lib/permissions";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AiProviderForm } from "@/components/settings/ai-provider-form";
import { ProviderConfigActions } from "@/components/settings/provider-config-actions";
import { decrypt, maskApiKey } from "@/lib/crypto";
import { LLM_PROVIDERS } from "@/lib/constants";

const PROVIDER_LABELS: Record<string, string> = Object.fromEntries(
  LLM_PROVIDERS.map((p) => [p.value, p.label])
);

export default async function AiSettingsPage() {
  const session = await auth();

  if (!isSuperAdmin(session?.user?.role)) {
    redirect("/settings");
  }

  const configs = session?.user?.id
    ? await db.query.llmProviderConfigs.findMany({
        where: eq(llmProviderConfigs.userId, session.user.id),
        orderBy: (c, { desc }) => [desc(c.updatedAt)],
      })
    : [];

  const configsWithMaskedKeys = configs.map((config) => {
    let maskedKey = "********";
    try {
      maskedKey = maskApiKey(
        decrypt({
          ciphertext: config.encryptedApiKey,
          iv: config.apiKeyIv,
          authTag: config.apiKeyAuthTag,
        })
      );
    } catch {
      maskedKey = "(unable to decrypt)";
    }
    return { ...config, maskedKey };
  });

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Configured providers</CardTitle>
          <CardDescription>
            Sentriq uses the active provider for AI chat, rule generation,
            rule explanations, and RAG-based search.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {configsWithMaskedKeys.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No AI provider configured yet. Add one below to enable the AI
              assistant.
            </p>
          ) : (
            <div className="flex flex-col divide-y">
              {configsWithMaskedKeys.map((config) => (
                <div
                  key={config.id}
                  className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0"
                >
                  <div className="flex flex-col gap-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">
                        {PROVIDER_LABELS[config.provider] ?? config.provider}
                      </span>
                      {config.isActive && (
                        <Badge variant="secondary">Active</Badge>
                      )}
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {config.model} · {config.maskedKey}
                      {config.baseUrl ? ` · ${config.baseUrl}` : ""}
                    </span>
                  </div>
                  <ProviderConfigActions
                    configId={config.id}
                    isActive={config.isActive}
                  />
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <AiProviderForm />
    </div>
  );
}
