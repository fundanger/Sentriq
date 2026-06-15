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
import { INTEGRATION_PLATFORMS, type IntegrationPlatformId } from "@/lib/constants";
import { saveIntegrationAction } from "@/actions/integrations";
import { AlertCircle, CheckCircle2 } from "lucide-react";

export function IntegrationForm() {
  const [state, formAction, isPending] = useActionState(saveIntegrationAction, undefined);
  const [platform, setPlatform] = useState<IntegrationPlatformId>(INTEGRATION_PLATFORMS[0].value);

  const platformMeta = useMemo(
    () => INTEGRATION_PLATFORMS.find((p) => p.value === platform) ?? INTEGRATION_PLATFORMS[0],
    [platform]
  );

  const fieldErrors = state?.fieldErrors ?? {};

  return (
    <form action={formAction}>
      <Card>
        <CardHeader>
          <CardTitle>Connect a platform</CardTitle>
          <CardDescription>
            Connect a SIEM, EDR, or WAF to push detection rules directly from
            Sentriq. Credentials are encrypted at rest with AES-256-GCM and
            only decrypted server-side when deploying rules.
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
              <Label htmlFor="platform">Platform</Label>
              <Select
                name="platform"
                value={platform}
                onValueChange={(v) => v && setPlatform(v as IntegrationPlatformId)}
              >
                <SelectTrigger id="platform" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {INTEGRATION_PLATFORMS.map((p) => (
                    <SelectItem key={p.value} value={p.value}>
                      {p.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">{platformMeta.description}</p>
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="name">Connection name</Label>
              <Input
                id="name"
                name="name"
                placeholder={`e.g. Production ${platformMeta.label}`}
                aria-invalid={!!fieldErrors.name}
                required
              />
              {fieldErrors.name && (
                <p className="text-xs text-destructive">{fieldErrors.name}</p>
              )}
            </div>
          </div>

          <div key={platform} className="grid gap-4 sm:grid-cols-2">
            {platformMeta.fields.map((field) => (
              <div key={field.key} className="flex flex-col gap-1.5">
                <Label htmlFor={field.key}>{field.label}</Label>
                <Input
                  id={field.key}
                  name={field.key}
                  type={field.type === "password" ? "password" : "text"}
                  autoComplete="off"
                  placeholder={field.placeholder}
                  aria-invalid={!!fieldErrors[field.key]}
                  required={field.required}
                />
                {field.helpText && (
                  <p className="text-xs text-muted-foreground">{field.helpText}</p>
                )}
                {fieldErrors[field.key] && (
                  <p className="text-xs text-destructive">{fieldErrors[field.key]}</p>
                )}
              </div>
            ))}
          </div>
        </CardContent>
        <CardFooter>
          <Button type="submit" disabled={isPending}>
            {isPending ? "Connecting..." : "Connect"}
          </Button>
        </CardFooter>
      </Card>
    </form>
  );
}
