"use client";

import { useActionState, useTransition } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  saveBrandingAction,
  resetBrandingAction,
  type BrandingResult,
} from "@/actions/platform-settings";
import { PLATFORM_DEFAULTS } from "@/lib/constants";
import type { PlatformSettings } from "@/lib/platform-settings";
import { Loader2 } from "lucide-react";

export function BrandingForm({ settings }: { settings: PlatformSettings }) {
  const [state, formAction, isPending] = useActionState<
    BrandingResult | undefined,
    FormData
  >(saveBrandingAction, undefined);
  const [isResetting, startReset] = useTransition();

  return (
    <form action={formAction} className="flex flex-col gap-4">
      {state?.error && (
        <Alert variant="destructive">
          <AlertDescription>{state.error}</AlertDescription>
        </Alert>
      )}
      {state?.success && (
        <Alert>
          <AlertDescription>{state.success}</AlertDescription>
        </Alert>
      )}

      <div className="flex flex-col gap-2">
        <Label htmlFor="siteName">Site name</Label>
        <Input
          id="siteName"
          name="siteName"
          defaultValue={
            settings.siteName === PLATFORM_DEFAULTS.siteName ? "" : settings.siteName
          }
          placeholder={PLATFORM_DEFAULTS.siteName}
          maxLength={60}
        />
        <p className="text-xs text-muted-foreground">
          Replaces &quot;Sentriq&quot; in the sidebar, page titles, and emails.
        </p>
        {state?.fieldErrors?.siteName && (
          <p className="text-xs text-destructive">{state.fieldErrors.siteName}</p>
        )}
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="accentColor">Accent color</Label>
        <div className="flex items-center gap-2">
          <Input
            id="accentColor"
            name="accentColor"
            type="text"
            defaultValue={
              settings.accentColor === PLATFORM_DEFAULTS.accentColor
                ? ""
                : settings.accentColor
            }
            placeholder={PLATFORM_DEFAULTS.accentColor}
            className="max-w-40"
          />
          <span
            className="size-8 shrink-0 rounded-md border border-border"
            style={{ backgroundColor: settings.accentColor }}
          />
        </div>
        <p className="text-xs text-muted-foreground">
          Hex color used for the primary accent across the UI.
        </p>
        {state?.fieldErrors?.accentColor && (
          <p className="text-xs text-destructive">{state.fieldErrors.accentColor}</p>
        )}
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="logoUrl">Logo URL</Label>
        <Input
          id="logoUrl"
          name="logoUrl"
          type="url"
          defaultValue={settings.logoUrl ?? ""}
          placeholder="https://example.com/logo.svg"
        />
        <p className="text-xs text-muted-foreground">
          Optional. Replaces the built-in wordmark in the sidebar.
        </p>
        {state?.fieldErrors?.logoUrl && (
          <p className="text-xs text-destructive">{state.fieldErrors.logoUrl}</p>
        )}
      </div>

      <div className="flex gap-2">
        <Button type="submit" disabled={isPending}>
          {isPending ? "Saving..." : "Save branding"}
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={isResetting}
          onClick={() => startReset(() => resetBrandingAction())}
        >
          {isResetting && <Loader2 className="animate-spin" />}
          Reset to defaults
        </Button>
      </div>
    </form>
  );
}
