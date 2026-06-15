"use client";

import { useActionState } from "react";
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
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Alert, AlertTitle } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { saveSsoConfigAction } from "@/actions/sso";
import { AlertCircle, CheckCircle2 } from "lucide-react";

const ROLE_OPTIONS = [
  { value: "viewer", label: "Viewer" },
  { value: "analyst", label: "Analyst" },
  { value: "admin", label: "Admin" },
  { value: "super_admin", label: "Super admin" },
] as const;

export function SsoConfigForm() {
  const [state, formAction, isPending] = useActionState(saveSsoConfigAction, undefined);

  const fieldErrors = state?.fieldErrors ?? {};

  return (
    <form action={formAction}>
      <Card>
        <CardHeader>
          <CardTitle>Add an OIDC provider</CardTitle>
          <CardDescription>
            Register any standards-compliant OpenID Connect provider (Entra
            ID, Okta, Auth0, generic OIDC). Client secrets are encrypted at
            rest with AES-256-GCM. The callback URL to register with your
            identity provider is{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">
              /api/auth/callback/sso-&lt;id&gt;
            </code>{" "}
            (shown after saving).
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
              <Label htmlFor="displayName">Display name</Label>
              <Input
                id="displayName"
                name="displayName"
                placeholder="e.g. Corporate Entra ID"
                aria-invalid={!!fieldErrors.displayName}
                required
              />
              {fieldErrors.displayName && (
                <p className="text-xs text-destructive">{fieldErrors.displayName}</p>
              )}
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="issuerUrl">Issuer URL</Label>
              <Input
                id="issuerUrl"
                name="issuerUrl"
                type="url"
                placeholder="https://login.microsoftonline.com/{tenant}/v2.0"
                aria-invalid={!!fieldErrors.issuerUrl}
                required
              />
              {fieldErrors.issuerUrl && (
                <p className="text-xs text-destructive">{fieldErrors.issuerUrl}</p>
              )}
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="clientId">Client ID</Label>
              <Input
                id="clientId"
                name="clientId"
                aria-invalid={!!fieldErrors.clientId}
                required
              />
              {fieldErrors.clientId && (
                <p className="text-xs text-destructive">{fieldErrors.clientId}</p>
              )}
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="clientSecret">Client secret</Label>
              <Input
                id="clientSecret"
                name="clientSecret"
                type="password"
                autoComplete="off"
                aria-invalid={!!fieldErrors.clientSecret}
                required
              />
              {fieldErrors.clientSecret && (
                <p className="text-xs text-destructive">{fieldErrors.clientSecret}</p>
              )}
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="groupsClaim">Groups claim name (optional)</Label>
              <Input
                id="groupsClaim"
                name="groupsClaim"
                placeholder="e.g. groups"
              />
              <p className="text-xs text-muted-foreground">
                The claim in the ID token containing the user&apos;s IdP
                group memberships, used for role mapping below.
              </p>
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="defaultRole">Default role</Label>
              <Select name="defaultRole" defaultValue="viewer">
                <SelectTrigger id="defaultRole" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ROLE_OPTIONS.map((r) => (
                    <SelectItem key={r.value} value={r.value}>
                      {r.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Assigned to users whose groups don&apos;t match any mapping
                below.
              </p>
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="groupRoleMapping">Group &rarr; role mapping (optional)</Label>
            <Textarea
              id="groupRoleMapping"
              name="groupRoleMapping"
              rows={4}
              placeholder={"security-admins = super_admin\nsecurity-analysts = analyst\nsoc-readonly = viewer"}
              className="font-mono text-xs"
            />
            <p className="text-xs text-muted-foreground">
              One mapping per line, in the form{" "}
              <code className="rounded bg-muted px-1 py-0.5">group = role</code>.
              Roles: super_admin, admin, analyst, viewer. The first matching
              group wins.
            </p>
          </div>
        </CardContent>
        <CardFooter>
          <Button type="submit" disabled={isPending}>
            {isPending ? "Saving..." : "Add provider"}
          </Button>
        </CardFooter>
      </Card>
    </form>
  );
}
