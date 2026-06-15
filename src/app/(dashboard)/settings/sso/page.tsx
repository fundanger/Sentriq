import { redirect } from "next/navigation";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { isSuperAdmin } from "@/lib/permissions";
import { SsoConfigForm } from "@/components/settings/sso-config-form";
import { SsoActions } from "@/components/settings/sso-actions";

const ROLE_LABELS: Record<string, string> = {
  super_admin: "Super admin",
  admin: "Admin",
  analyst: "Analyst",
  viewer: "Viewer",
};

export default async function SsoSettingsPage() {
  const session = await auth();

  if (!isSuperAdmin(session?.user?.role)) {
    redirect("/settings");
  }

  const configs = await db.query.ssoConfigs.findMany({
    orderBy: (c, { desc }) => [desc(c.updatedAt)],
  });

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Single sign-on</CardTitle>
          <CardDescription>
            Connect an OpenID Connect identity provider so your organization
            can sign in with existing corporate credentials. Local accounts
            continue to work alongside SSO. New providers are added disabled
            so you can verify the callback URL with your identity provider
            before enabling sign-in.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {configs.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No SSO providers configured yet. Add one below.
            </p>
          ) : (
            <div className="flex flex-col divide-y">
              {configs.map((config) => (
                <div
                  key={config.id}
                  className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0"
                >
                  <div className="flex flex-col gap-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{config.displayName}</span>
                      <Badge variant="secondary">OIDC</Badge>
                      <Badge
                        variant="outline"
                        className={
                          config.enabled
                            ? "border-emerald-500/30 bg-emerald-500/15 text-emerald-400"
                            : "text-muted-foreground"
                        }
                      >
                        {config.enabled ? "Enabled" : "Disabled"}
                      </Badge>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      Issuer: <span className="font-mono">{config.issuerUrl}</span>
                    </span>
                    <span className="text-xs text-muted-foreground">
                      Callback URL:{" "}
                      <span className="font-mono">
                        /api/auth/callback/sso-{config.id}
                      </span>
                    </span>
                    <span className="text-xs text-muted-foreground">
                      Default role: {ROLE_LABELS[config.defaultRole] ?? config.defaultRole}
                      {config.groupsClaim && (
                        <>
                          {" "}&middot; Groups claim:{" "}
                          <span className="font-mono">{config.groupsClaim}</span>
                        </>
                      )}
                    </span>
                  </div>
                  <SsoActions configId={config.id} enabled={config.enabled} />
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <SsoConfigForm />
    </div>
  );
}
