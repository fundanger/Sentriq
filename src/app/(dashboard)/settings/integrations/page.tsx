import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { isSuperAdmin } from "@/lib/permissions";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { IntegrationForm } from "@/components/settings/integration-form";
import { IntegrationActions } from "@/components/settings/integration-actions";
import { INTEGRATION_PLATFORMS } from "@/lib/constants";

const PLATFORM_LABELS: Record<string, string> = Object.fromEntries(
  INTEGRATION_PLATFORMS.map((p) => [p.value, p.label])
);

export default async function IntegrationsSettingsPage() {
  const session = await auth();

  if (!isSuperAdmin(session?.user?.role)) {
    redirect("/settings");
  }

  const allIntegrations = await db.query.integrations.findMany({
    orderBy: (i, { desc }) => [desc(i.updatedAt)],
  });

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Platform integrations</CardTitle>
          <CardDescription>
            Connect SIEM, EDR, and WAF platforms to deploy detection rules
            from Sentriq directly to your environment, and to track which
            rules are currently deployed where.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {allIntegrations.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No platform integrations configured yet. Connect one below.
            </p>
          ) : (
            <div className="flex flex-col divide-y">
              {allIntegrations.map((integration) => (
                <div
                  key={integration.id}
                  className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0"
                >
                  <div className="flex flex-col gap-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{integration.name}</span>
                      <Badge variant="secondary">
                        {PLATFORM_LABELS[integration.platform] ?? integration.platform}
                      </Badge>
                      {!integration.isActive && (
                        <Badge variant="outline" className="text-muted-foreground">
                          Disabled
                        </Badge>
                      )}
                      {integration.lastTestResult && (
                        <Badge
                          variant="outline"
                          className={
                            integration.lastTestResult === "success"
                              ? "border-emerald-500/30 bg-emerald-500/15 text-emerald-400"
                              : "border-red-500/30 bg-red-500/15 text-red-400"
                          }
                        >
                          {integration.lastTestResult === "success"
                            ? "Connection OK"
                            : "Connection failed"}
                        </Badge>
                      )}
                    </div>
                    {integration.lastTestedAt && (
                      <span className="text-xs text-muted-foreground">
                        Last tested {integration.lastTestedAt.toLocaleString()}
                      </span>
                    )}
                  </div>
                  <IntegrationActions
                    integrationId={integration.id}
                    isActive={integration.isActive}
                  />
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <IntegrationForm />
    </div>
  );
}
