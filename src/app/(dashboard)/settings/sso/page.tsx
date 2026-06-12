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
import { isSuperAdmin } from "@/lib/permissions";
import { KeyRound, ShieldCheck, Building2 } from "lucide-react";

const PROVIDERS = [
  {
    id: "entra",
    name: "Microsoft Entra ID",
    description: "Sign in with Azure AD / Entra ID via OIDC.",
    icon: Building2,
  },
  {
    id: "okta",
    name: "Okta",
    description: "Sign in with your organization's Okta tenant via OIDC.",
    icon: ShieldCheck,
  },
  {
    id: "generic",
    name: "Generic OIDC / SAML",
    description: "Connect any standards-compliant OIDC or SAML 2.0 provider.",
    icon: KeyRound,
  },
] as const;

export default async function SsoSettingsPage() {
  const session = await auth();

  if (!isSuperAdmin(session?.user?.role)) {
    redirect("/settings");
  }

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <CardTitle>Single sign-on</CardTitle>
            <Badge variant="outline" className="text-muted-foreground">
              Not enabled
            </Badge>
          </div>
          <CardDescription>
            Connect an identity provider so your organization can sign in
            with existing corporate credentials. Local accounts continue to
            work alongside SSO once configured.
          </CardDescription>
        </CardHeader>
      </Card>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {PROVIDERS.map((provider) => (
          <Card key={provider.id} className="opacity-60">
            <CardHeader>
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <provider.icon className="size-4 text-muted-foreground" />
                  <CardTitle className="text-sm">{provider.name}</CardTitle>
                </div>
                <Badge variant="outline" className="text-muted-foreground">
                  Coming soon
                </Badge>
              </div>
              <CardDescription className="text-xs">
                {provider.description}
              </CardDescription>
            </CardHeader>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">What to expect</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          <p>
            SSO configuration is not yet available in this release. When
            enabled, super admins will be able to register an OIDC or SAML
            provider here, map identity provider groups to Sentriq roles,
            and enforce SSO-only sign-in for the organization — without
            affecting existing local accounts.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
