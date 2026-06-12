import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function SsoSettingsPage() {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <CardTitle>Single sign-on</CardTitle>
          <Badge variant="outline" className="text-muted-foreground">
            Not enabled
          </Badge>
        </div>
        <CardDescription>
          Connect an OIDC or SAML identity provider so your organization can
          sign in with existing corporate credentials.
        </CardDescription>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">
        <p>
          SSO configuration is not yet available in this release. When
          enabled, administrators will be able to register an OIDC or SAML
          provider here without affecting existing local accounts.
        </p>
      </CardContent>
    </Card>
  );
}
