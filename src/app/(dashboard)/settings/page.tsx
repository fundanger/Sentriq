import { auth } from "@/lib/auth";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const ROLE_LABELS: Record<string, string> = {
  admin: "Administrator",
  analyst: "Analyst",
  viewer: "Viewer",
};

export default async function SettingsPage() {
  const session = await auth();
  const user = session?.user;

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Account</CardTitle>
          <CardDescription>
            Your Sentriq account details.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-2">
          <div className="flex flex-col gap-1">
            <span className="text-xs text-muted-foreground">Name</span>
            <span className="text-sm font-medium">{user?.name ?? "—"}</span>
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-xs text-muted-foreground">Email</span>
            <span className="text-sm font-medium">{user?.email ?? "—"}</span>
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-xs text-muted-foreground">Role</span>
            <div>
              <Badge variant="secondary" className="capitalize">
                {ROLE_LABELS[user?.role ?? ""] ?? user?.role ?? "—"}
              </Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>About Sentriq</CardTitle>
          <CardDescription>
            Enterprise-grade threat detection and prevention rule library.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          <p>
            Use the navigation to configure your AI provider, appearance
            preferences, security settings, user accounts, and SSO.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
