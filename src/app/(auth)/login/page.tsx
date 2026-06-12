import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { getPlatformSettings } from "@/lib/platform-settings";
import { LoginForm } from "./login-form";

export default async function LoginPage() {
  const settings = await getPlatformSettings();

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col items-center gap-2 text-center">
        <span className="font-heading text-2xl font-semibold tracking-tight">
          {settings.siteName}
        </span>
        <p className="text-sm text-muted-foreground">
          Threat detection &amp; prevention rule library
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Sign in</CardTitle>
          <CardDescription>
            Enter your credentials to access the platform.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <LoginForm />
        </CardContent>
      </Card>

      <p className="text-center text-xs text-muted-foreground">
        First time here? Sign in with the break-glass admin account:{" "}
        <span className="font-mono">admin@sentriq.local</span> /{" "}
        <span className="font-mono">password</span>
      </p>
    </div>
  );
}
