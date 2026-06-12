import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { getPlatformSettings } from "@/lib/platform-settings";
import { ChangePasswordForm } from "./change-password-form";

export default async function FirstRunPage() {
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
          <CardTitle>Set a new password</CardTitle>
          <CardDescription>
            You&apos;re signed in with the break-glass admin account. Choose
            a new password to continue.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <Alert>
            <AlertDescription>
              For security, the default break-glass password must be changed
              before you can access the platform. You&apos;ll be signed out
              and asked to log in again afterwards.
            </AlertDescription>
          </Alert>
          <ChangePasswordForm />
        </CardContent>
      </Card>
    </div>
  );
}
