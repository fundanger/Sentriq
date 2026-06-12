import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { ChangePasswordForm } from "@/app/(auth)/first-run/change-password-form";

export default function SecuritySettingsPage() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Password</CardTitle>
        <CardDescription>
          Update your account password. You&apos;ll be signed out after
          changing it.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="max-w-sm">
          <ChangePasswordForm />
        </div>
      </CardContent>
    </Card>
  );
}
