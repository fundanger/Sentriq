import { redirect } from "next/navigation";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { auth } from "@/lib/auth";
import { isSuperAdmin } from "@/lib/permissions";
import { getPlatformSettings } from "@/lib/platform-settings";
import { BrandingForm } from "@/components/settings/branding-form";

export default async function BrandingSettingsPage() {
  const session = await auth();

  if (!isSuperAdmin(session?.user?.role)) {
    redirect("/settings");
  }

  const settings = await getPlatformSettings();

  return (
    <Card>
      <CardHeader>
        <CardTitle>Branding</CardTitle>
        <CardDescription>
          Customize the site name, accent color, and logo shown across this
          Sentriq instance.
        </CardDescription>
      </CardHeader>
      <CardContent className="max-w-md">
        <BrandingForm settings={settings} />
      </CardContent>
    </Card>
  );
}
