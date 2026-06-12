import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { ThemePicker } from "@/components/settings/theme-picker";

export default function AppearanceSettingsPage() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Theme</CardTitle>
        <CardDescription>
          Choose how Sentriq looks. &quot;System&quot; follows your OS
          preference and updates automatically.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ThemePicker />
      </CardContent>
    </Card>
  );
}
