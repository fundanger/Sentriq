import type { ReactNode } from "react";
import { auth } from "@/lib/auth";
import { SettingsNav } from "@/components/settings/settings-nav";

export default async function SettingsLayout({ children }: { children: ReactNode }) {
  const session = await auth();
  const role = session?.user?.role ?? "viewer";

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="font-heading text-2xl font-semibold tracking-tight">
          Settings
        </h1>
        <p className="text-sm text-muted-foreground">
          Manage your AI provider, appearance, security, and platform
          configuration.
        </p>
      </div>

      <div className="flex flex-col gap-6 lg:flex-row">
        <SettingsNav role={role} />
        <div className="flex-1">{children}</div>
      </div>
    </div>
  );
}
