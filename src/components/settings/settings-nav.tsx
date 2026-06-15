"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import type { UserRole } from "@/lib/auth-types";

const NAV_ITEMS = [
  { href: "/settings", label: "General", superAdminOnly: false },
  { href: "/settings/ai", label: "AI Provider", superAdminOnly: true },
  { href: "/settings/appearance", label: "Appearance", superAdminOnly: false },
  { href: "/settings/branding", label: "Branding", superAdminOnly: true },
  { href: "/settings/security", label: "Security", superAdminOnly: false },
  { href: "/settings/users", label: "Users", superAdminOnly: true },
  { href: "/settings/integrations", label: "Integrations", superAdminOnly: true },
  { href: "/settings/sso", label: "SSO", superAdminOnly: true },
] as const;

export function SettingsNav({ role }: { role: UserRole }) {
  const pathname = usePathname();
  const items = NAV_ITEMS.filter((item) => !item.superAdminOnly || role === "super_admin");

  return (
    <nav className="flex shrink-0 gap-1 overflow-x-auto lg:w-48 lg:flex-col lg:overflow-visible">
      {items.map((item) => {
        const isActive =
          item.href === "/settings"
            ? pathname === "/settings"
            : pathname?.startsWith(item.href);

        return (
          <Link
            key={item.href}
            href={item.href}
            className={cn(
              "rounded-md px-3 py-1.5 text-sm font-medium whitespace-nowrap transition-colors",
              isActive
                ? "bg-muted text-foreground"
                : "text-muted-foreground hover:bg-muted/50 hover:text-foreground"
            )}
          >
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
