"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import {
  ShieldAlert,
  LayoutDashboard,
  Library,
  Settings,
  ChevronRight,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
} from "@/components/ui/sidebar";
import { DETECTION_LANGUAGES } from "@/lib/constants";
import type { PlatformSettings } from "@/lib/platform-settings";
import { SidebarNavLink } from "@/components/layout/sidebar-nav-link";
import { SidebarFilterLink } from "@/components/layout/sidebar-filter-link";

interface Category {
  id: string;
  name: string;
  slug: string;
}

export function AppSidebar({
  categories,
  platformSettings,
}: {
  categories: Category[];
  platformSettings: PlatformSettings;
}) {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const activeLanguage = pathname === "/rules" ? searchParams.get("language") : null;
  const activeCategory = pathname === "/rules" ? searchParams.get("category") : null;

  return (
    <Sidebar>
      <SidebarHeader>
        <Link
          href="/"
          className="flex items-center gap-2.5 px-2 py-1.5 text-sm font-semibold"
        >
          {platformSettings.logoUrl ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img
              src={platformSettings.logoUrl}
              alt={platformSettings.siteName}
              className="size-7 shrink-0 rounded-md object-contain"
            />
          ) : (
            <span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary/15 ring-1 ring-primary/30">
              <ShieldAlert className="size-4 text-primary" />
            </span>
          )}
          <span className="flex flex-col leading-none">
            <span className="font-heading text-base tracking-tight">
              {platformSettings.siteName}
            </span>
            <span className="text-[10px] font-medium uppercase tracking-widest text-muted-foreground">
              Detection Platform
            </span>
          </span>
        </Link>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              <SidebarNavLink href="/" isActive={pathname === "/"}>
                <LayoutDashboard />
                <span>Dashboard</span>
              </SidebarNavLink>
              <SidebarNavLink
                href="/rules"
                isActive={!!pathname?.startsWith("/rules")}
              >
                <Library />
                <span>Rule Library</span>
              </SidebarNavLink>
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarGroupLabel>Languages</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {DETECTION_LANGUAGES.filter((lang) => lang.kind === "language").map((lang) => (
                <SidebarFilterLink
                  key={lang.value}
                  href={`/rules?language=${lang.value}`}
                  isActive={activeLanguage === lang.value}
                  tooltip={lang.fullName}
                >
                  <ChevronRight className="size-3.5 opacity-50" />
                  <span>{lang.label}</span>
                </SidebarFilterLink>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarGroupLabel>Platforms</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {DETECTION_LANGUAGES.filter((lang) => lang.kind === "platform").map((lang) => (
                <SidebarFilterLink
                  key={lang.value}
                  href={`/rules?language=${lang.value}`}
                  isActive={activeLanguage === lang.value}
                  tooltip={lang.fullName}
                >
                  <ChevronRight className="size-3.5 opacity-50" />
                  <span>{lang.label}</span>
                </SidebarFilterLink>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarGroupLabel>Categories</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {categories.map((category) => (
                <SidebarFilterLink
                  key={category.id}
                  href={`/rules?category=${category.slug}`}
                  isActive={activeCategory === category.slug}
                  tooltip={category.name}
                >
                  <ChevronRight className="size-3.5 opacity-50" />
                  <span>{category.name}</span>
                </SidebarFilterLink>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter>
        <SidebarMenu>
          <SidebarNavLink
            href="/settings"
            isActive={!!pathname?.startsWith("/settings")}
          >
            <Settings />
            <span>Settings</span>
          </SidebarNavLink>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  );
}
