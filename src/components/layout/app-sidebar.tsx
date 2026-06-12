"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
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
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";
import { DETECTION_LANGUAGES } from "@/lib/constants";

interface Category {
  id: string;
  name: string;
  slug: string;
}

export function AppSidebar({ categories }: { categories: Category[] }) {
  const pathname = usePathname();

  return (
    <Sidebar>
      <SidebarHeader>
        <Link
          href="/"
          className="flex items-center gap-2.5 px-2 py-1.5 text-sm font-semibold"
        >
          <span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary/15 ring-1 ring-primary/30">
            <ShieldAlert className="size-4 text-primary" />
          </span>
          <span className="flex flex-col leading-none">
            <span className="font-heading text-base tracking-tight">
              Sentriq
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
              <SidebarMenuItem>
                <SidebarMenuButton
                  isActive={pathname === "/"}
                  render={<Link href="/" />}
                >
                  <LayoutDashboard />
                  <span>Dashboard</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton
                  isActive={pathname?.startsWith("/rules")}
                  render={<Link href="/rules" />}
                >
                  <Library />
                  <span>Rule Library</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarGroupLabel>Languages</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {DETECTION_LANGUAGES.map((lang) => (
                <SidebarMenuItem key={lang.value}>
                  <SidebarMenuButton
                    isActive={pathname === `/rules?language=${lang.value}`}
                    tooltip={lang.fullName}
                    render={<Link href={`/rules?language=${lang.value}`} />}
                  >
                    <ChevronRight className="size-3.5 opacity-50" />
                    <span>{lang.label}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarGroupLabel>Categories</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {categories.map((category) => (
                <SidebarMenuItem key={category.id}>
                  <SidebarMenuButton
                    isActive={pathname === `/rules?category=${category.slug}`}
                    tooltip={category.name}
                    render={<Link href={`/rules?category=${category.slug}`} />}
                  >
                    <ChevronRight className="size-3.5 opacity-50" />
                    <span>{category.name}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              isActive={pathname?.startsWith("/settings")}
              render={<Link href="/settings" />}
            >
              <Settings />
              <span>Settings</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  );
}
