import type { ReactNode } from "react";
import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { SidebarProvider, SidebarInset } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/layout/app-sidebar";
import { TopBar } from "@/components/layout/top-bar";
import { AiChatProvider } from "@/components/ai/chat-context";
import { AiChatDrawer } from "@/components/ai/ai-chat-drawer";
import { PageTransition } from "@/components/layout/page-transition";
import { KeyboardShortcuts } from "@/components/layout/keyboard-shortcuts";
import { getPlatformSettings } from "@/lib/platform-settings";

export default async function DashboardLayout({
  children,
}: {
  children: ReactNode;
}) {
  const session = await auth();
  if (!session?.user) {
    redirect("/login");
  }

  const [categories, platformSettings] = await Promise.all([
    db.query.categories.findMany({
      orderBy: (c, { asc }) => [asc(c.sortOrder)],
    }),
    getPlatformSettings(),
  ]);

  return (
    <AiChatProvider>
      <KeyboardShortcuts />
      <SidebarProvider>
        <AppSidebar categories={categories} platformSettings={platformSettings} />
        <SidebarInset>
          <TopBar session={session} />
          <PageTransition>{children}</PageTransition>
        </SidebarInset>
      </SidebarProvider>
      <AiChatDrawer />
    </AiChatProvider>
  );
}
