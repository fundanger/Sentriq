import type { ReactNode } from "react";
import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { SidebarProvider, SidebarInset } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/layout/app-sidebar";
import { TopBar } from "@/components/layout/top-bar";
import { AiChatProvider } from "@/components/ai/chat-context";
import { AiChatDrawer } from "@/components/ai/ai-chat-drawer";

export default async function DashboardLayout({
  children,
}: {
  children: ReactNode;
}) {
  const session = await auth();
  if (!session?.user) {
    redirect("/login");
  }

  const categories = await db.query.categories.findMany({
    orderBy: (c, { asc }) => [asc(c.sortOrder)],
  });

  return (
    <AiChatProvider>
      <SidebarProvider>
        <AppSidebar categories={categories} />
        <SidebarInset>
          <TopBar session={session} />
          <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">{children}</div>
        </SidebarInset>
      </SidebarProvider>
      <AiChatDrawer />
    </AiChatProvider>
  );
}
