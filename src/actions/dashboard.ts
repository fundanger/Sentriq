"use server";

import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { dashboardLayouts, type DashboardWidgetLayout } from "@/db/schema";
import { normalizeDashboardLayout, DEFAULT_DASHBOARD_LAYOUT } from "@/components/dashboard/widget-registry";

export async function saveDashboardLayoutAction(layout: DashboardWidgetLayout[]) {
  const session = await auth();
  if (!session?.user?.id) {
    throw new Error("You must be signed in to save a dashboard layout.");
  }

  const normalized = normalizeDashboardLayout(layout);

  await db
    .insert(dashboardLayouts)
    .values({
      id: crypto.randomUUID(),
      userId: session.user.id,
      layoutJson: normalized,
      updatedAt: new Date(),
    })
    .onConflictDoUpdate({
      target: dashboardLayouts.userId,
      set: {
        layoutJson: normalized,
        updatedAt: new Date(),
      },
    });

  revalidatePath("/");
}

export async function resetDashboardLayoutAction() {
  const session = await auth();
  if (!session?.user?.id) {
    throw new Error("You must be signed in to reset the dashboard layout.");
  }

  await db
    .insert(dashboardLayouts)
    .values({
      id: crypto.randomUUID(),
      userId: session.user.id,
      layoutJson: DEFAULT_DASHBOARD_LAYOUT,
      updatedAt: new Date(),
    })
    .onConflictDoUpdate({
      target: dashboardLayouts.userId,
      set: {
        layoutJson: DEFAULT_DASHBOARD_LAYOUT,
        updatedAt: new Date(),
      },
    });

  revalidatePath("/");
}
