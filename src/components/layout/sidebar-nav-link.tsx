"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import { motion } from "motion/react";
import { SidebarMenuButton, SidebarMenuItem } from "@/components/ui/sidebar";

export function SidebarNavLink({
  href,
  isActive,
  tooltip,
  children,
}: {
  href: string;
  isActive: boolean;
  tooltip?: string;
  children: ReactNode;
}) {
  return (
    <SidebarMenuItem>
      <SidebarMenuButton
        isActive={isActive}
        tooltip={tooltip}
        className="relative data-active:bg-transparent"
        render={<Link href={href} />}
      >
        {isActive && (
          <motion.span
            layoutId="sidebar-active-indicator"
            className="absolute inset-0 rounded-md bg-sidebar-accent"
            transition={{ type: "spring", bounce: 0.2, duration: 0.4 }}
          />
        )}
        <span className="relative z-10 flex items-center gap-2">
          {children}
        </span>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}
