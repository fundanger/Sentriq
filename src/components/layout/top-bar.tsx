import { Search, LogOut, UserRound, KeyRound } from "lucide-react";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Separator } from "@/components/ui/separator";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ThemeToggle } from "@/components/layout/theme-toggle";
import { AskAiButton } from "@/components/ai/ask-ai-button";
import { signOutAction } from "@/actions/auth";
import type { Session } from "next-auth";

function initialsFor(name: string | null | undefined, email: string) {
  if (name) {
    const parts = name.trim().split(/\s+/);
    if (parts.length === 1) return parts[0]!.slice(0, 2).toUpperCase();
    return (parts[0]![0] + parts[parts.length - 1]![0]).toUpperCase();
  }
  return email.slice(0, 2).toUpperCase();
}

export function TopBar({ session }: { session: Session }) {
  const user = session.user;
  const displayName = user?.name ?? user?.email ?? "User";
  const email = user?.email ?? "";

  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-border px-4">
      <SidebarTrigger />
      <Separator orientation="vertical" className="h-5" />

      <div className="relative flex-1 max-w-md">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search rules, MITRE techniques, CVEs..."
          className="pl-8"
        />
      </div>

      <div className="ml-auto flex items-center gap-2">
        <AskAiButton />
        <ThemeToggle />
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <Button variant="ghost" size="icon" className="rounded-full">
                <Avatar className="size-7">
                  <AvatarFallback className="text-xs">
                    {initialsFor(user?.name, email)}
                  </AvatarFallback>
                </Avatar>
              </Button>
            }
          />
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuGroup>
              <DropdownMenuLabel className="flex flex-col gap-0.5">
                <span className="text-sm font-medium">{displayName}</span>
                <span className="text-xs text-muted-foreground">{email}</span>
                {user?.role && (
                  <span className="mt-1 text-xs uppercase tracking-wide text-muted-foreground">
                    {user.role}
                  </span>
                )}
              </DropdownMenuLabel>
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuItem render={<a href="/settings/security" />}>
              <KeyRound />
              Security
            </DropdownMenuItem>
            <DropdownMenuItem render={<a href="/settings" />}>
              <UserRound />
              Settings
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <form action={signOutAction}>
              <DropdownMenuItem
                variant="destructive"
                render={<button type="submit" className="w-full" />}
              >
                <LogOut />
                Sign out
              </DropdownMenuItem>
            </form>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
