import { redirect } from "next/navigation";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardAction,
} from "@/components/ui/card";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { isSuperAdmin } from "@/lib/permissions";
import { UsersTable } from "@/components/settings/users-table";
import { CreateUserDialog } from "@/components/settings/create-user-dialog";

export default async function UsersSettingsPage() {
  const session = await auth();

  if (!isSuperAdmin(session?.user?.role)) {
    redirect("/settings");
  }

  const allUsers = await db.query.users.findMany({
    orderBy: (u, { asc }) => [asc(u.createdAt)],
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>User management</CardTitle>
        <CardDescription>
          Manage accounts and roles for your organization. Super admins have
          full platform access, including AI provider credentials and
          branding.
        </CardDescription>
        <CardAction>
          <CreateUserDialog />
        </CardAction>
      </CardHeader>
      <CardContent>
        <UsersTable
          users={allUsers.map((u) => ({
            id: u.id,
            name: u.name,
            email: u.email,
            role: u.role,
            isBreakGlass: u.isBreakGlass,
            lastLoginAt: u.lastLoginAt,
          }))}
          currentUserId={session!.user!.id!}
        />
      </CardContent>
    </Card>
  );
}
