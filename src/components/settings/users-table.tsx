"use client";

import { useState, useTransition } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { updateUserRoleAction, deleteUserAction } from "@/actions/users";
import type { UserRole } from "@/lib/auth-types";
import { Loader2, Trash2 } from "lucide-react";

const ROLE_OPTIONS: { value: UserRole; label: string }[] = [
  { value: "super_admin", label: "Super admin" },
  { value: "admin", label: "Admin" },
  { value: "analyst", label: "Analyst" },
  { value: "viewer", label: "Viewer" },
];

export interface UserRow {
  id: string;
  name: string | null;
  email: string;
  role: UserRole;
  isBreakGlass: boolean;
  lastLoginAt: Date | null;
}

export function UsersTable({
  users,
  currentUserId,
}: {
  users: UserRow[];
  currentUserId: string;
}) {
  return (
    <div className="flex flex-col divide-y">
      {users.map((user) => (
        <UserRowItem key={user.id} user={user} currentUserId={currentUserId} />
      ))}
    </div>
  );
}

function UserRowItem({
  user,
  currentUserId,
}: {
  user: UserRow;
  currentUserId: string;
}) {
  const [isUpdatingRole, startRoleUpdate] = useTransition();
  const [isDeleting, startDelete] = useTransition();
  const [confirmOpen, setConfirmOpen] = useState(false);

  const isSelf = user.id === currentUserId;
  const locked = user.isBreakGlass || isSelf;

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0">
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium">{user.name ?? "—"}</span>
          {user.isBreakGlass && <Badge variant="outline">Break-glass</Badge>}
          {isSelf && <Badge variant="secondary">You</Badge>}
        </div>
        <span className="text-xs text-muted-foreground">
          {user.email}
          {user.lastLoginAt
            ? ` · Last login ${user.lastLoginAt.toLocaleDateString()}`
            : " · Never logged in"}
        </span>
      </div>

      <div className="flex items-center gap-2">
        <Select
          value={user.role}
          disabled={locked || isUpdatingRole}
          onValueChange={(value) =>
            startRoleUpdate(() => updateUserRoleAction(user.id, value as UserRole))
          }
        >
          <SelectTrigger size="sm" className="w-36">
            {isUpdatingRole ? (
              <Loader2 className="size-3.5 animate-spin" />
            ) : (
              <SelectValue />
            )}
          </SelectTrigger>
          <SelectContent>
            {ROLE_OPTIONS.map((role) => (
              <SelectItem key={role.value} value={role.value}>
                {role.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            disabled={locked || isDeleting}
            onClick={() => setConfirmOpen(true)}
          >
            {isDeleting ? <Loader2 className="animate-spin" /> : <Trash2 />}
            Remove
          </Button>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Remove {user.name ?? user.email}?</DialogTitle>
              <DialogDescription>
                This permanently deletes the account. The user will no longer
                be able to sign in. This cannot be undone.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <DialogClose render={<Button type="button" variant="outline" />}>
                Cancel
              </DialogClose>
              <Button
                type="button"
                variant="destructive"
                disabled={isDeleting}
                onClick={() =>
                  startDelete(async () => {
                    await deleteUserAction(user.id);
                    setConfirmOpen(false);
                  })
                }
              >
                {isDeleting ? "Removing..." : "Remove"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </div>
  );
}
