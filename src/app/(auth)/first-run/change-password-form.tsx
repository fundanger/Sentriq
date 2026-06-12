"use client";

import { useActionState } from "react";
import { signOut } from "next-auth/react";
import {
  changePasswordAction,
  type ChangePasswordResult,
} from "@/actions/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";

export function ChangePasswordForm() {
  const [state, formAction, isPending] = useActionState<
    ChangePasswordResult | undefined,
    FormData
  >(async (prevState, formData) => {
    const result = await changePasswordAction(prevState, formData);
    if (!result.error) {
      await signOut({ redirectTo: "/login" });
    }
    return result;
  }, undefined);

  return (
    <form action={formAction} className="flex flex-col gap-4">
      {state?.error && (
        <Alert variant="destructive">
          <AlertDescription>{state.error}</AlertDescription>
        </Alert>
      )}

      <div className="flex flex-col gap-2">
        <Label htmlFor="newPassword">New password</Label>
        <Input
          id="newPassword"
          name="newPassword"
          type="password"
          autoComplete="new-password"
          required
          minLength={12}
        />
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="confirmPassword">Confirm new password</Label>
        <Input
          id="confirmPassword"
          name="confirmPassword"
          type="password"
          autoComplete="new-password"
          required
          minLength={12}
        />
      </div>

      <Button type="submit" disabled={isPending} className="mt-2">
        {isPending ? "Updating..." : "Update password and sign out"}
      </Button>
    </form>
  );
}
