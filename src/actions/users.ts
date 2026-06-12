"use server";

import { z } from "zod";
import bcrypt from "bcryptjs";
import { eq } from "drizzle-orm";
import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { users } from "@/db/schema";
import { isSuperAdmin } from "@/lib/permissions";
import type { UserRole } from "@/lib/auth-types";

const ROLE_VALUES = ["super_admin", "admin", "analyst", "viewer"] as const;

const createUserSchema = z.object({
  name: z.string().min(1, "Name is required.").max(100),
  email: z.string().email("Enter a valid email address."),
  role: z.enum(ROLE_VALUES),
  password: z.string().min(12, "Password must be at least 12 characters."),
});

export interface UserActionResult {
  error?: string;
  fieldErrors?: Record<string, string>;
  success?: string;
}

async function requireSuperAdmin() {
  const session = await auth();
  if (!isSuperAdmin(session?.user?.role)) {
    throw new Error("You must be a super admin to manage users.");
  }
  return session!;
}

export async function createUserAction(
  _prevState: UserActionResult | undefined,
  formData: FormData
): Promise<UserActionResult> {
  const session = await auth();
  if (!isSuperAdmin(session?.user?.role)) {
    return { error: "You must be a super admin to manage users." };
  }

  const parsed = createUserSchema.safeParse({
    name: formData.get("name")?.toString() ?? "",
    email: formData.get("email")?.toString() ?? "",
    role: formData.get("role")?.toString() ?? "",
    password: formData.get("password")?.toString() ?? "",
  });

  if (!parsed.success) {
    const fieldErrors: Record<string, string> = {};
    for (const issue of parsed.error.issues) {
      const key = issue.path[0];
      if (typeof key === "string" && !fieldErrors[key]) {
        fieldErrors[key] = issue.message;
      }
    }
    return { error: "Please fix the errors below.", fieldErrors };
  }

  const data = parsed.data;
  const existing = await db.query.users.findFirst({
    where: eq(users.email, data.email.toLowerCase()),
  });
  if (existing) {
    return {
      error: "Please fix the errors below.",
      fieldErrors: { email: "A user with this email already exists." },
    };
  }

  const passwordHash = await bcrypt.hash(data.password, 10);
  await db.insert(users).values({
    id: crypto.randomUUID(),
    email: data.email.toLowerCase(),
    name: data.name,
    passwordHash,
    role: data.role,
    isBreakGlass: false,
    mustChangePassword: true,
    createdAt: new Date(),
  });

  revalidatePath("/settings/users");
  return { success: "User created." };
}

export async function updateUserRoleAction(userId: string, role: UserRole) {
  const session = await requireSuperAdmin();

  if (userId === session.user.id) {
    throw new Error("You cannot change your own role.");
  }

  const target = await db.query.users.findFirst({ where: eq(users.id, userId) });
  if (target?.isBreakGlass) {
    throw new Error("The break-glass admin's role cannot be changed.");
  }

  await db.update(users).set({ role }).where(eq(users.id, userId));
  revalidatePath("/settings/users");
}

export async function deleteUserAction(userId: string) {
  const session = await requireSuperAdmin();

  if (userId === session.user.id) {
    throw new Error("You cannot remove your own account.");
  }

  const target = await db.query.users.findFirst({ where: eq(users.id, userId) });
  if (target?.isBreakGlass) {
    throw new Error("The break-glass admin account cannot be removed.");
  }

  await db.delete(users).where(eq(users.id, userId));
  revalidatePath("/settings/users");
}
