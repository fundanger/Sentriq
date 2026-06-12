import type { DefaultSession } from "next-auth";

export type UserRole = "super_admin" | "admin" | "analyst" | "viewer";

declare module "@auth/core/types" {
  interface User {
    role: UserRole;
    mustChangePassword: boolean;
  }

  interface Session {
    user: {
      id: string;
      role: UserRole;
      mustChangePassword: boolean;
    } & DefaultSession["user"];
  }
}

declare module "@auth/core/jwt" {
  interface JWT {
    role: UserRole;
    mustChangePassword: boolean;
  }
}
