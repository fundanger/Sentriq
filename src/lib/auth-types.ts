import type { DefaultSession } from "next-auth";

declare module "@auth/core/types" {
  interface User {
    role: "admin" | "analyst" | "viewer";
    mustChangePassword: boolean;
  }

  interface Session {
    user: {
      id: string;
      role: "admin" | "analyst" | "viewer";
      mustChangePassword: boolean;
    } & DefaultSession["user"];
  }
}

declare module "@auth/core/jwt" {
  interface JWT {
    role: "admin" | "analyst" | "viewer";
    mustChangePassword: boolean;
  }
}
