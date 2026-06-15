import NextAuth from "next-auth";
import type { UserRole } from "@/lib/auth-types";

/**
 * Edge/proxy-safe NextAuth config: no DB adapter or providers, since this is
 * only used to decode the JWT session cookie in `src/proxy.ts`. The full
 * config (with DrizzleAdapter, Credentials/SSO providers) lives in `auth.ts`.
 * A synchronous config object is required here — an async config factory
 * makes NextAuth's `auth` helper async, which breaks its use as a proxy
 * default export (it must return a function synchronously).
 */
export const { auth } = NextAuth({
  session: { strategy: "jwt" },
  trustHost: true,
  pages: {
    signIn: "/login",
  },
  providers: [],
  callbacks: {
    session: async ({ session, token }) => {
      if (session.user) {
        session.user.id = token.sub as string;
        session.user.role = token.role as UserRole;
        session.user.mustChangePassword = token.mustChangePassword as boolean;
      }
      return session;
    },
  },
});
