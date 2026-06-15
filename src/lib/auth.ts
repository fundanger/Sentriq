import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { DrizzleAdapter } from "@auth/drizzle-adapter";
import bcrypt from "bcryptjs";
import { db } from "@/db";
import { users, ssoConfigs } from "@/db/schema";
import { eq } from "drizzle-orm";
import { decrypt } from "@/lib/crypto";
import type { UserRole } from "@/lib/auth-types";
import type { OIDCConfig, Provider } from "@auth/core/providers";

interface SsoProfile {
  sub: string;
  email?: string;
  name?: string;
  [key: string]: unknown;
}

function resolveRoleFromGroups(
  config: { groupsClaim: string | null; groupRoleMappingJson: Record<string, UserRole> | null; defaultRole: UserRole },
  profile: SsoProfile
): UserRole {
  if (!config.groupsClaim || !config.groupRoleMappingJson) {
    return config.defaultRole;
  }

  const claimValue = profile[config.groupsClaim];
  const groups = Array.isArray(claimValue) ? claimValue.map(String) : [];

  for (const group of groups) {
    const mapped = config.groupRoleMappingJson[group];
    if (mapped) return mapped;
  }

  return config.defaultRole;
}

async function buildOidcProviders(): Promise<Provider[]> {
  const enabledConfigs = await db.query.ssoConfigs.findMany({
    where: eq(ssoConfigs.enabled, true),
  });

  const providers: Provider[] = [];

  for (const config of enabledConfigs) {
    if (config.providerType !== "oidc") continue;
    if (!config.issuerUrl || !config.clientId || !config.encryptedClientSecret || !config.clientSecretIv || !config.clientSecretAuthTag) {
      continue;
    }

    const clientSecret = decrypt({
      ciphertext: config.encryptedClientSecret,
      iv: config.clientSecretIv,
      authTag: config.clientSecretAuthTag,
    });

    const oidcConfig: OIDCConfig<SsoProfile> = {
      id: `sso-${config.id}`,
      name: config.displayName,
      type: "oidc",
      issuer: config.issuerUrl,
      clientId: config.clientId,
      clientSecret,
      checks: ["pkce", "state"],
      profile: (profile) => ({
        id: profile.sub,
        email: profile.email ?? null,
        name: profile.name ?? null,
        role: resolveRoleFromGroups(config, profile),
        mustChangePassword: false,
      }),
    };

    providers.push(oidcConfig as Provider);
  }

  return providers;
}

export const { handlers, signIn, signOut, auth } = NextAuth(async () => {
  const ssoProviders = await buildOidcProviders();

  return {
    adapter: DrizzleAdapter(db),
    session: { strategy: "jwt" },
    trustHost: true,
    pages: {
      signIn: "/login",
    },
    providers: [
      Credentials({
        credentials: {
          email: {},
          password: {},
        },
        authorize: async (credentials) => {
          const email = credentials?.email;
          const password = credentials?.password;
          if (typeof email !== "string" || typeof password !== "string") {
            return null;
          }

          const user = await db.query.users.findFirst({
            where: eq(users.email, email.toLowerCase()),
          });
          if (!user || !user.passwordHash) return null;

          const passwordMatches = await bcrypt.compare(password, user.passwordHash);
          if (!passwordMatches) return null;

          await db
            .update(users)
            .set({ lastLoginAt: new Date() })
            .where(eq(users.id, user.id));

          return {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            mustChangePassword: user.mustChangePassword,
          };
        },
      }),
      ...ssoProviders,
    ],
    callbacks: {
      signIn: async ({ user, account }) => {
        if (account?.provider?.startsWith("sso-") && user.id) {
          const ssoRole = (user as { role?: UserRole }).role;
          if (ssoRole) {
            await db
              .update(users)
              .set({ role: ssoRole, mustChangePassword: false, lastLoginAt: new Date() })
              .where(eq(users.id, user.id));
          }
        }

        return true;
      },
      jwt: async ({ token, user, account }) => {
        if (user) {
          if (account?.provider?.startsWith("sso-")) {
            const dbUser = await db.query.users.findFirst({ where: eq(users.id, user.id!) });
            token.role = dbUser?.role ?? "viewer";
            token.mustChangePassword = false;
          } else {
            token.role = user.role;
            token.mustChangePassword = user.mustChangePassword;
          }
        }
        return token;
      },
      session: async ({ session, token }) => {
        if (session.user) {
          session.user.id = token.sub as string;
          session.user.role = token.role as UserRole;
          session.user.mustChangePassword = token.mustChangePassword as boolean;
        }
        return session;
      },
    },
  };
});
