import type { UserRole } from "@/lib/auth-types";

/**
 * Role hierarchy for Sentriq:
 * - `super_admin`: platform owner. Only role with access to AI provider
 *   credentials, user management, SSO, and branding/whitelabel settings.
 * - `admin`: full rule/category/tag management, no platform-credential access.
 * - `analyst`: create/edit rules, use AI chat and generation.
 * - `viewer`: read-only browse + AI chat ("regular visitor" ceiling on public deployments).
 */

export function isSuperAdmin(role: UserRole | undefined): boolean {
  return role === "super_admin";
}

export function canManageRules(role: UserRole | undefined): boolean {
  return role === "super_admin" || role === "admin" || role === "analyst";
}

/** Settings pages that require super_admin: AI provider credentials, user management, SSO, branding. */
export function canAccessPlatformSettings(role: UserRole | undefined): boolean {
  return role === "super_admin";
}
