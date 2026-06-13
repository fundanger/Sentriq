import { cache } from "react";
import { db } from "@/db";
import { PLATFORM_DEFAULTS } from "@/lib/constants";

export interface PlatformSettings {
  siteName: string;
  accentColor: string;
  logoUrl: string | null;
}

/** Cached per-request: called from both root and dashboard layouts plus several pages. */
export const getPlatformSettings = cache(async (): Promise<PlatformSettings> => {
  const row = await db.query.platformSettings.findFirst({
    where: (s, { eq }) => eq(s.id, "default"),
  });

  return {
    siteName: row?.siteName ?? PLATFORM_DEFAULTS.siteName,
    accentColor: row?.accentColor ?? PLATFORM_DEFAULTS.accentColor,
    logoUrl: row?.logoUrl ?? PLATFORM_DEFAULTS.logoUrl,
  };
});
