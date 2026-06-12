import { db } from "@/db";
import { PLATFORM_DEFAULTS } from "@/lib/constants";

export interface PlatformSettings {
  siteName: string;
  accentColor: string;
  logoUrl: string | null;
}

export async function getPlatformSettings(): Promise<PlatformSettings> {
  const row = await db.query.platformSettings.findFirst({
    where: (s, { eq }) => eq(s.id, "default"),
  });

  return {
    siteName: row?.siteName ?? PLATFORM_DEFAULTS.siteName,
    accentColor: row?.accentColor ?? PLATFORM_DEFAULTS.accentColor,
    logoUrl: row?.logoUrl ?? PLATFORM_DEFAULTS.logoUrl,
  };
}
