"use client";

import { useEffect } from "react";
import { recordRecentlyViewedRule } from "@/lib/recently-viewed";
import type { DetectionLanguage, Severity } from "@/lib/constants";

export function TrackRecentlyViewed({
  slug,
  title,
  language,
  severity,
  categoryName,
}: {
  slug: string;
  title: string;
  language: DetectionLanguage;
  severity: Severity;
  categoryName?: string | null;
}) {
  useEffect(() => {
    recordRecentlyViewedRule({ slug, title, language, severity, categoryName });
  }, [slug, title, language, severity, categoryName]);

  return null;
}
