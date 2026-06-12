import { DETECTION_LANGUAGES } from "@/lib/constants";
import { LanguageCardLink } from "@/components/dashboard/language-card-link";
import type { DashboardData } from "@/lib/dashboard-data";

export function LanguageBreakdownWidget({ data }: { data: DashboardData }) {
  const countByLanguage = new Map(
    data.languageCounts.map((row) => [row.language, row.count])
  );

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-7">
      {DETECTION_LANGUAGES.map((lang) => (
        <LanguageCardLink
          key={lang.value}
          href={`/rules?language=${lang.value}`}
          count={countByLanguage.get(lang.value) ?? 0}
          label={lang.label}
        />
      ))}
    </div>
  );
}
