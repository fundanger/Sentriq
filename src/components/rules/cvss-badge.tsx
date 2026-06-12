import { cn } from "@/lib/utils";

function cvssBand(score: number) {
  if (score >= 9) return { label: "Critical", className: "bg-red-500/15 text-red-400 border-red-500/30" };
  if (score >= 7) return { label: "High", className: "bg-orange-500/15 text-orange-400 border-orange-500/30" };
  if (score >= 4) return { label: "Medium", className: "bg-amber-500/15 text-amber-400 border-amber-500/30" };
  if (score > 0) return { label: "Low", className: "bg-blue-500/15 text-blue-400 border-blue-500/30" };
  return { label: "None", className: "bg-slate-500/15 text-slate-400 border-slate-500/30" };
}

export function CvssBadge({ score, version }: { score: number; version: string }) {
  const band = cvssBand(score);
  return (
    <div
      className={cn(
        "inline-flex items-center gap-2 rounded-lg border px-3 py-1.5",
        band.className
      )}
    >
      <span className="text-lg font-semibold tabular-nums">{score.toFixed(1)}</span>
      <div className="flex flex-col leading-tight">
        <span className="text-xs font-medium">{band.label}</span>
        <span className="text-[10px] text-muted-foreground">CVSS {version}</span>
      </div>
    </div>
  );
}
