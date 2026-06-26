import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export function MetricTile({
  label,
  value,
  delta,
  hint,
  icon: Icon,
  tone = "primary",
  spark,
}: {
  label: string;
  value: string;
  delta?: string;
  hint?: string;
  icon: LucideIcon;
  tone?: "primary" | "accent" | "warning" | "destructive" | "success" | "info";
  /** 0..1 values, drawn as a tiny sparkline */
  spark?: number[];
}) {
  const toneText = {
    primary: "text-primary",
    accent: "text-accent",
    warning: "text-warning",
    destructive: "text-destructive",
    success: "text-success",
    info: "text-info",
  }[tone];

  const positive = delta?.startsWith("+");
  const negative = delta?.startsWith("-");

  return (
    <div className="hover-lift group relative overflow-hidden rounded-lg border border-border bg-card/70 p-4">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/40 to-transparent opacity-0 transition-opacity group-hover:opacity-100" />
      <div className="flex items-start justify-between">
        <div>
          <div className="text-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
          <div className="mt-2 flex items-baseline gap-2">
            <div className={cn("text-mono text-3xl font-bold tracking-tight", toneText)}>{value}</div>
            {delta && (
              <span
                className={cn(
                  "text-mono text-[11px] font-semibold",
                  positive ? "text-success" : negative ? "text-destructive" : "text-muted-foreground",
                )}
              >
                {delta}
              </span>
            )}
          </div>
          {hint && <div className="mt-1 text-mono text-[10px] text-muted-foreground">{hint}</div>}
        </div>
        <div className={cn("grid h-9 w-9 place-items-center rounded-md border border-border bg-background/40", toneText)}>
          <Icon className="h-4 w-4" />
        </div>
      </div>
      {spark && spark.length > 1 && (
        <svg viewBox="0 0 100 24" preserveAspectRatio="none" className="mt-3 h-7 w-full">
          <polyline
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            className={toneText}
            points={spark
              .map((v, i) => `${(i / (spark.length - 1)) * 100},${24 - Math.max(0, Math.min(1, v)) * 22}`)
              .join(" ")}
          />
        </svg>
      )}
    </div>
  );
}
