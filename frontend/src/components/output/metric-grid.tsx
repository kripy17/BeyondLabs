import { type ReactNode } from "react";
import { type LucideIcon } from "lucide-react";

export function MetricGrid({
  metrics,
  columns = 4,
}: {
  metrics: { label: string; value: ReactNode; tone?: "default" | "primary" | "success" | "warning" | "destructive" | "info" | "accent" | "muted"; icon?: LucideIcon }[];
  columns?: 2 | 3 | 4;
}) {
  const gridCls =
    columns === 2 ? "sm:grid-cols-2" :
    columns === 3 ? "sm:grid-cols-3" :
    "sm:grid-cols-2 md:grid-cols-4";
  return (
    <div className={"grid gap-2 " + gridCls}>
      {metrics.map((m, i) => {
        const toneCls =
          m.tone === "primary" ? "border-primary/30 text-primary" :
          m.tone === "success" ? "border-success/30 text-success" :
          m.tone === "warning" ? "border-warning/30 text-warning" :
          m.tone === "destructive" ? "border-destructive/30 text-destructive" :
          m.tone === "info" ? "border-info/30 text-info" :
          m.tone === "accent" ? "border-accent/30 text-accent" :
          m.tone === "muted" ? "border-divider-soft text-muted-foreground" :
          "border-divider-soft text-foreground";
        const Icon = m.icon;
        return (
          <div key={i} className={"group relative overflow-hidden rounded-md border bg-card/40 px-3 py-2.5 transition-all hover:-translate-y-[1px] hover:elevation-flat " + toneCls}>
            <span aria-hidden className="absolute inset-x-0 bottom-0 h-[2px] opacity-60 bg-current" />
            <div className="flex items-center justify-between gap-1.5">
              <span className="text-mono ba-text-3xs uppercase tracking-widest opacity-70">{m.label}</span>
              {Icon && <Icon className="h-3 w-3 opacity-60" />}
            </div>
            <div className="mt-1 text-mono text-lg font-semibold tabular-nums">{m.value}</div>
          </div>
        );
      })}
    </div>
  );
}
