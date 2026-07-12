import { type ReactNode } from "react";
import { Panel, Chip } from "@/components/soc";

const TONE_STYLES = {
  destructive: {
    panel: "bg-gradient-to-br from-destructive/[0.18] via-destructive/[0.06] to-card/30 border-destructive/30",
    accent: "bg-destructive shadow-[0_0_12px_hsl(var(--destructive)/0.5)]",
    badge: "destructive" as const,
    dots: "opacity-[0.08] [background-image:radial-gradient(hsl(var(--destructive))_1px,transparent_1px)]",
    title: "text-destructive",
    pulse: true,
  },
  warning: {
    panel: "bg-gradient-to-br from-warning/[0.15] via-warning/[0.05] to-card/30 border-warning/30",
    accent: "bg-warning shadow-[0_0_12px_hsl(var(--warning)/0.4)]",
    badge: "warning" as const,
    dots: "opacity-[0.08] [background-image:radial-gradient(hsl(var(--warning))_1px,transparent_1px)]",
    title: "text-warning",
    pulse: false,
  },
  success: {
    panel: "bg-gradient-to-br from-success/[0.12] via-success/[0.04] to-card/30 border-success/30",
    accent: "bg-success shadow-[0_0_12px_hsl(var(--success)/0.4)]",
    badge: "success" as const,
    dots: "opacity-[0.08] [background-image:radial-gradient(hsl(var(--success))_1px,transparent_1px)]",
    title: "text-success",
    pulse: false,
  },
  default: {
    panel: "bg-gradient-to-br from-card/85 via-card/55 to-card/30",
    accent: "bg-gradient-to-b from-primary/80 via-primary/40 to-transparent",
    badge: "primary" as const,
    dots: "opacity-[0.04] [background-image:radial-gradient(hsl(var(--primary))_1px,transparent_1px)]",
    title: "text-foreground",
    pulse: false,
  },
};

export function ResultBanner({
  badge,
  caseId,
  title,
  subtitle,
  reasons,
  metrics,
  sticky,
  tone = "default",
}: {
  badge: string;
  caseId?: string;
  title: string;
  subtitle?: string;
  reasons?: string[];
  metrics?: { label: string; value: ReactNode; tone?: "primary" | "warning" | "destructive" | "success" | "default" }[];
  sticky?: boolean;
  tone?: "destructive" | "warning" | "success" | "default";
}) {
  const s = TONE_STYLES[tone];
  return (
    <Panel sticky={sticky} className={`relative overflow-hidden ${s.panel}`}>
      {tone !== "default" && (
        <span aria-hidden className={`pointer-events-none absolute -right-8 -top-8 h-24 w-24 rounded-full blur-3xl ${tone === "destructive" ? "bg-destructive/20" : tone === "warning" ? "bg-warning/15" : "bg-success/15"}`} />
      )}
      <span aria-hidden className={`pointer-events-none absolute inset-y-0 left-0 w-[4px] ${s.accent} ${s.pulse ? "animate-pulse" : ""}`} />
      <span aria-hidden className={`pointer-events-none absolute inset-0 ${s.dots} [background-size:14px_14px]`} />
      <div className="relative grid gap-4 grid-cols-[1.4fr_1fr]">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Chip tone={s.badge}>{badge}</Chip>
            {caseId && (
              <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">
                id: <span className="text-foreground/85">{caseId}</span>
              </span>
            )}
          </div>
          <h2 className={`font-display mt-2 ${tone === "default" ? "text-2xl font-semibold" : "text-4xl font-black tracking-tight leading-[1.1]"} ${s.title}`}>{title}</h2>
          {subtitle && <p className="mt-1 ba-text-sm text-muted-foreground">{subtitle}</p>}
          {reasons && reasons.length > 0 && (
            <ul className="mt-3 space-y-1">
              {reasons.slice(0, 4).map((r, i) => (
                <li key={i} className="text-mono ba-text-sm text-foreground/80">
                  <span className="mr-2 text-primary">›</span>
                  {r}
                </li>
              ))}
            </ul>
          )}
        </div>
        {metrics && metrics.length > 0 && (
          <div className="grid grid-cols-2 gap-2 grid-cols-4">
            {metrics.map((m, i) => (
              <div
                key={i}
                className={
                  "group/m relative overflow-hidden rounded-md border bg-background/50 px-3 py-2 transition-all hover:-translate-y-[1px] " +
                  (m.tone === "primary" ? "border-primary/40 hover:border-primary/70" :
                   m.tone === "warning" ? "border-warning/40 hover:border-warning/70" :
                   m.tone === "destructive" ? "border-destructive/40 hover:border-destructive/70" :
                   m.tone === "success" ? "border-success/40 hover:border-success/70" :
                   "border-border hover:border-primary/40")
                }
              >
                <span aria-hidden className={"absolute inset-x-0 bottom-0 h-[2px] opacity-60 " +
                  (m.tone === "primary" ? "bg-primary" :
                   m.tone === "warning" ? "bg-warning" :
                   m.tone === "destructive" ? "bg-destructive" :
                   m.tone === "success" ? "bg-success" : "bg-border")} />
                <div className="text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground">{m.label}</div>
                <div
                  className={
                    "mt-0.5 tabular-nums " +
                    (tone !== "default" ? "font-display text-xl font-bold " : "text-mono text-xl font-semibold ") +
                    (m.tone === "primary" ? "text-primary" :
                     m.tone === "warning" ? "text-warning" :
                     m.tone === "destructive" ? "text-destructive" :
                     m.tone === "success" ? "text-success" :
                     "text-foreground")
                  }
                >
                  {m.value}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </Panel>
  );
}
