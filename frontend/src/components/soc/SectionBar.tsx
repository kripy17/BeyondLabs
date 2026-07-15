import { type ReactNode } from "react";
import { ArrowDownToLine, ArrowUpFromLine, Clock, Filter, Settings2, Sparkles, type LucideIcon } from "lucide-react";

const SECTION_ICONS: Record<string, LucideIcon> = {
  IN: ArrowDownToLine,
  OT: ArrowUpFromLine,
  RC: Clock,
  FL: Filter,
  CF: Settings2,
  AI: Sparkles,
};

export function SectionBar({
  id,
  label,
  meta,
  action,
  icon,
  priority = "primary",
  children,
}: {
  id: string;
  label: string;
  meta?: string;
  action?: ReactNode;
  icon?: LucideIcon;
  priority?: "primary" | "secondary" | "raw";
  children?: ReactNode;
}) {
  const Icon = icon ?? SECTION_ICONS[id.toUpperCase()];
  if (priority === "raw") {
    return (
      <>
        <div className="mb-2 mt-0.5 flex items-center gap-2">
          {Icon && <Icon className="h-3 w-3 text-muted-foreground" strokeWidth={2} />}
          <span className="text-mono ba-text-sm uppercase tracking-[0.18em] text-muted-foreground">{label}</span>
          {meta && <span className="text-mono ba-text-3xs text-muted-foreground/60">· {meta}</span>}
          <div className="h-px flex-1 bg-border/30" />
          {action}
        </div>
        {children}
      </>
    );
  }
  if (priority === "secondary") {
    return (
      <>
        <div className="group/sb mb-2 mt-0.5 flex items-center gap-2.5">
          <span className="relative grid h-5 w-5 place-items-center rounded-sm border border-divider-strong bg-card/40 text-muted-foreground">
            {Icon ? <Icon className="h-3 w-3" strokeWidth={2} /> : <span className="text-mono ba-text-3xs font-bold">{id.slice(0, 2).toUpperCase()}</span>}
          </span>
          <h3 className="text-mono ba-text-sm uppercase tracking-[0.2em] text-foreground/70">{label}</h3>
          <div className="h-px flex-1 bg-border/30" />
          {meta && <span className="rounded border border-divider-soft bg-card/20 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground/70">{meta}</span>}
          {action}
        </div>
        {children}
      </>
    );
  }
  return (
    <>
      <div className="group/sb mb-3 mt-1 flex items-center gap-3">
        <span className="relative grid h-6 w-6 place-items-center rounded-sm border border-primary/50 bg-primary/10 text-primary shadow-[0_0_0_1px_hsl(var(--background)),0_0_10px_-2px_hsl(var(--primary)/0.55)] transition-shadow group-hover/sb:shadow-[0_0_0_1px_hsl(var(--background)),0_0_14px_-1px_hsl(var(--primary)/0.8)]">
          {Icon ? (
            <Icon className="h-3.5 w-3.5" strokeWidth={2.25} />
          ) : (
            <span className="text-mono ba-text-3xs font-bold">{id.slice(0, 2).toUpperCase()}</span>
          )}
          <span aria-hidden className="absolute -right-0.5 -top-0.5 h-1 w-1 animate-pulse rounded-full bg-primary" />
        </span>
        <h2 className="font-display text-mono ba-text-sm uppercase tracking-[0.22em] text-foreground/90">
          {label}
        </h2>
        <div className="h-px flex-1 bg-gradient-to-r from-primary/30 via-border to-transparent" />
        {meta && <span className="rounded border border-divider-strong bg-card/40 px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground">{meta}</span>}
        {action}
      </div>
      {children}
    </>
  );
}
