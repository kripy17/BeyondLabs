import { useState, useCallback, type ReactNode } from "react";
import { ChevronDown, type LucideIcon } from "lucide-react";

export function Panel({
  title,
  icon: Icon,
  meta,
  actions,
  children,
  className = "",
  bodyClassName = "",
  collapsible,
  defaultCollapsed,
  storageKey,
  sticky,
  priority = "primary",
}: {
  title?: string;
  icon?: LucideIcon;
  meta?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  collapsible?: boolean;
  defaultCollapsed?: boolean;
  storageKey?: string;
  sticky?: boolean;
  priority?: "primary" | "secondary" | "raw";
}) {
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    if (storageKey) {
      try { return JSON.parse(localStorage.getItem(storageKey) || "null") ?? !!defaultCollapsed; } catch {}
    }
    return !!defaultCollapsed;
  });

  const toggle = useCallback(() => {
    setCollapsed((c) => {
      const next = !c;
      if (storageKey) {
        try { localStorage.setItem(storageKey, JSON.stringify(next)); } catch {}
      }
      return next;
    });
  }, [storageKey]);

  const canCollapse = collapsible && !!title;

  const borderCls = priority === "primary" ? "border-primary/40 group-hover/panel:border-primary/80" : priority === "secondary" ? "border-border/50 group-hover/panel:border-primary/40" : "border-transparent";
  const panelBorderCls = priority === "primary" ? "hover:border-primary/30" : priority === "secondary" ? "hover:border-primary/15" : "hover:border-border";
  const panelBgCls = priority === "raw" ? "bg-card/30" : "bg-card/60";
  const headerBorderCls = priority === "raw" ? "border-divider-soft" : "border-border";

  return (
    <section className={"group/panel ba-fade-in relative overflow-hidden rounded-md border border-border " + panelBgCls + " shadow-[inset_0_1px_0_hsl(var(--foreground)/0.04)] transition-colors " + panelBorderCls + " " + (sticky ? "sticky top-0 z-10 elevation-flat" : "") + " " + className}>
      {priority !== "raw" && (
        <>
          <span aria-hidden className={"pointer-events-none absolute left-0 top-0 h-2 w-2 border-l border-t transition-all group-hover/panel:h-2.5 group-hover/panel:w-2.5 " + borderCls} />
          <span aria-hidden className={"pointer-events-none absolute right-0 top-0 h-2 w-2 border-r border-t transition-all group-hover/panel:h-2.5 group-hover/panel:w-2.5 " + borderCls} />
          <span aria-hidden className={"pointer-events-none absolute left-0 bottom-0 h-2 w-2 border-l border-b transition-all group-hover/panel:h-2.5 group-hover/panel:w-2.5 " + borderCls} />
          <span aria-hidden className={"pointer-events-none absolute right-0 bottom-0 h-2 w-2 border-r border-b transition-all group-hover/panel:h-2.5 group-hover/panel:w-2.5 " + borderCls} />
        </>
      )}
      {title && (
        <header
          className={"flex items-center justify-between gap-2 border-b " + headerBorderCls + " px-4 py-2.5 " + (canCollapse ? "cursor-pointer select-none hover:bg-card/40" : "")}
          onClick={canCollapse ? toggle : undefined}
        >
          <div className="flex items-center gap-2 min-w-0">
            {canCollapse && (
              <ChevronDown className={"h-3 w-3 shrink-0 text-muted-foreground transition-transform " + (collapsed ? "-rotate-90" : "")} />
            )}
            {Icon && <Icon className={"h-3.5 w-3.5 shrink-0 " + (priority === "primary" ? "text-primary" : "text-muted-foreground")} />}
            <h3 className={"text-mono ba-text-sm uppercase tracking-[0.22em] truncate " + (priority === "primary" ? "text-foreground/90" : "text-muted-foreground")}>{title}</h3>
            {meta && <span className="text-mono ba-text-2xs text-muted-foreground shrink-0">· {meta}</span>}
          </div>
          {actions && <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>{actions}</div>}
        </header>
      )}
      {(!canCollapse || !collapsed) && (
        <div className={"p-4 " + bodyClassName}>{children}</div>
      )}
    </section>
  );
}
