import { useState, type ReactNode } from "react";
import { ChevronRight, type LucideIcon } from "lucide-react";

export function CollapsibleSection({
  id: _id,
  label,
  meta,
  icon: Icon,
  children,
  defaultCollapsed = false,
}: {
  id: string;
  label: string;
  meta?: string;
  icon?: LucideIcon;
  children: ReactNode;
  defaultCollapsed?: boolean;
}) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);
  return (
    <div className="rounded-md border border-divider-strong bg-card/40 overflow-hidden">
      <button
        onClick={() => setCollapsed((c) => !c)}
        className="flex w-full items-center gap-2 border-b border-divider-strong px-3 py-2 text-left hover:bg-accent/30 transition-colors"
      >
        {Icon && (
          <span className="grid h-5 w-5 place-items-center rounded-sm border border-primary/40 bg-primary/10 text-primary">
            <Icon className="h-3 w-3" strokeWidth={2.25} />
          </span>
        )}
        <span className="text-mono ba-text-sm uppercase tracking-[0.22em] text-foreground/90">{label}</span>
        {meta && <span className="text-mono ba-text-2xs text-muted-foreground">({meta})</span>}
        <div className="ml-auto">
          <ChevronRight className={"h-4 w-4 text-muted-foreground transition-transform " + (collapsed ? "" : "rotate-90")} />
        </div>
      </button>
      {!collapsed && <div className="p-3">{children}</div>}
    </div>
  );
}
