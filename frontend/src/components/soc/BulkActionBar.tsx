import { useCallback, useRef, useState } from "react";
import { Copy } from "lucide-react";

type BulkAction = {
  label: string;
  icon?: typeof Copy;
  onClick: (indices: number[]) => void;
  tone?: "default" | "primary" | "warning" | "destructive";
};

export function BulkActionBar({
  selected,
  total,
  onSelectAll,
  onClear,
  actions,
}: {
  selected: Set<number>;
  total: number;
  onSelectAll: () => void;
  onClear: () => void;
  actions: BulkAction[];
}) {
  if (selected.size === 0) return null;
  return (
    <div className="sticky top-0 z-20 -mx-1 mb-3 rounded-md border border-primary/40 bg-primary/5 px-3 py-2 shadow-[0_4px_20px_-4px_hsl(var(--primary)/0.25)] backdrop-blur-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="grid h-6 w-6 place-items-center rounded border border-primary/40 bg-primary/10 text-mono text-[10px] font-bold text-primary">
            {selected.size}
          </span>
          <span className="text-mono text-[10px] uppercase tracking-widest text-foreground/80">
            {selected.size} / {total} selected
          </span>
          <button onClick={onSelectAll} className="rounded border border-border px-1.5 py-0.5 text-mono text-[9px] uppercase tracking-widest text-muted-foreground hover:text-foreground">
            all
          </button>
          <button onClick={onClear} className="rounded border border-border px-1.5 py-0.5 text-mono text-[9px] uppercase tracking-widest text-muted-foreground hover:text-destructive">
            clear
          </button>
        </div>
        <div className="flex items-center gap-1.5">
          {actions.map((a, i) => {
            const Icon = a.icon;
            const toneCls =
              a.tone === "primary" ? "border-primary/50 bg-primary/10 text-primary hover:bg-primary/20" :
              a.tone === "warning" ? "border-warning/50 bg-warning/10 text-warning hover:bg-warning/20" :
              a.tone === "destructive" ? "border-destructive/50 bg-destructive/10 text-destructive hover:bg-destructive/20" :
              "border-border bg-card/60 text-muted-foreground hover:text-foreground";
            return (
              <button
                key={i}
                onClick={() => a.onClick([...selected])}
                className={"inline-flex items-center gap-1 rounded border px-2 py-1 text-mono text-[10px] uppercase tracking-widest transition-colors " + toneCls}
              >
                {Icon && <Icon className="h-3 w-3" />}
                {a.label}
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export function useSelection() {
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const lastClicked = useRef<number | null>(null);

  const toggle = useCallback((index: number, shiftKey: boolean) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (shiftKey && lastClicked.current !== null) {
        const start = Math.min(lastClicked.current, index);
        const end = Math.max(lastClicked.current, index);
        for (let i = start; i <= end; i++) {
          if (next.has(i)) next.delete(i);
          else next.add(i);
        }
      } else {
        if (next.has(index)) next.delete(index);
        else next.add(index);
      }
      lastClicked.current = index;
      return next;
    });
  }, []);

  const selectAll = useCallback((total: number) => {
    setSelected(new Set(Array.from({ length: total }, (_, i) => i)));
  }, []);

  const clear = useCallback(() => {
    setSelected(new Set());
    lastClicked.current = null;
  }, []);

  return { selected, toggle, selectAll, clear };
}
