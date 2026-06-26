import { useEffect, useMemo, useState } from "react";
import { cn } from "@/lib/utils";

/** Subtle animated dot-grid; cells light up at random for a "scanning" feel. */
export function AnimatedGrid({
  className,
  cols = 28,
  rows = 8,
  active = 6,
}: {
  className?: string;
  cols?: number;
  rows?: number;
  active?: number;
}) {
  const cells = useMemo(() => Array.from({ length: cols * rows }, (_, i) => i), [cols, rows]);
  const [lit, setLit] = useState<Set<number>>(new Set());

  useEffect(() => {
    const tick = () => {
      const next = new Set<number>();
      while (next.size < active) next.add(Math.floor(Math.random() * cells.length));
      setLit(next);
    };
    tick();
    const id = setInterval(tick, 1400);
    return () => clearInterval(id);
  }, [cells.length, active]);

  return (
    <div
      className={cn("pointer-events-none absolute inset-0 overflow-hidden opacity-[0.35]", className)}
      aria-hidden
    >
      <div
        className="grid h-full w-full"
        style={{ gridTemplateColumns: `repeat(${cols}, minmax(0,1fr))`, gridTemplateRows: `repeat(${rows}, minmax(0,1fr))` }}
      >
        {cells.map((i) => (
          <div key={i} className="relative border-r border-b border-border/30">
            <span
              className={cn(
                "absolute inset-[3px] rounded-sm transition-all duration-700",
                lit.has(i) ? "bg-primary/40 shadow-[0_0_8px_hsl(var(--primary)/0.6)]" : "bg-transparent"
              )}
            />
          </div>
        ))}
      </div>
    </div>
  );
}
