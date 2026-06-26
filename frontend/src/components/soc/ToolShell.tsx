import { useEffect, type ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { Zap, Eraser, CornerDownLeft } from "lucide-react";

/* ============================================================
 * ToolShell — adaptive workspace skeleton for every tool page.
 *
 * Provides:
 *  · Header strip: tool id chip, title, one-line purpose, state pill
 *  · Adaptive grid: "split" (40/60) for short-input tools,
 *                   "stack" (single column) for long-input tools
 *  · Sticky run bar with ⌘↵ run / ⌘. clear hotkeys
 *  · Per-tool output emphasis is left to children
 * ============================================================ */

export type ToolState = "idle" | "ready" | "parsing" | "error";

const STATE_TONE: Record<ToolState, string> = {
  idle: "border-border text-muted-foreground",
  ready: "border-success/50 bg-success/10 text-success",
  parsing: "border-primary/50 bg-primary/10 text-primary animate-pulse",
  error: "border-destructive/50 bg-destructive/10 text-destructive",
};

export function ToolShell({
  icon: Icon,
  title,
  purpose,
  state = "idle",
  layout = "stack",
  intake,
  output,
  onRun,
  onClear,
  canRun = false,
  runLabel = "analyse",
  meta,
}: {
  icon: LucideIcon;
  title: string;
  purpose: string;
  state?: ToolState;
  layout?: "split" | "stack";
  intake: ReactNode;
  output: ReactNode;
  onRun?: () => void;
  onClear?: () => void;
  canRun?: boolean;
  runLabel?: string;
  meta?: ReactNode;
}) {
  /* Hotkeys: ⌘/Ctrl+Enter → run, ⌘/Ctrl+. → clear */
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const meta = e.metaKey || e.ctrlKey;
      if (!meta) return;
      if (e.key === "Enter" && canRun && onRun) {
        e.preventDefault();
        onRun();
      } else if (e.key === "." && onClear) {
        e.preventDefault();
        onClear();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [canRun, onRun, onClear]);

  return (
    <div className="ba-fade-in space-y-4">
      {/* Header strip */}
      <header className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 border-b border-border/60 pb-3 sm:flex sm:flex-wrap">
        <div className="flex min-w-0 items-center gap-3">
          <span className="relative grid h-9 w-9 shrink-0 place-items-center rounded-md border border-primary/40 bg-primary/10 text-primary shadow-[0_0_0_3px_color-mix(in_oklab,var(--primary)_8%,transparent)]">
            <Icon className="h-4 w-4" />
            <span className="pointer-events-none absolute -right-0.5 -top-0.5 h-1.5 w-1.5 rounded-full bg-primary/80 shadow-[0_0_6px_var(--primary)]" />
          </span>
          <div className="min-w-0">
            <h1 className="truncate text-mono text-[15px] font-semibold tracking-tight text-foreground">{title}</h1>
            <p className="truncate text-[11px] text-muted-foreground">{purpose}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {meta}
          <span
            className={
              "inline-flex items-center gap-1 rounded border px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest " +
              STATE_TONE[state]
            }
          >
            <span className={"h-1.5 w-1.5 rounded-full " + (state === "ready" ? "bg-success" : state === "parsing" ? "bg-primary" : state === "error" ? "bg-destructive" : "bg-muted-foreground/60")} />
            {state}
          </span>
        </div>
      </header>

      {/* Adaptive body */}
      {layout === "split" ? (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
          <div className="space-y-3 lg:sticky lg:top-4 lg:self-start">
            {intake}
            <RunBar canRun={canRun} onRun={onRun} onClear={onClear} runLabel={runLabel} />
          </div>
          <div className="min-w-0 space-y-4">{output}</div>
        </div>
      ) : (
        <div className="space-y-4">
          {intake}
          <RunBar canRun={canRun} onRun={onRun} onClear={onClear} runLabel={runLabel} sticky />
          <div>{output}</div>
        </div>
      )}
    </div>
  );
}

function RunBar({
  canRun,
  onRun,
  onClear,
  runLabel,
  sticky = false,
}: {
  canRun: boolean;
  onRun?: () => void;
  onClear?: () => void;
  runLabel: string;
  sticky?: boolean;
}) {
  return (
    <div
      className={
        "flex flex-wrap items-center gap-2 rounded-md border border-border/70 bg-card/70 px-3 py-2 backdrop-blur " +
        (sticky ? "sticky top-2 z-10 shadow-sm" : "")
      }
    >
      <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
        run
      </span>
      <button
        type="button"
        onClick={onRun}
        disabled={!canRun}
        className="inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono text-[11px] uppercase tracking-widest text-primary transition-colors hover:bg-primary/20 disabled:cursor-not-allowed disabled:border-border disabled:bg-transparent disabled:text-muted-foreground"
      >
        <Zap className="h-3 w-3" />
        {runLabel}
        <span className="ml-1 hidden items-center gap-0.5 rounded border border-primary/30 px-1 text-[9px] opacity-80 sm:inline-flex">
          ⌘<CornerDownLeft className="h-2.5 w-2.5" />
        </span>
      </button>
      <button
        type="button"
        onClick={onClear}
        className="inline-flex items-center gap-1.5 rounded border border-border px-2 py-1 text-mono text-[11px] uppercase tracking-widest text-muted-foreground hover:border-destructive/50 hover:text-destructive"
      >
        <Eraser className="h-3 w-3" /> clear
        <span className="ml-1 hidden items-center rounded border border-border px-1 text-[9px] opacity-70 sm:inline-flex">⌘.</span>
      </button>
      <span className="ml-auto text-mono text-[10px] text-muted-foreground">
        auto-runs on paste
      </span>
    </div>
  );
}
