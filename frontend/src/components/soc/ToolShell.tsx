import { useEffect, type ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { Zap, Eraser, CornerDownLeft, Search } from "lucide-react";
import { useOutputFilter, OutputFilterBar, OutputFilter } from "@/components/soc/OutputFilter";

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
  intake: ReactNode;
  output: ReactNode;
  onRun?: () => void;
  onClear?: () => void;
  canRun?: boolean;
  runLabel?: string;
  meta?: ReactNode;
}) {
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

  const { filterText, setFilterText, showFilter, toggleFilter } = useOutputFilter();

  return (
    <div className="ba-fade-in space-y-4">
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
          <button
            onClick={toggleFilter}
            className={"inline-flex items-center gap-1 rounded border px-2 py-1 text-mono text-[10px] uppercase tracking-widest transition-colors " + (showFilter ? "border-primary/50 bg-primary/10 text-primary" : "border-border/60 text-muted-foreground hover:border-primary/40 hover:text-primary")}
            title="Toggle output filter (⌘F)"
          >
            <Search className="h-3 w-3" />
            filter
          </button>
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

      <section className="rounded-lg border border-border/70 bg-card/35 p-3 shadow-[0_18px_70px_-55px_var(--primary)] sm:p-4">
        <div className="space-y-3">{intake}</div>
      </section>

      <RunBar canRun={canRun} onRun={onRun} onClear={onClear} runLabel={runLabel} sticky />

      {showFilter && (
        <OutputFilterBar
          filterText={filterText}
          onChange={setFilterText}
          onClear={() => setFilterText("")}
           onClose={toggleFilter}
        />
      )}

      <div className="mx-auto h-7 w-px bg-gradient-to-b from-primary/50 via-border/70 to-transparent" aria-hidden />

      <section className="min-w-0 space-y-4">
        <OutputFilter query={filterText.toLowerCase()}>{output}</OutputFilter>
      </section>
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
