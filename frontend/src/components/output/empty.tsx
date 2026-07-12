import { type LucideIcon } from "lucide-react";

export function Empty({
  icon: Icon,
  title,
  hint,
  examples,
  onSample,
  shortcut,
}: {
  icon?: LucideIcon;
  title: string;
  hint?: string;
  examples?: string[];
  onSample?: (example: string) => void;
  shortcut?: string;
}) {
  return (
    <div className="relative flex flex-col items-center justify-center gap-2 overflow-hidden rounded-md border border-dashed border-border bg-background/30 py-10 text-center">
      <div aria-hidden className="pointer-events-none absolute inset-0 bg-[linear-gradient(transparent_95%,hsl(var(--border)/0.4)_95%)] bg-[length:100%_8px] opacity-40" />
      {Icon && (
        <div className="relative grid h-9 w-9 place-items-center rounded-md border border-border bg-card/60">
          <Icon className="h-4 w-4 text-muted-foreground/80" />
        </div>
      )}
      <div className="relative text-mono ba-text-base text-foreground/85">{title}</div>
      {hint && <div className="relative max-w-xs ba-text-sm text-muted-foreground">{hint}</div>}
      {examples && examples.length > 0 && (
        <div className="relative mt-2 flex flex-wrap justify-center gap-1.5">
          {examples.map((ex) =>
            onSample ? (
              <button
                key={ex}
                onClick={() => onSample(ex)}
                className="cursor-pointer rounded-full border border-divider-soft bg-card/40 px-2.5 py-0.5 text-mono ba-text-3xs text-muted-foreground transition-colors hover:border-primary/50 hover:text-foreground"
              >
                {ex}
              </button>
            ) : (
              <span key={ex} className="rounded-full border border-divider-soft bg-card/40 px-2.5 py-0.5 text-mono ba-text-3xs text-muted-foreground">
                {ex}
              </span>
            ),
          )}
        </div>
      )}
      {shortcut && (
        <div className="relative mt-1 flex items-center gap-1.5 text-mono ba-text-3xs text-muted-foreground/60">
          <kbd className="rounded border border-divider-soft bg-card/60 px-1 py-0.5 font-mono text-[10px] leading-none">{shortcut}</kbd>
          <span>to paste</span>
        </div>
      )}
    </div>
  );
}
