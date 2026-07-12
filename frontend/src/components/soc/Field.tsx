import { type ReactNode } from "react";

export function Field({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: ReactNode;
  tone?: "default" | "primary" | "success" | "warning" | "destructive" | "muted";
}) {
  const toneCls =
    tone === "primary" ? "text-primary" :
    tone === "success" ? "text-success" :
    tone === "warning" ? "text-warning" :
    tone === "destructive" ? "text-destructive" :
    tone === "muted" ? "text-muted-foreground" : "text-foreground";
  const dot =
    tone === "primary" ? "bg-primary" :
    tone === "success" ? "bg-success" :
    tone === "warning" ? "bg-warning" :
    tone === "destructive" ? "bg-destructive" :
    "bg-muted-foreground/30";
  return (
    <div className="group/f flex items-baseline justify-between gap-3 border-b border-dashed border-border/50 py-1.5 transition-colors last:border-b-0 hover:border-primary/40">
      <span className="flex items-center gap-1.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">
        <span className={"inline-block h-1 w-1 rounded-full " + dot} aria-hidden />
        {label}
      </span>
      <span className={"text-mono ba-text-base tabular-nums truncate " + toneCls}>{value}</span>
    </div>
  );
}
