import { cn } from "@/lib/utils";
import { type Severity } from "@/lib/severity";

const styles: Record<Severity, string> = {
  critical: "border-destructive/40 bg-destructive/15 text-destructive",
  high:     "border-destructive/40 bg-destructive/10 text-destructive",
  medium:   "border-warning/40 bg-warning/15 text-warning",
  low:      "border-info/40 bg-info/10 text-info",
  info:     "border-border bg-muted/40 text-muted-foreground",
};

export function SeverityBadge({ level, className }: { level: Severity; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-mono text-[10px] font-semibold uppercase tracking-widest",
        styles[level],
        className,
      )}
    >
      <span className="status-dot" /> {level}
    </span>
  );
}
