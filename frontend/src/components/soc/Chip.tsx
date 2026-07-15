import { type ReactNode } from "react";

export function Chip({
  children,
  tone = "default",
  actions,
}: {
  children: ReactNode;
  tone?: "default" | "primary" | "accent" | "success" | "warning" | "destructive" | "info";
  actions?: ReactNode;
}) {
  const cls =
    tone === "primary" ? "border-primary/40 bg-primary/10 text-primary" :
    tone === "accent" ? "border-accent/40 bg-accent/10 text-accent" :
    tone === "success" ? "border-success/40 bg-success/10 text-success" :
    tone === "warning" ? "border-warning/40 bg-warning/10 text-warning" :
    tone === "destructive" ? "border-destructive/40 bg-destructive/10 text-destructive" :
    tone === "info" ? "border-info/40 bg-info/10 text-info" :
    "border-border bg-card/50 text-muted-foreground";
  return (
    <span className={"inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-mono ba-text-2xs uppercase tracking-widest " + cls}>
      {children}
      {actions && <span className="ml-auto">{actions}</span>}
    </span>
  );
}
