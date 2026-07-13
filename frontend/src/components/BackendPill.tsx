import { useBackendStatus } from "@/lib/backend";

export function BackendPill({className}: {className?: string}) {
  const { status, latency } = useBackendStatus();

  const dot = status === "online" ? "bg-success" : status === "checking" ? "bg-warning" : "bg-destructive";
  const label = status === "online" ? `online ${latency}ms` : status === "checking" ? "checking…" : "offline";

  return (
    <div className={`inline-flex items-center gap-1.5 ${className ?? ""}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${dot} ${status === "checking" ? "animate-pulse" : ""}`} />
      <span className="text-mono text-[10px] uppercase tracking-widest text-sidebar-foreground/55">{label}</span>
    </div>
  );
}
