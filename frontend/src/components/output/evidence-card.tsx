import { Panel, Chip } from "@/components/soc";

export function EvidenceCard({
  severity = "info",
  title,
  reason,
  limitation,
  action,
}: {
  severity?: "info" | "warning" | "destructive" | "success";
  title: string;
  reason?: string;
  limitation?: string;
  action?: string;
}) {
  const bar =
    severity === "destructive" ? "bg-destructive" :
    severity === "warning" ? "bg-warning" :
    severity === "success" ? "bg-success" : "bg-info";
  return (
    <Panel
      className={
        "relative " + (
        severity === "destructive" ? "border-destructive/40" :
        severity === "warning" ? "border-warning/40" :
        severity === "success" ? "border-success/40" :
        "border-info/40")
      }
      bodyClassName="p-3 pl-4"
    >
      <span aria-hidden className={"pointer-events-none absolute inset-y-0 left-0 w-[3px] " + bar} />
      <div className="flex items-start gap-2">
        <Chip tone={severity === "destructive" ? "destructive" : severity === "warning" ? "warning" : severity === "success" ? "success" : "info"}>
          {severity}
        </Chip>
        <div className="min-w-0 flex-1">
          <div className="text-mono ba-text-base font-semibold text-foreground">{title}</div>
          {reason && <div className="mt-1 text-[11px] leading-relaxed text-muted-foreground"><span className="text-foreground/70">Reason:</span> {reason}</div>}
          {limitation && <div className="mt-1 text-[11px] leading-relaxed text-muted-foreground"><span className="text-foreground/70">Limitation:</span> {limitation}</div>}
          {action && <div className="mt-1 text-[11px] leading-relaxed text-muted-foreground"><span className="text-foreground/70">Action:</span> {action}</div>}
        </div>
      </div>
    </Panel>
  );
}
