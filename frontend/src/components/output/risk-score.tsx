import { Panel, Chip } from "@/components/soc";

export function RiskScore({
  score,
  label,
  confidence,
  scale = 100,
  tone = "warning",
}: {
  score: number;
  label: string;
  confidence?: string;
  scale?: number;
  tone?: "success" | "warning" | "destructive";
}) {
  const pct = Math.min(100, Math.max(0, Math.round((score / scale) * 100)));
  const barCls =
    tone === "destructive" ? "bg-destructive" :
    tone === "success" ? "bg-success" : "bg-warning";
  return (
    <Panel title={label} bodyClassName="p-3">
      <div className="flex items-end justify-between gap-2">
        <div className={"text-mono text-3xl font-bold " + (tone === "destructive" ? "text-destructive" : tone === "success" ? "text-success" : "text-warning")}>
          {score}
          <span className="ml-1 text-base text-muted-foreground">/{scale}</span>
        </div>
        {confidence && <Chip tone={tone === "destructive" ? "destructive" : tone === "success" ? "success" : "warning"}>{confidence}</Chip>}
      </div>
      <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-muted/40">
        <div className={"h-full transition-all " + barCls} style={{ width: `${pct}%` }} />
      </div>
    </Panel>
  );
}
