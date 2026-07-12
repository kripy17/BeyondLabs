import { useState } from "react";
import { toast } from "sonner";
import { Panel } from "@/components/soc";

function IocCopyBtn({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1200); }}
      aria-label="Copy IOC value"
      className="rounded border border-divider-soft bg-card/30 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground/60 opacity-0 transition-all hover:border-primary/40 hover:text-primary group-hover/ioc:opacity-100"
    >
      {copied ? "done" : "copy"}
    </button>
  );
}

function IocBulkCopy({ values, label }: { values: string[]; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(values.join("\n"));
        setCopied(true);
        toast(`Copied ${values.length} ${label}`);
        setTimeout(() => setCopied(false), 2000);
      }}
      aria-label={`Copy all ${label}`}
      className="rounded border border-divider-soft bg-card/30 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground/60 transition-all hover:border-primary/40 hover:text-primary"
    >
      {copied ? "done" : "copy all"}
    </button>
  );
}

export function IocInventory({
  groups,
  onSendTo,
}: {
  groups: { kind: string; items: string[]; tone?: "primary" | "warning" | "destructive" | "info" | "success" | "default" }[];
  onSendTo?: (kind: string, value: string) => void;
}) {
  return (
    <div className="grid gap-3 grid-cols-2">
      {groups.map((g) => {
        const dot =
          g.tone === "primary" ? "bg-primary" :
          g.tone === "warning" ? "bg-warning" :
          g.tone === "destructive" ? "bg-destructive" :
          g.tone === "info" ? "bg-info" :
          g.tone === "success" ? "bg-success" : "bg-muted-foreground/50";
        return (
          <Panel
            key={g.kind}
            title={g.kind}
            meta={`${g.items.length}`}
            bodyClassName="p-0"
            actions={
              <div className="flex items-center gap-1">
                {g.items.length > 0 && (
                  <IocBulkCopy values={g.items} label={g.kind} />
                )}
                <span className={"inline-block h-1.5 w-1.5 rounded-full " + dot} aria-hidden />
              </div>
            }
          >
            {g.items.length === 0 ? (
              <div className="px-4 py-3 text-mono ba-text-sm text-muted-foreground">no items</div>
            ) : (
              <ul className="divide-y divide-border/40">
                {g.items.map((v, idx) => (
                  <li key={v} className={"group/ioc flex items-center justify-between gap-2 px-3 py-1.5 transition-colors hover:bg-primary/5 " + (idx % 2 === 1 ? "bg-background/30" : "")}>
                    <div className="flex min-w-0 items-center gap-2">
                      <span className={"h-1 w-1 shrink-0 rounded-full " + dot} aria-hidden />
                      <code className="truncate text-mono ba-text-sm text-foreground/90">{v}</code>
                    </div>
                    <div className="flex shrink-0 items-center gap-1">
                      <IocCopyBtn value={v} />
                      {onSendTo && (
                        <button
                          onClick={() => onSendTo(g.kind, v)}
                          className="rounded border border-border bg-card/60 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground opacity-0 transition-all hover:border-primary/50 hover:text-primary group-hover/ioc:opacity-100"
                        >
                          send →
                        </button>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        );
      })}
    </div>
  );
}
