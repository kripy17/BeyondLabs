import { useState, useRef, useEffect } from "react";
import { useNavigate } from "@tanstack/react-router";
import { sendArtifact, sendToCase } from "@/lib/handoff";
import { Copy, ArrowRight, Radar, Globe2, ShieldAlert, Database, Terminal, Link2 } from "lucide-react";
import { toast } from "sonner";

const ACTIONS: Record<string, { label: string; icon: typeof ArrowRight; to: string; kind: string }[]> = {
  ip: [
    { label: "Recon", icon: Radar, to: "/recon", kind: "ip" },
    { label: "Terminal", icon: Terminal, to: "/terminal", kind: "ip" },
    { label: "Case", icon: Database, to: "/case", kind: "ip" },
  ],
  domain: [
    { label: "Recon", icon: Radar, to: "/recon", kind: "domain" },
    { label: "OSINT", icon: ShieldAlert, to: "/osint", kind: "domain" },
    { label: "URL Analyzer", icon: Link2, to: "/url", kind: "domain" },
    { label: "Case", icon: Database, to: "/case", kind: "domain" },
  ],
  url: [
    { label: "URL Analyzer", icon: Link2, to: "/url", kind: "url" },
    { label: "Case", icon: Database, to: "/case", kind: "url" },
  ],
  hash: [
    { label: "Case", icon: Database, to: "/case", kind: "hash" },
  ],
  email: [
    { label: "Phishing", icon: Globe2, to: "/phishing", kind: "email" },
    { label: "OSINT", icon: ShieldAlert, to: "/osint", kind: "email" },
    { label: "Case", icon: Database, to: "/case", kind: "email" },
  ],
  raw: [
    { label: "Case", icon: Database, to: "/case", kind: "raw" },
  ],
};

type IocKind = keyof typeof ACTIONS;

export function IocChip({ kind, value, className }: { kind: IocKind; value: string; className?: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const actions = ACTIONS[kind] ?? ACTIONS.raw;

  useEffect(() => {
    if (!open) return;
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  const tone = kind === "ip" ? "text-[var(--ansi-blue)]" : kind === "domain" ? "text-[var(--ansi-cyan)]" : kind === "url" ? "text-[var(--ansi-green)]" : kind === "hash" ? "text-[var(--ansi-magenta)]" : kind === "email" ? "text-[var(--ansi-yellow)]" : "text-foreground";

  return (
    <div ref={ref} className={`relative inline-flex ${className ?? ""}`}>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className={`inline-flex items-center gap-1 rounded-sm border border-divider-soft bg-card/60 px-1.5 py-0.5 text-mono text-[11px] ${tone} hover:bg-card hover:border-primary/40 transition-colors`}
      >
        {value}
      </button>
      {open && (
        <div className="absolute top-full left-0 z-50 mt-1 w-44 rounded-md border border-border bg-popover p-1 elevation-raised">
          <div className="px-2 py-1 text-[9px] uppercase tracking-widest text-muted-foreground">{kind} · handoff</div>
          <button
            type="button"
            onClick={() => { navigator.clipboard.writeText(value); setOpen(false); }}
            className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-mono text-[11px] text-foreground hover:bg-accent"
          >
            <Copy className="h-3 w-3 text-muted-foreground" /> Copy
          </button>
          {actions.map((a) => (
            <button
              key={a.to + a.kind}
              type="button"
              onClick={() => { sendArtifact({ kind: a.kind, value, source: window.location.pathname }); navigate({ to: a.to }); setOpen(false); }}
              className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-mono text-[11px] text-foreground hover:bg-accent"
            >
              <a.icon className="h-3 w-3 text-muted-foreground" /> {a.label} <ArrowRight className="ml-auto h-2.5 w-2.5 text-muted-foreground/50" />
            </button>
          ))}
          <div className="my-1 border-t border-divider-strong" />
          <button
            type="button"
            onClick={() => { sendToCase({ body: value, source: window.location.pathname, kind }); toast("Sent to case"); setOpen(false); }}
            className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-mono text-[11px] text-foreground hover:bg-accent"
          >
            <Database className="h-3 w-3 text-muted-foreground" /> Attach to case
          </button>
        </div>
      )}
    </div>
  );
}
