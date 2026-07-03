import { Link } from "@tanstack/react-router";
import { ChevronRight, Wand2, MailWarning, Radar, Activity, FileText, type LucideIcon } from "lucide-react";

const steps: { title: string; url: string; icon: LucideIcon; tag: string }[] = [
  { title: "Parse",     url: "/parser",   icon: Wand2,       tag: "01" },
  { title: "Triage",    url: "/phishing", icon: MailWarning, tag: "02" },
  { title: "Recon",     url: "/recon",    icon: Radar,    tag: "03" },
  { title: "Pivot",     url: "/siem",     icon: Activity, tag: "04" },
  { title: "Report",    url: "/case",     icon: FileText, tag: "05" },
];

export function WorkflowRibbon() {
  return (
    <div className="rounded-lg border border-border bg-card/40 p-3">
      <div className="mb-3 flex items-center justify-between">
        <div className="text-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
          investigation flow
        </div>
        <div className="text-mono text-[10px] text-muted-foreground">
          intake → triage → recon → pivot → report
        </div>
      </div>
      <div className="flex flex-wrap items-stretch gap-2">
        {steps.map((s, i) => (
          <div key={s.url} className="flex items-stretch gap-2">
            <Link
              to={s.url}
              className="hover-lift group flex min-w-[8.5rem] flex-1 items-center gap-3 rounded-md border border-border bg-background/50 px-3 py-2.5"
            >
              <div className="grid h-8 w-8 place-items-center rounded-md border border-border bg-card text-primary">
                <s.icon className="h-4 w-4" />
              </div>
              <div className="min-w-0">
                <div className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  {s.tag}
                </div>
                <div className="text-mono text-xs font-semibold">{s.title}</div>
              </div>
            </Link>
            {i < steps.length - 1 && (
              <div className="hidden items-center text-muted-foreground/50 flex">
                <ChevronRight className="h-4 w-4" />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
