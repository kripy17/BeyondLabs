import { useState } from "react";
import { Check, ChevronDown, ChevronRight, type LucideIcon } from "lucide-react";

export function VerdictBanner({
  verdict,
  tone = "warning",
  icon: Icon,
  score,
  details,
  collapsible = true,
}: {
  verdict: string;
  tone?: "success" | "warning" | "destructive" | "info";
  icon?: LucideIcon;
  score?: string;
  details?: string[];
  collapsible?: boolean;
}) {
  const [expanded, setExpanded] = useState(!collapsible);
  const IconEl = Icon ?? (tone === "destructive" ? ChevronDown : tone === "success" ? Check : ChevronRight);
  const toneCls =
    tone === "destructive" ? "border-destructive/40 bg-destructive/10 text-destructive" :
    tone === "success" ? "border-success/40 bg-success/10 text-success" :
    tone === "warning" ? "border-warning/40 bg-warning/10 text-warning" :
    "border-info/40 bg-info/10 text-info";
  return (
    <div className={"rounded-lg border-2 " + toneCls}>
      <button
        onClick={() => setExpanded((e) => !e)}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
      >
        <div className="flex items-center gap-3">
          <IconEl className="h-5 w-5" />
          <div>
            <div className="text-mono ba-text-base font-bold uppercase tracking-widest">{verdict}</div>
            {score !== undefined && <div className="text-mono ba-text-2xs opacity-80">score: {score}</div>}
          </div>
        </div>
        {collapsible && <ChevronRight className={"h-4 w-4 transition-transform " + (expanded ? "rotate-90" : "")} />}
      </button>
      {expanded && details && details.length > 0 && (
        <div className="border-t border-current/20 px-4 py-2">
          <ul className="space-y-1">
            {details.map((d, i) => (
              <li key={i} className="text-mono ba-text-sm leading-relaxed">• {d}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
