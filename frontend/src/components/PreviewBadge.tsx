import { FlaskConical } from "lucide-react";

/* Small badge marking an output section as preview / demo data
 * (purely client-side computation, no backend). */
export function PreviewBadge({ label = "preview · demo data" }: { label?: string }) {
  return (
    <span
      title="This page runs purely client-side. Values are computed from your input or sample fixtures; no live backend is contacted."
      className="inline-flex items-center gap-1 rounded border border-dashed border-warning/50 bg-warning/10 px-1.5 py-0.5 text-mono text-[9px] uppercase tracking-widest text-warning"
    >
      <FlaskConical className="h-3 w-3" />
      {label}
    </span>
  );
}
