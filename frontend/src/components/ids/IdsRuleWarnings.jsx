import { AlertTriangle, CheckCircle2 } from "lucide-react"

export default function IdsRuleWarnings({ review }) {
  const warnings = review?.warnings || []
  return (
    <section className="ba-utility-output-card space-y-3">
      <div className="flex items-center justify-between gap-3">
        <h3>Validation / warnings</h3>
        <span className={`ba-chip ${warnings.length ? "ba-status-warning" : "ba-status-local"}`}>{warnings.length ? `${warnings.length} review notes` : "no blocking warning"}</span>
      </div>
      {warnings.length ? (
        <div className="space-y-2">
          {warnings.map((warning) => (
            <p key={warning} className="ba-card" style={{ borderColor: "color-mix(in srgb, var(--neo-amber) 30%, transparent)", background: "color-mix(in srgb, var(--neo-amber) 10%, transparent)", color: "var(--neo-amber)" }}>
              <AlertTriangle className="mr-2 inline h-4 w-4" />{warning}
            </p>
          ))}
        </div>
      ) : (
        <p className="ba-card" style={{ borderColor: "color-mix(in srgb, var(--neo-emerald) 30%, transparent)", background: "color-mix(in srgb, var(--neo-emerald) 10%, transparent)", color: "var(--neo-emerald)" }}>
          <CheckCircle2 className="mr-2 inline h-4 w-4" />No obvious static validation issue found. Still validate against real Snort/Suricata syntax locally.
        </p>
      )}
    </section>
  )
}
