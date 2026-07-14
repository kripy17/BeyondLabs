export type Severity = "info" | "low" | "medium" | "high" | "critical";

export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityTone(sev: Severity): "info" | "warning" | "destructive" {
  switch (sev) {
    case "critical": return "destructive";
    case "high": return "destructive";
    case "medium": return "warning";
    case "low": return "info";
    case "info": return "info";
  }
}
