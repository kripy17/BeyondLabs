import { type Severity } from "@/lib/severity";

export type TriageStatus = "open" | "in_review" | "escalated" | "dismissed";

export type TriageItem = {
  id: string;
  ts: string;
  title: string;
  description: string;
  severity: Severity;
  source: string;
  sourceUrl?: string;
  status: TriageStatus;
  notes: string;
  tags: string[];
  updated: number;
};

export const LS_KEY = "ba.triage.v1";

export const STATUS_TONE: Record<TriageStatus, "default" | "warning" | "success" | "destructive" | "info"> = {
  open: "default",
  in_review: "warning",
  escalated: "destructive",
  dismissed: "info",
};

export const STATUS_ORDER: Record<TriageStatus, number> = {
  open: 0,
  in_review: 1,
  escalated: 2,
  dismissed: 3,
};

export function loadItems(): TriageItem[] {
  try {
    const raw = localStorage.getItem(LS_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function saveItems(items: TriageItem[]) {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(items));
  } catch {}
}

export function genId(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

export function statusLabel(s: TriageStatus): string {
  switch (s) {
    case "open": return "open";
    case "in_review": return "in review";
    case "escalated": return "escalated";
    case "dismissed": return "dismissed";
  }
}

export const STATUSES: TriageStatus[] = ["open", "in_review", "escalated", "dismissed"];

export const SOURCE_OPTIONS = ["manual", "siem", "detection", "phishing", "parser", "case"];
