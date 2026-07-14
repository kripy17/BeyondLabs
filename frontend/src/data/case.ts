import { ShieldAlert, Siren, Activity, StickyNote, Search, GitBranch, Crosshair } from "lucide-react";

export type EntryKind = "note" | "evidence" | "decision" | "action" | "ioc";
export type Entry = { id: string; ts: string; kind: EntryKind; body: string };
export type Case = {
  id: string;
  title: string;
  tags: string[];
  createdAt: string;
  state: "active" | "closed";
  entries: Entry[];
};

export const LS_KEY = "ba.cases.v2";
export const LS_ACTIVE = "ba.cases.active";

export const KIND_TONE: Record<EntryKind, "default" | "primary" | "warning" | "success" | "destructive"> = {
  note: "default", evidence: "primary", decision: "warning", action: "success", ioc: "destructive",
};
export const KIND_ICON: Record<EntryKind, typeof StickyNote> = {
  note: StickyNote, evidence: Search, decision: GitBranch, action: Crosshair, ioc: Siren,
};
export const KIND_COLOR: Record<EntryKind, string> = {
  note: "bg-muted-foreground/40", evidence: "bg-primary/60", decision: "bg-warning/60", action: "bg-success/60", ioc: "bg-destructive/60",
};

export function loadCases(): Case[] {
  try { const raw = localStorage.getItem(LS_KEY); return raw ? JSON.parse(raw) as Case[] : []; }
  catch { return []; }
}
export function saveCases(list: Case[]) {
  try {
    const serialized = JSON.stringify(list);
    if (serialized.length > 5_000_000) { return; }
    localStorage.setItem(LS_KEY, serialized);
  } catch { /* noop */ }
}
export function newId(prefix: string) {
  return `${prefix}-${crypto.randomUUID().slice(0, 8)}`;
}
export function newCaseTitle() {
  const d = new Date();
  const yy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  return `BA-${yy}${mm}${dd}-${hh}${mi}`;
}

export function autoDetectKind(text: string): EntryKind {
  if (!text.trim()) return "note";
  if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(text) || /https?:\/\//.test(text) || /\b[a-f0-9]{32}\b/i.test(text) || /\b[a-f0-9]{40}\b/i.test(text) || /\b[a-f0-9]{64}\b/i.test(text)) return "ioc";
  if (/^(decision|verdict|conclusion):/im.test(text)) return "decision";
  if (/^(action|todo|investigate|escalate):/im.test(text)) return "action";
  if (/\b(analysis|found|detected|evidence|observed):/im.test(text)) return "evidence";
  return "note";
}

export type TemplateDef = {
  id: string;
  label: string;
  icon: import("lucide-react").LucideIcon;
  entries: { kind: EntryKind; body: string }[];
};
export const CASE_TEMPLATES: TemplateDef[] = [
  {
    id: "phishing", label: "Phishing Triage", icon: ShieldAlert,
    entries: [
      { kind: "evidence", body: "## Header Analysis\n- **From:** \n- **Reply-To:** \n- **SPF:** \n- **DKIM:** \n- **DMARC:**" },
      { kind: "evidence", body: "## URL Analysis\n- **Original:** \n- **Redirect:** \n- **VT:**" },
      { kind: "evidence", body: "## Attachment\n- **Name:** \n- **Hash:** \n- **VT ratio:**" },
      { kind: "decision", body: "**Verdict:** [malicious / suspicious / benign]" },
      { kind: "action", body: "**Action:** [block sender / delete / escalate]" },
    ],
  },
  {
    id: "ransomware", label: "Ransomware Triage", icon: Siren,
    entries: [
      { kind: "evidence", body: "## Access\n- **Method:** \n- **Source IP:** \n- **User:**" },
      { kind: "evidence", body: "## Affected\n- **Hosts:** \n- **Count:**" },
      { kind: "evidence", body: "## Ransom Note\n- **File:** \n- **Contact:**" },
      { kind: "evidence", body: "## IOCs\n- **Hashes:** \n- **C2 IPs:** \n- **Registry:**" },
      { kind: "decision", body: "**Verdict:** [confirmed / suspicious / FP]" },
      { kind: "action", body: "**Action:** [isolate / block IOCs / notify]" },
    ],
  },
  {
    id: "suspicious-login", label: "Suspicious Login", icon: Activity,
    entries: [
      { kind: "evidence", body: "## Event\n- **Time:** \n- **User:** \n- **Source IP:** \n- **Geo:** \n- **UA:**" },
      { kind: "evidence", body: "## Risk\n- **Same IP before:** \n- **Impossible travel:** \n- **Known malicious IP:**" },
      { kind: "decision", body: "**Verdict:** [compromised / suspicious / valid]" },
      { kind: "action", body: "**Action:** [reset password / block IP / escalate]" },
    ],
  },
];
