/* Client-only artifact handoff between workspaces.
 * Stores a "pending" payload in localStorage that the destination
 * page can pick up on mount (mirrors reference repo behaviour). */

export type Handoff = {
  kind: string;            // ioc kind: url, domain, ip, hash, email, raw
  value: string;
  source: string;          // origin route, e.g. "/phishing"
  ts: number;
};

const KEY = "beyondlabs.pendingArtifact";

export function sendArtifact(h: Omit<Handoff, "ts">) {
  if (typeof window === "undefined") return;
  try { localStorage.setItem(KEY, JSON.stringify({ ...h, ts: Date.now() })); } catch {}
}

export function takePendingArtifact(): Handoff | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return null;
    localStorage.removeItem(KEY);
    return JSON.parse(raw) as Handoff;
  } catch { return null; }
}

export function peekPendingArtifact(): Handoff | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as Handoff) : null;
  } catch { return null; }
}

/* ── Case notebook handoff ── */
export type CaseHandoff = { body: string; source: string; kind: string };
const CASE_KEY = "ba.pendingCaseEntry";

export function sendToCase(h: CaseHandoff) {
  if (typeof window === "undefined") return;
  try { localStorage.setItem(CASE_KEY, JSON.stringify(h)); } catch {}
}

export function takePendingCaseEntry(): CaseHandoff | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem(CASE_KEY);
    if (!raw) return null;
    localStorage.removeItem(CASE_KEY);
    return JSON.parse(raw) as CaseHandoff;
  } catch { return null; }
}
