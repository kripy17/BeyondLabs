/* Client-only artifact handoff between workspaces.
 * Stores a "pending" payload in localStorage that the destination
 * page can pick up on mount (mirrors reference repo behaviour). */

export type Handoff = {
  kind: string;            // ioc kind: url, domain, ip, hash, email, raw
  value: string;
  source: string;          // origin route, e.g. "/phishing"
  ts: number;
};

const KEY = "beyondarch.pendingArtifact";

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
