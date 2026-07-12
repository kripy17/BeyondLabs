/* Client-only artifact handoff between workspaces.
 * Stores a "pending" payload in localStorage that the destination
 * page can pick up on mount (mirrors reference repo behaviour). */

import { storageGet, storageSet, storageRemove } from "@/lib/storage";

export type Handoff = {
  kind: string;            // ioc kind: url, domain, ip, hash, email, raw
  value: string;
  source: string;          // origin route, e.g. "/phishing"
  ts: number;
};

const KEY = "beyondlabs.pendingArtifact";

export function sendArtifact(h: Omit<Handoff, "ts">) {
  storageSet(KEY, { ...h, ts: Date.now() });
}

export function takePendingArtifact(): Handoff | null {
  const raw = storageGet<Handoff | null>(KEY, null);
  if (!raw) return null;
  storageRemove(KEY);
  return raw;
}

export function peekPendingArtifact(): Handoff | null {
  const raw = storageGet<Handoff | null>(KEY, null);
  return raw;
}

/* ── Case notebook handoff ── */
export type CaseHandoff = { body: string; source: string; kind: string };
const CASE_KEY = "ba.pendingCaseEntry";

export function sendToCase(h: CaseHandoff) {
  storageSet(CASE_KEY, h);
}

export function takePendingCaseEntry(): CaseHandoff | null {
  const raw = storageGet<CaseHandoff | null>(CASE_KEY, null);
  if (!raw) return null;
  storageRemove(CASE_KEY);
  return raw;
}
