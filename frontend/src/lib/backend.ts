import { useState, useEffect, useCallback } from "react";
import { storageGet, storageSet, storageRemove } from "@/lib/storage";

const LS_KEY = "beyondlabs.backendUrl";
const DEFAULT_URL =
  (import.meta.env.VITE_BEYONDLABS_API as string | undefined) ||
  "http://localhost:8000";

export function getBackendUrl(): string {
  return storageGet(LS_KEY, DEFAULT_URL);
}

export function setBackendUrl(url: string) {
  if (url && url.trim()) storageSet(LS_KEY, url.trim().replace(/\/+$/, ""));
  else storageRemove(LS_KEY);
}

export type BackendStatus = "unknown" | "checking" | "online" | "offline";

export type BackendPingResult = { ok: boolean; ms: number };

export async function pingBackend(signal?: AbortSignal): Promise<BackendPingResult> {
  const url = getBackendUrl();
  const start = performance.now();
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 3500);
    const res = await fetch(`${url}/api/hackingtool/categories`, {
      method: "GET",
      signal: signal ?? ctl.signal,
    });
    clearTimeout(t);
    const ms = Math.round(performance.now() - start);
    return { ok: res.ok, ms };
  } catch {
    const ms = Math.round(performance.now() - start);
    return { ok: false, ms };
  }
}

export type RunToolResponse = {
  tool_id?: string;
  command?: string;
  status?: "completed" | "failed" | "timeout" | "error" | "simulated";
  return_code?: number;
  stdout?: string;
  stderr?: string;
  error?: string;
  suggestion?: string;
};

export function useBackendStatus() {
  const [status, setStatus] = useState<BackendStatus>("unknown");
  const [latency, setLatency] = useState(0);

  const check = useCallback(async () => {
    setStatus("checking");
    const result = await pingBackend();
    setLatency(result.ms);
    setStatus(result.ok ? "online" : "offline");
  }, []);

  useEffect(() => {
    void check();
    const id = setInterval(check, 30000);
    return () => clearInterval(id);
  }, [check]);

  return { status, latency, check, online: status === "online" };
}

export async function runToolRemote(input: {
  category_id: string;
  tool_id: string;
  target?: string;
  args?: string;
}, signal?: AbortSignal): Promise<RunToolResponse> {
  const url = getBackendUrl();
  const res = await fetch(`${url}/api/hackingtool/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
    signal,
  });
  if (!res.ok) {
    throw new Error(`backend ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as RunToolResponse;
}
