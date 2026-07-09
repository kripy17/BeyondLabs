const LS_KEY = "beyondarch.backendUrl";
const DEFAULT_URL =
  (import.meta.env.VITE_BEYONDARCH_API as string | undefined) ||
  "http://localhost:8000";

export function getBackendUrl(): string {
  if (typeof window === "undefined") return DEFAULT_URL;
  try {
    return localStorage.getItem(LS_KEY) || DEFAULT_URL;
  } catch {
    return DEFAULT_URL;
  }
}

export function setBackendUrl(url: string) {
  try {
    if (url && url.trim()) localStorage.setItem(LS_KEY, url.trim().replace(/\/+$/, ""));
    else localStorage.removeItem(LS_KEY);
  } catch {}
}

export type BackendStatus = "unknown" | "checking" | "online" | "offline";

export async function pingBackend(signal?: AbortSignal): Promise<boolean> {
  const url = getBackendUrl();
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 3500);
    const res = await fetch(`${url}/api/hackingtool/categories`, {
      method: "GET",
      signal: signal ?? ctl.signal,
    });
    clearTimeout(t);
    return res.ok;
  } catch {
    return false;
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

export async function runToolRemote(input: {
  category_id: string;
  tool_id: string;
  target?: string;
  args?: string;
}): Promise<RunToolResponse> {
  const url = getBackendUrl();
  const res = await fetch(`${url}/api/hackingtool/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    throw new Error(`backend ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as RunToolResponse;
}
