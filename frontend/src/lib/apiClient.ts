const API_BASE = (import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000").replace(/\/$/, "")
const REQUEST_TIMEOUT = Number.parseInt(import.meta.env.VITE_REQUEST_TIMEOUT || "30000", 10)
const DEBUG_API_LOGS = import.meta.env.VITE_DEBUG_API_LOGS === "true"

interface RequestOptions {
  payload?: unknown;
  body?: FormData;
  headers?: Record<string, string>;
  timeout?: number;
  signal?: AbortSignal;
  retry?: boolean | { attempts: number; baseDelayMs: number };
}

const RETRIABLE_METHODS = new Set(["GET", "HEAD"]);

function isRetriableError(err: unknown): boolean {
  if (err instanceof DOMException && err.name === "AbortError") return true;
  if (err instanceof TypeError) return true;
  const msg = err instanceof Error ? err.message : "";
  return /\b(50[0-9]|timeout|network)/i.test(msg);
}

export class UserFacingError extends Error {
  suggestion: string | undefined
  constructor(message: string, suggestion?: string) {
    super(message)
    this.name = "UserFacingError"
    this.suggestion = suggestion
  }
}

export function userFacingError(err: unknown): UserFacingError {
  if (err instanceof UserFacingError) return err

  const msg = err instanceof Error ? err.message : String(err)
  const lower = msg.toLowerCase()

  if (err instanceof TypeError || lower.includes("failed to fetch") || lower.includes("networkerror") || lower.includes("network error")) {
    return new UserFacingError(
      "Backend unreachable",
      "Check that the FastAPI server is running on port 8000.\nRun `docker compose up` or `cd backend && python -m app.main`.",
    )
  }

  if (err instanceof DOMException && err.name === "AbortError") {
    return new UserFacingError(
      "Request timed out",
      "The scan may still be running — check the terminal for live output.",
    )
  }

  if (lower.includes("timeout")) {
    return new UserFacingError(
      "Request timed out",
      "If this is a long scan, try running it from the terminal tab with a longer timeout.",
    )
  }

  if (lower.includes("connection refused") || lower.includes("econnrefused")) {
    return new UserFacingError(
      "Connection refused",
      "The backend is not accepting connections.\nTry `docker compose up` or restart the FastAPI server.",
    )
  }

  if (lower.includes("nmap") && (lower.includes("not found") || lower.includes("cannot") || lower.includes("error"))) {
    return new UserFacingError(
      "Nmap not found on backend",
      "Install nmap on the backend host:\n`apt install nmap` (Debian) / `brew install nmap` (macOS).",
    )
  }

  if (lower.includes("command not found") || lower.includes("not found")) {
    return new UserFacingError(
      "Required binary not found",
      "Install the missing tool on the backend host. Check the terminal for which binary is missing.",
    )
  }

  if (lower.includes("500")) {
    return new UserFacingError(
      "Backend error (500)",
      "An internal error occurred. Check the terminal or backend logs for details.",
    )
  }

  return new UserFacingError(msg)
}

function joinUrl(path: string): string {
  if (/^https?:\/\//i.test(path)) return path
  return `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`
}

function logRequest(method: string, path: string, status: number, duration: number, error: string | null = null): void {
  if (!DEBUG_API_LOGS && !error) return

  const message = `${method} ${path} ${status || "network"} (${duration}ms)`

  if (error) {
    console.error(`${message} - ${error}`)
  } else {
    console.info(message)
  }
}

function createTimeoutSignal(timeoutMs: number): { signal: AbortSignal; cleanup: () => void } {
  const controller = new AbortController()
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs)

  return {
    signal: controller.signal,
    cleanup: () => window.clearTimeout(timeoutId),
  }
}

function combineSignals(s1: AbortSignal, s2: AbortSignal): AbortSignal {
  const controller = new AbortController()
  function onAbort() { controller.abort() }
  if (s1.aborted || s2.aborted) { controller.abort(); return controller.signal }
  s1.addEventListener("abort", onAbort, { once: true })
  s2.addEventListener("abort", onAbort, { once: true })
  return controller.signal
}

async function parseResponse(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") || ""

  if (contentType.includes("application/json")) {
    return response.json()
  }

  const text = await response.text()
  if (!text) return {}

  try {
    return JSON.parse(text)
  } catch {
    return { message: text.slice(0, 2000) }
  }
}

function messageFromErrorPayload(data: unknown, fallback: string): string {
  if (!data) return fallback
  if (typeof data === "string") return data
  if (typeof data === "object" && data !== null) {
    if ("detail" in data && typeof data.detail === "string") return data.detail
    if ("detail" in data && Array.isArray(data.detail)) return data.detail.map((item: { msg?: string } | string) => typeof item === "string" ? item : item.msg || JSON.stringify(item)).join("; ")
    if ("error" in data && typeof data.error === "string") return data.error
    if ("message" in data && typeof data.message === "string") return data.message
  }
  return fallback
}

async function requestJson<T = any>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
  const { payload, body, headers = {}, timeout = REQUEST_TIMEOUT, signal: externalSignal, retry } = options

  const maxAttempts = retry === true ? 3 : typeof retry === "object" ? retry.attempts : 1
  const baseDelay = retry === true ? 500 : typeof retry === "object" ? retry.baseDelayMs : 0
  const shouldRetry = maxAttempts > 1 && RETRIABLE_METHODS.has(method)

  let lastErr: unknown

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const startTime = performance.now()
    const { signal: timeoutSignal, cleanup } = createTimeoutSignal(timeout)
    const combinedSignal = externalSignal
      ? combineSignals(externalSignal, timeoutSignal)
      : timeoutSignal

    if (attempt > 0) {
      const delay = baseDelay * Math.pow(2, attempt - 1)
      await new Promise(r => setTimeout(r, delay))
    }

    try {
      const requestOptions: RequestInit & { headers: Record<string, string> } = {
        method,
        headers,
        signal: combinedSignal,
      }

      if (payload !== undefined) {
        requestOptions.headers = {
          "Content-Type": "application/json",
          ...headers,
        }
        requestOptions.body = JSON.stringify(payload)
      } else if (body !== undefined) {
        requestOptions.body = body
      }

      const response = await fetch(joinUrl(path), requestOptions)
      const data = await parseResponse(response)
      const duration = Math.round(performance.now() - startTime)

      if (!response.ok) {
        const error = messageFromErrorPayload(data, `${method} request failed with status ${response.status}`)
        logRequest(method, path, response.status, duration, error)
        const ufe = userFacingError(error)
        if (response.status >= 500) ufe.suggestion = "An internal error occurred. Check the terminal or backend logs for details."
        throw ufe
      }

      logRequest(method, path, response.status, duration)
      cleanup()
      return data as T
    } catch (err) {
      cleanup()
      const duration = Math.round(performance.now() - startTime)

      if (err instanceof DOMException && err.name === "AbortError") {
        logRequest(method, path, 0, duration, "Request timeout")
        if (shouldRetry && attempt < maxAttempts - 1) { lastErr = err; continue }
        throw userFacingError(err)
      }

      logRequest(method, path, 0, duration, err instanceof Error ? err.message : "Network request failed")

      if (shouldRetry && attempt < maxAttempts - 1 && isRetriableError(err)) {
        lastErr = err
        continue
      }

      throw err instanceof UserFacingError ? err : userFacingError(err)
    }
  }

  throw lastErr
}

export async function postJson<T = any>(path: string, payload?: unknown, timeout?: number, signal?: AbortSignal): Promise<T> {
  return requestJson<T>("POST", path, { payload, timeout, signal })
}

export async function getJson<T = any>(path: string, timeout?: number, signal?: AbortSignal): Promise<T> {
  return requestJson<T>("GET", path, { timeout, signal, retry: true })
}

export async function uploadFile<T = any>(path: string, file: File, timeout?: number, signal?: AbortSignal): Promise<T> {
  const formData = new FormData()
  formData.append("file", file)
  return requestJson<T>("POST", path, { body: formData, timeout, signal })
}

export { API_BASE, REQUEST_TIMEOUT }
