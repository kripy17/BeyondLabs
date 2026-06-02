/**
 * Centralized API client with timeout, resilient JSON parsing, and optional debug logging.
 */

const API_BASE = (import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000").replace(/\/$/, "")
const REQUEST_TIMEOUT = Number.parseInt(import.meta.env.VITE_REQUEST_TIMEOUT || "30000", 10)
const DEBUG_API_LOGS = import.meta.env.VITE_DEBUG_API_LOGS === "true"

function joinUrl(path) {
  if (/^https?:\/\//i.test(path)) return path
  return `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`
}

function logRequest(method, path, status, duration, error = null) {
  if (!DEBUG_API_LOGS && !error) return

  const message = `${method} ${path} ${status || "network"} (${duration}ms)`

  if (error) {
    console.error(`${message} - ${error}`)
  } else {
    console.info(message)
  }
}

function createTimeoutSignal(timeoutMs) {
  const controller = new AbortController()
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs)

  return {
    signal: controller.signal,
    cleanup: () => window.clearTimeout(timeoutId),
  }
}

async function parseResponse(response) {
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

function messageFromErrorPayload(data, fallback) {
  if (!data) return fallback
  if (typeof data === "string") return data
  if (typeof data.detail === "string") return data.detail
  if (Array.isArray(data.detail)) return data.detail.map((item) => item.msg || JSON.stringify(item)).join("; ")
  if (typeof data.error === "string") return data.error
  if (typeof data.message === "string") return data.message
  return fallback
}

async function requestJson(method, path, options = {}) {
  const { payload, body, headers = {}, timeout = REQUEST_TIMEOUT } = options
  const startTime = performance.now()
  const { signal, cleanup } = createTimeoutSignal(timeout)

  try {
    const requestOptions = {
      method,
      headers,
      signal,
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
      throw new Error(error)
    }

    logRequest(method, path, response.status, duration)
    return data
  } catch (err) {
    const duration = Math.round(performance.now() - startTime)

    if (err?.name === "AbortError") {
      const message = `Request timeout after ${timeout}ms`
      logRequest(method, path, 0, duration, message)
      throw new Error(message, { cause: err })
    }

    logRequest(method, path, 0, duration, err?.message || "Network request failed")
    throw err
  } finally {
    cleanup()
  }
}

export async function postJson(path, payload, timeout = REQUEST_TIMEOUT) {
  return requestJson("POST", path, { payload, timeout })
}

export async function getJson(path, timeout = REQUEST_TIMEOUT) {
  return requestJson("GET", path, { timeout })
}

export async function uploadFile(path, file, timeout = REQUEST_TIMEOUT) {
  const formData = new FormData()
  formData.append("file", file)
  return requestJson("POST", path, { body: formData, timeout })
}

export { API_BASE, REQUEST_TIMEOUT }
