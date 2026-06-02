import { postJson } from "../lib/apiClient"

export function base64Transform(text, action) {
  return postJson("/api/utils/base64", { text, action })
}

export function urlCodecTransform(text, action) {
  return postJson("/api/utils/url-codec", { text, action })
}

export function parseUrlUtility(url) {
  return postJson("/api/utils/url-parse", { url })
}

export function decodeJwt(token) {
  return postJson("/api/utils/jwt/decode", { token })
}

export function convertTimestamp(value) {
  return postJson("/api/utils/timestamp/convert", { value })
}

export function safeAnalyzeUrl(payload) {
  return postJson("/api/url/safe-analyze", {
    url: payload.url,
    allow_live_fetch: Boolean(payload.allow_live_fetch),
    max_redirects: payload.max_redirects ?? 5,
    timeout_seconds: payload.timeout_seconds ?? 8,
    allow_private_targets: Boolean(payload.allow_private_targets),
  }, 35000)
}
