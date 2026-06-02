import { postJson } from "../lib/apiClient"

export function passiveRecon(target, fetchOptions = {}) {
  return postJson("/api/recon/passive", {
    target,
    fetch_mode: fetchOptions.mode || "head_only",
    follow_redirects: Boolean(fetchOptions.follow_redirects),
    timeout_seconds: Number(fetchOptions.timeout_seconds || 8),
    fetch_web_files: Boolean(fetchOptions.fetch_web_files),
  })
}

export function runReconDnsLookup({ target, confirmPermission = false }) {
  return postJson("/api/recon/dns", {
    target,
    confirm_permission: Boolean(confirmPermission),
  }, 45000)
}

export function runReconNmapScan({ target, mode = "quick_tcp", confirmPermission = false, allowPrivate = false }) {
  return postJson("/api/recon/nmap", {
    target,
    mode,
    confirm_permission: Boolean(confirmPermission),
    allow_private: Boolean(allowPrivate),
  }, 150000)
}

export function runReconNmapCustom({ command, confirmPermission = false, allowPrivate = false }) {
  return postJson("/api/recon/nmap-custom", {
    command,
    confirm_permission: Boolean(confirmPermission),
    allow_private: Boolean(allowPrivate),
  }, 150000)
}

export function runReconWebExposure({ target, confirmPermission = false, timeoutSeconds = 8 }) {
  return postJson("/api/recon/web-exposure", {
    target,
    confirm_permission: Boolean(confirmPermission),
    timeout_seconds: Number(timeoutSeconds || 8),
  }, 45000)
}
