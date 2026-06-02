import { useEffect, useRef, useState } from "react"
import { AlertTriangle, X } from "lucide-react"
import { getJson } from "../../lib/apiClient"

const BANNER_HIDE_KEY = "ba:backend-banner-dismissed"

function isDismissed() {
  try { return sessionStorage.getItem(BANNER_HIDE_KEY) === "1" } catch { return false }
}

function markDismissed() {
  try { sessionStorage.setItem(BANNER_HIDE_KEY, "1") } catch {} // eslint-disable-line no-empty
}

export default function BaBackendBanner() {
  const [visible, setVisible] = useState(false)
  const dismissed = useRef(isDismissed())

  useEffect(() => {
    if (dismissed.current) return
    let mounted = true
    async function check() {
      try {
        await getJson("/health", 3000)
        if (mounted) setVisible(false)
      } catch {
        if (mounted) setVisible(true)
      }
    }
    check()
    const id = setInterval(check, 30000)
    return () => { mounted = false; clearInterval(id) }
  }, [])

  if (!visible) return null

  return (
    <div className="ba-backend-banner" role="alert">
      <AlertTriangle className="h-4 w-4" />
      <span>Backend unreachable — some features may be unavailable</span>
      <button type="button" onClick={() => { setVisible(false); markDismissed() }} aria-label="Dismiss">
        <X className="h-4 w-4" />
      </button>
    </div>
  )
}
