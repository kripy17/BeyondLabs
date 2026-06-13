import { useEffect } from "react"

const SEQUENCE_TIMEOUT = 800
const buffers = {}
let nextId = 0

export default function useShortcuts(shortcuts) {
  useEffect(() => {
    const id = `ks_${nextId++}`
    buffers[id] = ""

    function handleKey(event) {
      if (event.target.closest("input, textarea, select, [contenteditable]")) return
      if (event.ctrlKey || event.metaKey || event.altKey) return

      const key = event.key.toLowerCase()
      if (key === "escape") {
        buffers[id] = ""
        for (const s of shortcuts) {
          if (s.key === "Escape") { event.preventDefault(); s.action(event) }
        }
        return
      }

      if (key.length > 1) return
      if (event.key === "/" && event.shiftKey) return

      buffers[id] += key
      const seq = buffers[id]

      for (const s of shortcuts) {
        if (s.key === seq) {
          buffers[id] = ""
          event.preventDefault()
          s.action(event)
          return
        }
      }

      clearTimeout(buffers[`${id}_timer`])
      buffers[`${id}_timer`] = setTimeout(() => { buffers[id] = "" }, SEQUENCE_TIMEOUT)
    }

    window.addEventListener("keydown", handleKey)
    return () => {
      window.removeEventListener("keydown", handleKey)
      clearTimeout(buffers[`${id}_timer`])
      delete buffers[id]
      delete buffers[`${id}_timer`]
    }
  }, [shortcuts])
}
