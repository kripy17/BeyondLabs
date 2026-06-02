import { useCallback, useEffect, useState } from "react"

const SESSION_PREFIX = "beyondarch.session."

export function useSessionState(key, defaultValue) {
  const storageKey = SESSION_PREFIX + key
  const [value, setValue] = useState(() => {
    try {
      const saved = sessionStorage.getItem(storageKey)
      return saved !== null ? JSON.parse(saved) : defaultValue
    } catch {
      return defaultValue
    }
  })

  useEffect(() => {
    try {
      if (value === undefined || value === null) {
        sessionStorage.removeItem(storageKey)
      } else {
        sessionStorage.setItem(storageKey, JSON.stringify(value))
      }
    } catch {} // eslint-disable-line no-empty
  }, [storageKey, value])

  const reset = useCallback(() => {
    setValue(defaultValue)
    try { sessionStorage.removeItem(storageKey) } catch {} // eslint-disable-line no-empty
  }, [defaultValue, storageKey])

  return [value, setValue, reset]
}
