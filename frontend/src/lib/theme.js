export const THEME_STORAGE_KEY = "beyondarch.theme"
const LEGACY_THEME_STORAGE_KEY = "beyondarch_theme_v1"

export const THEMES = {
  dark: {
    label: "Dark SOC",
    description: "Dark command-deck theme for focused analyst work.",
  },
  light: {
    label: "Light analyst",
    description: "Default light workspace theme for screenshots, docs, and daytime review.",
  },
  blackout: {
    label: "Dark SOC",
    description: "Legacy alias for the default dark command-deck theme.",
  },
  "soc-glass": {
    label: "Dark SOC",
    description: "Legacy alias for the default dark command-deck theme.",
  },
}

export function normalizeTheme(value) {
  if (!value) return "light"
  if (value === "light") return "light"
  return "dark"
}

export function loadThemePreference() {
  try {
    const preferred = localStorage.getItem(THEME_STORAGE_KEY) || localStorage.getItem(LEGACY_THEME_STORAGE_KEY)
    return normalizeTheme(preferred)
  } catch {
    return "light"
  }
}

export function applyTheme(theme) {
  const next = normalizeTheme(theme)
  document.documentElement.classList.toggle("light", next === "light")
  document.documentElement.classList.toggle("dark", next === "dark")
  document.documentElement.dataset.theme = next
  document.documentElement.style.colorScheme = next
  return next
}

export function saveThemePreference(theme) {
  const next = normalizeTheme(theme)
  localStorage.setItem(THEME_STORAGE_KEY, next)
  localStorage.removeItem(LEGACY_THEME_STORAGE_KEY)
  applyTheme(next)
  window.dispatchEvent(new CustomEvent("beyondarch-theme-change", { detail: { theme: next } }))
  return next
}
