import { BookOpen, Globe, Moon, Sun, Terminal } from "lucide-react"

export const THEME_STORAGE_KEY = "beyondarch.theme"
const LEGACY_THEME_STORAGE_KEY = "beyondarch_theme_v1"

export const THEMES = {
  blue: {
    id: "blue",
    label: "Blue SOC",
    description: "Cobalt command-deck theme for focused analyst work",
    icon: Moon,
    base: "dark",
    variables: {},
  },
  cyberpunk: {
    id: "cyberpunk",
    label: "Cyberpunk",
    description: "Neon override with pink, cyan, and yellow accents",
    icon: Sun,
    base: "dark",
    variables: {},
  },
  terminal: {
    id: "terminal",
    label: "Terminal",
    description: "Green-on-black CRT monochrome terminal",
    icon: Terminal,
    base: "dark",
    variables: {},
  },
  spacePurple: {
    id: "spacePurple",
    label: "Space Purple",
    description: "Glass-morphism orbital command with violet nebula",
    icon: Globe,
    base: "dark",
    variables: {},
  },
  paperBrutal: {
    id: "paperBrutal",
    label: "Paper",
    description: "Warm paper brutalism with per-sector color accents",
    icon: BookOpen,
    base: "light",
    variables: {},
  },
}

export function getAllThemes() {
  return Object.values(THEMES)
}

export function getTheme(id) {
  return THEMES[id] || THEMES.blue
}

export function loadThemePreference() {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY) || localStorage.getItem(LEGACY_THEME_STORAGE_KEY) || "blue"
  } catch {
    return "blue"
  }
}

export function applyTheme(themeId) {
  const theme = getTheme(themeId)
  const root = document.documentElement

  root.classList.toggle("theme-cyberpunk", theme.id === "cyberpunk")
  root.classList.toggle("theme-terminal", theme.id === "terminal")
  root.classList.toggle("theme-space-purple", theme.id === "spacePurple")
  root.classList.toggle("theme-paper", theme.id === "paperBrutal")
  root.classList.toggle("dark", theme.base === "dark")
  root.classList.toggle("light", theme.base === "light")
  root.dataset.theme = theme.id
  root.style.colorScheme = theme.base === "light" ? "light" : "dark"

  return themeId
}

export function saveThemePreference(themeId) {
  const theme = getTheme(themeId)
  localStorage.setItem(THEME_STORAGE_KEY, theme.id)
  localStorage.removeItem(LEGACY_THEME_STORAGE_KEY)
  applyTheme(theme.id)
  window.dispatchEvent(new CustomEvent("beyondarch-theme-change", { detail: { theme: theme.id } }))
  return theme.id
}
