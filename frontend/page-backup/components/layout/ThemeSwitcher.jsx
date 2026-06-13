import { useCallback, useEffect, useRef, useState } from "react"
import { Check } from "lucide-react"
import { getAllThemes, loadThemePreference, saveThemePreference } from "../../lib/theme"

export default function ThemeSwitcher() {
  const [open, setOpen] = useState(false)
  const [current, setCurrent] = useState(() => loadThemePreference())
  const ref = useRef(null)

  const themes = getAllThemes()
  const CurrentIcon = themes.find((t) => t.id === current)?.icon || themes[0].icon

  const handleSelect = useCallback((id) => {
    saveThemePreference(id)
    setCurrent(id)
    setOpen(false)
  }, [])

  useEffect(() => {
    function handleThemeChange(e) {
      setCurrent(e.detail?.theme || loadThemePreference())
    }
    function handleClickOutside(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    window.addEventListener("beyondarch-theme-change", handleThemeChange)
    window.addEventListener("pointerdown", handleClickOutside)
    return () => {
      window.removeEventListener("beyondarch-theme-change", handleThemeChange)
      window.removeEventListener("pointerdown", handleClickOutside)
    }
  }, [])

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        type="button"
        className="cyber-btn"
        aria-label="Switch theme"
        aria-expanded={open}
        title="Switch theme"
        onClick={() => setOpen((v) => !v)}
        style={{ gap: ".35rem", width: "auto", padding: ".35rem .58rem", fontSize: ".72rem" }}
      >
        <CurrentIcon className="h-4 w-4" />
        <span style={{ fontSize: ".72rem", fontWeight: 800, textTransform: "uppercase", letterSpacing: ".1em", fontFamily: '"JetBrains Mono", ui-monospace, monospace' }}>Theme</span>
      </button>

      {open && (
        <div className="cyber-theme-dropdown"
          style={{
            position: "absolute", top: "100%", right: 0, zIndex: 200,
            minWidth: "11rem", marginTop: ".35rem",
            padding: ".25rem",
          }}
        >
          {themes.map((theme) => {
            const Icon = theme.icon
            const isActive = theme.id === current
            return (
              <button
                key={theme.id}
                type="button"
                onClick={() => handleSelect(theme.id)}
                style={{
                  display: "flex", alignItems: "center", gap: ".5rem",
                  width: "100%", padding: ".35rem .5rem",
                  border: "none", cursor: "pointer",
                  background: isActive ? "var(--clr-accent-30)" : "transparent",
                  color: isActive ? "var(--clr-accent)" : "var(--clr-text-sub)",
                  fontSize: ".78rem", fontWeight: isActive ? 950 : 700,
                  textAlign: "left", fontFamily: "inherit",
                }}
                onMouseEnter={(e) => { if (!isActive) e.currentTarget.style.background = "var(--clr-hover)" }}
                onMouseLeave={(e) => { if (!isActive) e.currentTarget.style.background = "transparent" }}
              >
                <Icon className="h-3.5 w-3.5" />
                <span style={{ flex: 1 }}>{theme.label}</span>
                {isActive && <Check className="h-3 w-3" />}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}
