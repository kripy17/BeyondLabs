import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { storageGet, storageSet } from "@/lib/storage";

export type ThemeId =
  | "terminal-noir"
  | "soc-console"
  | "editorial-dark"
  | "solar-flare"
  | "synthwave-grid"
  | "brutalist-light"
  | "newsprint-dark"
  | "custom";

export type ThemeMode = "auto" | "light" | "dark";

export const THEMES: { id: ThemeId; name: string; description: string; swatch: string[]; isLight?: boolean }[] = [
  { id: "terminal-noir",   name: "Terminal Noir",  description: "Pitch black · neon green CRT",    swatch: ["#020202", "#0a0a0a", "#39ff14"] },
  { id: "soc-console",     name: "SOC Console",    description: "Deep slate · cyan signal",        swatch: ["#0b1220", "#16243a", "#22d3ee"] },
  { id: "editorial-dark",  name: "Editorial Dark", description: "Warm dark · single red alert",    swatch: ["#191614", "#241f1c", "#e11d48"] },
  { id: "solar-flare",     name: "Solar Flare",    description: "Near-black · amber glow",         swatch: ["#0d0a06", "#1a140a", "#f59e0b"] },
  { id: "synthwave-grid",  name: "Synthwave Grid", description: "Indigo dusk · hot pink + cyan",   swatch: ["#0b0420", "#ff2e9a", "#22d3ee"] },
  { id: "newsprint-dark",  name: "Late Edition",   description: "Night press · amber + cyan slabs", swatch: ["#10131b", "#f1ead6", "#f2b84b"] },
  { id: "brutalist-light", name: "Broadsheet",     description: "Paper · ink · cobalt + red slabs", swatch: ["#f5f0e3", "#25211b", "#1f5fbf"], isLight: true },
  { id: "custom",          name: "Custom",         description: "Build your own — colors, mode",   swatch: ["#0f172a", "#1e293b", "#22d3ee"] },
];

const STORAGE_KEY = "beyondlabs-theme";
const MODE_KEY = "beyondlabs-theme-mode";
const DEFAULT: ThemeId = "soc-console";

type Ctx = { theme: ThemeId; setTheme: (t: ThemeId) => void; mode: ThemeMode; setMode: (m: ThemeMode) => void };
const ThemeCtx = createContext<Ctx>({ theme: DEFAULT, setTheme: () => {}, mode: "auto", setMode: () => {} });

function getInitialTheme(): ThemeId {
  const stored = storageGet<ThemeId>(STORAGE_KEY, DEFAULT);
  if (THEMES.some((t) => t.id === stored)) return stored;
  return DEFAULT;
}

function applyThemeAndMode(theme: ThemeId, mode: ThemeMode) {
  const isLight = THEMES.find((t) => t.id === theme)?.isLight ?? false;
  document.documentElement.setAttribute("data-theme", theme);
  document.documentElement.setAttribute("data-mode", mode);
  if (mode === "light") {
    document.documentElement.classList.remove("dark");
  } else if (mode === "dark") {
    document.documentElement.classList.add("dark");
  } else {
    document.documentElement.classList.toggle("dark", !isLight);
  }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeId>(getInitialTheme);
  const [mode, setModeState] = useState<ThemeMode>(() => storageGet<ThemeMode>(MODE_KEY, "auto"));

  useEffect(() => {
    applyThemeAndMode(theme, mode);
  }, [theme, mode]);

  const setTheme = (t: ThemeId) => {
    setThemeState(t);
    storageSet(STORAGE_KEY, t);
  };

  const setMode = (m: ThemeMode) => {
    setModeState(m);
    storageSet(MODE_KEY, m);
  };

  return <ThemeCtx.Provider value={{ theme, setTheme, mode, setMode }}>{children}</ThemeCtx.Provider>;
}

export const useTheme = () => useContext(ThemeCtx);
