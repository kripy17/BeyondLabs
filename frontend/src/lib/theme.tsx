import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

export type ThemeId =
  | "terminal-noir"
  | "soc-console"
  | "editorial-dark"
  | "solar-flare"
  | "synthwave-grid"
  | "brutalist-light"
  | "newsprint-dark"
  | "custom";

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


const STORAGE_KEY = "beyondarch-theme";
const DEFAULT: ThemeId = "terminal-noir";

type Ctx = { theme: ThemeId; setTheme: (t: ThemeId) => void };
const ThemeCtx = createContext<Ctx>({ theme: DEFAULT, setTheme: () => {} });

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeId>(DEFAULT);

  useEffect(() => {
    const stored = (typeof window !== "undefined" && localStorage.getItem(STORAGE_KEY)) as ThemeId | null;
    if (stored && THEMES.some((t) => t.id === stored)) {
      setThemeState(stored);
    }
  }, []);

  useEffect(() => {
    if (typeof document !== "undefined") {
      const isLight = THEMES.find((t) => t.id === theme)?.isLight ?? false;
      document.documentElement.setAttribute("data-theme", theme);
      document.documentElement.classList.toggle("dark", !isLight);
    }
  }, [theme]);

  const setTheme = (t: ThemeId) => {
    setThemeState(t);
    if (typeof window !== "undefined") localStorage.setItem(STORAGE_KEY, t);
  };

  return <ThemeCtx.Provider value={{ theme, setTheme }}>{children}</ThemeCtx.Provider>;
}

export const useTheme = () => useContext(ThemeCtx);
