import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  ShieldHalf, ShieldCheck, Radar, Terminal, Cpu, Bug, Crosshair, Hexagon,
  Zap, Flame, Eye, Skull, Binary, Compass, type LucideIcon,
} from "lucide-react";
import { GROUPS } from "./workspaces";
import { useTheme } from "./theme";

export const BRAND_ICONS: { key: string; icon: LucideIcon }[] = [
  { key: "shield-half", icon: ShieldHalf },
  { key: "shield-check", icon: ShieldCheck },
  { key: "radar", icon: Radar },
  { key: "terminal", icon: Terminal },
  { key: "cpu", icon: Cpu },
  { key: "bug", icon: Bug },
  { key: "crosshair", icon: Crosshair },
  { key: "hexagon", icon: Hexagon },
  { key: "zap", icon: Zap },
  { key: "flame", icon: Flame },
  { key: "eye", icon: Eye },
  { key: "skull", icon: Skull },
  { key: "binary", icon: Binary },
  { key: "compass", icon: Compass },
];
export const getBrandIcon = (key: string): LucideIcon =>
  BRAND_ICONS.find((b) => b.key === key)?.icon ?? ShieldHalf;

export type SansFont =
  | "Space Grotesk" | "Inter" | "Outfit" | "Geist"
  | "DM Sans" | "Manrope" | "Plus Jakarta Sans" | "Sora";
export type MonoFont =
  | "JetBrains Mono" | "IBM Plex Mono" | "Fira Code" | "Geist Mono"
  | "Source Code Pro" | "Space Mono";
export type Density = "comfortable" | "compact";



export type CustomTheme = {
  isLight: boolean;
  background: string;
  foreground: string;
  card: string;
  border: string;
  muted: string;
  primary: string;
  accent: string;
  destructive: string;
};

export const DEFAULT_CUSTOM_THEME: CustomTheme = {
  isLight: false,
  background: "#0f172a",
  foreground: "#e2e8f0",
  card: "#131c2e",
  border: "#1f2a40",
  muted: "#1a2438",
  primary: "#22d3ee",
  accent: "#a78bfa",
  destructive: "#f87171",
};

export const CUSTOM_THEME_PRESETS: { name: string; theme: CustomTheme }[] = [
  { name: "Slate Cyan",    theme: DEFAULT_CUSTOM_THEME },
  { name: "Mint Forest",   theme: { isLight: false, background: "#06120d", foreground: "#d7f5e6", card: "#0b1c14", border: "#143626", muted: "#0f2419", primary: "#34d399", accent: "#fbbf24", destructive: "#f87171" } },
  { name: "Royal Plum",    theme: { isLight: false, background: "#140b22", foreground: "#ece4ff", card: "#1d1330", border: "#2e2148", muted: "#221836", primary: "#c084fc", accent: "#22d3ee", destructive: "#fb7185" } },
  { name: "Sand Paper",    theme: { isLight: true,  background: "#faf7f0", foreground: "#1c1917", card: "#ffffff", border: "#e7e2d5", muted: "#f1ecdf", primary: "#b45309", accent: "#0f766e", destructive: "#b91c1c" } },
  { name: "Arctic White",  theme: { isLight: true,  background: "#f8fafc", foreground: "#0f172a", card: "#ffffff", border: "#e2e8f0", muted: "#f1f5f9", primary: "#0ea5e9", accent: "#6366f1", destructive: "#dc2626" } },
];

export type DashboardSections = {
  commandStrip: boolean;
  workflowRibbon: boolean;
  metrics: boolean;
  continueRow: boolean;
  pinned: boolean;
  tracks: boolean;
  workspaces: boolean;
  footer: boolean;
};

export type Prefs = {
  brandName: string;
  brandTagline: string;
  brandIcon: string;
  accent: string | null;
  radius: number;
  density: Density;
  sansFont: SansFont;
  monoFont: MonoFont;
  fontScale: number; // 0.85 - 1.15 (root font-size multiplier)
  letterSpacing: number; // -0.02 - 0.06 (em)
  monoLigatures: boolean;
  panelOpacity: number; // 0.75 - 1
  zebraStripes: boolean;
  focusRingBoost: boolean;
  reduceMotion: boolean;
  reducedTransparency: boolean;
  highContrast: boolean;
  slashOpensPalette: boolean;
  showBreadcrumb: boolean;
  showTopbar: boolean;
  customTheme: CustomTheme;
  sidebar: {
    hiddenGroups: string[];
    pinned: string[];
    order: string[];
  };
  dashboardSections: DashboardSections;
};


const STORAGE_KEY = "ba.prefs.v1";

const DEFAULT: Prefs = {
  brandName: "BeyondLabs",
  brandTagline: "soc · workbench",
  brandIcon: "shield-half",
  accent: null,
  radius: 0.5,
  density: "comfortable",
  sansFont: "Space Grotesk",
  monoFont: "JetBrains Mono",
  fontScale: 1,
  letterSpacing: 0,
  monoLigatures: true,
  panelOpacity: 1,
  zebraStripes: true,
  focusRingBoost: false,
  reduceMotion: false,
  reducedTransparency: false,
  highContrast: false,
  slashOpensPalette: true,
  showBreadcrumb: true,
  showTopbar: true,
  customTheme: DEFAULT_CUSTOM_THEME,

  dashboardSections: {
    commandStrip: true,
    workflowRibbon: true,
    metrics: true,
    continueRow: true,
    pinned: true,
    tracks: true,
    workspaces: true,
    footer: true,
  },
  sidebar: {
    hiddenGroups: [],
    pinned: [],
    order: GROUPS.map((g) => g.label),
  },
};

type Ctx = {
  prefs: Prefs;
  setPrefs: (patch: Partial<Prefs>) => void;
  setSidebar: (patch: Partial<Prefs["sidebar"]>) => void;
  togglePin: (url: string) => void;
  toggleHidden: (group: string) => void;
  moveGroup: (label: string, dir: -1 | 1) => void;
  reset: () => void;
};

const PrefsCtx = createContext<Ctx>({
  prefs: DEFAULT,
  setPrefs: () => {},
  setSidebar: () => {},
  togglePin: () => {},
  toggleHidden: () => {},
  moveGroup: () => {},
  reset: () => {},
});

const SANS_STACK: Record<SansFont, string> = {
  "Space Grotesk":     `"Space Grotesk", ui-sans-serif, system-ui, sans-serif`,
  "Inter":             `"Inter", ui-sans-serif, system-ui, sans-serif`,
  "Outfit":            `"Outfit", ui-sans-serif, system-ui, sans-serif`,
  "Geist":             `"Geist", ui-sans-serif, system-ui, sans-serif`,
  "DM Sans":           `"DM Sans", ui-sans-serif, system-ui, sans-serif`,
  "Manrope":           `"Manrope", ui-sans-serif, system-ui, sans-serif`,
  "Plus Jakarta Sans": `"Plus Jakarta Sans", ui-sans-serif, system-ui, sans-serif`,
  "Sora":              `"Sora", ui-sans-serif, system-ui, sans-serif`,
};
const MONO_STACK: Record<MonoFont, string> = {
  "JetBrains Mono":  `"JetBrains Mono", ui-monospace, "SF Mono", Menlo, monospace`,
  "IBM Plex Mono":   `"IBM Plex Mono", ui-monospace, "SF Mono", Menlo, monospace`,
  "Fira Code":       `"Fira Code", ui-monospace, "SF Mono", Menlo, monospace`,
  "Geist Mono":      `"Geist Mono", ui-monospace, "SF Mono", Menlo, monospace`,
  "Source Code Pro": `"Source Code Pro", ui-monospace, "SF Mono", Menlo, monospace`,
  "Space Mono":      `"Space Mono", ui-monospace, "SF Mono", Menlo, monospace`,
};

// Token map for the custom theme — derives surface/text colors from the user's
// chosen primaries (mix with bg/fg) so a single picker drives many tokens.
const CUSTOM_TOKEN_KEYS = [
  "--background", "--foreground", "--card", "--card-foreground",
  "--popover", "--popover-foreground", "--primary", "--primary-foreground",
  "--secondary", "--secondary-foreground", "--muted", "--muted-foreground",
  "--accent", "--accent-foreground", "--destructive", "--destructive-foreground",
  "--border", "--input", "--ring",
  "--chart-1", "--chart-2", "--chart-3",
  "--sidebar", "--sidebar-foreground", "--sidebar-primary",
  "--sidebar-primary-foreground", "--sidebar-accent",
  "--sidebar-accent-foreground", "--sidebar-border", "--sidebar-ring",
  "--info", "--success", "--warning",
];

function applyCustomTheme(r: HTMLElement, c: CustomTheme) {
  const fgOnPrimary = c.isLight ? "#ffffff" : "#0b0b0f";
  const mixSoft = `color-mix(in oklab, ${c.foreground} 70%, ${c.background})`;
  r.style.setProperty("--background", c.background);
  r.style.setProperty("--foreground", c.foreground);
  r.style.setProperty("--card", c.card);
  r.style.setProperty("--card-foreground", c.foreground);
  r.style.setProperty("--popover", c.card);
  r.style.setProperty("--popover-foreground", c.foreground);
  r.style.setProperty("--primary", c.primary);
  r.style.setProperty("--primary-foreground", fgOnPrimary);
  r.style.setProperty("--secondary", c.muted);
  r.style.setProperty("--secondary-foreground", c.foreground);
  r.style.setProperty("--muted", c.muted);
  r.style.setProperty("--muted-foreground", mixSoft);
  r.style.setProperty("--accent", c.accent);
  r.style.setProperty("--accent-foreground", fgOnPrimary);
  r.style.setProperty("--destructive", c.destructive);
  r.style.setProperty("--destructive-foreground", "#ffffff");
  r.style.setProperty("--border", c.border);
  r.style.setProperty("--input", c.card);
  r.style.setProperty("--ring", c.primary);
  r.style.setProperty("--chart-1", c.primary);
  r.style.setProperty("--chart-2", c.accent);
  r.style.setProperty("--chart-3", c.destructive);
  r.style.setProperty("--sidebar", c.card);
  r.style.setProperty("--sidebar-foreground", c.foreground);
  r.style.setProperty("--sidebar-primary", c.primary);
  r.style.setProperty("--sidebar-primary-foreground", fgOnPrimary);
  r.style.setProperty("--sidebar-accent", c.muted);
  r.style.setProperty("--sidebar-accent-foreground", c.foreground);
  r.style.setProperty("--sidebar-border", c.border);
  r.style.setProperty("--sidebar-ring", c.primary);
  r.style.setProperty("--info", c.accent);
  r.style.setProperty("--success", c.primary);
  r.classList.toggle("dark", !c.isLight);
}

function clearCustomTheme(r: HTMLElement) {
  for (const k of CUSTOM_TOKEN_KEYS) r.style.removeProperty(k);
}

function applyToDOM(p: Prefs) {
  if (typeof document === "undefined") return;
  const r = document.documentElement;
  r.style.setProperty("--radius", `${p.radius}rem`);
  r.style.setProperty("--font-sans", SANS_STACK[p.sansFont]);
  r.style.setProperty("--font-mono", MONO_STACK[p.monoFont]);
  r.style.setProperty("--ba-font-scale", String(p.fontScale));
  r.style.setProperty("--ba-letter-spacing", `${p.letterSpacing}em`);
  r.style.setProperty("--ba-panel-opacity", String(p.panelOpacity));
  r.style.setProperty("--ba-mono-features", p.monoLigatures ? `"calt", "liga"` : `"calt" off, "liga" off`);
  r.dataset.density = p.density;
  r.dataset.motion = p.reduceMotion ? "reduce" : "full";
  r.dataset.topbar = p.showTopbar ? "on" : "off";
  r.dataset.zebra = p.zebraStripes ? "on" : "off";
  r.dataset.focusBoost = p.focusRingBoost ? "on" : "off";
  r.dataset.transparency = p.reducedTransparency ? "reduce" : "full";
  r.dataset.contrast = p.highContrast ? "high" : "normal";

  // Custom theme builder — overrides token block when active.
  if (r.dataset.theme === "custom") {
    applyCustomTheme(r, p.customTheme);
  } else {
    clearCustomTheme(r);
  }

  // Manual accent override — broad sweep so the user's choice is actually visible.
  // Touches primary surfaces too; when unset, theme CSS drives accent naturally.
  const accentKeys = [
    "--accent", "--ring", "--primary", "--info",
    "--sidebar-primary", "--sidebar-ring", "--chart-1",
  ];
  if (p.accent) {
    for (const k of accentKeys) r.style.setProperty(k, p.accent);
  } else if (r.dataset.theme !== "custom") {
    for (const k of accentKeys) r.style.removeProperty(k);
  }
}


export function PrefsProvider({ children }: { children: ReactNode }) {
  const [prefs, setState] = useState<Prefs>(DEFAULT);
  const [loaded, setLoaded] = useState(false);
  const { theme } = useTheme();
  const lastTheme = useRef<string | null>(null);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as Partial<Prefs>;
        const merged: Prefs = {
          ...DEFAULT,
          ...parsed,
          brandName: !parsed.brandName || parsed.brandName === "BeyondArch" ? DEFAULT.brandName : parsed.brandName,
          sidebar: { ...DEFAULT.sidebar, ...(parsed.sidebar ?? {}) },
        };
        const known = new Set(merged.sidebar.order);
        for (const g of GROUPS) if (!known.has(g.label)) merged.sidebar.order.push(g.label);
        setState(merged);
      }
    } catch { /* ignore */ }
    setLoaded(true);
  }, []);

  // When the theme changes (after first paint), clear any manual accent override
  // so the new theme's CSS-defined accent takes over. The user can re-pick an
  // override in Settings; that override sticks until the next theme switch.
  useEffect(() => {
    if (lastTheme.current === null) {
      lastTheme.current = theme;
      return;
    }
    if (lastTheme.current !== theme) {
      lastTheme.current = theme;
      setState((p) => (p.accent === null ? p : { ...p, accent: null }));
    }
  }, [theme]);

  useEffect(() => {
    applyToDOM(prefs);
    if (!loaded) return;
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs)); } catch { /* ignore */ }
  }, [prefs, theme, loaded]);


  const setPrefs = useCallback((patch: Partial<Prefs>) => {
    setState((p) => ({ ...p, ...patch }));
  }, []);

  const setSidebar = useCallback((patch: Partial<Prefs["sidebar"]>) => {
    setState((p) => ({ ...p, sidebar: { ...p.sidebar, ...patch } }));
  }, []);

  const togglePin = useCallback((url: string) => {
    setState((p) => {
      const next = p.sidebar.pinned.includes(url)
        ? p.sidebar.pinned.filter((u) => u !== url)
        : [...p.sidebar.pinned, url];
      return { ...p, sidebar: { ...p.sidebar, pinned: next } };
    });
  }, []);

  const toggleHidden = useCallback((label: string) => {
    setState((p) => {
      const next = p.sidebar.hiddenGroups.includes(label)
        ? p.sidebar.hiddenGroups.filter((l) => l !== label)
        : [...p.sidebar.hiddenGroups, label];
      return { ...p, sidebar: { ...p.sidebar, hiddenGroups: next } };
    });
  }, []);

  const moveGroup = useCallback((label: string, dir: -1 | 1) => {
    setState((p) => {
      const order = [...p.sidebar.order];
      const i = order.indexOf(label);
      const j = i + dir;
      if (i < 0 || j < 0 || j >= order.length) return p;
      [order[i], order[j]] = [order[j], order[i]];
      return { ...p, sidebar: { ...p.sidebar, order } };
    });
  }, []);

  const reset = useCallback(() => setState(DEFAULT), []);

  const value = useMemo<Ctx>(() => ({ prefs, setPrefs, setSidebar, togglePin, toggleHidden, moveGroup, reset }),
    [prefs, setPrefs, setSidebar, togglePin, toggleHidden, moveGroup, reset]);

  return <PrefsCtx.Provider value={value}>{children}</PrefsCtx.Provider>;
}

export const usePrefs = () => useContext(PrefsCtx);

export const SANS_OPTIONS: SansFont[] = [
  "Space Grotesk", "Inter", "Outfit", "Geist",
  "DM Sans", "Manrope", "Plus Jakarta Sans", "Sora",
];
export const MONO_OPTIONS: MonoFont[] = [
  "JetBrains Mono", "IBM Plex Mono", "Fira Code", "Geist Mono",
  "Source Code Pro", "Space Mono",
];
export const ACCENT_PRESETS = [
  "#22d3ee", "#a78bfa", "#f472b6", "#fb923c",
  "#facc15", "#4ade80", "#60a5fa", "#f87171",
];
