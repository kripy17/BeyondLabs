import { createFileRoute } from "@tanstack/react-router";
import { PageShell } from "@/components/PageShell";
import { useTheme, THEMES, type ThemeId } from "@/lib/theme";
import {
  usePrefs, SANS_OPTIONS, MONO_OPTIONS, ACCENT_PRESETS, BRAND_ICONS, getBrandIcon,
  CUSTOM_THEME_PRESETS, DEFAULT_CUSTOM_THEME, type CustomTheme,
} from "@/lib/prefs";
import { GROUPS } from "@/lib/workspaces";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Palette, Type, Layers, Sliders, Sparkles, Pin, Eye, EyeOff, ArrowUp, ArrowDown,
  RotateCcw, Trash2, Check, Tag, Paintbrush, Download, Upload, Sun, Moon,
} from "lucide-react";
import { clearRecents } from "@/lib/recents";
import { useEffect, useRef, useState } from "react";

export const Route = createFileRoute("/settings")({
  head: () => ({ meta: [{ title: "Settings — BeyondArch" }] }),
  component: SettingsPage,
});

function SettingsPage() {
  const { theme, setTheme } = useTheme();
  const { prefs, setPrefs, togglePin, toggleHidden, moveGroup, reset } = usePrefs();
  const fileRef = useRef<HTMLInputElement>(null);
  const [sectionFilter, setSectionFilter] = useState("");
  const SECTION_JUMP = [
    { id: "BR", label: "Brand" },
    { id: "TH", label: "Theme Gallery" },
    { id: "CT", label: "Custom Theme" },
    { id: "AC", label: "Accent" },
    { id: "DR", label: "Density" },
    { id: "TY", label: "Typography" },
    { id: "SB", label: "Sidebar" },
    { id: "QL", label: "Motion & QoL" },
  ] as const;

  // Theme preview is scoped to the gallery stage only — never mutates global theme until Apply.
  const [previewTheme, setPreviewTheme] = useState<ThemeId>(theme);
  useEffect(() => { setPreviewTheme(theme); }, [theme]);
  const themeDirty = previewTheme !== theme;
  const handleThemePreview = (id: ThemeId) => setPreviewTheme(id);
  const handleThemeApply = () => setTheme(previewTheme);
  const handleThemeCancel = () => setPreviewTheme(theme);

  // Custom theme builder uses a local draft. Nothing mutates global prefs/theme
  // until the user clicks Apply — the preview stage renders directly from draft.
  const [draftCustom, setDraftCustom] = useState<CustomTheme>(prefs.customTheme);
  useEffect(() => { setDraftCustom(prefs.customTheme); }, [prefs.customTheme]);
  const customDirty =
    JSON.stringify(draftCustom) !== JSON.stringify(prefs.customTheme) || theme !== "custom";
  const patchDraft = (patch: Partial<CustomTheme>) => {
    setDraftCustom((d) => ({ ...d, ...patch }));
    setPreviewTheme("custom"); // keep the gallery stage in sync with draft edits
  };
  const setDraftAndPreview = (next: CustomTheme) => {
    setDraftCustom(next);
    setPreviewTheme("custom");
  };
  const applyCustom = () => {
    setPrefs({ customTheme: draftCustom });
    if (theme !== "custom") setTheme("custom");
  };
  const revertCustom = () => setDraftCustom(prefs.customTheme);

  const exportPrefs = () => {
    const blob = new Blob([JSON.stringify(prefs, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `beyondarch-prefs-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const importPrefs = async (file: File) => {
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      setPrefs(parsed);
    } catch { /* ignore bad file */ }
  };


  return (
    <PageShell
      eyebrow="// settings"
      title="Workspace."
      description="Theme, layout, typography, motion. Everything persists locally — no account, no sync."
      crumbs={[{ label: "Settings" }]}
      actions={
        <div className="flex items-center gap-1.5">
          <input
            ref={fileRef}
            type="file"
            accept="application/json"
            className="hidden"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) importPrefs(f); e.target.value = ""; }}
          />
          <Button variant="outline" size="sm" className="text-mono gap-1.5" onClick={() => fileRef.current?.click()}>
            <Upload className="h-3.5 w-3.5" /> import
          </Button>
          <Button variant="outline" size="sm" className="text-mono gap-1.5" onClick={exportPrefs}>
            <Download className="h-3.5 w-3.5" /> export
          </Button>
          <Button variant="outline" size="sm" className="text-mono gap-1.5" onClick={() => reset()}>
            <RotateCcw className="h-3.5 w-3.5" /> reset
          </Button>
        </div>
      }

    >
      {/* Section quick-jump */}
      <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-border/60 bg-card/30 px-3 py-2">
        <input
          value={sectionFilter}
          onChange={(e) => setSectionFilter(e.target.value)}
          placeholder="Filter settings…"
          className="text-mono h-7 min-w-0 max-w-full flex-1 rounded border border-border/60 bg-background/60 px-2 text-[11px] text-foreground placeholder:text-muted-foreground/60 outline-none transition-colors focus:border-primary/50 md:max-w-[200px]"
        />
        <div className="flex flex-wrap gap-1">
          {SECTION_JUMP.filter((s) => !sectionFilter || s.label.toLowerCase().includes(sectionFilter.toLowerCase())).map((s) => (
            <a
              key={s.id}
              href={`#panel-${s.id}`}
              onClick={(e) => { e.preventDefault(); document.getElementById(`panel-${s.id}`)?.scrollIntoView({ behavior: "smooth", block: "start" }); }}
              className="rounded border border-border/50 bg-background/40 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground transition-colors hover:border-primary/40 hover:text-primary"
            >
              {s.label}
            </a>
          ))}
        </div>
      </div>

      {/* BRAND */}
      <Panel id="BR" label="brand" icon={Tag}
        right={<span className="text-mono text-[10px] text-muted-foreground">name · tagline · icon</span>}>
        <div className="grid gap-5 md:grid-cols-[1fr_auto]">
          <div className="space-y-3">
            <div>
              <Label>app name</Label>
              <Input
                className="mt-2 text-mono"
                value={prefs.brandName}
                maxLength={32}
                onChange={(e) => setPrefs({ brandName: e.target.value || "BeyondArch" })}
                placeholder="BeyondArch"
              />
            </div>
            <div>
              <Label>tagline</Label>
              <Input
                className="mt-2 text-mono"
                value={prefs.brandTagline}
                maxLength={40}
                onChange={(e) => setPrefs({ brandTagline: e.target.value })}
                placeholder="soc · workbench"
              />
            </div>
            <div>
              <Label>icon</Label>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {BRAND_ICONS.map(({ key, icon: I }) => {
                  const active = prefs.brandIcon === key;
                  return (
                    <button
                      key={key}
                      onClick={() => setPrefs({ brandIcon: key })}
                      aria-label={key}
                      className={
                        "grid h-9 w-9 place-items-center rounded-md border transition-all hover:-translate-y-0.5 " +
                        (active
                          ? "border-primary/70 bg-primary/15 text-primary shadow-glow"
                          : "border-border bg-card/40 text-muted-foreground hover:text-foreground")
                      }
                    >
                      <I className="h-4 w-4" />
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
          {/* Live preview chip */}
          <div className="flex flex-col items-stretch gap-2 rounded-md border border-border/70 bg-card/40 p-3 md:w-56">
            <div className="text-mono text-[9.5px] uppercase tracking-[0.22em] text-muted-foreground">preview</div>
            <div className="flex items-center gap-2.5 rounded-md border border-border bg-background/60 p-2.5">
              <div className="relative grid h-9 w-9 shrink-0 place-items-center rounded-md bg-gradient-to-br from-primary to-accent text-primary-foreground shadow-glow">
                {(() => { const I = getBrandIcon(prefs.brandIcon); return <I className="h-4 w-4" />; })()}
              </div>
              <div className="min-w-0">
                <div className="text-mono text-[13px] font-bold leading-tight truncate">{prefs.brandName || "BeyondArch"}</div>
                <div className="text-mono text-[9.5px] uppercase tracking-[0.22em] text-muted-foreground truncate">
                  {prefs.brandTagline || "—"}
                </div>
              </div>
            </div>
            <Button
              variant="ghost" size="sm" className="text-mono text-[11px]"
              onClick={() => setPrefs({ brandName: "BeyondArch", brandTagline: "soc · workbench", brandIcon: "shield-half" })}
            >
              reset brand
            </Button>
          </div>
        </div>
      </Panel>

      {/* THEME — stage + list, sticky apply bar */}
      <Panel id="TH" label="theme · gallery" icon={Palette}
        right={
          <div className="flex items-center gap-2">
            {themeDirty && (
              <span className="text-mono inline-flex items-center gap-1 rounded-sm border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-[9.5px] uppercase tracking-[0.22em] text-primary">
                <Eye className="h-2.5 w-2.5" /> previewing
              </span>
            )}
            <span className="text-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
              active · <span className="text-foreground">{theme}</span>
            </span>
          </div>
        }>
        <ThemeGallery
          previewTheme={previewTheme}
          activeTheme={theme}
          onPreview={handleThemePreview}
          onApply={handleThemeApply}
          onCancel={handleThemeCancel}
          dirty={themeDirty}
          draftCustom={draftCustom}
        />

      </Panel>

      {/* CUSTOM THEME BUILDER — draft + Apply, never mutates the live app on its own */}
      {/* CUSTOM THEME BUILDER — only revealed once "Custom" is selected in the gallery (or already active) */}
      {(previewTheme === "custom" || theme === "custom") && (
      <Panel id="CT" label="custom theme · builder" icon={Paintbrush}
        right={
          <div className="flex items-center gap-2">
            {theme === "custom" ? (
              <span className="inline-flex items-center gap-1 rounded-sm border border-success/40 bg-success/10 px-1.5 py-0.5 text-mono text-[9.5px] uppercase tracking-[0.22em] text-success">
                <span className="h-1.5 w-1.5 rounded-full bg-success" /> active
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 rounded-sm border border-border bg-card/60 px-1.5 py-0.5 text-mono text-[9.5px] uppercase tracking-[0.22em] text-muted-foreground">
                <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/60" /> draft
              </span>
            )}
            {customDirty && (
              <span className="inline-flex items-center gap-1 rounded-sm border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-mono text-[9.5px] uppercase tracking-[0.22em] text-primary">
                <Eye className="h-2.5 w-2.5" /> unsaved
              </span>
            )}
            <Button variant="ghost" size="sm" className="text-mono text-[10px] h-6 gap-1"
              onClick={() => setDraftAndPreview(DEFAULT_CUSTOM_THEME)}>
              <RotateCcw className="h-3 w-3" /> reset colors
            </Button>
          </div>
        }>
        {/* Live draft strip — compact summary so the preview lives in the gallery above */}
        <div className="mb-4 flex items-center gap-3 rounded-md border border-border/70 bg-background/40 px-3 py-2">
          <div className="flex h-8 overflow-hidden rounded-sm border border-border/70 shadow-inner">
            {(["background", "card", "muted", "border", "foreground", "primary", "accent", "destructive"] as const).map((k) => (
              <span key={k} className="h-full w-3" style={{ background: draftCustom[k] as string }} title={k} />
            ))}
          </div>
          <div className="min-w-0">
            <div className="text-mono text-[10px] uppercase tracking-[0.22em] text-muted-foreground">draft · {draftCustom.isLight ? "light" : "dark"}</div>
            <div className="text-[11px] text-muted-foreground">
              Live preview renders in <span className="text-mono text-foreground/80">theme · gallery</span> above when <span className="text-mono text-foreground/80">Custom</span> is selected.
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="text-mono ml-auto text-[10.5px] gap-1.5"
            onClick={() => {
              setPreviewTheme("custom");
              document.getElementById("panel-TH")?.scrollIntoView({ behavior: "smooth", block: "start" });
            }}
          >
            <Eye className="h-3 w-3" /> preview in gallery
          </Button>
        </div>

        <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
          {/* LEFT — mode + presets */}
          <div className="space-y-5">
            {/* mode */}
            <div>
              <Label>mode</Label>
              <div className="mt-2 grid grid-cols-2 gap-2">
                {([
                  ["dark", false, Moon, "Inverted surfaces, glow accents"],
                  ["light", true, Sun, "Paper surfaces, ink type"],
                ] as const).map(([lbl, val, I, hint]) => {
                  const active = draftCustom.isLight === val;
                  return (
                    <button
                      key={lbl}
                      onClick={() => patchDraft({ isLight: val })}
                      className={
                        "group flex items-center gap-2.5 rounded-md border px-3 py-2 text-left transition-all " +
                        (active
                          ? "border-primary/60 bg-primary/10 shadow-glow"
                          : "border-border/70 bg-card/40 hover:border-primary/40")
                      }
                    >
                      <span className={"grid h-7 w-7 place-items-center rounded-sm border " + (active ? "border-primary/50 bg-primary/15 text-primary" : "border-border bg-background/60 text-muted-foreground")}>
                        <I className="h-3.5 w-3.5" />
                      </span>
                      <div className="min-w-0">
                        <div className="text-mono text-[11px] uppercase tracking-[0.22em] text-foreground/90">{lbl}</div>
                        <div className="text-[10.5px] text-muted-foreground truncate">{hint}</div>
                      </div>
                      {active && <Check className="ml-auto h-3.5 w-3.5 text-primary" />}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* presets */}
            <div>
              <Label>start from a preset</Label>
              <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
                {CUSTOM_THEME_PRESETS.map((p) => {
                  const matches = JSON.stringify(p.theme) === JSON.stringify(draftCustom);
                  return (
                    <button
                      key={p.name}
                      onClick={() => setDraftAndPreview(p.theme)}
                      className={
                        "group flex items-center gap-2.5 rounded-md border px-2.5 py-2 text-left transition-all " +
                        (matches
                          ? "border-primary/60 bg-primary/10"
                          : "border-border/70 bg-card/40 hover:border-primary/40 hover:-translate-y-0.5")
                      }
                    >
                      <span className="flex h-8 overflow-hidden rounded-sm border border-border/70 shadow-inner">
                        <span className="h-full w-2.5" style={{ background: p.theme.background }} />
                        <span className="h-full w-2.5" style={{ background: p.theme.card }} />
                        <span className="h-full w-2.5" style={{ background: p.theme.primary }} />
                        <span className="h-full w-2.5" style={{ background: p.theme.accent }} />
                        <span className="h-full w-2.5" style={{ background: p.theme.destructive }} />
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="text-mono text-[11px] text-foreground/90 truncate">{p.name}</div>
                        <div className="text-mono text-[9.5px] uppercase tracking-widest text-muted-foreground">
                          {p.theme.isLight ? "light" : "dark"}
                        </div>
                      </div>
                      {matches && <Check className="h-3.5 w-3.5 text-primary" />}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* RIGHT — tokens */}
          <div>
            <Label>tokens</Label>
            <div className="mt-2 grid gap-2 sm:grid-cols-2">
              {([
                ["background", "background"],
                ["foreground", "foreground"],
                ["card / surface", "card"],
                ["border", "border"],
                ["muted", "muted"],
                ["primary", "primary"],
                ["accent", "accent"],
                ["destructive", "destructive"],
              ] as const).map(([label, key]) => (
                <ColorSwatch
                  key={key}
                  label={label}
                  value={draftCustom[key] as string}
                  onChange={(v) => patchDraft({ [key]: v } as Partial<CustomTheme>)}
                />
              ))}
            </div>
          </div>
        </div>


        {/* Sticky apply bar — only appears when there are pending changes */}
        {customDirty && (
          <div className="sticky bottom-2 mt-4 flex flex-wrap items-center gap-2 rounded-md border border-primary/40 bg-card/95 px-3 py-2 shadow-glow backdrop-blur">
            <span className="text-mono text-[10.5px] uppercase tracking-[0.22em] text-muted-foreground">
              {theme === "custom"
                ? "draft differs from active custom theme"
                : "draft ready — apply to switch the workspace to custom"}
            </span>
            <div className="ml-auto flex items-center gap-1.5">
              <Button variant="ghost" size="sm" className="text-mono text-[10.5px] gap-1.5" onClick={revertCustom}>
                <RotateCcw className="h-3 w-3" /> revert
              </Button>
              <Button size="sm" className="text-mono text-[10.5px] gap-1.5" onClick={applyCustom}>
                <Check className="h-3.5 w-3.5" /> apply{theme !== "custom" ? " & activate" : ""}
              </Button>
            </div>
          </div>
        )}
      </Panel>
      )}



      {/* ACCENT */}

      <Panel id="AC" label="accent override" icon={Sparkles}
        right={<span className="text-mono text-[10px] text-muted-foreground">applies to primary · ring · charts</span>}>
        <div className="flex flex-wrap items-center gap-2">
          {ACCENT_PRESETS.map((hex) => (
            <button
              key={hex}
              onClick={() => setPrefs({ accent: hex })}
              className={
                "group relative h-8 w-8 rounded-md border-2 transition-all hover:scale-110 " +
                (prefs.accent === hex ? "border-foreground shadow-glow" : "border-border/50")
              }
              style={{ background: hex }}
              aria-label={`Set accent ${hex}`}
            >
              {prefs.accent === hex && <Check className="absolute inset-0 m-auto h-4 w-4 text-background" />}
            </button>
          ))}
          <label className="text-mono ml-2 inline-flex items-center gap-2 rounded-md border border-border bg-card/60 px-2 py-1 text-[11px] text-muted-foreground">
            custom
            <input
              type="color"
              value={prefs.accent ?? "#22d3ee"}
              onChange={(e) => setPrefs({ accent: e.target.value })}
              className="h-5 w-7 cursor-pointer rounded border-0 bg-transparent"
            />
          </label>
          {prefs.accent && (
            <Button variant="ghost" size="sm" className="text-mono text-[11px]" onClick={() => setPrefs({ accent: null })}>
              clear
            </Button>
          )}
          <span className="text-mono ml-auto text-[10px] text-muted-foreground">
            {prefs.accent ? `active · ${prefs.accent}` : "theme default"}
          </span>
        </div>
      </Panel>

      {/* DENSITY + RADIUS */}
      <Panel id="DR" label="density & radius" icon={Sliders}>
        <div className="grid gap-5 md:grid-cols-2">
          <div>
            <Label>density</Label>
            <div className="mt-2 inline-flex rounded-md border border-border bg-card/40 p-0.5">
              {(["comfortable", "compact"] as const).map((d) => (
                <button
                  key={d}
                  onClick={() => setPrefs({ density: d })}
                  className={
                    "text-mono rounded px-3 py-1 text-[11px] uppercase tracking-widest transition-colors " +
                    (prefs.density === d ? "bg-primary/20 text-primary" : "text-muted-foreground hover:text-foreground")
                  }
                >
                  {d}
                </button>
              ))}
            </div>
          </div>
          <div>
            <Label>corner radius · {prefs.radius.toFixed(2)}rem</Label>
            <div className="mt-3 flex items-center gap-3">
              <Slider
                value={[prefs.radius]}
                onValueChange={(v) => setPrefs({ radius: v[0] })}
                min={0} max={1} step={0.05}
                className="flex-1"
              />
              <div className="grid h-10 w-14 place-items-center border border-border bg-card/60 text-mono text-[10px] text-muted-foreground" style={{ borderRadius: `${prefs.radius}rem` }}>
                preview
              </div>
            </div>
          </div>
        </div>
      </Panel>

      {/* TYPOGRAPHY */}
      <Panel id="TY" label="typography" icon={Type}
        right={<span className="text-mono text-[10px] text-muted-foreground">{Math.round(prefs.fontScale * 100)}% scale</span>}>
        <div className="space-y-5">
          <div>
            <Label>font size · {Math.round(prefs.fontScale * 100)}%</Label>
            <div className="mt-3 flex items-center gap-3">
              <span className="text-mono text-[10px] text-muted-foreground">A</span>
              <Slider
                value={[prefs.fontScale]}
                onValueChange={(v) => setPrefs({ fontScale: v[0] })}
                min={0.85} max={1.15} step={0.025}
                className="flex-1"
              />
              <span className="text-mono text-[15px] text-foreground">A</span>
              <Button
                variant="ghost" size="sm" className="text-mono text-[11px]"
                onClick={() => setPrefs({ fontScale: 1 })}
              >
                reset
              </Button>
            </div>
          </div>

          <div>
            <Label>letter spacing · {prefs.letterSpacing >= 0 ? "+" : ""}{prefs.letterSpacing.toFixed(3)}em</Label>
            <div className="mt-3 flex items-center gap-3">
              <span className="text-mono text-[10px] text-muted-foreground" style={{ letterSpacing: "-0.02em" }}>tight</span>
              <Slider
                value={[prefs.letterSpacing]}
                onValueChange={(v) => setPrefs({ letterSpacing: v[0] })}
                min={-0.02} max={0.06} step={0.005}
                className="flex-1"
              />
              <span className="text-mono text-[11px] text-muted-foreground" style={{ letterSpacing: "0.06em" }}>loose</span>
              <Button variant="ghost" size="sm" className="text-mono text-[11px]" onClick={() => setPrefs({ letterSpacing: 0 })}>
                reset
              </Button>
            </div>
          </div>

          <Row label="Monospace ligatures" desc="Turn on programming ligatures (&rarr;, !=, ===, ...) in code/data.">
            <Switch checked={prefs.monoLigatures} onCheckedChange={(v) => setPrefs({ monoLigatures: v })} />
          </Row>

          <div className="grid gap-5 md:grid-cols-2">
            <FontPicker
              title="sans (UI)"
              options={SANS_OPTIONS}
              value={prefs.sansFont}
              onChange={(v) => setPrefs({ sansFont: v })}
              sample="The quick brown fox jumps over 1234567890"
              mono={false}
            />
            <FontPicker
              title="mono (data, IDs)"
              options={MONO_OPTIONS}
              value={prefs.monoFont}
              onChange={(v) => setPrefs({ monoFont: v })}
              sample="BA-7F · 0x1A3F · {ttp:T1059}"
              mono={true}
            />
          </div>
        </div>
      </Panel>

      {/* SIDEBAR LAYOUT */}
      <Panel id="SB" label="sidebar layout" icon={Layers}
        right={<span className="text-mono text-[10px] text-muted-foreground">drag-free reorder</span>}>
        <div className="space-y-2">
          {prefs.sidebar.order.map((label, i) => {
            const grp = GROUPS.find((g) => g.label === label);
            if (!grp) return null;
            const hidden = prefs.sidebar.hiddenGroups.includes(label);
            return (
              <div key={label} className="rounded-md border border-border/70 bg-card/40">
                <div className="flex items-center gap-2 px-3 py-2">
                  {(() => { const GIcon = grp.items[0]?.icon; return GIcon ? (
                    <span className="grid h-5 w-5 place-items-center rounded-sm border border-primary/40 bg-primary/10 text-primary">
                      <GIcon className="h-3 w-3" strokeWidth={2.25} />
                    </span>
                  ) : null; })()}
                  <span className="text-mono text-[12px] font-semibold tracking-tight">{label}</span>
                  <span className="text-mono text-[10px] text-muted-foreground">{grp.items.length} items</span>
                  <div className="ml-auto flex items-center gap-1">
                    <IconBtn label="up" disabled={i === 0} onClick={() => moveGroup(label, -1)}><ArrowUp className="h-3 w-3" /></IconBtn>
                    <IconBtn label="down" disabled={i === prefs.sidebar.order.length - 1} onClick={() => moveGroup(label, 1)}><ArrowDown className="h-3 w-3" /></IconBtn>
                    <IconBtn label="visibility" onClick={() => toggleHidden(label)}>
                      {hidden ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                    </IconBtn>
                  </div>
                </div>
                {!hidden && (
                  <ul className="divide-y divide-border/50 border-t border-border/60">
                    {grp.items.map((it) => {
                      const pinned = prefs.sidebar.pinned.includes(it.url);
                      return (
                        <li key={it.url} className="flex items-center gap-2 px-3 py-1.5">
                          <it.icon className="h-3.5 w-3.5 text-primary/80" />
                          <span className="text-mono text-[11.5px] text-foreground/90">{it.title}</span>
                          <span className="truncate text-[10.5px] text-muted-foreground">— {it.desc}</span>
                          <button
                            onClick={() => togglePin(it.url)}
                            className={
                              "ml-auto inline-flex items-center gap-1 rounded border px-1.5 py-px text-mono text-[10px] uppercase tracking-widest transition-colors " +
                              (pinned ? "border-primary/50 bg-primary/15 text-primary" : "border-border/60 text-muted-foreground hover:text-foreground")
                            }
                          >
                            <Pin className="h-2.5 w-2.5" /> {pinned ? "pinned" : "pin"}
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            );
          })}
        </div>
      </Panel>

      {/* MOTION + QOL */}
      <Panel id="QL" label="motion & qol" icon={Sparkles}>
        <div className="grid gap-3 md:grid-cols-2">
          <Row label="Reduce motion" desc="Disable mount fades, hover micro-anim and pulses.">
            <Switch checked={prefs.reduceMotion} onCheckedChange={(v) => setPrefs({ reduceMotion: v })} />
          </Row>
          <Row label="Open palette with /" desc="Press / anywhere to open the command palette.">
            <Switch checked={prefs.slashOpensPalette} onCheckedChange={(v) => setPrefs({ slashOpensPalette: v })} />
          </Row>
          <Row label="Show breadcrumb" desc="Hide for the cleanest topbar.">
            <Switch checked={prefs.showBreadcrumb} onCheckedChange={(v) => setPrefs({ showBreadcrumb: v })} />
          </Row>
          <Row label="Show topbar" desc="Toggle the topbar on screens that don't need it.">
            <Switch checked={prefs.showTopbar} onCheckedChange={(v) => setPrefs({ showTopbar: v })} />
          </Row>
          <Row label="Zebra rows" desc="Alternate shading on tables &amp; IOC inventories for scan-ability.">
            <Switch checked={prefs.zebraStripes} onCheckedChange={(v) => setPrefs({ zebraStripes: v })} />
          </Row>
          <Row label="High-contrast focus" desc="Thicker focus ring + glow for keyboard-only navigation.">
            <Switch checked={prefs.focusRingBoost} onCheckedChange={(v) => setPrefs({ focusRingBoost: v })} />
          </Row>
          <div className="md:col-span-2 rounded-md border border-border/70 bg-card/40 px-3 py-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-mono text-[12px] font-medium text-foreground">Panel opacity &middot; {Math.round(prefs.panelOpacity * 100)}%</div>
                <div className="text-[11px] text-muted-foreground">Blend workspace cards with the theme backdrop.</div>
              </div>
              <Button variant="ghost" size="sm" className="text-mono text-[11px]" onClick={() => setPrefs({ panelOpacity: 1 })}>
                reset
              </Button>
            </div>
            <div className="mt-3 flex items-center gap-3">
              <span className="text-mono text-[10px] text-muted-foreground">75%</span>
              <Slider
                value={[prefs.panelOpacity]}
                onValueChange={(v) => setPrefs({ panelOpacity: v[0] })}
                min={0.75} max={1} step={0.01}
                className="flex-1"
              />
              <span className="text-mono text-[10px] text-muted-foreground">100%</span>
            </div>
          </div>
          <Row label="Clear recents" desc="Wipe the recent-workspace history.">
            <Button variant="outline" size="sm" className="text-mono gap-1.5" onClick={clearRecents}>
              <Trash2 className="h-3.5 w-3.5" /> clear
            </Button>
          </Row>
        </div>
      </Panel>
    </PageShell>
  );
}

function ColorSwatch({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <label className="group flex items-center gap-3 rounded-md border border-border/70 bg-card/40 px-3 py-2 transition-colors hover:border-primary/40">
      <div
        className="relative h-9 w-9 shrink-0 overflow-hidden rounded-md border border-border/80 shadow-inner"
        style={{ background: value }}
      >
        <input
          type="color"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="absolute inset-0 h-full w-full cursor-pointer opacity-0"
          aria-label={`pick ${label}`}
        />
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-mono text-[10px] uppercase tracking-[0.22em] text-muted-foreground">{label}</div>
        <input
          value={value}
          onChange={(e) => onChange(e.target.value)}
          spellCheck={false}
          className="mt-0.5 w-full bg-transparent text-mono text-[12px] text-foreground outline-none"
        />
      </div>
    </label>
  );
}

function CustomThemePreview({ ct }: { ct: CustomTheme }) {
  const onPrimary = ct.isLight ? "#ffffff" : "#0b0b0f";
  const fgSoft = ct.foreground + "b3";
  const fgFaint = ct.foreground + "66";

  const surfaceStyle: React.CSSProperties = {
    background: ct.background,
    color: ct.foreground,
    borderColor: ct.border,
    // expose tokens for nested helpers
    ["--p" as never]: ct.primary,
    ["--a" as never]: ct.accent,
    ["--b" as never]: ct.border,
    ["--c" as never]: ct.card,
    ["--m" as never]: ct.muted,
    ["--d" as never]: ct.destructive,
  };

  return (
    <div className="overflow-hidden rounded-md border shadow-lg" style={surfaceStyle}>
      {/* Faux topbar */}
      <div className="flex items-center gap-2 border-b px-3 py-2" style={{ borderColor: ct.border, background: ct.card }}>
        <span className="flex gap-1">
          <span className="h-2.5 w-2.5 rounded-full" style={{ background: ct.destructive }} />
          <span className="h-2.5 w-2.5 rounded-full" style={{ background: ct.accent }} />
          <span className="h-2.5 w-2.5 rounded-full" style={{ background: ct.primary }} />
        </span>
        <span className="text-mono text-[10.5px] uppercase tracking-[0.22em]" style={{ color: fgSoft }}>
          preview · {ct.isLight ? "light" : "dark"}
        </span>
        <span className="ml-auto text-mono text-[10px]" style={{ color: fgFaint }}>workspace://demo</span>
      </div>

      <div className="space-y-4 p-3.5">
        {/* Heading + body */}
        <div>
          <div className="text-[17px] font-semibold leading-tight">Multi-state preview</div>
          <div className="mt-1 text-[12px]" style={{ color: fgSoft }}>
            Inspect tokens across common UI states.{" "}
            <a className="underline decoration-dotted underline-offset-4" style={{ color: ct.primary }} href="#">a link</a>{" · "}
            <a className="underline decoration-dotted underline-offset-4" style={{ color: ct.accent }} href="#">accent link</a>
          </div>
        </div>

        {/* Buttons */}
        <div>
          <div className="text-mono text-[9.5px] uppercase tracking-[0.22em]" style={{ color: fgFaint }}>buttons</div>
          <div className="mt-2 flex flex-wrap gap-2">
            <button className="text-mono rounded-md px-2.5 py-1.5 text-[11px] font-medium shadow-sm transition-transform hover:-translate-y-px"
              style={{ background: ct.primary, color: onPrimary }}>primary</button>
            <button className="text-mono rounded-md px-2.5 py-1.5 text-[11px] font-medium shadow-sm transition-transform hover:-translate-y-px"
              style={{ background: ct.accent, color: onPrimary }}>accent</button>
            <button className="text-mono rounded-md border px-2.5 py-1.5 text-[11px]"
              style={{ borderColor: ct.border, background: ct.card, color: ct.foreground }}>outline</button>
            <button className="text-mono rounded-md px-2.5 py-1.5 text-[11px]"
              style={{ background: "transparent", color: fgSoft }}>ghost</button>
            <button className="text-mono rounded-md px-2.5 py-1.5 text-[11px] font-medium"
              style={{ background: ct.destructive, color: "#fff" }}>destructive</button>
            <button className="text-mono rounded-md border px-2.5 py-1.5 text-[11px] opacity-50"
              style={{ borderColor: ct.border, color: ct.foreground }} disabled>disabled</button>
          </div>
        </div>

        {/* Badges + input */}
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <div className="text-mono text-[9.5px] uppercase tracking-[0.22em]" style={{ color: fgFaint }}>badges</div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              <span className="text-mono rounded-sm px-1.5 py-0.5 text-[10px]"
                style={{ background: ct.primary + "26", color: ct.primary, border: `1px solid ${ct.primary}66` }}>active</span>
              <span className="text-mono rounded-sm px-1.5 py-0.5 text-[10px]"
                style={{ background: ct.accent + "26", color: ct.accent, border: `1px solid ${ct.accent}66` }}>tag</span>
              <span className="text-mono rounded-sm px-1.5 py-0.5 text-[10px]"
                style={{ background: ct.muted, color: fgSoft, border: `1px solid ${ct.border}` }}>muted</span>
              <span className="text-mono rounded-sm px-1.5 py-0.5 text-[10px]"
                style={{ background: ct.destructive + "26", color: ct.destructive, border: `1px solid ${ct.destructive}66` }}>error</span>
            </div>
          </div>
          <div>
            <div className="text-mono text-[9.5px] uppercase tracking-[0.22em]" style={{ color: fgFaint }}>input</div>
            <div className="mt-2 flex items-center gap-2">
              <input
                defaultValue="ba-7f / lookup"
                className="text-mono w-full rounded-md border px-2 py-1 text-[11.5px] outline-none transition-colors focus:ring-2"
                style={{
                  background: ct.card,
                  color: ct.foreground,
                  borderColor: ct.border,
                  // @ts-expect-error -- css var for focus tint
                  "--tw-ring-color": ct.primary + "66",
                }}
              />
            </div>
          </div>
        </div>

        {/* Card */}
        <div className="rounded-md border p-3" style={{ borderColor: ct.border, background: ct.card }}>
          <div className="flex items-center gap-2">
            <span className="grid h-5 w-5 place-items-center rounded-sm"
              style={{ background: ct.primary + "26", color: ct.primary, border: `1px solid ${ct.primary}66` }}>
              <Sparkles className="h-3 w-3" />
            </span>
            <div className="text-mono text-[10.5px] uppercase tracking-[0.22em]" style={{ color: fgSoft }}>card · surface</div>
            <span className="ml-auto text-mono text-[10px]" style={{ color: fgFaint }}>3 items</span>
          </div>
          <div className="mt-2 space-y-1.5">
            {["Lookup IOC indicator", "Run detection draft", "Compose pivot summary"].map((t, i) => (
              <div key={t} className="flex items-center gap-2 rounded-sm px-2 py-1 text-[11.5px]"
                style={{ background: i === 0 ? ct.muted : "transparent", color: ct.foreground }}>
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: i === 0 ? ct.primary : ct.border }} />
                <span className="truncate">{t}</span>
                <span className="ml-auto text-mono text-[9.5px]" style={{ color: fgFaint }}>0{i + 1}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Form controls: select / toggle / checkboxes / radios */}
        <div className="rounded-md border p-3" style={{ borderColor: ct.border, background: ct.card }}>
          <div className="flex items-center gap-2">
            <span className="text-mono text-[10.5px] uppercase tracking-[0.22em]" style={{ color: fgSoft }}>form · controls</span>
            <span className="ml-auto text-mono text-[9.5px]" style={{ color: fgFaint }}>live</span>
          </div>
          <div className="mt-2.5 grid gap-3 sm:grid-cols-2">
            {/* select */}
            <label className="block">
              <span className="text-mono text-[10px] uppercase tracking-[0.22em]" style={{ color: fgFaint }}>severity</span>
              <select
                defaultValue="high"
                className="text-mono mt-1 w-full appearance-none rounded-md border px-2 py-1.5 text-[11.5px] outline-none"
                style={{ background: ct.background, color: ct.foreground, borderColor: ct.border }}
              >
                <option value="low">low</option>
                <option value="medium">medium</option>
                <option value="high">high</option>
                <option value="critical">critical</option>
              </select>
            </label>

            {/* toggle */}
            <div className="flex items-center justify-between rounded-md border px-2.5 py-1.5"
              style={{ borderColor: ct.border, background: ct.background }}>
              <span className="text-mono text-[11px]" style={{ color: ct.foreground }}>auto-run on paste</span>
              <span aria-hidden className="relative inline-flex h-5 w-9 items-center rounded-full transition-colors"
                style={{ background: ct.primary }}>
                <span className="absolute right-0.5 h-4 w-4 rounded-full shadow"
                  style={{ background: onPrimary }} />
              </span>
            </div>

            {/* checkboxes */}
            <div>
              <div className="text-mono text-[10px] uppercase tracking-[0.22em]" style={{ color: fgFaint }}>enrichers</div>
              <div className="mt-1.5 grid gap-1">
                {[["VirusTotal", true], ["AbuseIPDB", true], ["Shodan", false]].map(([n, on]) => (
                  <label key={n as string} className="flex items-center gap-2 text-[11.5px]" style={{ color: ct.foreground }}>
                    <span
                      className="grid h-3.5 w-3.5 place-items-center rounded-sm border"
                      style={{
                        borderColor: on ? ct.primary : ct.border,
                        background: on ? ct.primary : "transparent",
                      }}
                    >
                      {on ? <Check className="h-3 w-3" style={{ color: onPrimary }} /> : null}
                    </span>
                    <span className="text-mono">{n as string}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* radio */}
            <div>
              <div className="text-mono text-[10px] uppercase tracking-[0.22em]" style={{ color: fgFaint }}>output format</div>
              <div className="mt-1.5 grid gap-1">
                {[["json", true], ["yaml", false], ["markdown", false]].map(([n, on]) => (
                  <label key={n as string} className="flex items-center gap-2 text-[11.5px]" style={{ color: ct.foreground }}>
                    <span
                      className="grid h-3.5 w-3.5 place-items-center rounded-full border"
                      style={{
                        borderColor: on ? ct.primary : ct.border,
                        background: ct.background,
                      }}
                    >
                      {on ? <span className="h-1.5 w-1.5 rounded-full" style={{ background: ct.primary }} /> : null}
                    </span>
                    <span className="text-mono">{n as string}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-hidden rounded-md border" style={{ borderColor: ct.border, background: ct.card }}>
          <div className="flex items-center gap-2 border-b px-3 py-2"
            style={{ borderColor: ct.border, background: ct.muted }}>
            <span className="text-mono text-[10.5px] uppercase tracking-[0.22em]" style={{ color: fgSoft }}>indicators</span>
            <span className="ml-auto text-mono text-[9.5px]" style={{ color: fgFaint }}>3 rows</span>
          </div>
          <table className="w-full border-collapse text-left">
            <thead>
              <tr className="text-mono text-[9.5px] uppercase tracking-[0.22em]" style={{ color: fgFaint }}>
                <th className="px-3 py-1.5 font-normal">ioc</th>
                <th className="px-3 py-1.5 font-normal">type</th>
                <th className="px-3 py-1.5 font-normal text-right">score</th>
                <th className="px-3 py-1.5 font-normal">verdict</th>
              </tr>
            </thead>
            <tbody>
              {[
                ["185.220.101.7", "ipv4", 92, "malicious", ct.destructive],
                ["paypa1-login.co", "domain", 71, "suspicious", ct.accent],
                ["a1b2c3d4e5f6", "sha1", 12, "benign", ct.primary],
              ].map((row, i) => (
                <tr key={i} className="border-t" style={{ borderColor: ct.border + "55" }}>
                  <td className="text-mono px-3 py-1.5 text-[11px]" style={{ color: ct.foreground }}>{row[0] as string}</td>
                  <td className="text-mono px-3 py-1.5 text-[10.5px]" style={{ color: fgSoft }}>{row[1] as string}</td>
                  <td className="text-mono px-3 py-1.5 text-right text-[11px]" style={{ color: ct.foreground }}>{row[2] as number}</td>
                  <td className="px-3 py-1.5">
                    <span
                      className="text-mono inline-block rounded-sm px-1.5 py-0.5 text-[9.5px] uppercase tracking-[0.18em]"
                      style={{
                        background: (row[4] as string) + "22",
                        color: row[4] as string,
                        border: `1px solid ${(row[4] as string)}66`,
                      }}
                    >
                      {row[3] as string}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>


        {/* Alert */}
        <div className="flex items-start gap-2 rounded-md border px-2.5 py-2"
          style={{ borderColor: ct.destructive + "66", background: ct.destructive + "1a" }}>
          <span className="mt-0.5 h-2 w-2 shrink-0 rounded-full" style={{ background: ct.destructive }} />
          <div className="min-w-0">
            <div className="text-mono text-[10.5px] uppercase tracking-[0.22em]" style={{ color: ct.destructive }}>destructive alert</div>
            <div className="text-[11.5px]" style={{ color: fgSoft }}>This action cannot be undone. Verify the target host before continuing.</div>
          </div>
        </div>

        {/* Dialog mock */}
        <div className="relative overflow-hidden rounded-md border"
          style={{ borderColor: ct.border, background: ct.muted }}>
          <div className="absolute inset-0 opacity-60" style={{ background: `repeating-linear-gradient(45deg, transparent 0 6px, ${ct.border}33 6px 7px)` }} />
          <div className="relative m-3 rounded-md border shadow-2xl" style={{ borderColor: ct.border, background: ct.card }}>
            <div className="border-b px-3 py-2" style={{ borderColor: ct.border }}>
              <div className="text-mono text-[11px] uppercase tracking-[0.22em]" style={{ color: ct.foreground }}>confirm action</div>
            </div>
            <div className="px-3 py-2 text-[11.5px]" style={{ color: fgSoft }}>
              Apply the custom theme tokens to the active workspace?
            </div>
            <div className="flex items-center justify-end gap-2 border-t px-3 py-2" style={{ borderColor: ct.border }}>
              <button className="text-mono rounded-md px-2 py-1 text-[10.5px]" style={{ color: fgSoft }}>cancel</button>
              <button className="text-mono rounded-md px-2.5 py-1 text-[10.5px] font-medium" style={{ background: ct.primary, color: onPrimary }}>apply</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}



/* =========================================================
 *  ThemeGallery — stage + scrollable list + sticky apply
 * ========================================================= */
function ThemeGallery({
  previewTheme, activeTheme, onPreview, onApply, onCancel, dirty, draftCustom,
}: {
  previewTheme: ThemeId; activeTheme: ThemeId;
  onPreview: (id: ThemeId) => void; onApply: () => void; onCancel: () => void; dirty: boolean;
  draftCustom?: CustomTheme;
}) {
  const [filter, setFilter] = useState<"all" | "dark" | "light">("all");
  const previewMeta = THEMES.find((t) => t.id === previewTheme)!;
  const list = THEMES.filter((t) =>
    filter === "all" ? true : filter === "light" ? !!t.isLight : !t.isLight
  );

  // When previewing "custom", inject the draft tokens directly on the stage so
  // unsaved color edits are reflected immediately (without touching global DOM).
  const stageStyle: React.CSSProperties | undefined =
    previewTheme === "custom" && draftCustom
      ? {
          ["--background" as never]: draftCustom.background,
          ["--foreground" as never]: draftCustom.foreground,
          ["--card" as never]: draftCustom.card,
          ["--border" as never]: draftCustom.border,
          ["--muted" as never]: draftCustom.muted,
          ["--primary" as never]: draftCustom.primary,
          ["--primary-foreground" as never]: draftCustom.isLight ? "#ffffff" : "#0b0b0f",
          ["--accent" as never]: draftCustom.accent,
          ["--accent-foreground" as never]: draftCustom.isLight ? "#ffffff" : "#0b0b0f",
          ["--destructive" as never]: draftCustom.destructive,
          ["--destructive-foreground" as never]: "#ffffff",
          ["--muted-foreground" as never]: draftCustom.foreground + "b3",
          ["--success" as never]: draftCustom.primary,
          ["--warning" as never]: draftCustom.accent,
        }
      : undefined;

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
      {/* LEFT — live stage */}
      <div className="relative overflow-hidden rounded-md border border-border bg-[var(--card)]" data-theme={previewTheme} style={stageStyle}>

        <div className="flex items-center justify-between border-b border-border/60 bg-[var(--background)] px-3 py-2">
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-destructive/70" />
            <span className="h-2 w-2 rounded-full bg-warning/70" />
            <span className="h-2 w-2 rounded-full bg-success/70" />
            <span className="text-mono ml-3 text-[10px] uppercase tracking-[0.25em] text-muted-foreground">
              {previewMeta.name.toLowerCase()} · preview
            </span>
          </div>
          <div className="flex gap-0.5">
            {previewMeta.swatch.map((c, i) => (
              <span key={i} className="h-3.5 w-2 rounded-[1px] border border-border/40" style={{ background: c }} />
            ))}
          </div>
        </div>
        <div className="relative bg-[var(--background)] p-4">
          <div className="absolute inset-0 opacity-40 aurora-glow" aria-hidden />
          <div className="relative space-y-3">
            <div className="flex items-baseline justify-between">
              <div>
                <div className="text-mono text-[10px] uppercase tracking-[0.28em] text-[var(--muted-foreground)]">workspace</div>
                <div className="font-display text-xl text-[var(--foreground)]">{previewMeta.name}</div>
              </div>
              <span className="text-mono rounded-sm border border-[var(--border)] bg-[var(--card)] px-1.5 py-0.5 text-[9px] uppercase tracking-widest text-[var(--muted-foreground)]">
                {previewMeta.isLight ? "light" : "dark"}
              </span>
            </div>

            <div className="grid grid-cols-3 gap-2">
              {[
                { label: "primary",  v: "var(--primary)" },
                { label: "accent",   v: "var(--accent)" },
                { label: "success",  v: "var(--success)" },
                { label: "warning",  v: "var(--warning)" },
                { label: "destruct", v: "var(--destructive)" },
                { label: "muted",    v: "var(--muted)" },
              ].map((s) => (
                <div key={s.label} className="rounded-sm border border-[var(--border)] bg-[var(--card)] p-1.5">
                  <div className="h-6 w-full rounded-[2px]" style={{ background: s.v }} />
                  <div className="text-mono mt-1 text-[9px] uppercase tracking-widest text-[var(--muted-foreground)]">{s.label}</div>
                </div>
              ))}
            </div>

            <div className="rounded-sm border border-[var(--border)] bg-[var(--card)] p-2">
              <div className="text-mono text-[9.5px] uppercase tracking-widest text-[var(--muted-foreground)]">sample · panel</div>
              <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                <span className="text-mono rounded-sm bg-[var(--primary)] px-2 py-1 text-[10px] font-semibold text-[var(--primary-foreground)]">primary</span>
                <span className="text-mono rounded-sm border border-[var(--border)] px-2 py-1 text-[10px] text-[var(--foreground)]">outline</span>
                <span className="text-mono rounded-sm bg-[var(--accent)] px-2 py-1 text-[10px] font-semibold text-[var(--accent-foreground)]">accent</span>
                <span className="text-mono ml-auto rounded-sm bg-[var(--destructive)] px-2 py-1 text-[10px] font-semibold text-[var(--destructive-foreground)]">alert</span>
              </div>
              <div className="mt-2 grid grid-cols-[1fr_auto] items-center gap-2 border-t border-[var(--border)] pt-2">
                <div className="text-mono text-[10.5px] text-[var(--foreground)]">indicator.exe · severity high</div>
                <span className="text-mono rounded-sm border border-[var(--border)] px-1.5 py-0.5 text-[9px] uppercase tracking-widest text-[var(--muted-foreground)]">12 hits</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* RIGHT — filter + list + sticky apply */}
      <div className="flex flex-col overflow-hidden rounded-md border border-border bg-card">
        <div className="flex items-center justify-between gap-2 border-b border-border/60 px-2 py-1.5">
          <div className="flex gap-1">
            {(["all", "dark", "light"] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={[
                  "text-mono rounded-sm border px-2 py-1 text-[10px] uppercase tracking-widest transition-colors",
                  filter === f
                    ? "border-primary/60 bg-primary/10 text-primary"
                    : "border-border/60 text-muted-foreground hover:border-border hover:text-foreground",
                ].join(" ")}
              >
                {f === "dark" ? <Moon className="mr-1 inline h-3 w-3" /> : f === "light" ? <Sun className="mr-1 inline h-3 w-3" /> : null}
                {f}
              </button>
            ))}
          </div>
          <span className="text-mono text-[10px] text-muted-foreground">{list.length} themes</span>
        </div>

        <div className="max-h-[420px] overflow-y-auto p-1.5">
          {list.map((t) => {
            const isPreview = previewTheme === t.id;
            const isActive = activeTheme === t.id;
            return (
              <button
                key={t.id}
                onClick={() => onPreview(t.id)}
                className={[
                  "group flex w-full items-center gap-3 rounded-sm border px-2 py-2 text-left transition-all",
                  isPreview
                    ? "border-primary/60 bg-primary/5 shadow-[0_0_0_1px_var(--primary)]/10"
                    : "border-transparent hover:border-border/70 hover:bg-muted/40",
                ].join(" ")}
              >
                <div className="flex gap-0.5">
                  {t.swatch.map((c, i) => (
                    <span key={i} className="h-9 w-2 rounded-[1px] border border-border/40" style={{ background: c }} />
                  ))}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-mono flex items-center gap-1.5 text-[12px] font-semibold tracking-tight">
                    {t.name}
                    {isActive && (
                      <span className="text-mono rounded-sm border border-border/60 bg-muted/40 px-1 py-px text-[8.5px] uppercase tracking-widest text-muted-foreground">
                        active
                      </span>
                    )}
                    {isPreview && !isActive && (
                      <span className="text-mono inline-flex items-center gap-0.5 rounded-sm border border-primary/40 bg-primary/10 px-1 py-px text-[8.5px] uppercase tracking-widest text-primary">
                        <Eye className="h-2 w-2" /> preview
                      </span>
                    )}
                  </div>
                  <div className="text-[10.5px] text-muted-foreground">{t.description}</div>
                </div>
                {isPreview && <Check className="h-3.5 w-3.5 shrink-0 text-primary" />}
              </button>
            );
          })}
        </div>

        <div className="sticky bottom-0 flex items-center justify-between gap-2 border-t border-border/60 bg-muted/30 px-3 py-2 backdrop-blur">
          <div className="text-mono text-[10px] text-muted-foreground">
            {dirty
              ? <>changes not saved · <span className="text-foreground">{previewTheme}</span></>
              : "click a theme to preview"}
          </div>
          <div className="flex gap-1.5">
            <Button variant="ghost" size="sm" className="text-mono h-7 gap-1 text-[10px] uppercase tracking-widest"
              disabled={!dirty} onClick={onCancel}>
              <RotateCcw className="h-3 w-3" /> cancel
            </Button>
            <Button size="sm" className="text-mono h-7 gap-1 text-[10px] uppercase tracking-widest"
              disabled={!dirty} onClick={onApply}>
              <Check className="h-3 w-3" /> apply
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

function ThemeCard({ id, active, previewing = false, onClick }: { id: ThemeId; active: boolean; previewing?: boolean; onClick: () => void }) {
  const t = THEMES.find((x) => x.id === id)!;
  return (
    <button
      onClick={onClick}
      data-theme={id}
      className={
        "group relative overflow-hidden rounded-md border bg-[var(--card)] p-0 text-left transition-all hover:-translate-y-0.5 " +
        (previewing
          ? "border-primary ring-2 ring-primary/40 shadow-glow"
          : active
            ? "border-primary/70 shadow-glow"
            : "border-border hover:border-primary/40")
      }
    >
      {previewing && (
        <span className="text-mono absolute right-1 top-1 z-10 inline-flex items-center gap-1 rounded-sm border border-primary/50 bg-primary/15 px-1 py-0.5 text-[8.5px] uppercase tracking-widest text-primary">
          <Eye className="h-2.5 w-2.5" /> preview
        </span>
      )}
      {/* preview surface in the theme's own tokens */}
      <div className="relative h-24 w-full bg-[var(--background)] p-2">
        <div className="absolute inset-0 opacity-50 aurora-glow" aria-hidden />
        <div className="relative flex h-full flex-col justify-between">
          <div className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full" style={{ background: "var(--primary)" }} />
            <span className="h-2 w-2 rounded-full" style={{ background: "var(--accent)" }} />
            <span className="h-2 w-2 rounded-full" style={{ background: "var(--success)" }} />
            <span className="ml-auto h-2 w-8 rounded" style={{ background: "var(--border)" }} />
          </div>
          <div className="flex items-end gap-1">
            <span className="h-6 w-6 rounded" style={{ background: "var(--card)" }} />
            <span className="h-4 w-10 rounded" style={{ background: "var(--primary)" }} />
            <span className="h-3 w-6 rounded" style={{ background: "var(--accent)" }} />
          </div>
        </div>
      </div>
      <div className="border-t border-border/60 px-3 py-2">
        <div className="flex items-center justify-between">
          <div className="text-mono text-[12px] font-semibold tracking-tight text-[var(--foreground)]">{t.name}</div>
          {active && <Check className="h-3.5 w-3.5 text-primary" />}
        </div>
        <div className="text-mono text-[10px] text-[var(--muted-foreground)]">{t.description}</div>
      </div>
    </button>
  );
}

function FontPicker<T extends string>({ title, options, value, onChange, sample, mono }: {
  title: string; options: readonly T[]; value: T; onChange: (v: T) => void; sample: string; mono: boolean;
}) {
  return (
    <div>
      <Label>{title}</Label>
      <div className="mt-2 grid gap-2">
        {options.map((opt) => (
          <button
            key={opt}
            onClick={() => onChange(opt)}
            className={
              "flex items-center gap-3 rounded-md border bg-card/40 px-3 py-2 text-left transition-colors hover:bg-card " +
              (value === opt ? "border-primary/60 ring-1 ring-primary/40" : "border-border/70")
            }
          >
            <div className="min-w-0 flex-1">
              <div className="text-mono text-[11px] uppercase tracking-widest text-muted-foreground">{opt}</div>
              <div
                className="truncate text-[14px] text-foreground"
                style={{ fontFamily: mono ? `"${opt}", ui-monospace, monospace` : `"${opt}", ui-sans-serif, sans-serif` }}
              >
                {sample}
              </div>
            </div>
            {value === opt && <Check className="h-3.5 w-3.5 text-primary" />}
          </button>
        ))}
      </div>
    </div>
  );
}

function Panel({ id, label, icon: Icon, right, children }: {
  id?: string; label: string; icon: typeof Palette; right?: React.ReactNode; children: React.ReactNode;
}) {
  return (
    <section id={id ? `panel-${id}` : undefined} className="rounded-md border border-border bg-card/30 scroll-mt-24">
      <header className="flex items-center gap-2 border-b border-border/70 px-3 py-2">
        <span className="grid h-5 w-5 place-items-center rounded-sm border border-primary/40 bg-primary/10 text-primary">
          <Icon className="h-3 w-3" strokeWidth={2.25} />
        </span>
        <h2 className="text-mono text-[11px] uppercase tracking-[0.22em] text-foreground/90">{label}</h2>
        <div className="ml-auto">{right}</div>
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

function Label({ children }: { children: React.ReactNode }) {
  return <div className="text-mono text-[10.5px] uppercase tracking-[0.22em] text-muted-foreground">{children}</div>;
}

function Row({ label, desc, children }: { label: string; desc: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-3 rounded-md border border-border/70 bg-card/40 px-3 py-2.5">
      <div className="min-w-0 flex-1">
        <div className="text-mono text-[12px] font-medium text-foreground">{label}</div>
        <div className="text-[11px] text-muted-foreground">{desc}</div>
      </div>
      {children}
    </div>
  );
}

function IconBtn({ children, onClick, disabled, label }: { children: React.ReactNode; onClick: () => void; disabled?: boolean; label: string }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      className="grid h-6 w-6 place-items-center rounded border border-border bg-background/60 text-muted-foreground transition-colors hover:border-primary/50 hover:text-foreground disabled:opacity-40"
    >
      {children}
    </button>
  );
}
