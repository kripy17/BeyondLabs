import { useEffect, useRef, useState } from "react";
import { Check, Eye, Moon, Palette, Sun, X } from "lucide-react";
import { THEMES, useTheme, type ThemeId, type ThemeMode } from "@/lib/theme";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Button } from "@/components/ui/button";

/** Temporarily mutate the live <html data-theme> without persisting. */
function applyPreview(id: ThemeId) {
  if (typeof document === "undefined") return;
  const isLight = THEMES.find((t) => t.id === id)?.isLight ?? false;
  document.documentElement.setAttribute("data-theme", id);
  document.documentElement.classList.toggle("dark", !isLight);
}

const MODE_ICONS: Record<ThemeMode, typeof Sun> = { auto: Eye, light: Sun, dark: Moon };
const MODE_LABELS: Record<ThemeMode, string> = { auto: "Auto", light: "Light", dark: "Dark" };

export function ThemeSwitcher({ compact = false }: { compact?: boolean }) {
  const { theme, setTheme, mode, setMode } = useTheme();
  const current = THEMES.find((t) => t.id === theme) ?? THEMES[0];

  const [open, setOpen] = useState(false);
  const [preview, setPreview] = useState<ThemeId>(theme);
  const original = useRef<ThemeId>(theme);
  const applied = useRef(false);

  // Sync when popover opens, snapshot the applied theme.
  useEffect(() => {
    if (open) {
      original.current = theme;
      setPreview(theme);
      applied.current = false;
    }
  }, [open, theme]);

  const handlePreview = (id: ThemeId) => {
    setPreview(id);
    applyPreview(id);
  };

  const handleApply = () => {
    applied.current = true;
    setTheme(preview);
    setOpen(false);
  };

  const handleCancel = () => {
    applyPreview(original.current);
    setPreview(original.current);
    setOpen(false);
  };

  // If popover closes by outside-click, treat as cancel (revert preview).
  const handleOpenChange = (next: boolean) => {
    if (!next && preview !== original.current && !applied.current) {
      applyPreview(original.current);
      setPreview(original.current);
    }
    setOpen(next);
  };

  const dirty = preview !== original.current;

  return (
    <Popover open={open} onOpenChange={handleOpenChange}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          size={compact ? "icon" : "sm"}
          className="text-mono w-full justify-start gap-2 text-xs"
        >
          <Palette className="h-3.5 w-3.5" />
          {!compact && (
            <>
              <span className="truncate">{current.name}</span>
              <div className="ml-auto flex gap-0.5">
                {current.swatch.map((c, i) => (
                  <span
                    key={i}
                    className="h-3 w-1.5 rounded-[1px] border border-divider-soft"
                    style={{ background: c }}
                  />
                ))}
              </div>
            </>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" sideOffset={8} className="w-80 p-0">
        <div className="flex items-center justify-between border-b border-divider-strong px-3 py-2">
          <div className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            Theme · preview
          </div>
          {dirty && (
            <span className="text-mono inline-flex items-center gap-1 rounded-sm border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-[9px] uppercase tracking-widest text-primary">
              <Eye className="h-2.5 w-2.5" /> unsaved
            </span>
          )}
        </div>

        <div className="max-h-[360px] overflow-y-auto p-1">
          {THEMES.map((t) => {
            const isPreview = preview === t.id;
            const isApplied = theme === t.id;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => handlePreview(t.id)}
                className={[
                  "group flex w-full items-center gap-3 rounded-sm border px-2 py-2 text-left transition-colors",
                  isPreview
                    ? "border-primary/60 bg-primary/5"
                    : "border-transparent hover:border-divider-strong hover:bg-muted/40",
                ].join(" ")}
              >
                <div className="flex gap-0.5">
                  {t.swatch.map((c, i) => (
                    <span
                      key={i}
                      className="h-7 w-2 rounded-[1px] border border-divider-soft"
                      style={{ background: c }}
                    />
                  ))}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-mono flex items-center gap-1.5 text-xs font-semibold">
                    {t.name}
                    {isApplied && (
                      <span className="text-mono rounded-sm border border-divider-strong px-1 py-px text-[8px] uppercase tracking-widest text-muted-foreground">
                        active
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-muted-foreground">{t.description}</div>
                </div>
                {isPreview && <Check className="h-3.5 w-3.5 shrink-0 text-primary" />}
              </button>
            );
          })}
        </div>

        <div className="flex items-center justify-between gap-2 border-t border-divider-strong bg-muted/20 px-3 py-2">
          <div className="flex items-center gap-1 rounded-md border border-divider-soft bg-card/40 p-0.5">
            {(["dark", "light", "auto"] as ThemeMode[]).map((m) => {
              const Icon = MODE_ICONS[m];
              return (
                <button
                  key={m}
                  type="button"
                  onClick={() => setMode(m)}
                  className={`grid h-6 w-6 place-items-center rounded text-[10px] transition-colors ${
                    mode === m ? "bg-primary/20 text-primary" : "text-muted-foreground hover:text-foreground"
                  }`}
                  title={MODE_LABELS[m]}
                >
                  <Icon className="h-3 w-3" />
                </button>
              );
            })}
          </div>
          <div className="text-mono text-[10px] text-muted-foreground">
            {dirty ? "Previewing — not saved" : "No changes"}
          </div>
          <div className="flex gap-1.5">
            <Button
              variant="ghost"
              size="sm"
              className="text-mono h-7 gap-1 text-[10px] uppercase tracking-widest"
              onClick={handleCancel}
            >
              <X className="h-3 w-3" /> Cancel
            </Button>
            <Button
              size="sm"
              className="text-mono h-7 gap-1 text-[10px] uppercase tracking-widest"
              disabled={!dirty}
              onClick={handleApply}
            >
              <Check className="h-3 w-3" /> Apply
            </Button>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}
