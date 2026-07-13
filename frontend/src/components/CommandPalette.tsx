import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandSeparator } from "@/components/ui/command";
import { GROUPS, findItem, type WorkspaceItem } from "@/lib/workspaces";
import { useRecents } from "@/lib/recents";
import { useTheme, THEMES } from "@/lib/theme";
import { usePrefs } from "@/lib/prefs";
import { useLocker } from "@/lib/locker";
import { Plus, Palette, RotateCcw, Sparkles, Search, PackageOpen } from "lucide-react";
import Fuse from "fuse.js";

export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const navigate = useNavigate();
  const { theme, setTheme } = useTheme();
  const { reset } = usePrefs();
  const recents = useRecents();
  const locker = useLocker();
  const [searchValue, setSearchValue] = useState("");

  useEffect(() => {
    if (!open) setSearchValue("");
  }, [open]);

  const go = (url: string) => { onOpenChange(false); navigate({ to: url }); };

  const fuse = useMemo(() => new Fuse(
    GROUPS.flatMap((g) => g.items.map((it) => ({ ...it, _group: g.label }))),
    { keys: ["title", "desc", "group"], threshold: 0.3, distance: 80 }
  ), []);

  const fuzzyItems: (WorkspaceItem & { _group: string })[] = useMemo(() => {
    if (!searchValue.trim()) return GROUPS.flatMap((g) => g.items.map((it) => ({ ...it, _group: g.label })));
    return fuse.search(searchValue).map((r) => r.item);
  }, [searchValue, fuse]);

  const fuzzyGrouped = useMemo(() => {
    const map = new Map<string, (WorkspaceItem & { _group: string })[]>();
    for (const it of fuzzyItems) {
      const g = it._group;
      if (!map.has(g)) map.set(g, []);
      map.get(g)!.push(it);
    }
    return Array.from(map.entries());
  }, [fuzzyItems]);

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange}>
      <CommandInput
        placeholder="Search workspaces…"
        onValueChange={(v) => setSearchValue(v)}
        value={searchValue}
      />

      {searchValue && (
        <div className="flex items-center gap-2 border-b border-divider-soft bg-background/40 px-3 py-1.5 text-mono text-[10px] text-muted-foreground">
          <Search className="h-3 w-3" />
          <span>
            Filtering for "<span className="text-foreground/70">{searchValue}</span>"
          </span>
        </div>
      )}

      <CommandList className="max-h-[70vh]">
        <CommandEmpty>No results.</CommandEmpty>

        {recents.length > 0 && (
          <>
            <CommandGroup heading="Recent">
              {recents.map((url) => {
                const it = findItem(url);
                if (!it) return null;
                const Icon = it.icon;
                return (
                  <CommandItem key={`r-${url}`} onSelect={() => go(url)} value={`recent ${it.title} ${it.desc}`}>
                    <Icon className="h-4 w-4" />
                    <span className="text-mono text-[12.5px]">{it.title}</span>
                    <span className="ml-auto text-mono text-[10px] text-muted-foreground">{it.group.toLowerCase()}</span>
                  </CommandItem>
                );
              })}
            </CommandGroup>
            <CommandSeparator />
          </>
        )}

        {fuzzyGrouped.map(([groupLabel, items]) => (
          <CommandGroup key={groupLabel} heading={groupLabel}>
            {items.map((it) => {
              const Icon = it.icon;
              return (
                <CommandItem key={it.url} onSelect={() => go(it.url)} value={`${it.title} ${it.desc} ${it.group}`}>
                  <Icon className="h-4 w-4" />
                  <span className="text-mono text-[12.5px]">{it.title}</span>
                  <span className="ml-auto truncate text-[11px] text-muted-foreground">{it.desc}</span>
                </CommandItem>
              );
            })}
          </CommandGroup>
        ))}

        <CommandSeparator />
        <CommandGroup heading="Actions">
          <CommandItem onSelect={() => go("/parser")} value="new session start investigation parser">
            <Plus className="h-4 w-4" />
            <span className="text-mono text-[12.5px]">New session</span>
          </CommandItem>
          {locker.count > 0 && (
            <CommandItem onSelect={() => { onOpenChange(false); }} value="view ioc locker">
              <PackageOpen className="h-4 w-4" />
              <span className="text-mono text-[12.5px]">View IOC locker</span>
              <span className="ml-auto text-mono text-[10px] text-muted-foreground">{locker.count} items</span>
            </CommandItem>
          )}
          <CommandItem
            onSelect={() => {
              const ids = THEMES.map((t) => t.id);
              const next = ids[(ids.indexOf(theme) + 1) % ids.length];
              setTheme(next);
            }}
            value="cycle theme switch"
          >
            <Palette className="h-4 w-4" />
            <span className="text-mono text-[12.5px]">Cycle theme</span>
            <span className="ml-auto text-mono text-[10px] text-muted-foreground">{theme}</span>
          </CommandItem>
          <CommandItem onSelect={() => { reset(); onOpenChange(false); }} value="reset preferences defaults">
            <RotateCcw className="h-4 w-4" />
            <span className="text-mono text-[12.5px]">Reset preferences</span>
          </CommandItem>
          <CommandItem onSelect={() => go("/")} value="dashboard home">
            <Sparkles className="h-4 w-4" />
            <span className="text-mono text-[12.5px]">Go to Command Deck</span>
          </CommandItem>
        </CommandGroup>
      </CommandList>

      <div className="flex items-center gap-3 border-t border-divider-soft bg-background/60 px-3 py-1 text-mono text-[10px] text-muted-foreground">
        <span className="flex items-center gap-1"><kbd className="rounded border border-border/50 bg-card/40 px-1">↑↓</kbd> navigate</span>
        <span className="flex items-center gap-1"><kbd className="rounded border border-border/50 bg-card/40 px-1">↵</kbd> open</span>
        <span className="flex items-center gap-1"><kbd className="rounded border border-border/50 bg-card/40 px-1">Esc</kbd> close</span>
      </div>
    </CommandDialog>
  );
}

const SHORTCUTS = [
  { key: "⌘K", action: "Open command palette" },
  { key: "/", action: "Search workspaces" },
  { key: "?", action: "Show shortcuts" },
  { key: "Esc", action: "Close search / clear input" },
  { key: "↑↓", action: "Navigate search results" },
  { key: "↵", action: "Open selected result" },
  { key: "g p", action: "Go to Parser" },
  { key: "g f", action: "Go to Phishing" },
  { key: "g u", action: "Go to URL Analyzer" },
  { key: "g r", action: "Go to Recon" },
  { key: "g m", action: "Go to MITRE" },
  { key: "g c", action: "Go to Case" },
  { key: "g s", action: "Go to Snippets" },
  { key: "g d", action: "Go to Detection" },
  { key: "g t", action: "Go to Toolkit" },
  { key: "g h", action: "Go to Command Deck" },
  { key: "g a", action: "Go to Activity Feed" },
  { key: "n",   action: "New case" },
] as const;

const PANEL_SHORTCUTS = [
  { key: "j", action: "Next result" },
  { key: "k", action: "Previous result" },
  { key: "y", action: "Copy selected row" },
  { key: "e", action: "Enrich selected IOC" },
  { key: "c", action: "Attach selected to case" },
  { key: ".", action: "Context menu" },
] as const;

export function ShortcutsDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  if (!open) return null;
  return (
    <>
      <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm" onClick={onClose} />
      <div className="fixed left-1/2 top-1/2 z-50 w-full max-w-xs -translate-x-1/2 -translate-y-1/2 rounded-md border border-border bg-popover p-4 elevation-floating">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-mono text-[10px] uppercase tracking-[0.22em] text-foreground/80">Keyboard shortcuts</h2>
          <button onClick={onClose} className="grid h-5 w-5 place-items-center rounded text-muted-foreground hover:text-foreground">✕</button>
        </div>
        <div className="space-y-1.5">
          {SHORTCUTS.map((s) => (
            <div key={s.key} className="flex items-center justify-between gap-3">
              <span className="text-mono ba-text-sm text-foreground/80">{s.action}</span>
              <kbd className="rounded border border-divider-strong bg-background/60 px-1.5 py-0.5 text-mono text-[10px] text-primary">{s.key}</kbd>
            </div>
          ))}
        </div>
        <div className="my-3 border-t border-border/50" />
        <div className="mb-2 text-mono text-[10px] uppercase tracking-[0.22em] text-muted-foreground/80">Panel navigation</div>
        <div className="space-y-1.5">
          {PANEL_SHORTCUTS.map((s) => (
            <div key={s.key} className="flex items-center justify-between gap-3">
              <span className="text-mono ba-text-sm text-foreground/80">{s.action}</span>
              <kbd className="rounded border border-divider-strong bg-background/60 px-1.5 py-0.5 text-mono text-[10px] text-primary">{s.key}</kbd>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

export function useCommandPalette() {
  const [open, setOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const navigate = useNavigate();
  const { prefs } = usePrefs();
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const meta = e.metaKey || e.ctrlKey;
      if (meta && e.key.toLowerCase() === "k") { e.preventDefault(); setOpen((o) => !o); return; }
      if (prefs.slashOpensPalette && e.key === "/" && document.activeElement?.tagName !== "INPUT" && document.activeElement?.tagName !== "TEXTAREA") {
        e.preventDefault(); setOpen(true);
      }
      if (e.key === "?" && !meta && document.activeElement?.tagName !== "INPUT" && document.activeElement?.tagName !== "TEXTAREA") {
        e.preventDefault(); setShortcutsOpen((o) => !o);
      }
      if (e.key === "Escape") { setShortcutsOpen(false); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [prefs.slashOpensPalette]);

  /* Navigation shortcuts: G + key */
  useEffect(() => {
    let gPending = false;
    let gTimer: ReturnType<typeof setTimeout>;
    const NAV_MAP: Record<string, string> = {
      p: "/parser", s: "/settings", h: "/", f: "/phishing",
      d: "/detection", i: "/siem", r: "/recon", t: "/hacking-toolkit",
      c: "/chef", m: "/mitre", n: "/case",
    };
    const onNavKey = (e: KeyboardEvent) => {
      if (e.key === "g" && !e.metaKey && !e.ctrlKey && !e.repeat) {
        gPending = true;
        clearTimeout(gTimer);
        gTimer = setTimeout(() => { gPending = false; }, 1000);
        return;
      }
      if (gPending && NAV_MAP[e.key.toLowerCase()]) {
        e.preventDefault();
        gPending = false;
        clearTimeout(gTimer);
        navigate({ to: NAV_MAP[e.key.toLowerCase()] });
      }
    };
    window.addEventListener("keydown", onNavKey);
    return () => window.removeEventListener("keydown", onNavKey);
  }, [navigate]);

  return { open, setOpen, shortcutsOpen, setShortcutsOpen };
}
