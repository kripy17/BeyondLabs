import { useEffect, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandSeparator } from "@/components/ui/command";
import { GROUPS, findItem } from "@/lib/workspaces";
import { useRecents } from "@/lib/recents";
import { useTheme, THEMES } from "@/lib/theme";
import { usePrefs } from "@/lib/prefs";
import { Plus, Palette, Settings as SettingsIcon, RotateCcw, Sparkles } from "lucide-react";

export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const navigate = useNavigate();
  const { theme, setTheme } = useTheme();
  const { reset } = usePrefs();
  const recents = useRecents();

  const go = (url: string) => { onOpenChange(false); navigate({ to: url }); };

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange}>
      <CommandInput placeholder="Search workspaces, run an action…" />
      <CommandList className="max-h-[60vh]">
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

        {GROUPS.map((g) => (
          <CommandGroup key={g.label} heading={g.label}>
            {g.items.map((it) => {
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
          <CommandItem onSelect={() => go("/parser")} value="new session start triage parser">
            <Plus className="h-4 w-4" />
            <span className="text-mono text-[12.5px]">New session</span>
          </CommandItem>
          <CommandItem onSelect={() => go("/settings")} value="open settings preferences">
            <SettingsIcon className="h-4 w-4" />
            <span className="text-mono text-[12.5px]">Open settings</span>
          </CommandItem>
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
    </CommandDialog>
  );
}

export function useCommandPalette() {
  const [open, setOpen] = useState(false);
  const { prefs } = usePrefs();
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const meta = e.metaKey || e.ctrlKey;
      if (meta && e.key.toLowerCase() === "k") { e.preventDefault(); setOpen((o) => !o); return; }
      if (prefs.slashOpensPalette && e.key === "/" && document.activeElement?.tagName !== "INPUT" && document.activeElement?.tagName !== "TEXTAREA") {
        e.preventDefault(); setOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [prefs.slashOpensPalette]);
  return { open, setOpen };
}
