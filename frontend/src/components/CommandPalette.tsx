import { useEffect, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandSeparator } from "@/components/ui/command";
import { GROUPS, findItem } from "@/lib/workspaces";
import { useRecents } from "@/lib/recents";
import { useTheme, THEMES } from "@/lib/theme";
import { usePrefs } from "@/lib/prefs";
import { useLocker } from "@/lib/locker";
import { Plus, Palette, Settings as SettingsIcon, RotateCcw, Sparkles, Search, PackageOpen } from "lucide-react";

const MITRE_QUICK: { id: string; name: string }[] = [
  { id: "T1059", name: "Command and Scripting Interpreter" },
  { id: "T1059.001", name: "PowerShell" },
  { id: "T1566", name: "Phishing" },
  { id: "T1566.001", name: "Spearphishing Attachment" },
  { id: "T1566.002", name: "Spearphishing Link" },
  { id: "T1071", name: "Application Layer Protocol" },
  { id: "T1071.001", name: "Web Protocols" },
  { id: "T1055", name: "Process Injection" },
  { id: "T1003", name: "OS Credential Dumping" },
  { id: "T1082", name: "System Information Discovery" },
  { id: "T1047", name: "Windows Management Instrumentation" },
  { id: "T1204", name: "User Execution" },
  { id: "T1053", name: "Scheduled Task/Job" },
  { id: "T1485", name: "Data Destruction" },
  { id: "T1490", name: "Inhibit System Recovery" },
  { id: "T1134", name: "Access Token Manipulation" },
  { id: "T1547", name: "Boot or Logon Autostart Execution" },
  { id: "T1036", name: "Masquerading" },
  { id: "T1550", name: "Use Alternate Authentication Material" },
  { id: "T1574", name: "Hijack Execution Flow" },
];

export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const navigate = useNavigate();
  const { theme, setTheme } = useTheme();
  const { reset } = usePrefs();
  const recents = useRecents();
  const locker = useLocker();

  const go = (url: string) => { onOpenChange(false); navigate({ to: url }); };

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange}>
      <CommandInput placeholder="Search workspaces, MITRE, settings…" />
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
        <CommandGroup heading="MITRE Techniques">
          {MITRE_QUICK.map((t) => (
            <CommandItem key={t.id} onSelect={() => go("/mitre")} value={`mitre ${t.id} ${t.name}`}>
              <Search className="h-4 w-4" />
              <span className="text-mono text-[12.5px]">{t.id}</span>
              <span className="ml-auto truncate text-[11px] text-muted-foreground">{t.name}</span>
            </CommandItem>
          ))}
        </CommandGroup>

        <CommandSeparator />
        <CommandGroup heading="Settings">
          {[
            { id: "BR", label: "Brand" },
            { id: "TH", label: "Theme Gallery" },
            { id: "CT", label: "Custom Theme" },
            { id: "AC", label: "Accent" },
            { id: "DR", label: "Density" },
            { id: "TY", label: "Typography" },
            { id: "SB", label: "Sidebar" },
            { id: "ACY", label: "Accessibility" },
            { id: "QL", label: "Motion & QoL" },
            { id: "DB", label: "Dashboard" },
            { id: "KS", label: "Shortcuts" },
            { id: "DP", label: "Data & Privacy" },
          ].map((s) => (
            <CommandItem key={s.id} onSelect={() => { onOpenChange(false); navigate({ to: "/settings", hash: `panel-${s.id}` }); }}
              value={`settings ${s.label} ${s.id}`}>
              <SettingsIcon className="h-4 w-4" />
              <span className="text-mono text-[12.5px]">{s.label}</span>
            </CommandItem>
          ))}
        </CommandGroup>

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
] as const;

export function ShortcutsDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  if (!open) return null;
  return (
    <>
      <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm" onClick={onClose} />
      <div className="fixed left-1/2 top-1/2 z-50 w-full max-w-xs -translate-x-1/2 -translate-y-1/2 rounded-md border border-border bg-popover p-4 shadow-xl">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-mono text-[10px] uppercase tracking-[0.22em] text-foreground/80">Keyboard shortcuts</h2>
          <button onClick={onClose} className="grid h-5 w-5 place-items-center rounded text-muted-foreground hover:text-foreground">✕</button>
        </div>
        <div className="space-y-1.5">
          {SHORTCUTS.map((s) => (
            <div key={s.key} className="flex items-center justify-between gap-3">
              <span className="text-mono text-[11px] text-foreground/80">{s.action}</span>
              <kbd className="rounded border border-border/60 bg-background/60 px-1.5 py-0.5 text-mono text-[10px] text-primary">{s.key}</kbd>
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
  return { open, setOpen, shortcutsOpen, setShortcutsOpen };
}
