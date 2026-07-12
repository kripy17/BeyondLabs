import { useState } from "react";
import { useLocker, guessType, type LockerItem } from "@/lib/locker";
import { X, Trash2, PackageOpen, FileText, ExternalLink, Copy, NotebookPen, Terminal, ChevronUp } from "lucide-react";
import { toast } from "sonner";

const TYPE_COLORS: Record<string, string> = {
  ipv4: "text-blue-400", ipv6: "text-blue-400",
  domain: "text-emerald-400", url: "text-emerald-400",
  sha256: "text-orange-400", sha1: "text-orange-400", md5: "text-orange-400",
  email: "text-violet-400",
  file: "text-cyan-400",
};

export function IocLockerTrigger({ onClick, count }: { onClick: () => void; count: number }) {
  const [showMenu, setShowMenu] = useState(false);
  const [showTerminal, setShowTerminal] = useState(false);

  return (
    <>
      <div className="fixed bottom-6 right-6 z-40 flex flex-col items-end gap-2">
        {showMenu && (
          <>
            <div className="fixed inset-0 z-40" onClick={() => setShowMenu(false)} />
            <div className="z-50 flex flex-col gap-1 rounded-lg border border-border bg-card p-1.5 elevation-raised">
              <button
                onClick={() => { setShowMenu(false); onClick(); }}
                className="flex items-center gap-2 rounded-md px-3 py-2 text-left text-mono text-[11px] text-foreground/80 hover:bg-primary/5"
              >
                <PackageOpen className="h-4 w-4 text-primary" />
                <span>IOC Locker</span>
                {count > 0 && (
                  <span className="ml-auto rounded-full bg-destructive px-1.5 py-0.5 text-mono text-[9px] font-bold text-destructive-foreground">
                    {count > 99 ? "99+" : count}
                  </span>
                )}
              </button>
              <button
                onClick={() => { setShowMenu(false); setShowTerminal(true); }}
                className="flex items-center gap-2 rounded-md px-3 py-2 text-left text-mono text-[11px] text-foreground/80 hover:bg-primary/5"
              >
                <Terminal className="h-4 w-4 text-primary" />
                <span>Terminal</span>
              </button>
            </div>
          </>
        )}

        <button
          onClick={() => setShowMenu((v) => !v)}
          className="flex h-12 w-12 items-center justify-center rounded-full border border-primary/40 bg-primary/15 text-primary shadow-glow transition-all hover:-translate-y-0.5 hover:bg-primary/25"
          aria-label="Quick actions"
        >
          {showMenu ? <ChevronUp className="h-5 w-5" /> : <PackageOpen className="h-5 w-5" />}
          {!showMenu && count > 0 && (
            <span className="absolute -right-1 -top-1 flex h-5 w-5 items-center justify-center rounded-full bg-destructive text-mono text-[9px] font-bold text-destructive-foreground">
              {count > 99 ? "99+" : count}
            </span>
          )}
        </button>
      </div>

      {showTerminal && (
        <QuickTerminalPanel onClose={() => setShowTerminal(false)} />
      )}
    </>
  );
}

export function IocLockerPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { items, remove, clear } = useLocker();

  return (
    <>
      {open && (
        <div className="fixed inset-0 z-50 bg-black/30 backdrop-blur-sm" onClick={onClose} />
      )}
      <div
        className={
          "fixed bottom-0 right-0 top-0 z-50 flex w-full max-w-md flex-col border-l border-border bg-background/95 backdrop-blur transition-transform duration-300 " +
          (open ? "translate-x-0" : "translate-x-full")
        }
      >
        <header className="flex items-center gap-2 border-b border-divider-strong px-4 py-3">
          <span className="grid h-7 w-7 place-items-center rounded-md border border-primary/40 bg-primary/10 text-primary">
            <PackageOpen className="h-4 w-4" />
          </span>
          <h2 className="text-mono text-[12px] uppercase tracking-[0.22em] text-foreground/90">IOC Locker</h2>
          <span className="text-mono text-[10px] text-muted-foreground">{items.length} items</span>
          <div className="ml-auto flex items-center gap-1">
            {items.length > 0 && (
              <button
                onClick={() => { clear(); toast("Locker cleared"); }}
                className="rounded border border-divider-strong px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground transition-colors hover:border-destructive/50 hover:text-destructive"
              >
                clear all
              </button>
            )}
            <button onClick={onClose} className="grid h-7 w-7 place-items-center rounded-md border border-border text-muted-foreground hover:text-foreground">
              <X className="h-4 w-4" />
            </button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto">
          {items.length === 0 ? (
            <div className="flex flex-col items-center gap-2 px-4 py-16 text-mono text-[11.5px] text-muted-foreground">
              <PackageOpen className="h-8 w-8 opacity-40" />
              <p>No IOCs collected yet.</p>
              <p className="text-[10px]">Use the locker from any workspace.</p>
            </div>
          ) : (
            <div className="divide-y divide-border/50">
              {items.map((item) => (
                <LockerRow key={item.id} item={item} onRemove={remove} />
              ))}
            </div>
          )}
        </div>

        {items.length > 0 && (
          <footer className="border-t border-divider-strong px-4 py-2">
            <div className="flex items-center gap-2 text-mono text-[10px] text-muted-foreground">
              <span>{items.filter((i) => i.type === "ipv4" || i.type === "domain").length} network</span>
              <span className="text-border/60">·</span>
              <span>{items.filter((i) => i.type === "sha256" || i.type === "sha1" || i.type === "md5").length} hashes</span>
              <span className="text-border/60">·</span>
              <span>{items.filter((i) => i.type === "url").length} urls</span>
            </div>
          </footer>
        )}
      </div>
    </>
  );
}

function QuickTerminalPanel({ onClose }: { onClose: () => void }) {
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<{ cmd: string; output: string }[]>([]);

  const runCommand = async () => {
    if (!input.trim()) return;
    const cmd = input.trim();
    setInput("");
    setHistory((h) => [...h, { cmd, output: "running…" }]);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/terminal/exec", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: cmd }),
      });
      const data = await res.json();
      setHistory((h) => h.map((entry, i) => i === h.length - 1 ? { ...entry, output: data.output || data.error || "(no output)" } : entry));
    } catch {
      setHistory((h) => h.map((entry, i) => i === h.length - 1 ? { ...entry, output: "error: backend unreachable" } : entry));
    }
  };

  return (
    <>
      <div className="fixed inset-0 z-50 bg-black/30 backdrop-blur-sm" onClick={onClose} />
      <div className="fixed bottom-0 right-0 z-50 flex w-full max-w-lg flex-col rounded-t-xl border border-border bg-background/95 backdrop-blur shadow-2xl" style={{ maxHeight: "50vh" }}>
        <header className="flex items-center gap-2 border-b border-divider-strong px-4 py-2.5">
          <span className="grid h-6 w-6 place-items-center rounded border border-primary/40 bg-primary/10 text-primary">
            <Terminal className="h-3.5 w-3.5" />
          </span>
          <h2 className="text-mono text-[11px] uppercase tracking-[0.22em] text-foreground/90">Quick Terminal</h2>
          <span className="text-mono text-[9px] text-muted-foreground">local</span>
          <button onClick={onClose} className="ml-auto grid h-6 w-6 place-items-center rounded border border-border text-muted-foreground hover:text-foreground">
            <X className="h-3.5 w-3.5" />
          </button>
        </header>
        <div className="flex-1 overflow-y-auto p-3 space-y-2" style={{ minHeight: "8rem" }}>
          {history.length === 0 ? (
            <div className="flex items-center justify-center py-8 text-mono text-[10.5px] text-muted-foreground/60">
              Type a command below to run on the local host.
            </div>
          ) : (
            history.map((entry, i) => (
              <div key={i}>
                <div className="flex items-center gap-1.5 text-mono text-[11px] text-foreground/90">
                  <span className="text-primary">$</span> {entry.cmd}
                </div>
                <pre className="mt-0.5 whitespace-pre-wrap rounded bg-background/80 px-2.5 py-1.5 text-mono text-[10.5px] leading-relaxed text-foreground/80">{entry.output}</pre>
              </div>
            ))
          )}
        </div>
        <div className="border-t border-divider-strong px-3 py-2">
          <div className="flex items-center gap-1.5 rounded-md border border-divider-strong bg-background/60 px-2.5">
            <span className="text-mono text-[11px] text-primary">$</span>
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") runCommand(); }}
              placeholder="run a command…"
              className="flex-1 bg-transparent py-1.5 text-mono text-[11.5px] outline-none placeholder:text-muted-foreground/50"
              autoFocus
            />
          </div>
        </div>
      </div>
    </>
  );
}

function LockerRow({ item, onRemove }: { item: LockerItem; onRemove: (id: string) => void }) {
  const { updateNote } = useLocker();
  const [editingNote, setEditingNote] = useState(false);
  const [noteDraft, setNoteDraft] = useState(item.note ?? "");
  const ts = new Date(item.ts).toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });

  return (
    <div className="group px-4 py-2.5 transition-colors hover:bg-card/30">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span className={"text-mono text-[9.5px] uppercase tracking-widest " + (TYPE_COLORS[item.type] ?? "text-muted-foreground")}>
              {item.type}
            </span>
            <span className="text-mono text-[9px] text-muted-foreground/60">{ts}</span>
          </div>
          <code className="mt-0.5 block truncate text-[12px] text-foreground">{item.value}</code>
          <span className="text-mono text-[9.5px] text-muted-foreground/70">from {item.source}</span>
        </div>
        <div className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
          <button
            onClick={() => { navigator.clipboard.writeText(item.value); toast("Copied"); }}
            className="grid h-6 w-6 place-items-center rounded border border-border text-muted-foreground hover:text-foreground"
            aria-label="Copy"
          >
            <Copy className="h-3 w-3" />
          </button>
          <button
            onClick={() => onRemove(item.id)}
            className="grid h-6 w-6 place-items-center rounded border border-border text-muted-foreground hover:text-destructive"
            aria-label="Remove"
          >
            <X className="h-3 w-3" />
          </button>
        </div>
      </div>

      {(item.note || editingNote) && (
        <div className="mt-1.5 flex items-start gap-1">
          <NotebookPen className="mt-0.5 h-3 w-3 shrink-0 text-muted-foreground/60" />
          {editingNote ? (
            <div className="flex flex-1 items-center gap-1">
              <input
                value={noteDraft}
                onChange={(e) => setNoteDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") { updateNote(item.id, noteDraft); setEditingNote(false); }
                  if (e.key === "Escape") { setNoteDraft(item.note ?? ""); setEditingNote(false); }
                }}
                onBlur={() => { updateNote(item.id, noteDraft); setEditingNote(false); }}
                className="min-w-0 flex-1 rounded border border-divider-strong bg-background/60 px-1.5 py-0.5 text-mono text-[10.5px] text-foreground outline-none"
                placeholder="Add a note…"
                autoFocus
              />
            </div>
          ) : (
            <button onClick={() => { setEditingNote(true); }} className="flex-1 text-left text-[10.5px] text-muted-foreground/80 hover:text-foreground">
              {item.note}
            </button>
          )}
        </div>
      )}

      {!item.note && !editingNote && (
        <button
          onClick={() => { setEditingNote(true); setNoteDraft(item.note ?? ""); }}
          className="mt-1 text-mono text-[9.5px] text-muted-foreground/50 hover:text-foreground/70"
        >
          + add note
        </button>
      )}
    </div>
  );
}
