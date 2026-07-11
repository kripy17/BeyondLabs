import { useState } from "react";
import { useLocker, guessType, type LockerItem } from "@/lib/locker";
import { X, Trash2, PackageOpen, FileText, ExternalLink, Copy, NotebookPen } from "lucide-react";
import { toast } from "sonner";

const TYPE_COLORS: Record<string, string> = {
  ipv4: "text-blue-400", ipv6: "text-blue-400",
  domain: "text-emerald-400", url: "text-emerald-400",
  sha256: "text-orange-400", sha1: "text-orange-400", md5: "text-orange-400",
  email: "text-violet-400",
  file: "text-cyan-400",
};

export function IocLockerTrigger({ onClick, count }: { onClick: () => void; count: number }) {
  return (
    <button
      onClick={onClick}
      className="fixed bottom-6 right-6 z-40 flex h-12 w-12 items-center justify-center rounded-full border border-primary/40 bg-primary/15 text-primary shadow-glow transition-all hover:-translate-y-0.5 hover:bg-primary/25"
      aria-label="Open IOC locker"
    >
      <PackageOpen className="h-5 w-5" />
      {count > 0 && (
        <span className="absolute -right-1 -top-1 flex h-5 w-5 items-center justify-center rounded-full bg-destructive text-mono text-[9px] font-bold text-destructive-foreground">
          {count > 99 ? "99+" : count}
        </span>
      )}
    </button>
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
        <header className="flex items-center gap-2 border-b border-border/70 px-4 py-3">
          <span className="grid h-7 w-7 place-items-center rounded-md border border-primary/40 bg-primary/10 text-primary">
            <PackageOpen className="h-4 w-4" />
          </span>
          <h2 className="text-mono text-[12px] uppercase tracking-[0.22em] text-foreground/90">IOC Locker</h2>
          <span className="text-mono text-[10px] text-muted-foreground">{items.length} items</span>
          <div className="ml-auto flex items-center gap-1">
            {items.length > 0 && (
              <button
                onClick={() => { clear(); toast("Locker cleared"); }}
                className="rounded border border-border/60 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground transition-colors hover:border-destructive/50 hover:text-destructive"
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
          <footer className="border-t border-border/70 px-4 py-2">
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

function LockerRow({ item, onRemove }: { item: LockerItem; onRemove: (id: string) => void }) {
  const { updateNote } = useLocker();
  const [editingNote, setEditingNote] = useState(false);
  const [noteDraft, setNoteDraft] = useState(item.note);
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
                  if (e.key === "Escape") { setNoteDraft(item.note); setEditingNote(false); }
                }}
                onBlur={() => { updateNote(item.id, noteDraft); setEditingNote(false); }}
                className="min-w-0 flex-1 rounded border border-border/60 bg-background/60 px-1.5 py-0.5 text-mono text-[10.5px] text-foreground outline-none"
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
          onClick={() => { setEditingNote(true); setNoteDraft(item.note); }}
          className="mt-1 text-mono text-[9.5px] text-muted-foreground/50 hover:text-foreground/70"
        >
          + add note
        </button>
      )}
    </div>
  );
}
