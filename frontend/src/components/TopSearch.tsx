import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { Search, Command as CmdIcon, CornerDownLeft, X, Loader2, ArrowRight } from "lucide-react";
import { ALL_ITEMS } from "@/lib/workspaces";

export function TopSearch({ onOpenPalette }: { onOpenPalette: () => void }) {
  const [q, setQ] = useState("");
  const [debounced, setDebounced] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [loading, setLoading] = useState(false);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const navigate = useNavigate();

  // Debounced query — gives a brief "searching" affordance and avoids jitter
  useEffect(() => {
    if (q !== debounced) setLoading(true);
    const t = setTimeout(() => {
      setDebounced(q);
      setLoading(false);
    }, 120);
    return () => clearTimeout(t);
  }, [q, debounced]);

  const needle = debounced.trim().toLowerCase();
  const hits = needle
    ? ALL_ITEMS.filter((i) =>
        i.title.toLowerCase().includes(needle)
        || i.desc.toLowerCase().includes(needle)
        || i.group.toLowerCase().includes(needle)
      ).slice(0, 6)
    : [];

  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (!wrapRef.current?.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener("mousedown", onDown);
    return () => window.removeEventListener("mousedown", onDown);
  }, []);

  useEffect(() => { setActive(0); }, [debounced]);

  const closeAndClear = () => { setOpen(false); setQ(""); setDebounced(""); };
  const focused = open;

  return (
    <div ref={wrapRef} className="relative w-full max-w-[460px]">
      <div
        className={
          "group relative flex items-center transition-all duration-200 " +
          (focused ? "scale-[1.01]" : "")
        }
      >
        <div className="pointer-events-none absolute left-2.5 grid h-3.5 w-3.5 place-items-center">
          {loading ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
          ) : (
            <Search className="h-3.5 w-3.5 text-muted-foreground transition-colors group-focus-within:text-primary" />
          )}
        </div>
        <input
          ref={inputRef}
          value={q}
          onChange={(e) => { setQ(e.target.value); setOpen(true); }}
          onFocus={() => setOpen(true)}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") { e.preventDefault(); setOpen(true); setActive((a) => Math.min(a + 1, Math.max(hits.length - 1, 0))); }
            else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
            else if (e.key === "Enter") {
              if (hits[active]) { e.preventDefault(); closeAndClear(); navigate({ to: hits[active].url }); }
              else if (!needle) { e.preventDefault(); setOpen(false); onOpenPalette(); }
            }
            else if (e.key === "Escape") {
              e.preventDefault();
              if (q) { setQ(""); setDebounced(""); }
              else { setOpen(false); inputRef.current?.blur(); }
            }
            else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
              e.preventDefault(); setOpen(false); onOpenPalette();
            }
          }}
          placeholder="Search workspaces…"
          className="text-mono h-8 w-full rounded-md border border-divider-strong bg-card/50 pl-8 pr-[88px] ba-text-base text-foreground placeholder:text-muted-foreground/70 outline-none transition-all focus:border-primary/60 focus:bg-card focus:shadow-[0_0_0_3px_color-mix(in_oklab,var(--primary)_18%,transparent)]"
          aria-label="Global search"
          aria-expanded={open}
          aria-controls="topsearch-listbox"
          role="combobox"
        />
        <div className="absolute right-1.5 flex items-center gap-1">
          {q && (
            <button
              type="button"
              onMouseDown={(e) => { e.preventDefault(); setQ(""); setDebounced(""); inputRef.current?.focus(); }}
              className="grid h-5 w-5 place-items-center rounded text-muted-foreground/70 transition-colors hover:bg-muted/60 hover:text-foreground"
              aria-label="Clear search"
              title="Clear (Esc)"
            >
              <X className="h-3 w-3" />
            </button>
          )}
          <kbd className="text-mono pointer-events-none inline-flex items-center gap-0.5 rounded border border-divider-strong bg-background/60 px-1 py-0.5 text-[10px] text-muted-foreground/70">
            <CmdIcon className="h-2.5 w-2.5" />K
          </kbd>
        </div>
      </div>

      {open && (
        <div
          id="topsearch-listbox"
          role="listbox"
          className="absolute left-0 right-0 top-full z-50 mt-1.5 origin-top overflow-hidden rounded-md border border-border bg-popover elevation-raised duration-150 animate-in fade-in-0 zoom-in-95 slide-in-from-top-1"
        >
          {/* Results */}
          {needle && hits.length > 0 && (
            <ul className="max-h-[60vh] overflow-y-auto py-1">
              {hits.map((h, i) => (
                <li key={h.url} role="option" aria-selected={i === active}>
                  <Link
                    to={h.url}
                    onClick={closeAndClear}
                    onMouseEnter={() => setActive(i)}
                    className={
                      "flex items-center gap-2 px-2.5 py-2 text-mono ba-text-base transition-colors " +
                      (i === active ? "bg-accent/15 text-foreground" : "text-foreground/90 hover:bg-muted/60")
                    }
                  >
                    <h.icon className="h-3.5 w-3.5 text-primary" />
                    <span className="flex-1 truncate">{h.title}</span>
                    <span className="truncate text-[10.5px] text-muted-foreground">{h.group.toLowerCase()}</span>
                    {i === active && <CornerDownLeft className="h-3 w-3 text-muted-foreground" />}
                  </Link>
                </li>
              ))}
            </ul>
          )}

          {/* Empty results for an active query */}
          {needle && !loading && hits.length === 0 && (
            <div className="px-3 py-6 text-center">
              <div className="text-mono ba-text-sm uppercase tracking-widest text-muted-foreground">
                no matches for "{debounced}"
              </div>
              <p className="mt-1 text-[11px] text-muted-foreground/80">
                Try a tool name, IOC type, or section.
              </p>
            </div>
          )}

          {/* Footer — palette CTA */}
          <button
            onMouseDown={(e) => { e.preventDefault(); setOpen(false); onOpenPalette(); }}
            className="group/cta flex w-full items-center justify-between gap-2 border-t border-border bg-card/60 px-2.5 py-1.5 text-mono text-[10.5px] uppercase tracking-widest text-muted-foreground transition-colors hover:bg-card hover:text-foreground"
          >
            <span className="inline-flex items-center gap-1.5">
              <CmdIcon className="h-3 w-3" />
              open command palette
              <ArrowRight className="h-3 w-3 -translate-x-0.5 opacity-0 transition-all group-hover/cta:translate-x-0 group-hover/cta:opacity-100" />
            </span>
            <kbd className="rounded border border-divider-strong bg-background/60 px-1 py-px text-[10px]">
              <CmdIcon className="inline h-2.5 w-2.5" /> K
            </kbd>
          </button>
        </div>
      )}
    </div>
  );
}
