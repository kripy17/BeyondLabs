import { useState, useRef, useEffect } from "react";
import { Copy, Check, Link2, FileCode } from "lucide-react";
import { defang } from "@/lib/ioc-patterns";

type CopyAsOption = "raw" | "defanged" | "markdown-link";

const OPTIONS: { key: CopyAsOption; label: string; icon: typeof Copy }[] = [
  { key: "raw", label: "Raw", icon: Copy },
  { key: "defanged", label: "Defanged", icon: FileCode },
  { key: "markdown-link", label: "Markdown link", icon: Link2 },
];

export function CopyAsDropdown({ value, label }: { value: string; label?: string }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState<CopyAsOption | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  useEffect(() => {
    return () => { if (timerRef.current) clearTimeout(timerRef.current); };
  }, []);

  const doCopy = async (opt: CopyAsOption) => {
    let text = value;
    if (opt === "defanged") text = defang(value);
    else if (opt === "markdown-link") text = `[${label || value}](${value.startsWith("http") ? value : `https://${value}`})`;

    try { await navigator.clipboard.writeText(text); } catch {}
    setCopied(opt);
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => { setCopied(null); setOpen(false); }, 800);
  };

  return (
    <div ref={ref} className="relative inline-block">
      <button onClick={() => setOpen((o) => !o)}
        className="inline-flex items-center gap-1 rounded border border-border/60 bg-card/50 px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:border-primary/40 hover:text-primary"
        title="Copy as…"
      >
        <Copy className="h-3 w-3" />
      </button>
      {open && (
        <div className="absolute right-0 top-full z-50 mt-1 w-36 rounded border border-border bg-popover p-1 shadow-lg">
          {OPTIONS.map((opt) => (
            <button key={opt.key} onClick={() => doCopy(opt.key)}
              className="flex w-full items-center gap-2 rounded px-2 py-1 text-mono ba-text-sm text-foreground/85 hover:bg-primary/10"
            >
              {copied === opt.key ? <Check className="h-3.5 w-3.5 text-success" /> : <opt.icon className="h-3.5 w-3.5 text-muted-foreground" />}
              {opt.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
