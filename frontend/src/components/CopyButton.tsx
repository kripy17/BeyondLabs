import { useState } from "react";
import { Copy, Check } from "lucide-react";

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}
      aria-label={copied ? "Copied" : label}
      className="inline-flex items-center gap-1 rounded border border-divider-strong px-1.5 py-px text-mono text-[9.5px] uppercase tracking-widest text-muted-foreground transition-colors hover:border-primary/40 hover:text-primary"
    >
      {copied ? <Check className="h-2.5 w-2.5" /> : <Copy className="h-2.5 w-2.5" />}
      {copied ? "copied" : "copy"}
    </button>
  );
}

export function CopyInline({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}
      aria-label="Copy value"
      className="inline-flex items-center justify-center rounded p-0.5 text-muted-foreground/60 opacity-0 transition-opacity hover:text-primary group-hover:opacity-100"
    >
      {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
    </button>
  );
}
