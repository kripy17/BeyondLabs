import { Database } from "lucide-react";
import { useActiveCase, type EntryKind } from "@/lib/case";

export function AttachButton({ body, kind, source, label }: { body: string; kind: EntryKind; source: string; label?: string }) {
  const { addEntry, activeCase } = useActiveCase();
  if (!activeCase) return null;
  return (
    <button
      type="button"
      onClick={() => addEntry(body, kind, source)}
      className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1 text-mono text-[9px] uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground transition-colors"
      title={`Attach to case: ${activeCase.title}`}
    >
      <Database className="h-3 w-3" />
      {label ?? "case"}
    </button>
  );
}
