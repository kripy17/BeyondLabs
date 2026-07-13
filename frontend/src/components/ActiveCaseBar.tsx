import { FolderOpen, Plus } from "lucide-react";
import { useActiveCase } from "@/lib/case";
import { Link } from "@tanstack/react-router";

export function ActiveCaseBar() {
  const { activeCase } = useActiveCase();
  if (!activeCase) return null;

  const iocCount = activeCase.entries.filter((e) => e.kind === "ioc").length;
  const entryCount = activeCase.entries.length;

  return (
    <div className="flex items-center gap-2 border-b border-divider-strong bg-card/30 px-4 py-1">
      <Link
        to="/case"
        className="inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-mono text-[10px] text-foreground/70 transition-colors hover:bg-primary/10 hover:text-primary"
      >
        <FolderOpen className="h-3 w-3 shrink-0" />
        <span className="font-medium text-foreground/90">{activeCase.title}</span>
      </Link>
      <span className="text-muted-foreground/30">·</span>
      <span className="text-mono text-[10px] text-muted-foreground">{entryCount} entries</span>
      {iocCount > 0 && (
        <>
          <span className="text-muted-foreground/30">·</span>
          <span className="text-mono text-[10px] text-warning">{iocCount} IOCs</span>
        </>
      )}
      <div className="ml-auto">
        <Link
          to="/case"
          className="inline-flex items-center gap-1 rounded border border-primary/20 bg-primary/5 px-2 py-0.5 text-mono text-[9px] uppercase tracking-widest text-primary transition-colors hover:bg-primary/15"
        >
          <Plus className="h-2.5 w-2.5" /> case
        </Link>
      </div>
    </div>
  );
}
