import { useState, useEffect, useCallback, type ReactNode } from "react";
import { Search } from "lucide-react";

export function useOutputFilter() {
  const [filterText, setFilterText] = useState("");
  const [showFilter, setShowFilter] = useState(false);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "f" && !showFilter) {
        e.preventDefault();
        setShowFilter(true);
      }
      if (e.key === "Escape" && showFilter) {
        setShowFilter(false);
        setFilterText("");
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [showFilter]);

  const toggleFilter = useCallback(() => {
    setShowFilter((s) => {
      if (s) setFilterText("");
      return !s;
    });
  }, []);

  return { filterText, setFilterText, showFilter, setShowFilter, toggleFilter };
}

export function OutputFilterBar({
  filterText,
  onChange,
  onClear,
  onClose,
}: {
  filterText: string;
  onChange: (v: string) => void;
  onClear: () => void;
  onClose: () => void;
}) {
  return (
    <div className="relative">
      <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
      <input
        type="text"
        value={filterText}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Filter output panels and findings…"
        autoFocus
        className="w-full rounded-lg border border-primary/40 bg-card/80 py-2 pl-9 pr-16 text-mono text-[12px] text-foreground placeholder:text-muted-foreground/50 focus:border-primary focus:outline-none shadow-sm"
      />
      <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
        {filterText && (
          <button
            onClick={onClear}
            className="rounded px-1.5 py-0.5 text-mono text-[10px] text-muted-foreground hover:text-foreground"
          >
            clear
          </button>
        )}
        <button
          onClick={onClose}
          className="rounded px-1.5 py-0.5 text-mono text-[10px] text-muted-foreground hover:text-foreground"
        >
          esc
        </button>
      </div>
    </div>
  );
}

export function OutputFilter({
  query,
  children,
}: {
  query: string;
  children: ReactNode;
}) {
  if (!query.trim()) return <>{children}</>;
  const filtered = filterNode(children, query.toLowerCase());
  if (filtered == null) {
    return <p className="text-mono text-[11px] text-muted-foreground text-center py-8">No panels match filter.</p>;
  }
  return <>{filtered}</>;
}

function filterNode(node: ReactNode, query: string): ReactNode {
  if (typeof node === "string") {
    return node.toLowerCase().includes(query) ? node : null;
  }
  if (node == null || typeof node !== "object") return node;
  if ("props" in node && node.props && typeof node.props === "object") {
    const props = node.props as Record<string, unknown>;
    const childArray = Array.isArray(props.children)
      ? props.children.map((c: ReactNode) => filterNode(c, query)).filter(Boolean)
      : [filterNode(props.children as ReactNode, query)].filter(Boolean);
    if (childArray.length > 0) {
      return <>{childArray}</>;
    }
    const text = extractText(node);
    if (text.toLowerCase().includes(query)) return node;
    return null;
  }
  return node;
}

function extractText(node: ReactNode): string {
  if (typeof node === "string") return node;
  if (node == null || typeof node !== "object") return "";
  if ("props" in node && node.props && typeof node.props === "object") {
    const props = node.props as Record<string, unknown>;
    const children = props.children;
    return Array.isArray(children) ? children.map(extractText).join(" ") : extractText(children as ReactNode);
  }
  return "";
}
