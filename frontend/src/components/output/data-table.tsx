import { type ReactNode, useState, useMemo } from "react";
import { ArrowUp, ArrowDown, ArrowUpDown } from "lucide-react";

export type Column<T> = {
  key: string;
  label: string;
  align?: "left" | "right" | "center";
  sortable?: boolean;
  sortValue?: (row: T) => string | number;
  width?: string;
  render: (row: T, idx: number) => ReactNode;
};

export function DataTable<T extends Record<string, unknown>>({
  columns,
  rows,
  className = "",
  emptyMessage = "No data",
}: {
  columns: Column<T>[];
  rows: T[];
  className?: string;
  emptyMessage?: string;
}) {
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const sorted = useMemo(() => {
    if (!sortKey) return rows;
    const col = columns.find((c) => c.key === sortKey);
    if (!col) return rows;
    return [...rows].sort((a, b) => {
      const aVal = col.sortValue ? col.sortValue(a) : (a[sortKey] as string | number);
      const bVal = col.sortValue ? col.sortValue(b) : (b[sortKey] as string | number);
      if (aVal < bVal) return sortDir === "asc" ? -1 : 1;
      if (aVal > bVal) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
  }, [rows, sortKey, sortDir, columns]);

  const toggleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  if (rows.length === 0) {
    return (
      <div className="flex items-center justify-center rounded border border-dashed border-border/50 bg-background/30 py-8">
        <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground/60">{emptyMessage}</span>
      </div>
    );
  }

  return (
    <div className={`overflow-x-auto rounded border border-border/50 ${className}`}>
      <table className="w-full border-collapse">
        <thead>
          <tr className="border-b border-border/50 bg-background/60">
            {columns.map((col) => (
              <th
                key={col.key}
                className={`sticky top-0 z-10 whitespace-nowrap border-0 bg-background/90 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground backdrop-blur-sm ${
                  col.sortable ? "cursor-pointer select-none hover:text-foreground/80" : ""
                } ${col.align === "right" ? "text-right" : col.align === "center" ? "text-center" : "text-left"}`}
                style={col.width ? { width: col.width, minWidth: col.width } : undefined}
                onClick={() => col.sortable && toggleSort(col.key)}
              >
                <span className="inline-flex items-center gap-1">
                  {col.label}
                  {col.sortable && (
                    sortKey === col.key
                      ? sortDir === "asc" ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />
                      : <ArrowUpDown className="h-3 w-3 text-muted-foreground/40" />
                  )}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row, i) => (
            <tr
              key={(row.id as string) ?? i}
              className={`group/trow border-b border-divider-soft transition-colors hover:bg-accent/10 ${
                i % 2 === 1 ? "bg-background/30" : "bg-transparent"
              }`}
            >
              {columns.map((col) => (
                <td
                  key={col.key}
                  className={`border-0 px-3 py-2 ba-text-sm text-foreground/85 ${
                    col.align === "right" ? "text-right tabular-nums" : col.align === "center" ? "text-center" : "text-left"
                  } group-first/trow:border-l-2 group-first/trow:border-l-transparent group-hover/trow:border-l-primary/50`}
                >
                  {col.render(row, i)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
