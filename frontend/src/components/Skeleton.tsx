export function Skeleton({ className = "", lines = 1 }: { className?: string; lines?: number }) {
  if (lines === 1) {
    return <div className={`animate-pulse rounded bg-border/60 ${className}`} />;
  }
  return (
    <div className="space-y-2">
      {Array.from({ length: lines }, (_, i) => (
        <div
          key={i}
          className={`animate-pulse rounded bg-border/60 ${className}`}
          style={{ width: i === lines - 1 ? "60%" : "100%" }}
        />
      ))}
    </div>
  );
}

export function PanelSkeleton({ title = true, lines = 3 }: { title?: boolean; lines?: number }) {
  return (
    <div className="group/panel relative overflow-hidden rounded-md border border-border bg-card/60">
      <span aria-hidden className="pointer-events-none absolute left-0 top-0 h-2 w-2 border-l border-t border-primary/20" />
      <span aria-hidden className="pointer-events-none absolute right-0 top-0 h-2 w-2 border-r border-t border-primary/20" />
      <span aria-hidden className="pointer-events-none absolute left-0 bottom-0 h-2 w-2 border-l border-b border-primary/20" />
      <span aria-hidden className="pointer-events-none absolute right-0 bottom-0 h-2 w-2 border-r border-b border-primary/20" />
      {title && (
        <div className="border-b border-border px-4 py-2.5">
          <Skeleton className="h-4 w-32" />
        </div>
      )}
      <div className="p-4">
        <Skeleton className="h-3 w-full" lines={lines} />
      </div>
    </div>
  );
}
