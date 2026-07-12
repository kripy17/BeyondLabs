export function NmapPortSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="flex items-center gap-3">
          <div className="ba-skeleton h-4 w-16 rounded" />
          <div className="ba-skeleton h-4 w-32 rounded" />
          <div className="ba-skeleton h-4 w-12 rounded" />
          <div className="ba-skeleton h-4 w-24 rounded" />
        </div>
      ))}
    </div>
  );
}

export function PhishingVerdictSkeleton() {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <div className="ba-skeleton h-12 w-12 rounded-full" />
        <div className="flex flex-col gap-1.5">
          <div className="ba-skeleton h-4 w-48 rounded" />
          <div className="ba-skeleton h-3 w-32 rounded" />
        </div>
      </div>
      <div className="grid grid-cols-3 gap-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="ba-skeleton h-16 rounded-md" />
        ))}
      </div>
      <div className="flex gap-2">
        <div className="ba-skeleton h-6 w-20 rounded-full" />
        <div className="ba-skeleton h-6 w-24 rounded-full" />
        <div className="ba-skeleton h-6 w-16 rounded-full" />
      </div>
    </div>
  );
}
