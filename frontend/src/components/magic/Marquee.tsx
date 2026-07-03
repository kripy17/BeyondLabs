import type { ReactNode } from "react";

export function Marquee({
  children,
  className,
  speed = 40,
  pauseOnHover = true,
}: {
  children: ReactNode;
  className?: string;
  speed?: number;
  pauseOnHover?: boolean;
}) {
  return (
    <div className={"group relative flex overflow-hidden " + (className ?? "")}>
      <div
        className={"flex shrink-0 items-center gap-3 ba-marquee will-change-transform" + (pauseOnHover ? " group-hover:[animation-play-state:paused]" : "")}
        style={{ animationDuration: `${speed}s` }}
      >
        {children}
      </div>
      <div
        aria-hidden
        className={"flex shrink-0 items-center gap-3 ba-marquee will-change-transform" + (pauseOnHover ? " group-hover:[animation-play-state:paused]" : "")}
        style={{ animationDuration: `${speed}s` }}
      >
        {children}
      </div>
      <div className="pointer-events-none absolute inset-y-0 left-0 w-12 bg-gradient-to-r from-background to-transparent" />
      <div className="pointer-events-none absolute inset-y-0 right-0 w-12 bg-gradient-to-l from-background to-transparent" />
    </div>
  );
}
