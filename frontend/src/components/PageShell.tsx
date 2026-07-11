import type { ReactNode } from "react";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { ChevronRight, Settings as SettingsIcon, Wifi, ShieldCheck, WifiOff } from "lucide-react";
import { useBackendStatus } from "@/lib/backend";
import { Link } from "@tanstack/react-router";
import { TopSearch } from "./TopSearch";
import { CommandPalette, ShortcutsDialog, useCommandPalette } from "./CommandPalette";
import { usePrefs, getBrandIcon } from "@/lib/prefs";

export type Crumb = { label: string; href?: string };
export type JumpLink = { label: string; to: string };

export function PageShell({
  eyebrow,
  title,
  description,
  actions,
  crumbs,
  meta,
  jumps,
  children,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
  crumbs?: Crumb[];
  meta?: { label: string; value: string; tone?: "default" | "primary" | "warning" | "destructive" | "success" | "muted" }[];
  jumps?: JumpLink[];
  children: ReactNode;
}) {
  const { prefs } = usePrefs();
  const palette = useCommandPalette();
  const BrandIcon = getBrandIcon(prefs.brandIcon);
  const { status } = useBackendStatus();

  return (
    <div className="flex min-h-screen flex-col">
      {/* Top bar */}
      {prefs.showTopbar && (
      <header className="sticky top-0 z-30 flex h-12 items-center gap-2 border-b border-border/70 bg-background/85 px-3 backdrop-blur-md supports-[backdrop-filter]:bg-background/70">

        <SidebarTrigger className="-ml-1 h-8 w-8 text-foreground/70 hover:text-foreground" />
        <div className="mx-0.5 h-5 w-px bg-border/60" />

        {/* Brand chip (collapsed-friendly) */}
        <Link to="/" className="inline-flex items-center gap-1.5 rounded-md border border-border/60 bg-card/40 px-2 py-1 text-foreground hover:border-primary/40 hover:text-primary">
          <BrandIcon className="h-3.5 w-3.5 text-primary" />
          <span className="text-mono text-[11px] font-semibold tracking-tight">{prefs.brandName}</span>
        </Link>

        {prefs.showBreadcrumb && crumbs && crumbs.length > 0 && (
          <nav
            aria-label="Breadcrumb"
            className="ml-1 flex min-w-0 items-center rounded-md border border-border/60 bg-card/40 px-1.5 py-1 text-mono text-[11px] text-muted-foreground shadow-sm"
          >
            {crumbs.map((c, i) => {
              const last = i === crumbs.length - 1;
              return (
                <span key={i} className="flex items-center gap-1 truncate">
                  {i > 0 && <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground/50" />}
                  {c.href && !last ? (
                    <Link
                      to={c.href}
                      className="group/crumb relative rounded px-1.5 py-0.5 uppercase tracking-widest text-[10px] text-muted-foreground transition-colors hover:bg-primary/10 hover:text-primary"
                    >
                      {c.label}
                      <span className="pointer-events-none absolute inset-x-1.5 -bottom-px h-px scale-x-0 bg-primary transition-transform duration-200 group-hover/crumb:scale-x-100" />
                    </Link>
                  ) : (
                    <span
                      aria-current={last ? "page" : undefined}
                      className={
                        "truncate px-1.5 py-0.5 uppercase tracking-widest text-[10px] " +
                        (last ? "rounded bg-primary/10 font-semibold text-primary" : "text-foreground/85")
                      }
                    >
                      {c.label}
                    </span>
                  )}
                </span>
              );
            })}
          </nav>
        )}

        <div className="mx-auto flex flex-1 justify-center px-3">
          <TopSearch onOpenPalette={() => palette.setOpen(true)} />
        </div>

        {/* Status cluster */}
        <div className="flex items-center gap-1.5">
          <span className="inline-flex items-center gap-1 rounded-md border border-success/30 bg-success/10 px-1.5 py-1 text-mono text-[10px] uppercase tracking-widest text-success" title="All local — nothing sent over the wire">
            <ShieldCheck className="h-3 w-3" /> local
          </span>
          <span
            className={
              "inline-flex items-center gap-1 rounded-md border px-1.5 py-1 text-mono text-[10px] uppercase tracking-widest " +
              (status === "online"
                ? "border-success/30 bg-success/10 text-success"
                : status === "checking"
                  ? "border-warning/30 bg-warning/10 text-warning"
                  : "border-border/60 bg-card/40 text-muted-foreground")
            }
            title={status === "online" ? "Backend reachable" : "Backend offline"}
          >
            {status === "online" ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
            {status}
          </span>
        </div>

        <Link
          to="/settings"
          className="grid h-8 w-8 place-items-center rounded-md border border-border/70 bg-card/40 text-muted-foreground transition-colors hover:border-primary/50 hover:bg-card hover:text-foreground"
          aria-label="Settings"
          title="Settings"
        >
          <SettingsIcon className="h-3.5 w-3.5" />
        </Link>
      </header>
      )}


      <CommandPalette open={palette.open} onOpenChange={palette.setOpen} />
      <ShortcutsDialog open={palette.shortcutsOpen} onClose={() => palette.setShortcutsOpen(false)} />

      {/* Page hero */}
      <div className="relative overflow-hidden border-b border-border">
        <div className="ba-hero-fx" aria-hidden />
        <div className="relative mx-auto w-full max-w-full px-6 py-8 ba-fade-in">
          {eyebrow && (
            <div className="text-mono mb-2 text-[10px] uppercase tracking-[0.24em] text-primary">
              {eyebrow}
            </div>
          )}
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div className="min-w-0">
              <h1 className="gradient-text text-3xl font-bold tracking-tight text-[2.25rem]">{title}</h1>
              {description && (
                <p className="mt-2 max-w-3xl text-sm leading-[1.75] text-muted-foreground">{description}</p>
              )}
              {jumps && jumps.length > 0 && (
                <div className="mt-3 flex flex-wrap items-center gap-1.5">
                  <span className="text-mono text-[9px] uppercase tracking-[0.2em] text-muted-foreground/50">jump→</span>
                  {jumps.map((j) => (
                    <Link
                      key={j.to}
                      to={j.to}
                      className="rounded border border-border/50 bg-card/40 px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground transition-colors hover:border-primary/40 hover:text-primary"
                    >
                      {j.label}
                    </Link>
                  ))}
                </div>
              )}
              {meta && meta.length > 0 && (
                <div className="mt-4 flex flex-wrap items-center gap-2">
                  {meta.map((m, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-2 rounded-md border border-border/70 bg-card/60 px-2.5 py-1"
                    >
                      <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                        {m.label}
                      </span>
                      <span
                        className={
                          "text-mono text-xs font-semibold " +
                          (m.tone === "warning"
                            ? "text-warning"
                            : m.tone === "destructive"
                            ? "text-destructive"
                            : m.tone === "success"
                            ? "text-success"
                            : m.tone === "primary"
                            ? "text-primary"
                            : "text-foreground")
                        }
                      >
                        {m.value}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
            {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
          </div>
        </div>
      </div>

      <main className="min-w-0 flex-1 px-6 py-6">
        <div className="mx-auto min-w-0 max-w-full space-y-6">{children}</div>
      </main>

      <footer className="border-t border-border px-6 py-4">
        <div className="mx-auto flex max-w-full flex-wrap items-center justify-between gap-2 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          <span>beyondlabs · local soc workbench</span>
          <span>analyst-led · no detonation · bounded scans</span>
        </div>
      </footer>
    </div>
  );
}
