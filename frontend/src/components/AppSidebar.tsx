import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import {
  Pin, Settings as SettingsIcon, Search, ChevronDown, X,
} from "lucide-react";
import {
  Sidebar, SidebarContent, SidebarHeader, SidebarFooter, useSidebar,
} from "@/components/ui/sidebar";
import { GROUPS, findItem, type WorkspaceItem } from "@/lib/workspaces";
import { usePrefs, getBrandIcon } from "@/lib/prefs";
import { ThemeSwitcher } from "@/components/ThemeSwitcher";
import { cn } from "@/lib/utils";

function Row({
  item, active, pinned, onTogglePin, collapsed,
}: {
  item: WorkspaceItem;
  active: boolean;
  pinned: boolean;
  onTogglePin: (url: string) => void;
  collapsed: boolean;
}) {
  const Icon = item.icon;
  return (
    <li className="relative">
      <Link
        to={item.url}
        title={collapsed ? item.title : undefined}
        className={cn(
          "group/row relative flex h-8 items-center gap-2.5 rounded-md px-2 transition-colors",
          "text-mono text-[13px] tracking-tight",
          active
            ? "bg-sidebar-accent text-sidebar-accent-foreground"
            : "text-sidebar-foreground/75 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground",
        )}
      >
        <span
          aria-hidden
          className={cn(
            "absolute left-0 top-1/2 h-4 w-[2px] -translate-y-1/2 rounded-r transition-all",
            active ? "bg-primary shadow-[0_0_8px_var(--primary)]" : "bg-transparent group-hover/row:bg-sidebar-border",
          )}
        />
        <Icon className={cn("h-4 w-4 shrink-0 transition-transform", active ? "text-primary" : "group-hover/row:scale-110")} />
        {!collapsed && <span className="flex-1 truncate">{item.title}</span>}
        {!collapsed && (
          <button
            type="button"
            onClick={(e) => { e.preventDefault(); e.stopPropagation(); onTogglePin(item.url); }}
            aria-label={pinned ? "Unpin" : "Pin"}
            className={cn(
              "grid h-5 w-5 place-items-center rounded transition-all",
              pinned
                ? "text-primary opacity-100"
                : "text-sidebar-foreground/40 opacity-0 group-hover/row:opacity-100 hover:bg-sidebar-accent hover:text-sidebar-foreground",
            )}
          >
            {pinned ? <Pin className="h-3 w-3 fill-current" /> : <Pin className="h-3 w-3" />}
          </button>
        )}
      </Link>
    </li>
  );
}

function GroupBlock({
  label, count, collapsed, defaultOpen, children,
}: {
  label: string; count: number; collapsed: boolean; defaultOpen: boolean; children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  useEffect(() => { if (defaultOpen) setOpen(true); }, [defaultOpen]);
  if (collapsed) return <div className="px-1.5 py-1">{children}</div>;
  return (
    <div className="px-1.5 py-1">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="group/g flex w-full items-center gap-1.5 rounded px-1.5 py-1 text-mono text-[9.5px] font-medium uppercase tracking-[0.22em] text-sidebar-foreground/45 hover:text-sidebar-foreground/80"
      >
        <ChevronDown className={cn("h-2.5 w-2.5 transition-transform", open ? "" : "-rotate-90")} />
        <span>{label}</span>
        <span className="ml-auto rounded-sm border border-sidebar-border/60 bg-sidebar-accent/40 px-1 text-[9px] tracking-widest text-sidebar-foreground/55">
          {count}
        </span>
      </button>
      {open && <ul className="mt-0.5 space-y-px">{children}</ul>}
    </div>
  );
}

export function AppSidebar({ onResize }: { onResize?: (px: number) => void }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const isActive = (url: string) => (url === "/" ? pathname === "/" : pathname === url || pathname.startsWith(url + "/"));
  const { prefs, togglePin } = usePrefs();
  const BrandIcon = getBrandIcon(prefs.brandIcon);
  const { state } = useSidebar();
  const collapsed = state === "collapsed";

  const resizing = useRef(false);

  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    resizing.current = true;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    const onMove = (ev: MouseEvent) => {
      if (!resizing.current) return;
      onResize?.(ev.clientX);
    };

    const onUp = () => {
      resizing.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };

    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }, [onResize]);

  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();

  const order = prefs.sidebar.order.length ? prefs.sidebar.order : GROUPS.map((g) => g.label);
  const ordered = order
    .map((label) => GROUPS.find((g) => g.label === label))
    .filter((g): g is NonNullable<typeof g> => !!g && !prefs.sidebar.hiddenGroups.includes(g.label) && g.label !== "System");

  const pinnedItems = prefs.sidebar.pinned
    .map(findItem)
    .filter((x): x is NonNullable<typeof x> => !!x);

  const filtered = useMemo(() => {
    if (!q) return ordered;
    return ordered
      .map((g) => ({ ...g, items: g.items.filter((i) => i.title.toLowerCase().includes(q) || i.desc.toLowerCase().includes(q)) }))
      .filter((g) => g.items.length > 0);
  }, [ordered, q]);

  const totalCount = ordered.reduce((s, g) => s + g.items.length, 0);
  const visibleCount = filtered.reduce((s, g) => s + g.items.length, 0);

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="border-b border-sidebar-border/70 p-0">
        <Link to="/" className="flex items-center gap-2.5 px-3 py-3">
          <div className="relative grid h-8 w-8 shrink-0 place-items-center rounded-md bg-gradient-to-br from-sidebar-primary to-accent text-sidebar-primary-foreground shadow-glow">
            <BrandIcon className="h-4 w-4" />
            <span className="absolute -bottom-0.5 -right-0.5 h-1.5 w-1.5 rounded-full bg-success ring-2 ring-sidebar ba-glow" aria-hidden />
          </div>
          <div className="min-w-0 group-data-[collapsible=icon]:hidden">
            <div className="text-mono text-[13px] font-bold leading-tight tracking-tight truncate">{prefs.brandName}</div>
            <div className="text-mono text-[9.5px] uppercase tracking-[0.22em] text-sidebar-foreground/55 truncate">{prefs.brandTagline}</div>
          </div>
        </Link>

        <div className="px-2 pb-2 group-data-[collapsible=icon]:hidden">
          <div className="group/search relative">
            <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-sidebar-foreground/40 group-focus-within/search:text-primary transition-colors" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter workspaces"
              className="h-7 w-full rounded-md border border-sidebar-border/70 bg-sidebar-accent/30 pl-7 pr-7 text-mono text-[11px] text-sidebar-foreground placeholder:text-sidebar-foreground/40 outline-none transition-all focus:border-primary/60 focus:bg-sidebar-accent/60 focus:ring-2 focus:ring-primary/15"
            />
            {query ? (
              <button
                type="button"
                onClick={() => setQuery("")}
                className="absolute right-1 top-1/2 grid h-5 w-5 -translate-y-1/2 place-items-center rounded text-sidebar-foreground/50 hover:bg-sidebar-accent hover:text-sidebar-foreground"
                aria-label="Clear filter"
              >
                <X className="h-3 w-3" />
              </button>
            ) : (
              <kbd className="pointer-events-none absolute right-1.5 top-1/2 -translate-y-1/2 rounded border border-sidebar-border/60 bg-sidebar/50 px-1 text-mono text-[9px] uppercase tracking-widest text-sidebar-foreground/45">
                filter
              </kbd>
            )}
          </div>
        </div>
      </SidebarHeader>

      <SidebarContent className="gap-0">
        {!q && pinnedItems.length > 0 && (
          <GroupBlock label="Pinned" count={pinnedItems.length} collapsed={collapsed} defaultOpen>
            {pinnedItems.map((item) => (
              <Row key={`pin-${item.url}`} item={item} active={isActive(item.url)} pinned onTogglePin={togglePin} collapsed={collapsed} />
            ))}
          </GroupBlock>
        )}

        {filtered.map((g) => {
          const hasActive = g.items.some((i) => isActive(i.url));
          return (
            <GroupBlock key={g.label} label={g.label} count={g.items.length} collapsed={collapsed} defaultOpen={!!q || hasActive || true}>
              {g.items.map((item) => (
                <Row
                  key={item.url}
                  item={item}
                  active={isActive(item.url)}
                  pinned={prefs.sidebar.pinned.includes(item.url)}
                  onTogglePin={togglePin}
                  collapsed={collapsed}
                />
              ))}
            </GroupBlock>
          );
        })}

        {q && filtered.length === 0 && (
          <div className="px-4 py-6 text-center text-mono text-[11px] text-sidebar-foreground/50 group-data-[collapsible=icon]:hidden">
            No workspaces match &ldquo;{query}&rdquo;
          </div>
        )}

      </SidebarContent>

      <SidebarFooter className="border-t border-sidebar-border/70 gap-2 p-2">
        <div className="group-data-[collapsible=icon]:hidden">
          <ThemeSwitcher />
        </div>

        <div className="flex items-center gap-1">
          <Link
            to="/settings"
            title="Settings"
            className={cn(
              "flex h-8 flex-1 items-center gap-2 rounded-md px-2 text-mono text-[12px] transition-colors",
              isActive("/settings")
                ? "bg-sidebar-accent text-sidebar-accent-foreground"
                : "text-sidebar-foreground/75 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground",
            )}
          >
            <SettingsIcon className="h-4 w-4 shrink-0" />
            <span className="group-data-[collapsible=icon]:hidden">Settings</span>
            <kbd className="ml-auto rounded border border-sidebar-border/60 bg-sidebar/60 px-1 text-mono text-[9px] uppercase tracking-widest text-sidebar-foreground/55 group-data-[collapsible=icon]:hidden">⌘,</kbd>
          </Link>
        </div>

        <div className="text-center text-mono text-[9px] uppercase tracking-[0.22em] text-sidebar-foreground/35 group-data-[collapsible=icon]:hidden">
          {q ? `${visibleCount} of ${totalCount}` : `${totalCount} workspaces`}
        </div>
      </SidebarFooter>

      {/* Resize handle — fixed to right edge of sidebar */}
      {!collapsed && (
        <div
          onMouseDown={handleResizeStart}
          className="fixed top-0 z-[60] hidden h-full w-3 cursor-col-resize md:block"
          style={{ left: `calc(var(--sidebar-width) - 4px)` }}
        >
          <div className="ml-0.5 mt-1/2 h-8 w-0.5 rounded-full bg-sidebar-border/0 transition-all group-hover/resize:bg-sidebar-border/60 group-active/resize:bg-primary/50" />
        </div>
      )}
    </Sidebar>
  );
}
