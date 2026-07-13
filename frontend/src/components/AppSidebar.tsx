import { useState, useEffect } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import {
  Pin, Settings as SettingsIcon, ChevronDown, Notebook,
} from "lucide-react";
import {
  Sidebar, SidebarContent, SidebarHeader, SidebarFooter, useSidebar,
} from "@/components/ui/sidebar";
import { GROUPS, findItem, type WorkspaceItem } from "@/lib/workspaces";
import { usePrefs, getBrandIcon } from "@/lib/prefs";
import { useActiveCase } from "@/lib/case";
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
          "text-mono ba-text-base tracking-tight",
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
        <Icon className={cn("h-4 w-4 shrink-0 transition-transform translate-y-[0.5px]", active ? "text-primary" : "group-hover/row:scale-110")} />
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

export function AppSidebar() {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const isActive = (url: string) => (url === "/" ? pathname === "/" : pathname === url || pathname.startsWith(url + "/"));
  const { prefs, togglePin } = usePrefs();
  const BrandIcon = getBrandIcon(prefs.brandIcon);
  const { state } = useSidebar();
  const collapsed = state === "collapsed";
  const { activeCase } = useActiveCase();

  const order = prefs.sidebar.order.length ? prefs.sidebar.order : GROUPS.map((g) => g.label);
  const ordered = order
    .map((label) => GROUPS.find((g) => g.label === label))
    .filter((g): g is NonNullable<typeof g> => !!g && !prefs.sidebar.hiddenGroups.includes(g.label) && g.label !== "System");

  const pinnedItems = prefs.sidebar.pinned
    .map(findItem)
    .filter((x): x is NonNullable<typeof x> => !!x);

  const totalCount = ordered.reduce((s, g) => s + g.items.length, 0);

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="border-b border-sidebar-border/70 p-0">
        <Link to="/" className="flex items-center gap-2.5 px-3 py-3">
          <div className="relative grid h-8 w-8 shrink-0 place-items-center rounded-md bg-gradient-to-br from-sidebar-primary to-accent text-sidebar-primary-foreground shadow-glow">
            <BrandIcon className="h-4 w-4" />
            <span className="absolute -bottom-0.5 -right-0.5 h-1.5 w-1.5 rounded-full bg-success ring-2 ring-sidebar ba-glow" aria-hidden />
          </div>
          <div className="min-w-0 group-data-[collapsible=icon]:hidden">
            <div className="text-mono ba-text-base font-bold leading-tight tracking-tight truncate">{prefs.brandName}</div>
          </div>
        </Link>

        <div className="group-data-[collapsible=icon]:hidden px-2 pb-2 space-y-1">
          {activeCase && (
            <Link to="/case" className="flex items-center gap-1.5 rounded-md border border-sidebar-border/70 bg-sidebar-accent/20 px-2 py-1 text-mono text-[10px] text-sidebar-foreground/60 hover:text-sidebar-foreground transition-colors">
              <Notebook className="h-3 w-3 shrink-0 text-primary/70" />
              <span className="truncate">{activeCase.title}</span>
              <span className="ml-auto rounded-sm border border-sidebar-border/60 bg-sidebar-accent/30 px-1 text-[8px] uppercase tracking-widest text-sidebar-foreground/45">{activeCase.state}</span>
            </Link>
          )}
        </div>
      </SidebarHeader>

      <SidebarContent className="gap-0">
        {pinnedItems.length > 0 && (
          <GroupBlock label="Pinned" count={pinnedItems.length} collapsed={collapsed} defaultOpen>
            {pinnedItems.map((item) => (
              <Row key={`pin-${item.url}`} item={item} active={isActive(item.url)} pinned onTogglePin={togglePin} collapsed={collapsed} />
            ))}
          </GroupBlock>
        )}

        {ordered.map((g) => {
          return (
            <GroupBlock key={g.label} label={g.label} count={g.items.length} collapsed={collapsed} defaultOpen={true}>
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
      </SidebarContent>

      <SidebarFooter className="border-t border-sidebar-border/70 gap-1 p-2">
        <div className="group-data-[collapsible=icon]:hidden">
          <ThemeSwitcher />
        </div>

        <div className="flex items-center gap-1">
          <Link
            to="/settings"
            title="Settings"
            className={cn(
              "flex h-8 flex-1 items-center gap-2 rounded-md px-2 text-mono ba-text-base transition-colors",
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
          {totalCount} workspaces
        </div>
      </SidebarFooter>


    </Sidebar>
  );
}
