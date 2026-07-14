import { useState, useRef, useEffect } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Outlet, Link, createRootRouteWithContext, useRouter, useLocation } from "@tanstack/react-router";

import { ThemeProvider } from "@/lib/theme";
import { PrefsProvider } from "@/lib/prefs";
import { LockerProvider, useLocker } from "@/lib/locker";
import { useRouteRecorder } from "@/lib/recents";
import { SidebarProvider, SidebarInset } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/AppSidebar";
import { ActiveCaseBar } from "@/components/ActiveCaseBar";
import { Toaster } from "@/components/Toaster";
import { IocLockerTrigger, IocLockerPanel } from "@/components/IocLocker";
import { sendToCase } from "@/lib/handoff";
import { StickyNote, Pen } from "lucide-react";
import { CommandPalette, ShortcutsDialog, useCommandPalette } from "@/components/CommandPalette";


function NotFoundComponent() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="max-w-lg">
        <div className="mb-6 text-mono text-[10px] uppercase tracking-[0.24em] text-primary">
          beyondlabs / terminal
        </div>
        <div className="mb-2 text-mono ba-text-base text-muted-foreground">
          <span className="text-primary">$</span> navigate <span className="text-warning">/wild-path</span>
        </div>
        <div className="text-mono ba-text-base text-destructive">
          command not found: /wild-path
        </div>
        <pre className="my-4 text-mono text-[11px] leading-relaxed text-muted-foreground">
{`  hint: try one of
    /parser       — investigation
    /phishing     — email analysis
    /url          — URL analyzer
    /recon        — recon & exposure
    /mitre        — ATT&CK coverage
    /case         — case notebook
    /detection    — detection workspace
    /settings     — preferences
  or run \`help\` for all routes`}
        </pre>
        <div className="mt-6">
          <Link
            to="/"
            className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-3 py-1.5 text-mono text-[11px] uppercase tracking-widest text-primary transition-colors hover:bg-primary/20"
          >
            <span className="ba-text-base">$</span> cd ~
          </Link>
        </div>
      </div>
    </div>
  );
}

function ErrorComponent({ error, reset }: { error: Error; reset: () => void }) {
  console.error(error);
  const router = useRouter();

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="max-w-md text-center">
        <div className="mb-4 text-mono text-[10px] uppercase tracking-[0.24em] text-destructive">
          runtime / exception
        </div>
        <h1 className="text-xl font-semibold tracking-tight text-foreground">
          This page didn't load
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Something went wrong. Try refreshing or head back home.
        </p>
        <div className="mt-6 flex flex-wrap justify-center gap-2">
          <button
            onClick={() => { router.invalidate(); reset(); }}
            className="inline-flex items-center gap-1.5 rounded-md border border-primary/40 bg-primary/10 px-3 py-1.5 text-mono text-[11px] uppercase tracking-widest text-primary transition-colors hover:bg-primary/20"
          >
            $ retry
          </button>
          <Link
            to="/"
            className="inline-flex items-center gap-1.5 rounded-md border border-divider-strong bg-card/40 px-3 py-1.5 text-mono text-[11px] uppercase tracking-widest text-muted-foreground transition-colors hover:text-foreground"
          >
            $ cd ~
          </Link>
        </div>
      </div>
    </div>
  );
}

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: RootComponent,
  notFoundComponent: NotFoundComponent,
  errorComponent: ErrorComponent,
});

function RouteRecorder() {
  useRouteRecorder();
  return null;
}

function RootComponent() {
  const { queryClient } = Route.useRouteContext();
  const [lockerOpen, setLockerOpen] = useState(false);
  const palette = useCommandPalette();

  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <PrefsProvider>
          <LockerProvider>
          <SidebarProvider>
            <AppSidebar />
            <SidebarInset className="w-full">
              <ActiveCaseBar />
              <RouteRecorder />
              <Outlet />
              <LockerUI open={lockerOpen} onOpenChange={setLockerOpen} />
              <Toaster />
            </SidebarInset>
            <CommandPalette open={palette.open} onOpenChange={palette.setOpen} />
            <ShortcutsDialog open={palette.shortcutsOpen} onClose={() => palette.setShortcutsOpen(false)} />
          </SidebarProvider>
          </LockerProvider>
        </PrefsProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

function ActiveCaseAttach() {
  const [showPanel, setShowPanel] = useState(false);
  const [text, setText] = useState("");
  const panelRef = useRef<HTMLDivElement>(null);
  const location = useLocation();

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) setShowPanel(false);
    };
    if (showPanel) { document.addEventListener("mousedown", onClick); return () => document.removeEventListener("mousedown", onClick); }
  }, [showPanel]);

  const activeId = (() => { try { return localStorage.getItem("ba.cases.active") || ""; } catch { return ""; } })();
  const hasActive = activeId.length > 0;

  const doAttach = () => {
    if (!text.trim() || !hasActive) return;
    sendToCase({ body: text.trim(), source: location.pathname, kind: "evidence" });
    setText("");
    setShowPanel(false);
  };

  return (
    <div className="relative">
      <button
        onClick={() => hasActive && setShowPanel((o) => !o)}
        title={hasActive ? "Attach to active case" : "No active case"}
        className={"fixed bottom-4 right-16 z-40 grid h-9 w-9 place-items-center rounded-full border shadow-sm transition-all " + (hasActive ? "border-primary/50 bg-primary/15 text-primary hover:bg-primary/25" : "border-border/50 bg-card/40 text-muted-foreground/50 cursor-not-allowed")}
      >
        <StickyNote className="h-4 w-4" />
      </button>
      {showPanel && hasActive && (
        <div ref={panelRef} className="fixed bottom-16 right-16 z-50 w-72 rounded-md border border-border bg-popover p-3 shadow-lg">
          <p className="mb-1.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Attach to case <span className="text-primary">{activeId}</span></p>
          <textarea
            autoFocus
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) { e.preventDefault(); doAttach(); } if (e.key === "Escape") setShowPanel(false); }}
            placeholder="Evidence text…"
            rows={3}
            className="w-full rounded border border-border bg-background/60 p-2 text-mono text-[11px] text-foreground outline-none focus:border-primary/50 resize-none"
          />
          <div className="mt-1.5 flex items-center justify-between">
            <span className="text-mono text-[9px] text-muted-foreground/60">⌘↵ to attach</span>
            <button onClick={doAttach} disabled={!text.trim()} className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest text-primary hover:bg-primary/20 disabled:opacity-40">
              attach
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function Scratchpad() {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const textRef = useRef(text);
  textRef.current = text;
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    try { const v = localStorage.getItem("ba.scratchpad"); if (v) setText(v); } catch {}
  }, []);

  useEffect(() => {
    const timer = setInterval(() => {
      try { localStorage.setItem("ba.scratchpad", textRef.current); } catch {}
    }, 3000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) setOpen(false);
    };
    if (open) { document.addEventListener("mousedown", onClick); return () => document.removeEventListener("mousedown", onClick); }
  }, [open]);

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        title="Scratchpad"
        className={"fixed bottom-4 left-4 z-40 grid h-9 w-9 place-items-center rounded-full border shadow-sm transition-all " + (open ? "border-primary/50 bg-primary/15 text-primary" : "border-border/50 bg-card/40 text-muted-foreground hover:border-primary/30 hover:text-primary")}
      >
        <Pen className="h-4 w-4" />
      </button>
      {open && (
        <div ref={panelRef} className="fixed bottom-16 left-4 z-50 w-72 rounded-md border border-border bg-popover p-3 shadow-lg">
          <p className="mb-1.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Scratchpad</p>
          <textarea
            autoFocus
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Escape") setOpen(false); }}
            placeholder="Quick notes…"
            rows={6}
            className="w-full rounded border border-border bg-background/60 p-2 text-mono text-[11px] text-foreground outline-none focus:border-primary/50 resize-none"
          />
          <div className="mt-1 text-right text-mono text-[9px] text-muted-foreground/60">auto-saves</div>
        </div>
      )}
    </div>
  );
}

function LockerUI({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { count } = useLocker();
  return (
    <>
      <ActiveCaseAttach />
      <Scratchpad />
      <IocLockerTrigger onClick={() => onOpenChange(true)} count={count} />
      <IocLockerPanel open={open} onClose={() => onOpenChange(false)} />
    </>
  );
}
