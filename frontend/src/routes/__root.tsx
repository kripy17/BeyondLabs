import { useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Outlet, Link, createRootRouteWithContext, useRouter } from "@tanstack/react-router";

import { ThemeProvider } from "@/lib/theme";
import { PrefsProvider } from "@/lib/prefs";
import { LockerProvider, useLocker } from "@/lib/locker";
import { useRouteRecorder } from "@/lib/recents";
import { useBackendStatus } from "@/lib/backend";
import { SidebarProvider, SidebarInset } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/AppSidebar";
import { Toaster } from "@/components/Toaster";
import { IocLockerTrigger, IocLockerPanel } from "@/components/IocLocker";


function NotFoundComponent() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="max-w-lg">
        <div className="mb-6 text-mono text-[10px] uppercase tracking-[0.24em] text-primary">
          beyondlabs / terminal
        </div>
        <div className="mb-2 text-mono text-[13px] text-muted-foreground">
          <span className="text-primary">$</span> navigate <span className="text-warning">/wild-path</span>
        </div>
        <div className="text-mono text-[13px] text-destructive">
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
            <span className="text-[13px]">$</span> cd ~
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
            className="inline-flex items-center gap-1.5 rounded-md border border-border/60 bg-card/40 px-3 py-1.5 text-mono text-[11px] uppercase tracking-widest text-muted-foreground transition-colors hover:text-foreground"
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

function BackendBanner() {
  const { status } = useBackendStatus();
  if (status === "online" || status === "unknown") return null;
  return (
    <div className="flex items-center gap-2 border-b border-warning/30 bg-warning/10 px-4 py-1.5 text-mono text-[11px] text-warning">
      <span className="h-1.5 w-1.5 rounded-full bg-warning" />
      <span>
        {status === "checking"
          ? "checking backend…"
          : "Backend offline — running in local-only mode"}
      </span>
    </div>
  );
}

function RootComponent() {
  const { queryClient } = Route.useRouteContext();
  const [lockerOpen, setLockerOpen] = useState(false);

  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <PrefsProvider>
          <LockerProvider>
          <SidebarProvider>
            <BackendBanner />
            <AppSidebar />
            <SidebarInset className="w-full">
              <RouteRecorder />
              <Outlet />
              <LockerUI open={lockerOpen} onOpenChange={setLockerOpen} />
              <Toaster />
            </SidebarInset>
          </SidebarProvider>
          </LockerProvider>
        </PrefsProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

function LockerUI({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { count } = useLocker();
  return (
    <>
      <IocLockerTrigger onClick={() => onOpenChange(true)} count={count} />
      <IocLockerPanel open={open} onClose={() => onOpenChange(false)} />
    </>
  );
}
