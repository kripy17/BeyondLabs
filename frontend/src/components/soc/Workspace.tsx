import { useEffect, useRef, useState, useCallback, type ReactNode } from "react";
import {
  Check, Copy, Eraser, Loader2, Play, Upload, ChevronDown, ChevronRight,
  ArrowDownToLine, ArrowUpFromLine, Clock, Filter, Settings2, Sparkles,
  type LucideIcon,
} from "lucide-react";

/* ============================================================
 * Shared workspace primitives. Mirror the reference BeyondArch
 * structure (intake card → status → result banner → key fields
 * → ioc inventory → send-to) using our quieter mono aesthetic.
 * ============================================================ */

/* Map legacy 2-letter chip ids to expressive icons. */
const SECTION_ICONS: Record<string, LucideIcon> = {
  IN: ArrowDownToLine,
  OT: ArrowUpFromLine,
  RC: Clock,
  FL: Filter,
  CF: Settings2,
  AI: Sparkles,
};

/* ── Section divider with an icon chip + dashed rule ── */
export function SectionBar({
  id,
  label,
  meta,
  action,
  icon,
}: {
  id: string;
  label: string;
  meta?: string;
  action?: ReactNode;
  icon?: LucideIcon;
}) {
  const Icon = icon ?? SECTION_ICONS[id.toUpperCase()];
  return (
    <div className="group/sb mb-3 mt-1 flex items-center gap-3">
      <span className="relative grid h-6 w-6 place-items-center rounded-sm border border-primary/50 bg-primary/10 text-primary shadow-[0_0_0_1px_hsl(var(--background)),0_0_10px_-2px_hsl(var(--primary)/0.55)] transition-shadow group-hover/sb:shadow-[0_0_0_1px_hsl(var(--background)),0_0_14px_-1px_hsl(var(--primary)/0.8)]">
        {Icon ? (
          <Icon className="h-3.5 w-3.5" strokeWidth={2.25} />
        ) : (
          <span className="text-mono text-[9px] font-bold">{id.slice(0, 2).toUpperCase()}</span>
        )}
        <span aria-hidden className="absolute -right-0.5 -top-0.5 h-1 w-1 animate-pulse rounded-full bg-primary" />
      </span>
      <h2 className="text-mono text-[11px] uppercase tracking-[0.22em] text-foreground/90">
        {label}
      </h2>
      <div className="h-px flex-1 bg-gradient-to-r from-primary/30 via-border to-transparent" />
      {meta && <span className="rounded border border-border/60 bg-card/40 px-1.5 py-0.5 text-mono text-[10px] text-muted-foreground">{meta}</span>}
      {action}
    </div>
  );
}

/* ── Panel with corner ticks + optional header ── */
export function Panel({
  title,
  icon: Icon,
  meta,
  actions,
  children,
  className = "",
  bodyClassName = "",
  collapsible,
  defaultCollapsed,
  storageKey,
  sticky,
}: {
  title?: string;
  icon?: LucideIcon;
  meta?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  collapsible?: boolean;
  defaultCollapsed?: boolean;
  storageKey?: string;
  sticky?: boolean;
}) {
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    if (storageKey) {
      try { return JSON.parse(localStorage.getItem(storageKey) || "null") ?? !!defaultCollapsed; } catch {}
    }
    return !!defaultCollapsed;
  });

  const toggle = useCallback(() => {
    setCollapsed((c) => {
      const next = !c;
      if (storageKey) {
        try { localStorage.setItem(storageKey, JSON.stringify(next)); } catch {}
      }
      return next;
    });
  }, [storageKey]);

  const canCollapse = collapsible && !!title;

  return (
    <section className={"group/panel ba-fade-in relative overflow-hidden rounded-md border border-border bg-card/60 transition-colors hover:border-primary/30 " + (sticky ? "sticky top-0 z-10 shadow-sm" : "") + " " + className}>
      <span aria-hidden className="pointer-events-none absolute left-0 top-0 h-2 w-2 border-l border-t border-primary/40 transition-all group-hover/panel:h-2.5 group-hover/panel:w-2.5 group-hover/panel:border-primary/80" />
      <span aria-hidden className="pointer-events-none absolute right-0 top-0 h-2 w-2 border-r border-t border-primary/40 transition-all group-hover/panel:h-2.5 group-hover/panel:w-2.5 group-hover/panel:border-primary/80" />
      <span aria-hidden className="pointer-events-none absolute left-0 bottom-0 h-2 w-2 border-l border-b border-primary/40 transition-all group-hover/panel:h-2.5 group-hover/panel:w-2.5 group-hover/panel:border-primary/80" />
      <span aria-hidden className="pointer-events-none absolute right-0 bottom-0 h-2 w-2 border-r border-b border-primary/40 transition-all group-hover/panel:h-2.5 group-hover/panel:w-2.5 group-hover/panel:border-primary/80" />
      {title && (
        <header
          className={"flex items-center justify-between gap-2 border-b border-border px-4 py-2.5 " + (canCollapse ? "cursor-pointer select-none hover:bg-card/40" : "")}
          onClick={canCollapse ? toggle : undefined}
        >
          <div className="flex items-center gap-2 min-w-0">
            {canCollapse && (
              <ChevronDown className={"h-3 w-3 shrink-0 text-muted-foreground transition-transform " + (collapsed ? "-rotate-90" : "")} />
            )}
            {Icon && <Icon className="h-3.5 w-3.5 text-primary shrink-0" />}
            <h3 className="text-mono text-[11px] uppercase tracking-[0.22em] truncate">{title}</h3>
            {meta && <span className="text-mono text-[10px] text-muted-foreground shrink-0">· {meta}</span>}
          </div>
          {actions && <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>{actions}</div>}
        </header>
      )}
      {(!canCollapse || !collapsed) && (
        <div className={"p-4 " + bodyClassName}>{children}</div>
      )}
    </section>
  );
}

/* ── Label/value mono row ── */
export function Field({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: ReactNode;
  tone?: "default" | "primary" | "success" | "warning" | "destructive" | "muted";
}) {
  const toneCls =
    tone === "primary" ? "text-primary" :
    tone === "success" ? "text-success" :
    tone === "warning" ? "text-warning" :
    tone === "destructive" ? "text-destructive" :
    tone === "muted" ? "text-muted-foreground" : "text-foreground";
  const dot =
    tone === "primary" ? "bg-primary" :
    tone === "success" ? "bg-success" :
    tone === "warning" ? "bg-warning" :
    tone === "destructive" ? "bg-destructive" :
    "bg-muted-foreground/30";
  return (
    <div className="group/f flex items-baseline justify-between gap-3 border-b border-dashed border-border/50 py-1.5 transition-colors last:border-b-0 hover:border-primary/40">
      <span className="flex items-center gap-1.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
        <span className={"inline-block h-1 w-1 rounded-full " + dot} aria-hidden />
        {label}
      </span>
      <span className={"text-mono text-[12px] tabular-nums truncate " + toneCls}>{value}</span>
    </div>
  );
}

/* ── Inline status chip ── */
export function Chip({
  children,
  tone = "default",
}: {
  children: ReactNode;
  tone?: "default" | "primary" | "accent" | "success" | "warning" | "destructive" | "info";
}) {
  const cls =
    tone === "primary" ? "border-primary/40 bg-primary/10 text-primary" :
    tone === "accent" ? "border-accent/40 bg-accent/10 text-accent" :
    tone === "success" ? "border-success/40 bg-success/10 text-success" :
    tone === "warning" ? "border-warning/40 bg-warning/10 text-warning" :
    tone === "destructive" ? "border-destructive/40 bg-destructive/10 text-destructive" :
    tone === "info" ? "border-info/40 bg-info/10 text-info" :
    "border-border bg-card/50 text-muted-foreground";
  return (
    <span className={"inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-mono text-[10px] uppercase tracking-widest " + cls}>
      {children}
    </span>
  );
}

/* ── Toolbar row above an output area ── */
export function Toolbar({ children }: { children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-border bg-muted/20 px-3 py-2">
      {children}
    </div>
  );
}

/* ── Empty state ── */
export function Empty({
  icon: Icon,
  title,
  hint,
}: {
  icon?: LucideIcon;
  title: string;
  hint?: string;
}) {
  return (
    <div className="relative flex flex-col items-center justify-center gap-2 overflow-hidden rounded-md border border-dashed border-border bg-background/30 py-10 text-center">
      <div aria-hidden className="pointer-events-none absolute inset-0 bg-[linear-gradient(transparent_95%,hsl(var(--border)/0.4)_95%)] bg-[length:100%_8px] opacity-40" />
      {Icon && (
        <div className="relative grid h-9 w-9 place-items-center rounded-md border border-border bg-card/60">
          <Icon className="h-4 w-4 text-muted-foreground/80" />
        </div>
      )}
      <div className="relative text-mono text-[12px] text-foreground/85">{title}</div>
      {hint && <div className="relative max-w-xs text-[11px] text-muted-foreground">{hint}</div>}
    </div>
  );
}

/* ── Intake card: textarea + sample loader + canonical actions ── */
export type IntakeSample = { key: string; label: string; hint?: string };
export type IntakeRun = {
  label?: string;
  icon?: LucideIcon;
  onClick: () => void;
  hint?: string;          // e.g. "⌘↵"
  busy?: boolean;
  disabled?: boolean;
};

export function IntakeCard({
  icon: Icon = undefined,
  title = "Input Terminal",
  value,
  onChange,
  onPaste,
  placeholder,
  samples,
  onLoadSample,
  primaryAction,
  secondaryActions,
  rightMeta,
  rows = 8,
  run,
  onClear,
  onFile,
  fileAccept = ".txt,.log,.json,.eml,.csv,.yaml,.yml,.rules,.conf",
  showCopy = true,
  notice,
}: {
  icon?: LucideIcon;
  title?: string;
  value: string;
  onChange: (v: string) => void;
  onPaste?: (text: string) => void;
  placeholder?: string;
  samples?: IntakeSample[];
  onLoadSample?: (key: string) => void;
  primaryAction?: ReactNode;
  secondaryActions?: ReactNode;
  rightMeta?: ReactNode;
  rows?: number;
  run?: IntakeRun;
  onClear?: () => void;
  onFile?: (text: string, file: File) => void;
  fileAccept?: string;
  showCopy?: boolean;
  notice?: string;
}) {
  const [copied, setCopied] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [flash, setFlash] = useState<string>("");
  const fileRef = useRef<HTMLInputElement>(null);
  const lastSampleRef = useRef<string>("");

  // Auto-flash banner when a sample is loaded or value pasted from caller
  useEffect(() => {
    if (notice) {
      setFlash(notice);
      const t = setTimeout(() => setFlash(""), 2400);
      return () => clearTimeout(t);
    }
  }, [notice]);

  const flashNotice = (msg: string) => {
    setFlash(msg);
    setTimeout(() => setFlash(""), 2400);
  };

  const handleCopy = async () => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {/* noop */}
  };

  const handleClear = () => {
    if (onClear) onClear();
    else onChange("");
  };

  const handleFiles = async (files: FileList | null) => {
    if (!files || !files[0]) return;
    const f = files[0];
    try {
      const txt = await f.text();
      onChange(txt);
      onFile?.(txt, f);
      flashNotice(`loaded ${f.name} · ${txt.length.toLocaleString()} chars`);
    } catch {/* noop */}
  };

  const handleSample = (key: string) => {
    onLoadSample?.(key);
    lastSampleRef.current = key;
    const s = samples?.find((x) => x.key === key);
    if (s) flashNotice(`${s.label} sample loaded${run?.label ? ` — press ${run.hint ?? "Run"} to ${run.label.toLowerCase()}` : ""}`);
  };

  

  return (
    <Panel
      title={title}
      icon={Icon}
      meta={rightMeta as unknown as string}
      bodyClassName="p-0"
      className={dragOver ? "ring-1 ring-primary/60" : ""}
    >
      <div
        onDragOver={(e) => { if (onFile) { e.preventDefault(); setDragOver(true); } }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          if (!onFile) return;
          e.preventDefault();
          setDragOver(false);
          handleFiles(e.dataTransfer.files);
        }}
        className="relative"
      >
        {dragOver && (
          <div className="pointer-events-none absolute inset-0 z-10 grid place-items-center bg-primary/5 backdrop-blur-[1px]">
            <div className="rounded border border-dashed border-primary/60 bg-card/80 px-3 py-1.5 text-mono text-[11px] uppercase tracking-widest text-primary">
              drop file to load
            </div>
          </div>
        )}
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onPaste={(e) => {
            if (!onPaste) return;
            const text = e.clipboardData.getData("text");
            if (text) queueMicrotask(() => onPaste(text));
          }}
          rows={rows}
          spellCheck={false}
          placeholder={placeholder ?? "[WAITING_FOR_INPUT]\n\nPaste raw artifact, log line, URL, hash, or rule — or drop a file."}
          className="w-full resize-y bg-background/40 px-4 py-3 text-mono text-[12px] leading-relaxed text-foreground outline-none placeholder:text-muted-foreground/60"
        />
      </div>

      {/* Flash notice */}
      {flash && (
        <div className="flex items-center gap-2 border-t border-primary/30 bg-primary/10 px-3 py-1.5">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-primary" />
          <span className="text-mono text-[11px] text-primary">{flash}</span>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t border-border bg-muted/15 px-3 py-2">
        {/* Sample loader */}
        {samples && samples.length > 0 && (
          <label className="group/sample relative inline-flex items-center gap-1.5">
            <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">sample</span>
            <span className="relative inline-block">
              <select
                value=""
                onChange={(e) => { if (e.target.value) handleSample(e.target.value); }}
                title="Load a sample input"
                className="min-w-[150px] appearance-none rounded border border-border bg-card/70 py-1 pl-2.5 pr-7 text-mono text-[10px] uppercase tracking-widest text-foreground/85 outline-none transition-colors hover:border-primary/50 hover:text-primary focus:border-primary/60"
              >
                <option value="" disabled>load sample…</option>
                {samples.map((s) => (
                  <option key={s.key} value={s.key}>{s.label}{s.hint ? ` — ${s.hint}` : ""}</option>
                ))}
              </select>
              <ChevronDown className="pointer-events-none absolute right-1.5 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground group-hover/sample:text-primary" />
            </span>
          </label>
        )}

        <div className="ml-auto flex items-center gap-1.5">
          {/* Built-in file upload */}
          {onFile && (
            <>
              <input
                ref={fileRef}
                type="file"
                accept={fileAccept}
                className="hidden"
                onChange={(e) => { handleFiles(e.target.files); e.target.value = ""; }}
              />
              <button
                type="button"
                onClick={() => fileRef.current?.click()}
                title="Upload file (or drop one onto the input)"
                className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
              >
                <Upload className="h-3 w-3" /> upload
              </button>
            </>
          )}

          {/* Built-in copy */}
          {showCopy && (
            <button
              type="button"
              onClick={handleCopy}
              disabled={!value}
              title="Copy input"
              className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground disabled:opacity-40 disabled:hover:border-border disabled:hover:text-muted-foreground"
            >
              {copied ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> copy</>}
            </button>
          )}

          {/* Built-in clear */}
          {(onClear || value) && (
            <button
              type="button"
              onClick={handleClear}
              disabled={!value}
              title="Clear input"
              className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground transition-colors hover:border-destructive/40 hover:text-destructive disabled:opacity-40 disabled:hover:border-border disabled:hover:text-muted-foreground"
            >
              <Eraser className="h-3 w-3" /> clear
            </button>
          )}

          {/* Caller-provided extras */}
          {secondaryActions}

          {/* Canonical run button */}
          {run ? (
            <button
              type="button"
              onClick={run.onClick}
              disabled={run.disabled || run.busy}
              className="group inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono text-[10px] uppercase tracking-widest text-primary transition-all hover:bg-primary/20 hover:shadow-[0_0_12px_-2px_hsl(var(--primary)/0.45)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              {run.busy
                ? <Loader2 className="h-3 w-3 animate-spin" />
                : run.icon
                  ? <run.icon className="h-3 w-3" />
                  : <Play className="h-3 w-3" />}
              <span>{run.busy ? "running" : (run.label ?? "run")}</span>
              {run.hint && !run.busy && (
                <kbd className="rounded border border-primary/40 bg-background/40 px-1 text-[9px] tracking-widest text-primary/80 group-hover:border-primary/60">
                  {run.hint}
                </kbd>
              )}
            </button>
          ) : primaryAction}
        </div>
      </div>
    </Panel>
  );
}


/* ── Status bar under intake (Idle/Ready/chars/lines) ── */
export function StatusBar({
  stats,
}: {
  stats: { label: string; value: ReactNode; tone?: "default" | "primary" | "success" | "warning" | "destructive" | "muted" }[];
}) {
  return (
    <div className="relative flex flex-wrap items-center gap-x-5 gap-y-1.5 overflow-hidden rounded-md border border-border bg-card/40 px-3 py-2">
      <span aria-hidden className="pointer-events-none absolute inset-y-0 left-0 w-[2px] bg-primary/50" />
      {stats.map((s, i) => {
        const dot =
          s.tone === "primary" ? "bg-primary" :
          s.tone === "success" ? "bg-success" :
          s.tone === "warning" ? "bg-warning animate-pulse" :
           s.tone === "destructive" ? "bg-destructive" :
           s.tone === "muted" ? "bg-muted-foreground/40" :
          "bg-foreground/40";
        return (
          <div key={i} className="flex items-center gap-1.5">
            <span className={"inline-block h-1.5 w-1.5 rounded-full " + dot} />
            <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">{s.label}</span>
            <span
              className={
                "text-mono text-[11px] tabular-nums " +
                (s.tone === "primary" ? "text-primary" :
                 s.tone === "success" ? "text-success" :
                 s.tone === "warning" ? "text-warning" :
                  s.tone === "destructive" ? "text-destructive" :
                  s.tone === "muted" ? "text-muted-foreground" :
                 "text-foreground")
              }
            >
              {s.value}
            </span>
          </div>
        );
      })}
    </div>
  );
}

/* ── Result Banner: ARTIFACT_INTAKE / VERDICT / SNAPSHOT badge + title + metric row ── */
export function ResultBanner({
  badge,
  caseId,
  title,
  subtitle,
  reasons,
  metrics,
  sticky,
}: {
  badge: string;
  caseId?: string;
  title: string;
  subtitle?: string;
  reasons?: string[];
  metrics?: { label: string; value: ReactNode; tone?: "primary" | "warning" | "destructive" | "success" | "default" }[];
  sticky?: boolean;
}) {
  return (
    <Panel sticky={sticky} className="relative overflow-hidden bg-gradient-to-br from-card/85 via-card/55 to-card/30">
      <span aria-hidden className="pointer-events-none absolute inset-y-0 left-0 w-[3px] bg-gradient-to-b from-primary/80 via-primary/40 to-transparent" />
      <span aria-hidden className="pointer-events-none absolute inset-0 opacity-[0.04] [background-image:radial-gradient(hsl(var(--primary))_1px,transparent_1px)] [background-size:14px_14px]" />
      <div className="relative grid gap-4 grid-cols-[1.4fr_1fr]">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Chip tone="primary">{badge}</Chip>
            {caseId && (
              <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                id: <span className="text-foreground/85">{caseId}</span>
              </span>
            )}
          </div>
          <h2 className="mt-2 text-xl font-semibold text-foreground text-2xl">{title}</h2>
          {subtitle && <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>}
          {reasons && reasons.length > 0 && (
            <ul className="mt-3 space-y-1">
              {reasons.slice(0, 4).map((r, i) => (
                <li key={i} className="text-mono text-[11px] text-foreground/80">
                  <span className="mr-2 text-primary">›</span>
                  {r}
                </li>
              ))}
            </ul>
          )}
        </div>
        {metrics && metrics.length > 0 && (
          <div className="grid grid-cols-2 gap-2 grid-cols-4">
            {metrics.map((m, i) => (
              <div
                key={i}
                className={
                  "group/m relative overflow-hidden rounded-md border bg-background/50 px-3 py-2 transition-all hover:-translate-y-[1px] " +
                  (m.tone === "primary" ? "border-primary/40 hover:border-primary/70" :
                   m.tone === "warning" ? "border-warning/40 hover:border-warning/70" :
                   m.tone === "destructive" ? "border-destructive/40 hover:border-destructive/70" :
                   m.tone === "success" ? "border-success/40 hover:border-success/70" :
                   "border-border hover:border-primary/40")
                }
              >
                <span aria-hidden className={"absolute inset-x-0 bottom-0 h-[2px] opacity-60 " +
                  (m.tone === "primary" ? "bg-primary" :
                   m.tone === "warning" ? "bg-warning" :
                   m.tone === "destructive" ? "bg-destructive" :
                   m.tone === "success" ? "bg-success" : "bg-border")} />
                <div className="text-mono text-[9px] uppercase tracking-widest text-muted-foreground">{m.label}</div>
                <div
                  className={
                    "mt-0.5 text-mono text-xl font-semibold tabular-nums " +
                    (m.tone === "primary" ? "text-primary" :
                     m.tone === "warning" ? "text-warning" :
                     m.tone === "destructive" ? "text-destructive" :
                     m.tone === "success" ? "text-success" :
                     "text-foreground")
                  }
                >
                  {m.value}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </Panel>
  );
}

/* ── Key Fields grid (used for parsed entities) ── */
export function KeyFields({ items }: { items: { label: string; value: ReactNode; tone?: "default" | "primary" | "success" | "warning" | "destructive" | "muted" }[] }) {
  return (
    <div className="grid gap-x-6 gap-y-0 grid-cols-2">
      {items.map((f, i) => (
        <Field key={i} label={f.label} value={f.value} tone={f.tone} />
      ))}
    </div>
  );
}

/* ── IOC Inventory: grouped list of indicators with send-to actions ── */
export function IocInventory({
  groups,
  onSendTo,
}: {
  groups: { kind: string; items: string[]; tone?: "primary" | "warning" | "destructive" | "info" | "success" | "default" }[];
  onSendTo?: (kind: string, value: string) => void;
}) {
  return (
    <div className="grid gap-3 grid-cols-2">
      {groups.map((g) => {
        const dot =
          g.tone === "primary" ? "bg-primary" :
          g.tone === "warning" ? "bg-warning" :
          g.tone === "destructive" ? "bg-destructive" :
          g.tone === "info" ? "bg-info" :
          g.tone === "success" ? "bg-success" : "bg-muted-foreground/50";
        return (
          <Panel
            key={g.kind}
            title={g.kind}
            meta={`${g.items.length}`}
            bodyClassName="p-0"
            actions={<span className={"inline-block h-1.5 w-1.5 rounded-full " + dot} aria-hidden />}
          >
            {g.items.length === 0 ? (
              <div className="px-4 py-3 text-mono text-[11px] text-muted-foreground">no items</div>
            ) : (
              <ul className="divide-y divide-border/40">
                {g.items.map((v, idx) => (
                  <li key={v} className={"group/ioc flex items-center justify-between gap-2 px-3 py-1.5 transition-colors hover:bg-primary/5 " + (idx % 2 === 1 ? "bg-background/30" : "")}>
                    <div className="flex min-w-0 items-center gap-2">
                      <span className={"h-1 w-1 shrink-0 rounded-full " + dot} aria-hidden />
                      <code className="truncate text-mono text-[11px] text-foreground/90">{v}</code>
                    </div>
                    {onSendTo && (
                      <button
                        onClick={() => onSendTo(g.kind, v)}
                        className="shrink-0 rounded border border-border bg-card/60 px-1.5 py-0.5 text-mono text-[9px] uppercase tracking-widest text-muted-foreground opacity-0 transition-all hover:border-primary/50 hover:text-primary group-hover/ioc:opacity-100"
                      >
                        send →
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        );
      })}
    </div>
  );
}

/* ── Row of "send to {workspace}" actions ── */
export function SendToRow({
  targets,
}: {
  targets: { label: string; to: string; icon?: LucideIcon; onClick?: () => void }[];
}) {
  return (
    <Panel title="Case Handoff" bodyClassName="p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          send artifact to:
        </span>
        {targets.map((t) => {
          const Icon = t.icon;
          return (
            <a
              key={t.to}
              href={t.to}
              onClick={t.onClick}
              className="group/st inline-flex items-center gap-1.5 rounded border border-border bg-card/70 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-foreground/80 transition-all hover:-translate-y-[1px] hover:border-primary/60 hover:bg-primary/5 hover:text-primary hover:shadow-[0_0_10px_-2px_hsl(var(--primary)/0.4)]"
            >
              {Icon && <Icon className="h-3 w-3 transition-transform group-hover/st:scale-110" />}
              {t.label}
              <span aria-hidden className="text-muted-foreground/60 transition-transform group-hover/st:translate-x-0.5 group-hover/st:text-primary">→</span>
            </a>
          );
        })}

      </div>
    </Panel>
  );
}

/* ── Evidence card — case-ready finding with reason/limitation ── */
export function EvidenceCard({
  severity = "info",
  title,
  reason,
  limitation,
  action,
}: {
  severity?: "info" | "warning" | "destructive" | "success";
  title: string;
  reason?: string;
  limitation?: string;
  action?: string;
}) {
  const bar =
    severity === "destructive" ? "bg-destructive" :
    severity === "warning" ? "bg-warning" :
    severity === "success" ? "bg-success" : "bg-info";
  return (
    <Panel
      className={
        "relative " + (
        severity === "destructive" ? "border-destructive/40" :
        severity === "warning" ? "border-warning/40" :
        severity === "success" ? "border-success/40" :
        "border-info/40")
      }
      bodyClassName="p-3 pl-4"
    >
      <span aria-hidden className={"pointer-events-none absolute inset-y-0 left-0 w-[3px] " + bar} />
      <div className="flex items-start gap-2">
        <Chip tone={severity === "destructive" ? "destructive" : severity === "warning" ? "warning" : severity === "success" ? "success" : "info"}>
          {severity}
        </Chip>
        <div className="min-w-0 flex-1">
          <div className="text-mono text-[12px] font-semibold text-foreground">{title}</div>
          {reason && <div className="mt-1 text-[11px] leading-relaxed text-muted-foreground"><span className="text-foreground/70">Reason:</span> {reason}</div>}
          {limitation && <div className="mt-1 text-[11px] leading-relaxed text-muted-foreground"><span className="text-foreground/70">Limitation:</span> {limitation}</div>}
          {action && <div className="mt-1 text-[11px] leading-relaxed text-muted-foreground"><span className="text-foreground/70">Action:</span> {action}</div>}
        </div>
      </div>
    </Panel>
  );
}

/* ── Risk gauge — large score readout ── */
export function RiskScore({
  score,
  label,
  confidence,
  scale = 100,
  tone = "warning",
}: {
  score: number;
  label: string;
  confidence?: string;
  scale?: number;
  tone?: "success" | "warning" | "destructive";
}) {
  const pct = Math.min(100, Math.max(0, Math.round((score / scale) * 100)));
  const barCls =
    tone === "destructive" ? "bg-destructive" :
    tone === "success" ? "bg-success" : "bg-warning";
  return (
    <Panel title={label} bodyClassName="p-3">
      <div className="flex items-end justify-between gap-2">
        <div className={"text-mono text-3xl font-bold " + (tone === "destructive" ? "text-destructive" : tone === "success" ? "text-success" : "text-warning")}>
          {score}
          <span className="ml-1 text-base text-muted-foreground">/{scale}</span>
        </div>
        {confidence && <Chip tone={tone === "destructive" ? "destructive" : tone === "success" ? "success" : "warning"}>{confidence}</Chip>}
      </div>
      <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-muted/40">
        <div className={"h-full transition-all " + barCls} style={{ width: `${pct}%` }} />
      </div>
    </Panel>
  );
}

/* ── Verdict Banner — prominent verdict display with collapsible details ── */
export function VerdictBanner({
  verdict,
  tone = "warning",
  icon: Icon,
  score,
  details,
  collapsible = true,
}: {
  verdict: string;
  tone?: "success" | "warning" | "destructive" | "info";
  icon?: LucideIcon;
  score?: string;
  details?: string[];
  collapsible?: boolean;
}) {
  const [expanded, setExpanded] = useState(!collapsible);
  const IconEl = Icon ?? (tone === "destructive" ? ChevronDown : tone === "success" ? Check : ChevronRight);
  const toneCls =
    tone === "destructive" ? "border-destructive/40 bg-destructive/10 text-destructive" :
    tone === "success" ? "border-success/40 bg-success/10 text-success" :
    tone === "warning" ? "border-warning/40 bg-warning/10 text-warning" :
    "border-info/40 bg-info/10 text-info";
  return (
    <div className={"rounded-lg border-2 " + toneCls}>
      <button
        onClick={() => setExpanded((e) => !e)}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
      >
        <div className="flex items-center gap-3">
          <IconEl className="h-5 w-5" />
          <div>
            <div className="text-mono text-[12px] font-bold uppercase tracking-widest">{verdict}</div>
            {score !== undefined && <div className="text-mono text-[10px] opacity-80">score: {score}</div>}
          </div>
        </div>
        {collapsible && <ChevronRight className={"h-4 w-4 transition-transform " + (expanded ? "rotate-90" : "")} />}
      </button>
      {expanded && details && details.length > 0 && (
        <div className="border-t border-current/20 px-4 py-2">
          <ul className="space-y-1">
            {details.map((d, i) => (
              <li key={i} className="text-mono text-[11px] leading-relaxed">• {d}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

/* ── Metric Grid — responsive metric tiles ── */
export function MetricGrid({
  metrics,
  columns = 4,
}: {
  metrics: { label: string; value: ReactNode; tone?: "default" | "primary" | "success" | "warning" | "destructive" | "info" | "accent" | "muted"; icon?: LucideIcon }[];
  columns?: 2 | 3 | 4;
}) {
  const gridCls =
    columns === 2 ? "sm:grid-cols-2" :
    columns === 3 ? "sm:grid-cols-3" :
    "sm:grid-cols-2 md:grid-cols-4";
  return (
    <div className={"grid gap-2 " + gridCls}>
      {metrics.map((m, i) => {
        const toneCls =
          m.tone === "primary" ? "border-primary/30 text-primary" :
          m.tone === "success" ? "border-success/30 text-success" :
          m.tone === "warning" ? "border-warning/30 text-warning" :
          m.tone === "destructive" ? "border-destructive/30 text-destructive" :
          m.tone === "info" ? "border-info/30 text-info" :
          m.tone === "accent" ? "border-accent/30 text-accent" :
          m.tone === "muted" ? "border-border/30 text-muted-foreground" :
          "border-border/30 text-foreground";
        const Icon = m.icon;
        return (
          <div key={i} className={"group relative overflow-hidden rounded-md border bg-card/40 px-3 py-2.5 transition-all hover:-translate-y-[1px] hover:shadow-sm " + toneCls}>
            <span aria-hidden className="absolute inset-x-0 bottom-0 h-[2px] opacity-60 bg-current" />
            <div className="flex items-center justify-between gap-1.5">
              <span className="text-mono text-[9px] uppercase tracking-widest opacity-70">{m.label}</span>
              {Icon && <Icon className="h-3 w-3 opacity-60" />}
            </div>
            <div className="mt-1 text-mono text-lg font-semibold tabular-nums">{m.value}</div>
          </div>
        );
      })}
    </div>
  );
}

/* ── Two Column Output — side-by-side responsive grid ── */
export function TwoColumnOutput({
  left,
  right,
  ratio = "1:1",
}: {
  left: ReactNode;
  right: ReactNode;
  ratio?: "1:1" | "2:1" | "1:2" | "3:2" | "2:3";
}) {
  const gridCls =
    ratio === "2:1" ? "lg:grid-cols-[2fr_1fr]" :
    ratio === "1:2" ? "lg:grid-cols-[1fr_2fr]" :
    ratio === "3:2" ? "lg:grid-cols-[3fr_2fr]" :
    ratio === "2:3" ? "lg:grid-cols-[2fr_3fr]" :
    "lg:grid-cols-2";
  return (
    <div className={"grid gap-3 " + gridCls}>
      {left}
      {right}
    </div>
  );
}

/* ── Collapsible Section — full-width collapsible wrapper ── */
export function CollapsibleSection({
  id,
  label,
  meta,
  icon: Icon,
  children,
  defaultCollapsed = false,
}: {
  id: string;
  label: string;
  meta?: string;
  icon?: LucideIcon;
  children: ReactNode;
  defaultCollapsed?: boolean;
}) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);
  return (
    <div className="rounded-md border border-border/70 bg-card/40 overflow-hidden">
      <button
        onClick={() => setCollapsed((c) => !c)}
        className="flex w-full items-center gap-2 border-b border-border/60 px-3 py-2 text-left hover:bg-accent/30 transition-colors"
      >
        {Icon && (
          <span className="grid h-5 w-5 place-items-center rounded-sm border border-primary/40 bg-primary/10 text-primary">
            <Icon className="h-3 w-3" strokeWidth={2.25} />
          </span>
        )}
        <span className="text-mono text-[11px] uppercase tracking-[0.22em] text-foreground/90">{label}</span>
        {meta && <span className="text-mono text-[10px] text-muted-foreground">({meta})</span>}
        <div className="ml-auto">
          <ChevronRight className={"h-4 w-4 text-muted-foreground transition-transform " + (collapsed ? "" : "rotate-90")} />
        </div>
      </button>
      {!collapsed && <div className="p-3">{children}</div>}
    </div>
  );
}
