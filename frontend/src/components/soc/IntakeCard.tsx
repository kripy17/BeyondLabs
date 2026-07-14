import { useEffect, useRef, useState, type ReactNode } from "react";
import { Check, ChevronDown, Copy, Eraser, Loader2, Play, Upload, type LucideIcon } from "lucide-react";
import { copyText } from "@/lib/copy";
import { Panel } from "@/components/soc";

export type IntakeSample = { key: string; label: string; hint?: string };
export type IntakeRun = {
  label?: string;
  icon?: LucideIcon;
  onClick: () => void;
  hint?: string;
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
      await copyText(value);
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
            <div className="rounded border border-dashed border-primary/60 bg-card/80 px-3 py-1.5 text-mono ba-text-sm uppercase tracking-widest text-primary">
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
          className="w-full resize-y bg-background/40 px-4 py-3 text-mono ba-text-base leading-relaxed text-foreground outline-none placeholder:text-muted-foreground/60"
        />
      </div>

      {flash && (
        <div className="flex items-center gap-2 border-t border-primary/30 bg-primary/10 px-3 py-1.5">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-primary" />
          <span className="text-mono ba-text-sm text-primary">{flash}</span>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t border-border bg-muted/15 px-3 py-2">
        {samples && samples.length > 0 && (
          <label className="group/sample relative inline-flex items-center gap-1.5">
            <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">sample</span>
            <span className="relative inline-block">
              <select
                value=""
                onChange={(e) => { if (e.target.value) handleSample(e.target.value); }}
                title="Load a sample input"
                className="min-w-[150px] appearance-none rounded border border-border bg-card/70 py-1 pl-2.5 pr-7 text-mono ba-text-2xs uppercase tracking-widest text-foreground/85 outline-none transition-colors hover:border-primary/50 hover:text-primary focus:border-primary/60"
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
                className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
              >
                <Upload className="h-3 w-3" /> upload
              </button>
            </>
          )}

          {showCopy && (
            <button
              type="button"
              onClick={handleCopy}
              disabled={!value}
              title="Copy input"
              className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground disabled:opacity-40 disabled:hover:border-border disabled:hover:text-muted-foreground"
            >
              {copied ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> copy</>}
            </button>
          )}

          {(onClear || value) && (
            <button
              type="button"
              onClick={handleClear}
              disabled={!value}
              title="Clear input"
              className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground transition-colors hover:border-destructive/40 hover:text-destructive disabled:opacity-40 disabled:hover:border-border disabled:hover:text-muted-foreground"
            >
              <Eraser className="h-3 w-3" /> clear
            </button>
          )}

          {secondaryActions}

          {run ? (
            <button
              type="button"
              onClick={run.onClick}
              disabled={run.disabled || run.busy}
              className="group inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs uppercase tracking-widest text-primary transition-all hover:bg-primary/20 hover:shadow-[0_0_12px_-2px_hsl(var(--primary)/0.45)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              {run.busy
                ? <Loader2 className="h-3 w-3 animate-spin" />
                : run.icon
                  ? <run.icon className="h-3 w-3" />
                  : <Play className="h-3 w-3" />}
              <span>{run.busy ? "running" : (run.label ?? "run")}</span>
              {run.hint && !run.busy && (
                <kbd className="rounded border border-primary/40 bg-background/40 px-1 ba-text-3xs tracking-widest text-primary/80 group-hover:border-primary/60">
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
