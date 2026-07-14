import { useMemo, useState } from "react";
import { copyText } from "@/lib/copy";
import { Copy, Check, X, Download, WrapText, ArrowDownToLine } from "lucide-react";

type Props = {
  command: string;
  body: string;
  stderr?: string;
  status?: string;
  onClear?: () => void;
  filename?: string;
};

function tokenize(line: string): { cls: string; text: string }[] {
  const parts: { cls: string; text: string }[] = [];
  if (/^\s*#/.test(line))
    return [{ cls: "text-muted-foreground/70", text: line }];
  if (/^\s*\$/.test(line))
    return [{ cls: "text-primary/80", text: line }];

  const rx =
    /(\[(?:INFO|INF|OK|DEBUG|DBG|WARN(?:ING)?|ERR(?:OR)?|CRIT(?:ICAL)?|FATAL|SUCCESS|\+|-|\*|!)\])|(\bcritical\b|\bhigh\b|\bmedium\b|\blow\b|\bopen\b|\bclosed\b|\bfiltered\b)|(\b(?:GET|POST|PUT|DELETE|PATCH|HEAD)\b)|(\b[1-5][0-9]{2}\b)|(\b(?:\d{1,3}\.){3}\d{1,3}\b)|(\bhttps?:\/\/[^\s"'<>]+)|(\b\d{2,5}\/(?:tcp|udp))/gi;

  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(line))) {
    if (m.index > last) parts.push({ cls: "", text: line.slice(last, m.index) });
    const tok = m[0];
    const l = tok.toLowerCase();
    let cls = "text-foreground/90";
    if (m[1]) {
      if (/warn/i.test(tok)) cls = "text-warning font-semibold";
      else if (/err|fatal|crit|!/i.test(tok)) cls = "text-destructive font-semibold";
      else if (/ok|success|\+/i.test(tok)) cls = "text-success font-semibold";
      else cls = "text-info font-semibold";
    } else if (m[2]) {
      if (l === "critical" || l === "high") cls = "text-destructive font-semibold";
      else if (l === "medium" || l === "open") cls = "text-warning font-semibold";
      else if (l === "low" || l === "closed") cls = "text-muted-foreground";
      else if (l === "filtered") cls = "text-info";
    } else if (m[3]) {
      cls = "text-primary font-semibold";
    } else if (m[4]) {
      const code = parseInt(tok, 10);
      cls = code >= 500 ? "text-destructive" : code >= 400 ? "text-warning" : code >= 300 ? "text-info" : "text-success";
    } else if (m[5]) {
      cls = "text-accent";
    } else if (m[6]) {
      cls = "text-primary underline decoration-primary/40 underline-offset-2";
    } else if (m[7]) {
      cls = "text-warning";
    }
    parts.push({ cls, text: tok });
    last = m.index + tok.length;
  }
  if (last < line.length) parts.push({ cls: "", text: line.slice(last) });
  return parts;
}

export function TerminalOutput({ command, body, stderr, status, onClear, filename = "output.txt" }: Props) {
  const [copied, setCopied] = useState<string | null>(null);
  const [wrap, setWrap] = useState(true);
  const [showErr, setShowErr] = useState(false);

  const lines = useMemo(() => body.split("\n"), [body]);
  const errLines = useMemo(() => (stderr ? stderr.split("\n") : []), [stderr]);

  const totalBytes = (body?.length ?? 0) + (stderr?.length ?? 0);

  async function copy(key: string, text: string) {
    try {
      await copyText(text);
      setCopied(key);
      setTimeout(() => setCopied(null), 1200);
    } catch {
      /* noop */
    }
  }

  function download() {
    const blob = new Blob([`# ${command}\n\n${body}${stderr ? `\n\n# stderr\n${stderr}` : ""}`], {
      type: "text/plain;charset=utf-8",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  const statusTone =
    status === "completed" ? "bg-success/15 text-success border-success/40"
    : status === "failed" || status === "error" ? "bg-destructive/15 text-destructive border-destructive/40"
    : status === "timeout" ? "bg-warning/15 text-warning border-warning/40"
    : status === "simulated" ? "bg-info/15 text-info border-info/40"
    : "bg-muted/30 text-muted-foreground border-border";

  return (
    <div className="overflow-hidden rounded-xl border border-border bg-gradient-to-b from-background/40 to-background/80 shadow-[0_1px_0_0_hsl(var(--border))_inset,0_20px_60px_-30px_hsl(var(--primary)/0.35)]">
      {/* Window chrome */}
      <div className="flex items-center gap-3 border-b border-border bg-gradient-to-b from-muted/30 to-muted/10 px-3 py-2">
        <div className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-destructive/70 shadow-[0_0_0_1px_hsl(var(--destructive)/0.4)_inset]" />
          <span className="h-2.5 w-2.5 rounded-full bg-warning/80 shadow-[0_0_0_1px_hsl(var(--warning)/0.4)_inset]" />
          <span className="h-2.5 w-2.5 rounded-full bg-success/80 shadow-[0_0_0_1px_hsl(var(--success)/0.4)_inset]" />
        </div>
        <code className="min-w-0 flex-1 truncate rounded border border-divider-strong bg-background/60 px-2 py-1 text-mono text-[11px] text-foreground/85">
          <span className="text-primary/70">$</span> {command}
        </code>
        {status && (
          <span className={`shrink-0 rounded-full border px-2 py-0.5 text-mono text-[9.5px] uppercase tracking-widest ${statusTone}`}>
            {status}
          </span>
        )}
        <div className="flex shrink-0 items-center gap-1">
          <IconBtn active={wrap} onClick={() => setWrap((w) => !w)} title="Toggle wrap">
            <WrapText className="h-3 w-3" />
          </IconBtn>
          <IconBtn onClick={() => copy("out", body)} title="Copy stdout">
            {copied === "out" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
          </IconBtn>
          <IconBtn onClick={download} title="Download">
            <Download className="h-3 w-3" />
          </IconBtn>
          {onClear && (
            <IconBtn onClick={onClear} title="Clear" danger>
              <X className="h-3 w-3" />
            </IconBtn>
          )}
        </div>
      </div>

      {/* Body */}
      <div className="relative">
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 opacity-[0.06]"
          style={{
            backgroundImage:
              "repeating-linear-gradient(0deg, hsl(var(--foreground)) 0 1px, transparent 1px 3px)",
          }}
        />
        <div className="max-h-[28rem] overflow-auto ba-rail">
          <table className={`min-w-full border-separate border-spacing-0 text-mono text-[11.5px] leading-[1.55] ${wrap ? "" : ""}`}>
            <tbody>
              {lines.map((line, i) => {
                const toks = tokenize(line);
                return (
                  <tr key={i} className="group">
                    <td className="sticky left-0 z-[1] w-10 select-none border-r border-divider-soft bg-background/70 px-2 py-0.5 text-right align-top text-[10px] text-muted-foreground/60 group-hover:text-foreground/70">
                      {i + 1}
                    </td>
                    <td className={`px-3 py-0.5 align-top ${wrap ? "whitespace-pre-wrap break-words" : "whitespace-pre"}`}>
                      {toks.length === 0 ? (
                        <span>&nbsp;</span>
                      ) : (
                        toks.map((t, j) => (
                          <span key={j} className={t.cls}>
                            {t.text}
                          </span>
                        ))
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-border bg-background/50 px-3 py-1.5 text-mono text-[10px] text-muted-foreground">
          <span>{lines.length.toLocaleString()} lines</span>
          <span>·</span>
          <span>{totalBytes.toLocaleString()} bytes</span>
          {errLines.length > 0 && (
            <>
              <span>·</span>
              <button
                onClick={() => setShowErr((s) => !s)}
                className="inline-flex items-center gap-1 rounded border border-destructive/40 bg-destructive/10 px-1.5 py-0.5 text-destructive hover:bg-destructive/15"
              >
                <ArrowDownToLine className={`h-3 w-3 transition-transform ${showErr ? "rotate-180" : ""}`} />
                stderr · {errLines.length} lines
              </button>
            </>
          )}
        </div>

        {showErr && errLines.length > 0 && (
          <div className="max-h-56 overflow-auto ba-rail border-t border-destructive/30 bg-destructive/[0.04] px-3 py-2 text-mono text-[11px] text-destructive/90">
            <pre className="whitespace-pre-wrap">{stderr}</pre>
          </div>
        )}
      </div>
    </div>
  );
}

function IconBtn({
  children,
  onClick,
  title,
  active,
  danger,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  title: string;
  active?: boolean;
  danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      title={title}
      aria-label={title}
      className={
        "grid h-6 w-6 place-items-center rounded border transition-colors " +
        (active
          ? "border-primary/50 bg-primary/15 text-primary"
          : danger
          ? "border-border text-muted-foreground hover:border-destructive/50 hover:text-destructive"
          : "border-border text-muted-foreground hover:border-primary/50 hover:text-primary")
      }
    >
      {children}
    </button>
  );
}
