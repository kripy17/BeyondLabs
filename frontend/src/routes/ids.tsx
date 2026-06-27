import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { StatusBar, SectionBar, Panel, SendToRow, Chip, KeyFields, ResultBanner, RiskScore, EvidenceCard, IocInventory, VerdictBanner, MetricGrid, CollapsibleSection } from "@/components/soc/Workspace";
import { Shield, ArrowRight, Copy, Database, Check, Download, ShieldCheck, TriangleAlert as AlertTriangle, Activity } from "lucide-react";

export const Route = createFileRoute("/ids")({ component: IdsPage });

const TEMPLATES = {
  sqli:         { msg: "ET WEB_SERVER Possible SQLi in URI",          content: "union select",   flow: "to_server,established", classtype: "web-application-attack", port: "any"  as string | number, mitre: "T1190" },
  ssh_brute:    { msg: "Multiple SSH failed logins",                  content: "Failed password",flow: "to_server",             classtype: "attempted-recon",        port: 22,                            mitre: "T1110" },
  outbound4444: { msg: "Outbound connection to non-standard port 4444", content: "",             flow: "to_server,established", classtype: "trojan-activity",        port: 4444,                          mitre: "T1571" },
  beacon:       { msg: "Periodic beacon-like cadence",                content: "POST /pulse",    flow: "to_server,established", classtype: "command-and-control",    port: "any",                         mitre: "T1071" },
} as const;
type Key = keyof typeof TEMPLATES;

type Tok = { k: "kw" | "addr" | "op" | "port" | "str" | "field" | "punct" | "txt"; v: string };
function tokenize(rule: string): Tok[] {
  const out: Tok[] = [];
  const re = /(alert|tcp|udp|http|tls|icmp|any)|("(?:[^"\\]|\\.)*")|(->|<-|<>)|(\b\d+\b)|(\$\w+)|(\b(?:msg|content|nocase|flow|classtype|sid|rev|reference|threshold|pcre|http\.\w+|metadata):)|([;()])|(\s+)|(.)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rule))) {
    if      (m[1]) out.push({ k: "kw",    v: m[1] });
    else if (m[2]) out.push({ k: "str",   v: m[2] });
    else if (m[3]) out.push({ k: "op",    v: m[3] });
    else if (m[4]) out.push({ k: "port",  v: m[4] });
    else if (m[5]) out.push({ k: "addr",  v: m[5] });
    else if (m[6]) out.push({ k: "field", v: m[6] });
    else if (m[7]) out.push({ k: "punct", v: m[7] });
    else if (m[8]) out.push({ k: "txt",   v: m[8] });
    else if (m[9]) out.push({ k: "txt",   v: m[9] });
  }
  return out;
}
const TOK_CLASS: Record<Tok["k"], string> = {
  kw:    "text-primary font-semibold",
  str:   "text-success",
  op:    "text-warning",
  port:  "text-accent",
  addr:  "text-info",
  field: "text-[color:var(--chart-4,var(--accent))]",
  punct: "text-muted-foreground",
  txt:   "text-foreground/90",
};

const MITRE_MAP: Record<string, { name: string; tactic: string }> = {
  T1190: { name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  T1110: { name: "Brute Force", tactic: "Credential Access" },
  T1571: { name: "Non-Standard Port", tactic: "Command and Control" },
  T1071: { name: "Application Layer Protocol", tactic: "Command and Control" },
};

function genReport(templateKey: Key, rule: string, sid: string): string {
  const t = TEMPLATES[templateKey];
  const m = MITRE_MAP[t.mitre];
  return [
    `# IDS Rule Report`,
    `**Template:** ${templateKey}`,
    `**Message:** ${t.msg}`,
    `**MITRE:** ${t.mitre} — ${m?.name ?? ""}`,
    `**Tactic:** ${m?.tactic ?? ""}`,
    `**SID:** ${sid}`,
    "", "## Rule Body",
    rule,
  ].join("\n");
}

function IdsPage() {
  const [key, setKey] = useState<Key>("sqli");
  const [sid, setSid] = useState("2000001");
  const [src, setSrc] = useState("$EXTERNAL_NET");
  const [dst, setDst] = useState("$HOME_NET");
  const [proto, setProto] = useState<"tcp" | "udp" | "http">("tcp");
  const [copied, setCopied] = useState(false);
  const t = TEMPLATES[key];

  const rule = useMemo(
    () => `alert ${proto} ${src} any -> ${dst} ${t.port} (msg:"${t.msg}"; ${t.content ? `content:"${t.content}"; nocase; ` : ""}flow:${t.flow}; classtype:${t.classtype}; metadata:mitre ${t.mitre}; sid:${sid}; rev:1;)`,
    [proto, src, dst, t, sid]
  );
  const toks = useMemo(() => tokenize(rule), [rule]);

  const copy = () => { navigator.clipboard.writeText(rule); setCopied(true); setTimeout(() => setCopied(false), 1200); };

  const issues: { tone: "warning" | "destructive" | "success"; label: string; msg: string }[] = [];
  if (!/^\d+$/.test(sid))                 issues.push({ tone: "destructive", label: "sid",     msg: "SID must be numeric." });
  if (+sid < 1_000_000)                    issues.push({ tone: "warning",     label: "sid",     msg: "Custom SIDs should be ≥ 1,000,000 to avoid Talos/ET ranges." });
  if (!t.content)                          issues.push({ tone: "warning",     label: "content", msg: "Rule has no content match; volume could be high." });
  if (src === dst)                         issues.push({ tone: "warning",     label: "vars",    msg: "Source and destination variables are identical." });
  if (issues.length === 0)                 issues.push({ tone: "success",     label: "lint",    msg: "Looks structurally OK." });

  const severity = t.mitre === "T1190" || t.mitre === "T1110" ? "high" : "medium";
  const mitreMeta = MITRE_MAP[t.mitre];
  const score = severity === "high" ? 60 : 40;

  return (
    <PageShell
      eyebrow="TOOLS / IDS"
      title="IDS Rule Builder"
      description="Compose Suricata-style alert rules from a template, lint the structure, and copy."
      crumbs={[{ label: "Tools" }, { label: "IDS Builder" }]}
    >
      <SectionBar id="IN" label="Intake · template" />
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        {(Object.keys(TEMPLATES) as Key[]).map((k) => {
          const sel = key === k;
          return (
            <button key={k} onClick={() => setKey(k)} className={"rounded-md border p-3 text-left transition " + (sel ? "border-primary bg-primary/5" : "border-border bg-card/40 hover:border-primary/40")}>
              <div className="flex items-center justify-between">
                <span className="text-mono text-[11px] uppercase tracking-widest text-foreground">{k}</span>
                <Chip tone="primary">{TEMPLATES[k].mitre}</Chip>
              </div>
              <p className="mt-1 text-[11px] text-muted-foreground">{TEMPLATES[k].msg}</p>
              <div className="mt-1.5 flex flex-wrap gap-1 text-mono text-[9.5px] text-muted-foreground">
                <span className="rounded border border-border/60 px-1">{TEMPLATES[k].classtype}</span>
                <span className="rounded border border-border/60 px-1">port {TEMPLATES[k].port}</span>
              </div>
            </button>
          );
        })}
      </div>

      <SectionBar id="IN" label="Intake · parameters" />
      <Panel title="Rule parameters" icon={Shield}>
        <div className="grid gap-2 sm:grid-cols-4">
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">proto
            <select value={proto} onChange={(e) => setProto(e.target.value as any)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground">
              <option value="tcp">tcp</option><option value="udp">udp</option><option value="http">http</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">sid
            <input value={sid} onChange={(e) => setSid(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" />
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">source
            <input value={src} onChange={(e) => setSrc(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" />
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">destination
            <input value={dst} onChange={(e) => setDst(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" />
          </label>
        </div>
      </Panel>

      <StatusBar stats={[
        { label: "Template",  value: key,                 tone: "primary" },
        { label: "Proto",     value: proto },
        { label: "Classtype", value: t.classtype },
        { label: "MITRE",     value: t.mitre,             tone: "warning" },
      ]} />

      <SectionBar id="OT" label="Output · rule" />

      <div className="space-y-5">
        {/* Verdict Banner */}
        <VerdictBanner
          verdict={t.msg}
          tone={severity === "high" ? "warning" : "success"}
          icon={severity === "high" ? AlertTriangle : ShieldCheck}
          score={`${score}/100`}
          details={[
            `Template: ${key} · Suricata-style`,
            `MITRE ${t.mitre} · ${t.classtype}`,
            issues.some((i) => i.tone === "destructive") ? "Lint errors detected" : undefined,
          ].filter(Boolean)}
        />

        {/* Metrics */}
        <MetricGrid
          columns={4}
          metrics={[
            { label: "Proto", value: proto.toUpperCase(), tone: "primary" },
            { label: "Port", value: String(t.port) },
            { label: "MITRE", value: t.mitre, tone: "warning" },
            { label: "Severity", value: severity, tone: severity === "high" ? "destructive" : "success", icon: Activity },
            { label: "SID", value: sid },
            { label: "Classtype", value: t.classtype },
            { label: "Lint", value: issues.some((i) => i.tone === "destructive") ? "FAIL" : issues.some((i) => i.tone === "warning") ? "WARN" : "OK", tone: issues.some((i) => i.tone === "destructive") ? "destructive" : issues.some((i) => i.tone === "warning") ? "warning" : "success" },
            { label: "Template", value: key, tone: "primary" },
          ]}
        />

        <RiskScore score={score} label="Rule Severity" confidence={severity === "high" ? "very high" : "moderate"} tone={severity === "high" ? "warning" : "success"} />

        {/* Generated Rule */}
        <Panel title="Generated rule" icon={Shield} actions={
          <div className="flex items-center gap-1">
            <button onClick={copy} className="inline-flex items-center gap-1 rounded border border-border bg-background/60 px-2 py-0.5 text-mono text-[10px] uppercase hover:border-primary/40 hover:text-primary">
              {copied ? <><Check className="h-3 w-3" /> copied</> : <><Copy className="h-3 w-3" /> copy</>}
            </button>
            <button onClick={() => { const md = genReport(key, rule, sid); const blob = new Blob([md], { type: "text/markdown" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `ids-${key}-${sid}.md`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> md</button>
          </div>
        }>
          <pre className="overflow-x-auto rounded border border-border/50 bg-background/60 p-3 text-mono text-[12.5px] leading-relaxed">
            {toks.map((tk, i) => <span key={i} className={TOK_CLASS[tk.k]}>{tk.v}</span>)}
          </pre>
        </Panel>

        {/* Lint + Summary side-by-side */}
        <div className="grid gap-3 lg:grid-cols-[1.5fr_1fr]">
          <Panel title="Lint" className="lg:col-span-1">
            <ul className="space-y-1">
              {issues.map((it, i) => (
                <li key={i} className="flex items-start gap-2 rounded border border-border/50 bg-background/30 px-2 py-1.5">
                  <Chip tone={it.tone}>{it.label}</Chip>
                  <span className="text-[11.5px] text-foreground/85">{it.msg}</span>
                </li>
              ))}
            </ul>
          </Panel>
          <Panel title="Summary">
            <KeyFields items={[
              { label: "Message",   value: t.msg,       tone: "primary" },
              { label: "Classtype", value: t.classtype },
              { label: "Flow",      value: t.flow },
              { label: "Content",   value: t.content || "—" },
              { label: "MITRE",     value: t.mitre,     tone: "warning" },
              { label: "SID · rev", value: `${sid} · 1` },
            ]} />
          </Panel>
        </div>

        {/* Evidence Cards */}
        <CollapsibleSection id="EV" label="Evidence Cards" meta="2 insights" icon={AlertTriangle}>
          <div className="grid gap-3 md:grid-cols-2">
            <EvidenceCard severity="warning" title={t.msg} reason={`${t.classtype} · port ${t.port} · MITRE ${t.mitre}`} action="Deploy to testing sensor before production. Tune threshold to reduce FP." limitation="Template-based — adjust content match for your environment." />
            {mitreMeta && (
              <EvidenceCard severity="info" title={`MITRE ${t.mitre} — ${mitreMeta.name}`} reason={`Tactic: ${mitreMeta.tactic}. Coverage: enabled via this IDS rule.`} action="Cross-reference with detection editor for additional coverage layers." limitation="One rule per technique — recommend multiple detection layers." />
            )}
          </div>
        </CollapsibleSection>

        {/* IOC Inventory */}
        <CollapsibleSection id="IO" label="IOC Inventory" meta="3 items" icon={Database}>
          <IocInventory groups={[
            { kind: "MITRE ID", items: [t.mitre], tone: "warning" },
            { kind: "Classtype", items: [t.classtype], tone: "info" },
            { kind: "Content match", items: [t.content || "—"], tone: t.content ? "warning" : "default" },
          ]} onSendTo={() => {}} />
        </CollapsibleSection>
      </div>

      <SendToRow targets={[
        { label: "Detection & MITRE", to: "/detection", icon: ArrowRight },
        { label: "MITRE Coverage",    to: "/mitre",     icon: ArrowRight },
        { label: "Case Notebook",     to: "/case",      icon: Database },
      ]} />
    </PageShell>
  );
}
