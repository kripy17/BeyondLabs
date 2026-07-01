import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { ResultBanner, SectionBar, Panel, SendToRow, Chip, KeyFields, RiskScore, EvidenceCard, IocInventory, TwoColumnOutput, VerdictBanner, MetricGrid, CollapsibleSection } from "@/components/soc/Workspace";
import { ShieldAlert, Copy, ArrowRight, Database, Play, Sparkles, FileCode as FileCode2, Crosshair, Check, RotateCcw, ScrollText, FileSearch, Terminal, Download, Hash, ShieldCheck, TriangleAlert as AlertTriangle, Activity } from "lucide-react";

const FMT_ICONS = { sigma: ScrollText, yara: FileSearch, kql: Terminal } as const;

export const Route = createFileRoute("/detection")({ component: DetectionPage });

type Format = "sigma" | "yara" | "kql";

type Tpl = {
  rule: string;
  event: string;
  matcher: (event: string) => { hit: boolean; hits: string[] };
  technique: { id: string; name: string; tactic: string; platform: string; source: string };
  severity: "low" | "medium" | "high" | "critical";
};

const TEMPLATES: Record<Format, Tpl> = {
  sigma: {
    rule: `title: Suspicious PowerShell EncodedCommand
id: 6f1f0c20-1111-4444-8888-123456789abc
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: selection
tags:
  - attack.t1059.001
level: high`,
    event: `powershell.exe -NoP -EncodedCommand SQBFAFgA`,
    matcher: (e) => {
      const hits: string[] = [];
      if (/powershell\.exe/i.test(e)) hits.push("powershell.exe");
      if (/-EncodedCommand/i.test(e)) hits.push("-EncodedCommand");
      return { hit: hits.length === 2, hits };
    },
    technique: { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution", platform: "Windows", source: "Process creation (Sysmon 1, EID 4688)" },
    severity: "high",
  },
  yara: {
    rule: `rule Suspicious_PS_EncodedCommand {
  meta:
    author = "BeyondArch"
    reference = "T1059.001"
  strings:
    $a = "EncodedCommand" ascii wide nocase
    $b = "-NoP" ascii wide nocase
  condition:
    all of them
}`,
    event: `powershell.exe -NoP -EncodedCommand SQBFAFgA`,
    matcher: (e) => {
      const hits: string[] = [];
      if (/EncodedCommand/i.test(e)) hits.push("EncodedCommand");
      if (/-NoP/i.test(e)) hits.push("-NoP");
      return { hit: hits.length === 2, hits };
    },
    technique: { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution", platform: "Windows", source: "Strings / memory" },
    severity: "high",
  },
  kql: {
    rule: `DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any("EncodedCommand", "-enc ")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc`,
    event: `Timestamp=2026-06-25T10:42:13Z DeviceName=WS-014 AccountName=krish ProcessCommandLine="powershell.exe -NoP -EncodedCommand SQBFAFgA"`,
    matcher: (e) => {
      const hits: string[] = [];
      if (/powershell\.exe/i.test(e)) hits.push("powershell.exe");
      if (/EncodedCommand|-enc /i.test(e)) hits.push("EncodedCommand");
      return { hit: hits.length >= 2, hits };
    },
    technique: { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution", platform: "Windows / Defender XDR", source: "DeviceProcessEvents" },
    severity: "high",
  },
};

const SYNTAX: Record<Format, { kw: RegExp; str: RegExp; comment: RegExp }> = {
  sigma: { kw: /\b(title|id|status|logsource|product|category|detection|selection|condition|tags|level|description|author|references)\b/g, str: /'[^']*'|"[^"]*"/g, comment: /#.*$/gm },
  yara: { kw: /\b(rule|meta|strings|condition|ascii|wide|nocase|all|any|of|them|and|or|not)\b/g, str: /"[^"]*"/g, comment: /\/\/.*$/gm },
  kql: { kw: /\b(where|project|order by|desc|asc|has_any|has|contains|extend|summarize|count|by|let|datatable)\b/g, str: /"[^"]*"/g, comment: /\/\/.*$/gm },
};

function highlight(src: string, fmt: Format, matches: string[]) {
  const escape = (s: string) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]!));
  let html = escape(src);
  const s = SYNTAX[fmt];
  html = html.replace(s.comment, (m) => `<span class="text-muted-foreground italic">${m}</span>`);
  html = html.replace(s.str, (m) => `<span class="text-success">${m}</span>`);
  html = html.replace(s.kw, (m) => `<span class="text-primary">${m}</span>`);
  matches.forEach((m) => {
    const re = new RegExp(escape(m).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
    html = html.replace(re, (x) => `<mark class="rounded bg-warning/25 px-0.5 text-warning-foreground">${x}</mark>`);
  });
  return html;
}

function extractIocs(text: string): { ips: string[]; urls: string[]; hashes: string[] } {
  return {
    ips: Array.from(new Set(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [])),
    urls: Array.from(new Set(text.match(/https?:\/\/[^\s"']+/g) ?? [])),
    hashes: Array.from(new Set(text.match(/\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b/g) ?? [])),
  };
}

function genReport(tpl: Tpl, result: { hit: boolean; hits: string[] }, rule: string): string {
  return [
    `# Detection Rule Report`,
    `**Technique:** ${tpl.technique.id} — ${tpl.technique.name}`,
    `**Tactic:** ${tpl.technique.tactic}`,
    `**Format:** ${tpl.technique.platform}`,
    `**Severity:** ${tpl.severity}`,
    `**Verdict:** ${result.hit ? "MATCH" : "NO MATCH"}`,
    `**Tokens matched:** ${result.hits.join(", ") || "—"}`,
    "", "## Rule Body",
    rule,
    "", "## Event",
    tpl.event,
  ].join("\n");
}

function DetectionPage() {
  const [fmt, setFmt] = useState<Format>("sigma");
  const [rule, setRule] = useState(TEMPLATES.sigma.rule);
  const [event, setEvent] = useState(TEMPLATES.sigma.event);
  const [copied, setCopied] = useState(false);

  const tpl = TEMPLATES[fmt];
  const result = useMemo(() => tpl.matcher(event), [tpl, event]);

  const switchFmt = (f: Format) => { setFmt(f); setRule(TEMPLATES[f].rule); setEvent(TEMPLATES[f].event); };
  const reset = () => { setRule(tpl.rule); setEvent(tpl.event); };
  const copy = () => { navigator.clipboard.writeText(rule); setCopied(true); setTimeout(() => setCopied(false), 1200); };

  const ruleLines = rule.split("\n");
  const eventLines = event.split("\n");
  const iocs = useMemo(() => extractIocs(event), [event]);
  const score = result.hit ? (tpl.severity === "critical" ? 85 : tpl.severity === "high" ? 65 : tpl.severity === "medium" ? 40 : 20) : 0;

  return (
    <PageShell
      eyebrow="DETECTION / RULE EDITOR"
      title="Detection Editor"
      description="Compose Sigma · YARA · KQL detections and dry-run them against a candidate event — fully local, no SIEM hit."
      crumbs={[{ label: "Detection" }, { label: "Editor" }]}
    >
      <SectionBar id="IN" label="Intake · format & rule body" meta={`${ruleLines.length} lines · ${rule.length} chars`} />

      {/* Format selector with descriptive cards */}
      <div className="mb-3 grid gap-2 sm:grid-cols-3">
        {(["sigma", "yara", "kql"] as Format[]).map((f) => {
          const active = fmt === f;
          const desc = f === "sigma" ? "Vendor-neutral log rule" : f === "yara" ? "File / memory signature" : "Defender / Azure query";
          return (
            <button
              key={f}
              onClick={() => switchFmt(f)}
              className={
                "group relative flex items-center justify-between gap-3 overflow-hidden rounded-md border px-3 py-2 text-left transition-all " +
                (active ? "border-primary/60 bg-primary/10" : "border-border bg-card/40 hover:border-primary/30 hover:bg-card/70")
              }
            >
              <div className="flex items-center gap-2.5">
                <span className={"grid h-7 w-7 place-items-center rounded border " + (active ? "border-primary/60 bg-primary/20 text-primary" : "border-border/60 bg-background/60 text-muted-foreground")}>
                  {(() => { const Ic = FMT_ICONS[f]; return <Ic className="h-3.5 w-3.5" strokeWidth={2.25} />; })()}
                </span>
                <div>
                  <div className={"text-mono text-[11px] uppercase tracking-widest " + (active ? "text-primary" : "text-foreground/90")}>{f}</div>
                  <div className="text-[10px] text-muted-foreground">{desc}</div>
                </div>
              </div>
              {active && <Chip tone="primary">active</Chip>}
            </button>
          );
        })}
      </div>

      <div className="grid gap-3 lg:grid-cols-5">
        {/* Rule editor with line numbers + live syntax preview */}
        <Panel
          title={`rule · ${fmt}`}
          icon={FileCode2}
          meta={`${ruleLines.length} ln`}
          className="lg:col-span-3"
          actions={
            <>
              <button onClick={reset} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground"><RotateCcw className="h-3 w-3" /> reset</button>
              <button onClick={copy} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground">{copied ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> copy</>}</button>
            </>
          }
        >
          <div className="relative grid grid-cols-[2.5rem_1fr] overflow-hidden rounded border border-border/60 bg-background/60">
            <div aria-hidden className="select-none border-r border-border/40 bg-card/40 py-2 text-right">
              {ruleLines.map((_, i) => (
                <div key={i} className="px-2 text-mono text-[10.5px] leading-[1.5] text-muted-foreground/60">{i + 1}</div>
              ))}
            </div>
            <div className="relative">
              <pre
                aria-hidden
                className="pointer-events-none m-0 whitespace-pre-wrap break-words p-2 text-mono text-[12px] leading-[1.5] text-foreground/90"
                dangerouslySetInnerHTML={{ __html: highlight(rule, fmt, []) + "\n" }}
              />
              <textarea
                value={rule}
                onChange={(e) => setRule(e.target.value)}
                spellCheck={false}
                className="absolute inset-0 resize-none overflow-hidden bg-transparent p-2 text-mono text-[12px] leading-[1.5] text-transparent caret-primary outline-none"
                style={{ WebkitTextFillColor: "transparent" }}
              />
            </div>
          </div>
        </Panel>

        {/* Simulation pane */}
        <Panel
          title="simulate · event"
          icon={Sparkles}
          meta={`${eventLines.length} ln`}
          className="lg:col-span-2"
          actions={<Chip tone={result.hit ? "destructive" : "default"}>{result.hit ? "MATCH" : "no match"}</Chip>}
        >
          <div className="relative overflow-hidden rounded border border-border/60 bg-background/60">
            <pre
              aria-hidden
              className="pointer-events-none m-0 max-h-40 whitespace-pre-wrap break-words p-2 text-mono text-[11.5px] leading-[1.5] text-foreground/90"
              dangerouslySetInnerHTML={{ __html: highlight(event, fmt, result.hits) + "\n" }}
            />
            <textarea
              value={event}
              onChange={(e) => setEvent(e.target.value)}
              spellCheck={false}
              rows={Math.max(4, eventLines.length)}
              className="absolute inset-0 resize-none bg-transparent p-2 text-mono text-[11.5px] leading-[1.5] text-transparent caret-primary outline-none"
              style={{ WebkitTextFillColor: "transparent" }}
            />
          </div>

          <div className="mt-3 space-y-2">
            <div className="flex items-center justify-between text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              <span>token coverage</span>
              <span>{result.hits.length} / 2 conditions</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-border/40">
              <div
                className={"h-full transition-all " + (result.hit ? "bg-destructive" : "bg-warning")}
                style={{ width: `${Math.min(100, (result.hits.length / 2) * 100)}%` }}
              />
            </div>
            <div className="flex flex-wrap gap-1.5 pt-1">
              {(result.hits.length ? result.hits : ["—"]).map((h) => (
                <span key={h} className="inline-flex items-center gap-1 rounded border border-warning/40 bg-warning/10 px-1.5 py-0.5 text-mono text-[10px] text-warning"><Crosshair className="h-2.5 w-2.5" /> {h}</span>
              ))}
            </div>
            <button className="mt-1 inline-flex w-full items-center justify-center gap-1 rounded border border-primary/50 bg-primary/10 px-2.5 py-1.5 text-mono text-[10.5px] uppercase tracking-widest text-primary hover:bg-primary/20">
              <Play className="h-3 w-3" /> evaluate
            </button>
          </div>
        </Panel>
      </div>

      <SectionBar id="OT" label="Output · verdict & mapping" meta={result.hit ? "rule would fire" : "rule does not match"} />

      <div className="space-y-5">
        {/* Verdict Banner */}
        <VerdictBanner
          verdict={result.hit ? "Rule matches event" : "No match"}
          tone={result.hit ? "warning" : "success"}
          icon={result.hit ? AlertTriangle : ShieldCheck}
          score={`${score}/100`}
          details={[
            result.hit ? `${result.hits.length} token(s): ${result.hits.join(", ")}` : "",
            `${fmt.toUpperCase()} · ${tpl.severity} severity`,
            tpl.technique.id,
          ].filter(Boolean)}
        />

        {/* Metrics */}
        <MetricGrid
          columns={4}
          metrics={[
            { label: "Format", value: fmt.toUpperCase(), tone: "primary", icon: FileCode2 },
            { label: "Verdict", value: result.hit ? "MATCH" : "NO MATCH", tone: result.hit ? "destructive" : "success" },
            { label: "MITRE", value: tpl.technique.id, tone: "warning", icon: Crosshair },
            { label: "Severity", value: tpl.severity, tone: tpl.severity === "critical" || tpl.severity === "high" ? "destructive" : tpl.severity === "medium" ? "warning" : "default" },
            { label: "Tokens", value: result.hits.length },
            { label: "Confidence", value: `${score}%`, tone: score >= 60 ? "warning" : "success", icon: Activity },
            { label: "Platform", value: tpl.technique.platform.split("/")[0] },
            { label: "Tactic", value: tpl.technique.tactic },
          ]}
        />

        <RiskScore
          score={score}
          label="Detection Confidence"
          confidence={score < 20 ? "low" : score < 50 ? "moderate" : score < 80 ? "high" : "very high"}
          tone={score < 20 ? "success" : score < 60 ? "warning" : "destructive"}
        />

        {/* MITRE Mapping + Evidence side-by-side */}
        <TwoColumnOutput
          ratio="1:1"
          left={
            <Panel title="MITRE ATT&CK mapping" icon={Crosshair}>
              <KeyFields items={[
                { label: "Technique", value: `${tpl.technique.id} — ${tpl.technique.name}`, tone: "primary" },
                { label: "Tactic", value: tpl.technique.tactic },
                { label: "Platform", value: tpl.technique.platform },
                { label: "Data source", value: tpl.technique.source },
              ]} />
            </Panel>
          }
          right={
            (result.hit && result.hits.length > 0) ? (
              <EvidenceCard severity={tpl.severity === "high" || tpl.severity === "critical" ? "warning" : "info"} title="Detection signal" reason={`${result.hits.length} token(s) matched in event: ${result.hits.join(", ")}`} action="Deploy rule to SIEM/EDR for validation against production traffic." limitation="Static matcher — no false-positive rate data available." />
            ) : (
              <EvidenceCard severity="info" title="No match" reason="Rule does not match the supplied event. Revise rule logic or check event format." action="Adjust detection selection or collect a more representative event sample." limitation="Static evaluation only." />
            )
          }
        />

        {/* IOCs in event */}
        <Panel title="IOCs in event" icon={Hash} meta={`${iocs.ips.length + iocs.urls.length + iocs.hashes.length} total`}>
          <KeyFields items={[
            { label: "IPs", value: iocs.ips.length ? iocs.ips.join(", ") : "—" },
            { label: "URLs", value: iocs.urls.length ? iocs.urls.join(", ") : "—" },
            { label: "Hashes", value: iocs.hashes.length ? iocs.hashes.join(", ") : "—" },
          ]} />
        </Panel>

        {/* IOC Inventory */}
        <CollapsibleSection id="IO" label="IOC Inventory" meta={`${iocs.ips.length + iocs.urls.length + iocs.hashes.length} indicators`} icon={Database}>
          <IocInventory groups={[
            { kind: "IPv4", items: iocs.ips, tone: "info" },
            { kind: "URL", items: iocs.urls, tone: "warning" },
            { kind: "Hash", items: iocs.hashes, tone: "warning" },
          ]} onSendTo={() => {}} />
        </CollapsibleSection>

        {/* Report */}
        <Panel title="Report (markdown)" collapsible defaultCollapsed actions={
          <div className="flex items-center gap-1">
            <button onClick={() => { const md = genReport(tpl, result, rule); navigator.clipboard.writeText(md); }} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground"><Copy className="h-3 w-3" /> copy</button>
            <button onClick={() => { const md = genReport(tpl, result, rule); const blob = new Blob([md], { type: "text/markdown" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `detection-${tpl.technique.id}-${Date.now()}.md`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> md</button>
          </div>
        }>
          <pre className="max-h-48 overflow-auto rounded bg-background/60 p-3 text-mono text-[11px] text-foreground/90">{genReport(tpl, result, rule)}</pre>
        </Panel>

        <SendToRow targets={[
          { label: "MITRE Coverage", to: "/mitre", icon: ArrowRight },
          { label: "SOC Guide", to: "/guide", icon: ShieldAlert },
          { label: "Case Notebook", to: "/case", icon: Database },
        ]} />
      </div>
    </PageShell>
  );
}
