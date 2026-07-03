import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { SectionBar, Panel, SendToRow, Chip, KeyFields, EvidenceCard, VerdictBanner, MetricGrid, CollapsibleSection } from "@/components/soc/Workspace";
import { Shield, ArrowRight, Copy, Database, Check, Download, ShieldCheck, TriangleAlert as AlertTriangle, Activity, Loader2, Scan } from "lucide-react";
import { getIdsRuleTemplates, buildIdsRule, explainIdsRule } from "@/api/detection";

export const Route = createFileRoute("/ids")({ component: IdsPage });

type Tok = { k: "kw" | "addr" | "op" | "port" | "str" | "field" | "punct" | "txt"; v: string };

type BuildRuleResult = {
  rule: string;
  engine: string;
  rule_type: string;
  warnings?: string[];
  engine_notes?: string[];
  explanation?: string[];
};

type ExplainRuleResult = {
  parsed: boolean;
  error?: string;
  parsed_rule?: { action?: string; protocol?: string; src_ip?: string; src_port?: string; dst_ip?: string; dst_port?: string };
  warnings?: string[];
  explanation?: string[];
};

type RuleTemplateData = {
  engine?: string; action?: string; protocol?: string; src_ip?: string; src_port?: string;
  direction?: string; dst_ip?: string; dst_port?: string; msg?: string; content?: string;
  pcre?: string; flow?: string; classtype?: string; priority?: string; sid?: string;
  rev?: string; nocase?: boolean; http_uri?: boolean; http_header?: boolean;
};
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

function IdsPage() {
  const [templates, setTemplates] = useState<Record<string, { data: RuleTemplateData }> | null>(null);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [buildLoading, setBuildLoading] = useState(false);

  const [engine, setEngine] = useState("snort");
  const [action, setAction] = useState("alert");
  const [protocol, setProtocol] = useState("tcp");
  const [srcIp, setSrcIp] = useState("$EXTERNAL_NET");
  const [srcPort, setSrcPort] = useState("any");
  const [direction, setDirection] = useState("->");
  const [dstIp, setDstIp] = useState("$HOME_NET");
  const [dstPort, setDstPort] = useState("80");
  const [msg, setMsg] = useState("");
  const [content, setContent] = useState("");
  const [pcre, setPcre] = useState("");
  const [flow, setFlow] = useState("to_server,established");
  const [classtype, setClasstype] = useState("trojan-activity");
  const [priority, setPriority] = useState("2");
  const [sid, setSid] = useState("2000001");
  const [rev, setRev] = useState("1");
  const [extraOptions, setExtraOptions] = useState("");
  const [nocase, setNocase] = useState(true);
  const [httpUri, setHttpUri] = useState(false);
  const [httpHeader, setHttpHeader] = useState(false);

  const [result, setResult] = useState<BuildRuleResult | null>(null);
  const [explainResult, setExplainResult] = useState<ExplainRuleResult | null>(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getIdsRuleTemplates()
      .then((data) => { setTemplates(data as Record<string, { data: RuleTemplateData }>); setSelectedKey(Object.keys(data as Record<string, { data: RuleTemplateData }>)[0] ?? null); })
      .catch(() => { setTemplates({}); })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (templates && selectedKey && templates[selectedKey]) {
      const t = templates[selectedKey].data;
      setEngine(t.engine ?? "snort");
      setAction(t.action ?? "alert");
      setProtocol(t.protocol ?? "tcp");
      setSrcIp(t.src_ip ?? "$EXTERNAL_NET");
      setSrcPort(t.src_port ?? "any");
      setDirection(t.direction ?? "->");
      setDstIp(t.dst_ip ?? "$HOME_NET");
      setDstPort(String(t.dst_port ?? "80"));
      setMsg(t.msg ?? "");
      setContent(t.content ?? "");
      setPcre(t.pcre ?? "");
      setFlow(t.flow ?? "");
      setClasstype(t.classtype ?? "trojan-activity");
      setPriority(t.priority ?? "2");
      setSid(t.sid ?? "2000001");
      setRev(t.rev ?? "1");
      setNocase(t.nocase ?? false);
      setHttpUri(t.http_uri ?? false);
      setHttpHeader(t.http_header ?? false);
      setExtraOptions("");
      setResult(null);
      setExplainResult(null);
      setError(null);
    }
  }, [templates, selectedKey]);

  const handleBuild = async () => {
    setBuildLoading(true);
    setError(null);
    setExplainResult(null);
    try {
      const res = await buildIdsRule({
        engine, action, protocol,
        src_ip: srcIp, src_port: srcPort, direction, dst_ip: dstIp, dst_port: dstPort,
        msg, content, pcre, flow, classtype, priority, sid, rev,
        extra_options: extraOptions, nocase, http_uri: httpUri, http_header: httpHeader,
      }) as BuildRuleResult;
      setResult(res);
    } catch (e: any) {
      setError(e?.message || "Build failed");
    } finally {
      setBuildLoading(false);
    }
  };

  const handleExplain = async () => {
    if (!result?.rule) return;
    setExplainLoading(true);
    setExplainResult(null);
    try {
      const res = await explainIdsRule(result.rule) as ExplainRuleResult;
      setExplainResult(res);
    } catch (e: any) {
      setExplainResult({ parsed: false, error: e?.message || "Explain failed" });
    } finally {
      setExplainLoading(false);
    }
  };

  const copy = () => { if (result?.rule) { navigator.clipboard.writeText(result.rule); setCopied(true); setTimeout(() => setCopied(false), 1200); } };

  const templateKeys = templates ? Object.keys(templates) : [];
  const templateList = templateKeys.map((k) => ({ key: k, ...templates![k] }));
  const toks = useMemo(() => result?.rule ? tokenize(result.rule) : [], [result?.rule]);

  return (
    <PageShell
      eyebrow="TOOLS / IDS"
      title="IDS Rule Builder"
      description="Compose Snort / Suricata alert rules using the backend rule builder, then validate and explain."
      crumbs={[{ label: "Tools" }, { label: "IDS Builder" }]}
    >
      <SectionBar id="IN" label="Intake · template" />
      {loading ? (
        <div className="flex items-center gap-2 py-4 text-mono text-[11px] text-muted-foreground">
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> loading templates…
        </div>
      ) : (
        <div className="grid gap-2 grid-cols-2 grid-cols-4">
          {templateList.map((t) => {
            const sel = selectedKey === t.key;
            return (
              <button key={t.key} onClick={() => setSelectedKey(t.key)} className={"rounded-md border p-3 text-left transition " + (sel ? "border-primary bg-primary/5" : "border-border bg-card/40 hover:border-primary/40")}>
                <div className="flex items-center justify-between">
                  <span className="text-mono text-[11px] uppercase tracking-widest text-foreground">{t.data?.msg || t.key}</span>
                  {t.data?.sid && <Chip tone="primary">SID {t.data.sid}</Chip>}
                </div>
                <p className="mt-1 text-[11px] text-muted-foreground">{t.data?.classtype || ""} · port {t.data?.dst_port || "any"}</p>
              </button>
            );
          })}
        </div>
      )}

      <SectionBar id="PR" label="Parameters" />
      <Panel title="Rule parameters" icon={Shield}>
        <div className="grid gap-2 grid-cols-2 grid-cols-4">
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">engine
            <select value={engine} onChange={(e) => setEngine(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground">
              <option value="snort">snort</option><option value="suricata">suricata</option><option value="generic">generic</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">action
            <select value={action} onChange={(e) => setAction(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground">
              <option value="alert">alert</option><option value="log">log</option><option value="pass">pass</option><option value="drop">drop</option><option value="reject">reject</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">protocol
            <select value={protocol} onChange={(e) => setProtocol(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground">
              <option value="tcp">tcp</option><option value="udp">udp</option><option value="icmp">icmp</option><option value="http">http</option><option value="ip">ip</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">direction
            <select value={direction} onChange={(e) => setDirection(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground">
              <option value="->">-&gt;</option><option value="<>">&lt;&gt;</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">src ip
            <input value={srcIp} onChange={(e) => setSrcIp(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" />
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">src port
            <input value={srcPort} onChange={(e) => setSrcPort(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" />
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">dst ip
            <input value={dstIp} onChange={(e) => setDstIp(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" />
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">dst port
            <input value={dstPort} onChange={(e) => setDstPort(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" />
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">SID
            <input value={sid} onChange={(e) => setSid(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" />
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">rev
            <input value={rev} onChange={(e) => setRev(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" />
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">priority
            <input value={priority} onChange={(e) => setPriority(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" />
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">classtype
            <input value={classtype} onChange={(e) => setClasstype(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" />
          </label>
        </div>
        <div className="mt-2 grid gap-2 grid-cols-2">
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">msg
            <input value={msg} onChange={(e) => setMsg(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" />
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">flow
            <input value={flow} onChange={(e) => setFlow(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" placeholder="to_server,established" />
          </label>
        </div>
        <div className="mt-2 grid gap-2 grid-cols-2">
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">content match
            <input value={content} onChange={(e) => setContent(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" placeholder="literal string to match" />
          </label>
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">PCRE (optional)
            <input value={pcre} onChange={(e) => setPcre(e.target.value)} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" placeholder="/regex/i" />
          </label>
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-4">
          <label className="flex items-center gap-1.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            <input type="checkbox" checked={nocase} onChange={(e) => setNocase(e.target.checked)} className="rounded border-border" /> nocase
          </label>
          <label className="flex items-center gap-1.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            <input type="checkbox" checked={httpUri} onChange={(e) => setHttpUri(e.target.checked)} className="rounded border-border" /> http_uri
          </label>
          <label className="flex items-center gap-1.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            <input type="checkbox" checked={httpHeader} onChange={(e) => setHttpHeader(e.target.checked)} className="rounded border-border" /> http_header
          </label>
        </div>
        <div className="mt-2">
          <label className="flex flex-col gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">extra options (one per line)
            <textarea value={extraOptions} onChange={(e) => setExtraOptions(e.target.value)} rows={2} className="rounded border border-border bg-background/60 px-2 py-1 text-mono text-[12px] text-foreground" placeholder="threshold: type both, count 5, seconds 60;" />
          </label>
        </div>
        <div className="mt-3 flex items-center gap-2">
          <button
            onClick={handleBuild}
            disabled={buildLoading}
            className="inline-flex h-8 items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-3 text-mono text-[10.5px] uppercase tracking-widest text-primary hover:bg-primary/20 disabled:opacity-40"
          >
            {buildLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Shield className="h-3 w-3" />}
            {buildLoading ? "building..." : "build rule"}
          </button>
          {result && !explainResult && (
            <button onClick={handleExplain} disabled={explainLoading} className="inline-flex h-8 items-center gap-1.5 rounded border border-primary/40 bg-background/60 px-3 text-mono text-[10.5px] uppercase tracking-widest text-muted-foreground hover:text-primary disabled:opacity-40">
              {explainLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Scan className="h-3 w-3" />}
              {explainLoading ? "analysing..." : "explain"}
            </button>
          )}
        </div>
        {error && <p className="mt-2 text-mono text-[11px] text-destructive">{error}</p>}
      </Panel>

      {result && (
        <>
          <SectionBar id="OT" label="Output · rule" meta={`${result.engine} · ${result.rule_type}`} />

          <div className="space-y-5">
            <VerdictBanner
              verdict={result.rule.split("(")[0]?.trim() || "IDS Rule"}
              tone={result.warnings && result.warnings.length > 0 ? "warning" : "success"}
              icon={result.warnings && result.warnings.length > 0 ? AlertTriangle : ShieldCheck}
              details={[
                `Engine: ${result.engine} · ${result.rule_type}`,
                result.warnings && result.warnings.length > 0 ? `${result.warnings.length} warning(s)` : "No warnings",
              ].filter(Boolean)}
            />

            <MetricGrid
              columns={4}
              metrics={[
                { label: "Engine", value: result.engine.toUpperCase(), tone: "primary" },
                { label: "Warnings", value: String(result.warnings?.length || 0), tone: result.warnings && result.warnings.length > 0 ? "warning" : "success", icon: Activity },
                { label: "SID", value: sid },
                { label: "State", value: "draft", tone: "default" },
              ]}
            />

            <Panel title="Generated rule" icon={Shield} actions={
              <div className="flex items-center gap-1">
                <button onClick={copy} className="inline-flex items-center gap-1 rounded border border-border bg-background/60 px-2 py-0.5 text-mono text-[10px] uppercase hover:border-primary/40 hover:text-primary">
                  {copied ? <><Check className="h-3 w-3" /> copied</> : <><Copy className="h-3 w-3" /> copy</>}
                </button>
                <button onClick={() => { const blob = new Blob([result.rule], { type: "text/plain" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `ids-${sid}.rules`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> file</button>
              </div>
            }>
              <pre className="overflow-x-auto rounded border border-border/50 bg-background/60 p-3 text-mono text-[12.5px] leading-relaxed">
                {toks.map((tk, i) => <span key={i} className={TOK_CLASS[tk.k]}>{tk.v}</span>)}
              </pre>
            </Panel>

            {result.warnings && result.warnings.length > 0 && (
              <Panel title="Warnings" icon={AlertTriangle}>
                <ul className="space-y-1">
                  {result.warnings.map((w: string, i: number) => (
                    <li key={i} className="flex items-start gap-2 rounded border border-border/50 bg-background/30 px-2 py-1.5">
                      <Chip tone="warning">warn</Chip>
                      <span className="text-[11.5px] text-foreground/85">{w}</span>
                    </li>
                  ))}
                </ul>
              </Panel>
            )}

            {result.engine_notes && result.engine_notes.length > 0 && (
              <Panel title="Engine notes" icon={Shield}>
                <ul className="space-y-1">
                  {result.engine_notes.map((n: string, i: number) => (
                    <li key={i} className="flex items-start gap-2 text-[11.5px] text-foreground/85">
                      <span className="mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary/50" />
                      {n}
                    </li>
                  ))}
                </ul>
              </Panel>
            )}

            {result.explanation && result.explanation.length > 0 && (
              <Panel title="Rule explanation" icon={Scan}>
                <ol className="space-y-2">
                  {result.explanation.map((e: string, i: number) => (
                    <li key={i} className="flex items-start gap-2 text-[11.5px] leading-relaxed text-foreground/85">
                      <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-primary/20 text-mono text-[9px] text-primary">{i + 1}</span>
                      {e}
                    </li>
                  ))}
                </ol>
              </Panel>
            )}

            {explainResult && (
              <Panel title="Explain result" icon={Scan}>
                {explainResult.parsed === false ? (
                  <p className="text-mono text-[11px] text-destructive">{explainResult.error || "Could not parse rule"}</p>
                ) : (
                  <div className="space-y-3">
                    <div className="grid gap-2 grid-cols-4">
                      <KeyFields items={[
                        { label: "Action", value: explainResult.parsed_rule?.action || "—" },
                        { label: "Protocol", value: explainResult.parsed_rule?.protocol || "—" },
                        { label: "Src", value: `${explainResult.parsed_rule?.src_ip || "—"}:${explainResult.parsed_rule?.src_port || "—"}` },
                        { label: "Dst", value: `${explainResult.parsed_rule?.dst_ip || "—"}:${explainResult.parsed_rule?.dst_port || "—"}` },
                      ]} />
                    </div>
                    {explainResult.warnings && explainResult.warnings.length > 0 && (
                      <div className="space-y-1">
                        {explainResult.warnings.map((w: string, i: number) => (
                          <div key={i} className="flex items-start gap-2 rounded border border-border/50 bg-background/30 px-2 py-1">
                            <Chip tone="warning">warn</Chip>
                            <span className="text-[11px] text-foreground/85">{w}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    {explainResult.explanation && explainResult.explanation.length > 0 && (
                      <div className="space-y-1.5">
                        {explainResult.explanation.map((e: string, i: number) => (
                          <p key={i} className="text-[11.5px] leading-relaxed text-foreground/80">{e}</p>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </Panel>
            )}

            <CollapsibleSection id="EV" label="Evidence" meta="limitations & next steps" icon={AlertTriangle}>
              <div className="grid gap-3 grid-cols-2">
                <EvidenceCard severity="warning" title="Generated rule — analyst review required" reason="Rule syntax matches the engine format but has not been validated against live traffic." action="Deploy to a test sensor first. Run suricata -T or snort -T to validate." limitation="Generated rules are starting points. Tune thresholds and content matches per your environment." />
                <EvidenceCard severity="info" title={`Engine: ${result.engine}`} reason={`Warnings: ${result.warnings?.length || 0}. Rule type: ${result.rule_type}`} action="Consider adding threshold, reference, and metadata options for production." limitation="No PCAP-level validation — false-positive rate is unknown." />
              </div>
            </CollapsibleSection>
          </div>
        </>
      )}

      <SendToRow targets={[
        { label: "Detection & MITRE", to: "/detection", icon: ArrowRight },
        { label: "MITRE Coverage",    to: "/mitre",     icon: ArrowRight },
        { label: "Case Notebook",     to: "/case",      icon: Database },
      ]} />
    </PageShell>
  );
}
