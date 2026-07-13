import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { SectionBar, Panel, SendToRow, Chip, IocInventory } from "@/components/soc";
import { KeyFields, EvidenceCard, TwoColumnOutput, VerdictBanner, MetricGrid, CollapsibleSection, Empty } from "@/components/output";
import { useOutputFilter, OutputFilterBar, OutputFilter } from "@/components/soc/OutputFilter";
import { ShieldAlert, Copy, ArrowRight, Database, Play, Sparkles, Crosshair, Check, RotateCcw, ScrollText, FileSearch, Terminal, Download, Hash, ShieldCheck, TriangleAlert as AlertTriangle, Loader2, Plus, FileCode as FileCode2, Wand2, Search, BookMarked, Trash2, Edit3, Save, X, ListFilter, Info } from "lucide-react";
import { mapMitre, generateSigmaRule, getIdsRuleTemplates, buildIdsRule } from "@/api/detection";
import { sendToCase } from "@/lib/handoff";
import { useLocker } from "@/lib/locker";
import { pushTimelineEvent } from "@/lib/timeline";
import { toast } from "sonner";

const FMT_ICONS = { sigma: ScrollText, yara: FileSearch, kql: Terminal } as const;

function autoDetectFmt(text: string): Format | null {
  if (/^title:/m.test(text) && /^detection:/m.test(text)) return "sigma";
  if (/^rule\s/m.test(text) && /^\s{2}meta:/m.test(text)) return "yara";
  if (/\b(where\s|project\b|summarize\b)/i.test(text)) return "kql";
  return null;
}

export const Route = createFileRoute("/detection")({ component: DetectionPage });

type Format = "sigma" | "yara" | "kql";

type Tpl = {
  rule: string;
  event: string;
  matcher: (event: string) => { hit: boolean; hits: string[] };
  technique: { id: string; name: string; tactic: string; platform: string; source: string };
  severity: "low" | "medium" | "high" | "critical";
};

type MitreMatch = { technique_id: string; technique: string; tactic: string; confidence: string; matched_keywords?: string[] };
type MitreResult = { total_matches: number; matches: MitreMatch[]; note?: string };
type GenResult = { sigma_yaml?: string; mitre_mapping?: { matches?: MitreMatch[] }; _show?: boolean };

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
    Image|endswith: '\\\\powershell.exe'
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
    author = "BeyondLabs"
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

/* ── Rule library types ── */
type SavedRule = { id: string; name: string; format: Format; rule: string; event: string; created: number; updated: number; tags: string[] };
const RULES_KEY = "ba.detection.rules.v2";

function loadRules(): SavedRule[] {
  try { return JSON.parse(localStorage.getItem(RULES_KEY) || "[]"); } catch { return []; }
}
function saveRules(r: SavedRule[]) {
  try { localStorage.setItem(RULES_KEY, JSON.stringify(r)); } catch {}
}
function genId() { return crypto.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`; }

/* ── Rule validation ── */
type ValidationMsg = { type: "error" | "warning"; msg: string; line?: number };
function validateRule(rule: string, fmt: Format): ValidationMsg[] {
  const out: ValidationMsg[] = [];
  if (!rule.trim()) { out.push({ type: "error", msg: "Rule body is empty" }); return out; }
  if (fmt === "sigma") {
    if (!/^[a-z]/m.test(rule)) out.push({ type: "error", msg: "Sigma rules should start with a top-level YAML key" });
    if (!/title:\s*\S/.test(rule)) out.push({ type: "error", msg: "Missing required field: title" });
    if (!/detection:/m.test(rule)) out.push({ type: "error", msg: "Missing required section: detection" });
    if (!/condition:\s*\S/.test(rule)) out.push({ type: "error", msg: "Missing required field: condition" });
    if (!/logsource:/m.test(rule)) out.push({ type: "warning", msg: "Missing logsource section — rule may be hard to deploy" });
    if (!/level:\s*\S/.test(rule)) out.push({ type: "warning", msg: "Missing level (severity) field" });
    if (/id:\s*\S/.test(rule) && !/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(rule)) out.push({ type: "warning", msg: "id does not look like a UUID" });
  } else if (fmt === "yara") {
    if (!/^\s*rule\s+\w+/m.test(rule)) out.push({ type: "error", msg: "YARA rule must start with 'rule <name>'" });
    if (!/condition:/m.test(rule)) out.push({ type: "error", msg: "Missing required section: condition" });
    if (!/strings:/m.test(rule)) out.push({ type: "warning", msg: "No strings section — rule may never match" });
    if (/^\s*\$\w+\s*=\s*"[^"]*"\s*$/m.test(rule) === false && /strings:/m.test(rule)) out.push({ type: "warning", msg: "Strings section exists but no valid string definitions found" });
  } else if (fmt === "kql") {
    if (!/\|/.test(rule)) out.push({ type: "warning", msg: "KQL query has no pipe operators — likely incomplete" });
    if (!/where\s/i.test(rule)) out.push({ type: "warning", msg: "No 'where' clause — query returns all rows" });
    if (!/project\s/i.test(rule)) out.push({ type: "warning", msg: "No 'project' clause — consider limiting columns" });
  }
  return out;
}

/* ── Rule structure analysis ── */
type RuleField = { key: string; value: string };
function analyzeRule(rule: string, fmt: Format): RuleField[] {
  const fields: RuleField[] = [];
  if (fmt === "sigma") {
    const mTitle = rule.match(/^title:\s*(.+)$/m);
    if (mTitle) fields.push({ key: "title", value: mTitle[1] });
    const mId = rule.match(/^id:\s*(.+)$/m);
    if (mId) fields.push({ key: "id", value: mId[1] });
    const mStatus = rule.match(/^status:\s*(.+)$/m);
    if (mStatus) fields.push({ key: "status", value: mStatus[1] });
    const mLevel = rule.match(/^level:\s*(.+)$/m);
    if (mLevel) fields.push({ key: "level", value: mLevel[1] });
    const mProduct = rule.match(/product:\s*(.+)$/m);
    if (mProduct) fields.push({ key: "logsource.product", value: mProduct[1] });
    const mCategory = rule.match(/category:\s*(.+)$/m);
    if (mCategory) fields.push({ key: "logsource.category", value: mCategory[1] });
    const mCondition = rule.match(/condition:\s*(.+)$/m);
    if (mCondition) fields.push({ key: "condition", value: mCondition[1] });
    const tagsMatch = rule.match(/tags:\s*\n((?:\s+- .+\n?)*)/);
    if (tagsMatch) {
      const tags = tagsMatch[1].match(/- (.+)/g)?.map(t => t.replace(/^-\s*/, "").trim()) ?? [];
      fields.push({ key: "tags", value: tags.join(", ") || "—" });
    }
    const mDesc = rule.match(/^description:\s*(.+)$/m);
    if (mDesc) fields.push({ key: "description", value: mDesc[1] });
    const mAuthor = rule.match(/^author:\s*(.+)$/m);
    if (mAuthor) fields.push({ key: "author", value: mAuthor[1] });
  } else if (fmt === "yara") {
    const mName = rule.match(/^\s*rule\s+(\w+)/m);
    if (mName) fields.push({ key: "rule name", value: mName[1] });
    const metas = rule.match(/^\s+(\w+)\s*=\s*"([^"]*)"$/gm);
    if (metas) metas.forEach((m) => {
      const p = m.match(/^\s+(\w+)\s*=\s*"([^"]*)"$/);
      if (p) fields.push({ key: `meta.${p[1]}`, value: p[2] });
    });
    const strings = rule.match(/^\s+\$(\w+)\s*=\s*"([^"]*)"/gm);
    if (strings) strings.forEach((s) => {
      const p = s.match(/^\s+\$(\w+)\s*=\s*"([^"]*)"/);
      if (p) fields.push({ key: `string.${p[1]}`, value: p[2] });
    });
    const cMatch = rule.match(/condition:\s*(.+?)$/m);
    if (cMatch) fields.push({ key: "condition", value: cMatch[1].trim() });
  } else if (fmt === "kql") {
    const tableMatch = rule.match(/^(\w+)/);
    if (tableMatch && !/^(let|\/\/)/i.test(tableMatch[1])) fields.push({ key: "table", value: tableMatch[1] });
    const wheres = rule.match(/\|\s*where\s+(.+?)(?=\s*\|)/gi);
    if (wheres) wheres.forEach((w) => fields.push({ key: "filter", value: w.replace(/^\|\s*where\s+/i, "").trim() }));
    const projects = rule.match(/\|\s*project\s+(.+?)(?=\s*\|)/gi);
    if (projects) projects.forEach((p) => fields.push({ key: "project", value: p.replace(/^\|\s*project\s+/i, "").trim() }));
    const hasOps = rule.match(/\|\s*\w+/g);
    if (hasOps) fields.push({ key: "operators", value: hasOps.map(o => o.replace("|", "").trim()).filter(Boolean).join(", ") });
  }
  return fields;
}

function DetectionPage() {
  const { filterText, setFilterText, showFilter, setShowFilter, toggleFilter } = useOutputFilter();
  const [hasRun, setHasRun] = useState(false);
  const [fmt, setFmt] = useState<Format>("sigma");
  const [rule, setRule] = useState("");
  const [event, setEvent] = useState("");
  const [copied, setCopied] = useState(false);

  const [mitreResults, setMitreResults] = useState<MitreResult | null>(null);
  const [mitreLoading, setMitreLoading] = useState(false);
  const [mitreError, setMitreError] = useState<string | null>(null);

  const [genDescription, setGenDescription] = useState("");
  const [genSeverity, setGenSeverity] = useState<string>("medium");
  const [genLoading, setGenLoading] = useState(false);
  const [genResult, setGenResult] = useState<GenResult | null>(null);
  const [genError, setGenError] = useState<string | null>(null);
  const locker = useLocker();

  /* ── IDS Rule Generator ── */
  const [idsTemplates, setIdsTemplates] = useState<Record<string, unknown> | null>(null);
  const [idsSelected, setIdsSelected] = useState<string | null>(null);
  const [idsMsg, setIdsMsg] = useState("");
  const [idsContent, setIdsContent] = useState("");
  const [idsSid, setIdsSid] = useState("2000001");
  const [idsPriority, setIdsPriority] = useState("2");
  const [idsRule, setIdsRule] = useState<string | null>(null);
  const [idsBuildLoading, setIdsBuildLoading] = useState(false);
  const [idsCopied, setIdsCopied] = useState(false);
  const [idsShowPanel, setIdsShowPanel] = useState(false);

  useEffect(() => {
    getIdsRuleTemplates()
      .then((data) => { setIdsTemplates(data as Record<string, unknown>); const keys = Object.keys(data as Record<string, unknown>); if (keys.length) setIdsSelected(keys[0]); })
      .catch(() => setIdsTemplates({}));
  }, []);

  useEffect(() => {
    if (idsTemplates && idsSelected) {
      const t = (idsTemplates[idsSelected] as any)?.data || {};
      setIdsMsg(t.msg || "");
      setIdsContent(t.content || "");
      setIdsSid(t.sid || "2000001");
      setIdsPriority(t.priority || "2");
      setIdsRule(null);
    }
  }, [idsTemplates, idsSelected]);

  const handleIdsBuild = async () => {
    if (!idsMsg && !idsContent) return;
    setIdsBuildLoading(true);
    setIdsRule(null);
    try {
      const res = await buildIdsRule({
        engine: "snort", action: "alert", protocol: "tcp",
        src_ip: "$EXTERNAL_NET", src_port: "any", direction: "->", dst_ip: "$HOME_NET", dst_port: "80",
        msg: idsMsg, content: idsContent, pcre: "", flow: "to_server,established",
        classtype: "trojan-activity", priority: idsPriority, sid: idsSid, rev: "1",
        extra_options: "", nocase: true, http_uri: false, http_header: false,
      }) as any;
      setIdsRule(res.rule);
    } catch (e: any) {
      toast.error(e?.message || "IDS build failed", { description: e?.suggestion });
    } finally {
      setIdsBuildLoading(false);
    }
  };

  /* ── Rule library ── */
  const [showLib, setShowLib] = useState(false);
  const [savedRules, setSavedRules] = useState<SavedRule[]>(() => loadRules());
  const [libName, setLibName] = useState("");
  const [libTags, setLibTags] = useState("");
  const [libNotice, setLibNotice] = useState("");
  const [ruleSearch, setRuleSearch] = useState("");

  /* ── Validation & analysis ── */
  const [showAnalysis, setShowAnalysis] = useState(false);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") { setShowLib(false); setShowAnalysis(false); setIdsShowPanel(false); }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  const validation = useMemo(() => validateRule(rule, fmt), [rule, fmt]);
  const analysis = useMemo(() => analyzeRule(rule, fmt), [rule, fmt]);
  const hasErrors = validation.some(v => v.type === "error");
  const hasWarnings = validation.some(v => v.type === "warning");

  const tpl = TEMPLATES[fmt];
  const result = useMemo(() => tpl.matcher(event), [tpl, event]);

  const switchFmt = (f: Format) => { setFmt(f); setRule(TEMPLATES[f].rule); setEvent(TEMPLATES[f].event); setMitreResults(null); setMitreError(null); setGenResult(null); setGenError(null); setShowLib(false); };
  const reset = () => { setRule(""); setEvent(""); setHasRun(false); setMitreResults(null); };

  const handleEvaluate = useCallback(async () => {
    if (mitreLoading) return;
    setHasRun(true);
    setMitreLoading(true);
    setMitreError(null);
    try {
      const text = [rule, event].filter(Boolean).join("\n");
      const res = await mapMitre(text);
      setMitreResults(res as MitreResult);
      pushTimelineEvent({ source: "detection", verb: "mapped", detail: `MITRE mapping for ${fmt} rule`, result: `${(res as MitreResult).techniques?.length ?? 0} techniques` });
    } catch (e: any) {
      setMitreError(e?.message || "MITRE mapping failed");
    } finally {
      setMitreLoading(false);
    }
  }, [rule, event, mitreLoading, fmt]);

  const handleGenerate = useCallback(async () => {
    if (genLoading || !genDescription.trim()) return;
    setGenLoading(true);
    setGenError(null);
    try {
      const res = await generateSigmaRule(
        `Generated: ${genDescription.slice(0, 60)}`,
        genDescription,
        genSeverity,
        "",
      );
      setGenResult(res);
      pushTimelineEvent({ source: "detection", verb: "generated", detail: `Generated ${fmt} rule: ${genDescription.slice(0, 60)}`, result: genSeverity });
    } catch (e: any) {
      setGenError(e?.message || "Rule generation failed");
    } finally {
      setGenLoading(false);
    }
  }, [genDescription, genSeverity, genLoading, fmt]);

  const loadGenerated = () => {
    if (genResult?.sigma_yaml) {
      setRule(genResult.sigma_yaml);
      setGenResult(null);
      setGenDescription("");
    }
  };

  const copy = () => { try { navigator.clipboard.writeText(rule); } catch {/* noop */} setCopied(true); setTimeout(() => setCopied(false), 1200); };
  const clearMitre = () => setMitreResults(null);

  const ruleLines = rule.split("\n");
  const eventLines = event.split("\n");
  const iocs = useMemo(() => extractIocs(event), [event]);

  /* ── Library actions ── */
  const saveCurrent = () => {
    const name = libName.trim() || `Rule ${savedRules.length + 1}`;
    const tags = libTags.split(",").map(t => t.trim()).filter(Boolean);
    const existing = savedRules.findIndex(r => r.name === name && r.format === fmt);
    const entry: SavedRule = { id: existing >= 0 ? savedRules[existing].id : genId(), name, format: fmt, rule, event, created: existing >= 0 ? savedRules[existing].created : Date.now(), updated: Date.now(), tags };
    let next: SavedRule[];
    if (existing >= 0) { next = [...savedRules]; next[existing] = entry; }
    else next = [...savedRules, entry];
    setSavedRules(next);
    saveRules(next);
    setLibNotice(`Saved "${name}"`);
    pushTimelineEvent({ source: "detection", verb: existing >= 0 ? "updated-rule" : "saved-rule", detail: `${existing >= 0 ? "Updated" : "Saved"} ${fmt} rule: ${name}`, result: `${tags.length} tags` });
    setTimeout(() => setLibNotice(""), 2000);
  };
  const loadRule = (r: SavedRule) => {
    setFmt(r.format);
    setRule(r.rule);
    setEvent(r.event);
    setHasRun(false);
    setMitreResults(null);
    setShowLib(false);
  };
  const deleteRule = (id: string) => {
    const next = savedRules.filter(r => r.id !== id);
    setSavedRules(next);
    saveRules(next);
  };
  const duplicateRule = (r: SavedRule) => {
    const entry: SavedRule = { ...r, id: genId(), name: `${r.name} (copy)`, created: Date.now(), updated: Date.now() };
    const next = [...savedRules, entry];
    setSavedRules(next);
    saveRules(next);
    loadRule(entry);
  };

  const filteredSaved = ruleSearch.trim()
    ? savedRules.filter(r => r.name.toLowerCase().includes(ruleSearch.toLowerCase()) || r.tags.some(t => t.toLowerCase().includes(ruleSearch.toLowerCase())) || r.rule.toLowerCase().includes(ruleSearch.toLowerCase()))
    : savedRules;
  const fmtRules = filteredSaved.filter(r => r.format === fmt);
  const otherRules = filteredSaved.filter(r => r.format !== fmt);

  const refIcon = (f: Format) => { const Ic = FMT_ICONS[f]; return <Ic className="h-3 w-3" />; };

  return (
    <PageShell
      eyebrow="DETECTION / RULE EDITOR"
      title="Detection Editor"
      description="Compose Sigma · YARA · KQL detections, dry-run against events, map to MITRE ATT&CK, or generate Sigma rules from a description."
      crumbs={[{ label: "Detection" }]}
      jumps={[{ label: "SIEM", to: "/siem" }, { label: "Investigation", to: "/parser" }]}>
      <>
      <SectionBar id="IN" label="Intake · format & rule body" meta={`${ruleLines.length} lines · ${rule.length} chars`} />

      {/* Format selector with descriptive cards */}
      <div className="mb-3 grid gap-2 grid-cols-2 sm:grid-cols-3">
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
                <span className={"grid h-7 w-7 place-items-center rounded border " + (active ? "border-primary/60 bg-primary/20 text-primary" : "border-divider-strong bg-background/60 text-muted-foreground")}>
                  {refIcon(f)}
                </span>
                <div>
                  <div className={"text-mono ba-text-sm uppercase tracking-widest " + (active ? "text-primary" : "text-foreground/90")}>{f}</div>
                  <div className="ba-text-2xs text-muted-foreground">{desc}</div>
                </div>
              </div>
              {active && <Chip tone="primary">active</Chip>}
            </button>
          );
        })}
        {fmt === "sigma" && (
          <button
            onClick={() => setGenResult(genResult ? null : { _show: true })}
            className="group relative flex items-center justify-between gap-3 overflow-hidden rounded-md border border-dashed border-primary/40 px-3 py-2 text-left transition-all hover:border-primary/60 hover:bg-primary/5"
          >
            <div className="flex items-center gap-2.5">
              <span className="grid h-7 w-7 place-items-center rounded border border-primary/40 bg-primary/10 text-primary">
                <Wand2 className="h-3.5 w-3.5" strokeWidth={2.25} />
              </span>
              <div>
                <div className="text-mono ba-text-sm uppercase tracking-widest text-primary">generate</div>
                <div className="ba-text-2xs text-muted-foreground">Sigma from description</div>
              </div>
            </div>
          </button>
        )}
      </div>

      {/* Sigma generate panel */}
      {fmt === "sigma" && genResult && genResult._show && (
        <Panel title="Sigma generator" icon={Wand2} priority="secondary" className="mb-4" actions={
          genResult.sigma_yaml ? (
            <button onClick={loadGenerated} className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2 py-0.5 text-mono ba-text-2xs uppercase text-primary hover:bg-primary/20">
              <Plus className="h-3 w-3" /> load into editor
            </button>
          ) : null
        }>
          {!genResult.sigma_yaml ? (
            <div className="space-y-3">
              <label className="flex flex-col gap-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">
                attack description
                <textarea
                  value={genDescription}
                  onChange={(e) => setGenDescription(e.target.value)}
                  rows={3}
                  placeholder="e.g. PowerShell launching encoded command from可疑 IP..."
                  className="rounded border border-border bg-background/60 px-2 py-1.5 text-mono ba-text-base text-foreground placeholder:text-muted-foreground/40"
                />
              </label>
              <div className="flex items-end gap-2">
                <label className="flex flex-col gap-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">
                  severity
                  <select
                    value={genSeverity}
                    onChange={(e) => setGenSeverity(e.target.value)}
                    className="rounded border border-border bg-background/60 px-2 py-1 text-mono ba-text-base text-foreground"
                  >
                    <option value="informational">informational</option>
                    <option value="low">low</option>
                    <option value="medium">medium</option>
                    <option value="high">high</option>
                    <option value="critical">critical</option>
                  </select>
                </label>
                <button
                  onClick={handleGenerate}
                  disabled={genLoading || !genDescription.trim()}
                  className="inline-flex h-8 items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-3 text-mono text-[10.5px] uppercase tracking-widest text-primary hover:bg-primary/20 disabled:opacity-40"
                >
                  {genLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Wand2 className="h-3 w-3" />}
                  {genLoading ? "generating..." : "generate"}
                </button>
              </div>
              {genError && <p className="text-mono ba-text-sm text-destructive">{genError}</p>}
            </div>
          ) : (
            <div className="space-y-3">
              <pre className="max-h-60 overflow-auto rounded border border-border/50 bg-background/60 p-3 text-mono ba-text-sm leading-relaxed text-foreground/90">{genResult.sigma_yaml}</pre>
              {genResult.mitre_mapping?.matches && genResult.mitre_mapping.matches.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {genResult.mitre_mapping.matches.map((m: MitreMatch) => (
                    <Chip key={m.technique_id} tone="warning">{m.technique_id} — {m.technique}</Chip>
                  ))}
                </div>
              )}
            </div>
          )}
        </Panel>
      )}

      {/* Rule library button + panel */}
      <div className="mb-3">
        <button onClick={() => setShowLib(s => !s)} className={"inline-flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (showLib ? "border-primary/50 bg-primary/10 text-primary" : "border-border text-muted-foreground hover:text-foreground")}>
          <BookMarked className="h-3 w-3" />
          rule library
          {savedRules.length > 0 && <Chip tone={showLib ? "primary" : "default"}>{savedRules.length}</Chip>}
        </button>
      </div>

      {showLib && (
        <Panel title="Rule library" icon={BookMarked} priority="secondary" meta={`${savedRules.length} saved · ${fmtRules.length} in ${fmt}`} className="mb-4" actions={
          <span className="flex items-center gap-1.5 text-mono ba-text-2xs text-muted-foreground">
            {libNotice && <span className="text-success">{libNotice}</span>}
          </span>
        }>
          {/* Save current */}
          <div className="mb-4 flex flex-wrap items-center gap-2 rounded border border-divider-strong bg-background/30 p-2">
            <input
              value={libName}
              onChange={e => setLibName(e.target.value)}
              placeholder={`Rule name… (default: Rule ${savedRules.length + 1})`}
              className="min-w-0 flex-1 rounded border border-border bg-background/60 px-2 py-1 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground/50 focus:border-primary/50"
            />
            <input
              value={libTags}
              onChange={e => setLibTags(e.target.value)}
              placeholder="tags (comma)"
              className="w-32 rounded border border-border bg-background/60 px-2 py-1 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground/50 focus:border-primary/50"
            />
            <button onClick={saveCurrent} className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2 py-1 text-mono ba-text-2xs uppercase text-primary hover:bg-primary/20">
              <Save className="h-3 w-3" /> save current
            </button>
          </div>

          <div className="relative px-3 pb-1 pt-1">
            <Search className="absolute left-4 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground/50" />
            <input
              value={ruleSearch}
              onChange={e => setRuleSearch(e.target.value)}
              placeholder="search rules by name, tag, or content…"
              className="w-full rounded border border-border/50 bg-background/40 py-1 pl-6 pr-2 text-mono ba-text-2xs text-foreground outline-none placeholder:text-muted-foreground/40 focus:border-primary/40"
            />
          </div>
          {filteredSaved.length === 0 ? (
            <div className="text-center text-mono ba-text-sm text-muted-foreground py-4">{savedRules.length === 0 ? "No rules saved yet. Write a rule and save it above." : "No rules match your search."}</div>
          ) : (
            <div className="space-y-2 max-h-80 overflow-auto">
              {fmtRules.map(r => (
                <div key={r.id} className="flex items-center justify-between gap-2 rounded border border-border/50 bg-background/30 px-3 py-2 hover:border-primary/30">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-mono ba-text-base font-semibold text-foreground/90">{r.name}</span>
                      {r.tags.map(t => <Chip key={t} tone="info">{t}</Chip>)}
                    </div>
                    <div className="mt-0.5 flex items-center gap-2 text-mono ba-text-2xs text-muted-foreground">
                      <span className="uppercase tracking-widest">{r.format}</span>
                      <span>· {r.rule.length} chars</span>
                      <span>· saved {new Date(r.updated).toLocaleDateString()}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <button onClick={() => loadRule(r)} className="rounded border border-border px-1.5 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-primary"><Edit3 className="inline h-3 w-3" /> load</button>
                    <button onClick={() => duplicateRule(r)} aria-label="Duplicate rule" className="rounded border border-border px-1.5 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-primary"><Copy className="inline h-3 w-3" /></button>
                    <button onClick={() => deleteRule(r.id)} aria-label="Delete rule" className="rounded border border-border px-1.5 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-destructive"><Trash2 className="inline h-3 w-3" /></button>
                  </div>
                </div>
              ))}
              {otherRules.length > 0 && (
                <details className="group">
                  <summary className="cursor-pointer px-1 pt-2 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-foreground">
                    other formats ({otherRules.length})
                  </summary>
                  <div className="mt-1 space-y-1">
                    {otherRules.map(r => (
                      <div key={r.id} className="flex items-center justify-between gap-2 rounded border border-divider-soft bg-background/20 px-2.5 py-1.5">
                        <div className="min-w-0 flex-1">
                          <span className="text-mono ba-text-sm text-foreground/80">{r.name}</span>
                          <span className="ml-2 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground">{r.format}</span>
                        </div>
                        <button onClick={() => loadRule(r)} aria-label="Load rule" className="rounded border border-border px-1.5 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-primary"><Edit3 className="inline h-3 w-3" /></button>
                      </div>
                    ))}
                  </div>
                </details>
              )}
            </div>
          )}
        </Panel>
      )}

      <div className="grid gap-3 grid-cols-5">
        {/* Rule editor with line numbers + live syntax preview */}
        <Panel
          title={`rule · ${fmt}`}
          icon={FileCode2}
          meta={`${ruleLines.length} ln`}
          className="col-span-3"
          actions={
            <>
              {/* Validation badge */}
              {rule.trim() && (hasErrors || hasWarnings) && (
                <span className={"inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-mono ba-text-2xs " + (hasErrors ? "border-destructive/40 bg-destructive/10 text-destructive" : "border-warning/40 bg-warning/10 text-warning")}>
                  {hasErrors ? `${validation.filter(v => v.type === "error").length} err` : `${validation.filter(v => v.type === "warning").length} warn`}
                </span>
              )}
              <button onClick={() => setShowAnalysis(s => !s)} className={"inline-flex items-center gap-1 rounded border px-2 py-0.5 text-mono ba-text-2xs uppercase " + (showAnalysis ? "border-primary/50 bg-primary/10 text-primary" : "border-border text-muted-foreground hover:text-foreground")}>
                <Info className="h-3 w-3" /> analyze
              </button>
              <button onClick={() => { setRule(TEMPLATES[fmt].rule); setEvent(TEMPLATES[fmt].event); }} className="inline-flex items-center gap-1 rounded border border-border/50 px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> load sample</button>
              <button onClick={reset} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground"><RotateCcw className="h-3 w-3" /> reset</button>
              <button onClick={copy} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">{copied ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> copy</>}</button>
            </>
          }
        >
          <div className="relative grid grid-cols-[2.5rem_1fr] overflow-hidden rounded border border-divider-strong bg-background/60">
            <div aria-hidden className="select-none border-r border-divider-soft bg-card/40 py-2 text-right">
              {ruleLines.map((_, i) => (
                <div key={i} className="px-2 text-mono text-[10.5px] leading-[1.5] text-muted-foreground/60">{i + 1}</div>
              ))}
            </div>
            <div className="relative">
              <pre
                aria-hidden
                className="pointer-events-none m-0 whitespace-pre-wrap break-words p-2 text-mono ba-text-base leading-[1.5] text-foreground/90"
                dangerouslySetInnerHTML={{ __html: highlight(rule, fmt, []) + "\n" }}
              />
              <textarea
                value={rule}
                onChange={(e) => setRule(e.target.value)}
                onPaste={(e) => {
                  const text = e.clipboardData.getData("text");
                  const detected = autoDetectFmt(text);
                  if (detected && detected !== fmt) switchFmt(detected);
                }}
                spellCheck={false}
                className="absolute inset-0 resize-none overflow-hidden bg-transparent p-2 text-mono ba-text-base leading-[1.5] text-transparent caret-primary outline-none"
                style={{ WebkitTextFillColor: "transparent" }}
              />
            </div>
          </div>

          {/* Inline validation results */}
          {rule.trim() && (hasErrors || hasWarnings) && (
            <div className="mt-2 space-y-1">
              {validation.map((v, i) => (
                <div key={i} className={"flex items-start gap-2 rounded px-2 py-1 text-mono ba-text-2xs " + (v.type === "error" ? "bg-destructive/10 text-destructive" : "bg-warning/10 text-warning")}>
                  <span className="mt-0.5 shrink-0">{v.type === "error" ? <X className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />}</span>
                  <span>{v.msg}{v.line != null ? ` (line ${v.line})` : ""}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>

        {/* Simulation pane */}
        <Panel
          title="simulate · event"
          icon={Sparkles}
          meta={`${eventLines.length} ln`}
          className="col-span-2"
          actions={<Chip tone={result.hit ? "destructive" : "default"}>{result.hit ? "MATCH" : "no match"}</Chip>}
        >
          <div className="relative overflow-hidden rounded border border-divider-strong bg-background/60">
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
            <div className="flex items-center justify-between text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">
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
                <span key={h} className="inline-flex items-center gap-1 rounded border border-warning/40 bg-warning/10 px-1.5 py-0.5 text-mono ba-text-2xs text-warning"><Crosshair className="h-2.5 w-2.5" /> {h}</span>
              ))}
            </div>
            <button
              onClick={handleEvaluate}
              disabled={mitreLoading}
              className="mt-1 inline-flex w-full items-center justify-center gap-1 rounded border border-primary/50 bg-primary/10 px-2.5 py-1.5 text-mono text-[10.5px] uppercase tracking-widest text-primary hover:bg-primary/20 disabled:opacity-40"
            >
              {mitreLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
              {mitreLoading ? "mapping..." : "evaluate"}
            </button>
          </div>
        </Panel>
      </div>

      {/* Structural analysis panel */}
      {showAnalysis && analysis.length > 0 && (
        <Panel title={`Rule structure · ${fmt}`} icon={ListFilter} priority="secondary" meta={`${analysis.length} fields`} className="mt-3">
          <div className="grid gap-1.5 grid-cols-3">
            {analysis.map((f) => (
              <div key={f.key} className="rounded border border-divider-soft bg-background/30 px-2.5 py-1.5">
                <div className="text-mono text-[9.5px] uppercase tracking-widest text-muted-foreground">{f.key}</div>
                <div className="mt-0.5 truncate text-mono ba-text-sm text-foreground/90" title={f.value}>{f.value}</div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      <div className="flex items-center gap-2">
        <SectionBar id="OT" label="Output · verdict & mapping" meta={result.hit ? "rule would fire" : "rule does not match"} />
        {hasRun && (
          <button
            onClick={toggleFilter}
            className={"inline-flex shrink-0 items-center gap-1 rounded border px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (showFilter ? "border-primary/50 bg-primary/10 text-primary" : "border-divider-strong text-muted-foreground hover:border-primary/40 hover:text-primary")}
            title="Toggle output filter (⌘F)"
          >
            <Search className="h-3 w-3" />
            filter
          </button>
        )}
      </div>

      {showFilter && (
        <OutputFilterBar
          filterText={filterText}
          onChange={setFilterText}
          onClear={() => setFilterText("")}
          onClose={() => { setShowFilter(false); setFilterText(""); }}
        />
      )}

      {!hasRun ? (
        <Empty icon={ShieldAlert} title="Ready to evaluate" hint="Click 'evaluate' in the simulate pane to run the rule against the event and map to MITRE ATT&CK." />
      ) : (
        <OutputFilter query={filterText.toLowerCase()}>
        <div className="space-y-5">
        <VerdictBanner
          verdict={result.hit ? "Rule matches event" : "No match"}
          tone={result.hit ? "warning" : "success"}
          icon={result.hit ? AlertTriangle : ShieldCheck}
          details={[
            result.hit ? `${result.hits.length} token(s): ${result.hits.join(", ")}` : "",
            `${fmt.toUpperCase()} · ${tpl.severity} severity`,
            mitreResults?.matches?.[0]?.technique_id || tpl.technique.id,
            mitreResults ? `${mitreResults.total_matches} technique(s) mapped` : "",
          ].filter(Boolean)}
        />

        {/* Metrics */}
        <MetricGrid
          columns={4}
          metrics={[
            { label: "Format", value: fmt.toUpperCase(), tone: "primary", icon: FileCode2 },
            { label: "Verdict", value: result.hit ? "MATCH" : "NO MATCH", tone: result.hit ? "destructive" : "success" },
            { label: "MITRE", value: mitreResults?.matches?.[0]?.technique_id || tpl.technique.id, tone: "warning", icon: Crosshair },
            { label: "Severity", value: tpl.severity, tone: tpl.severity === "critical" || tpl.severity === "high" ? "destructive" : tpl.severity === "medium" ? "warning" : "default" },
            { label: "Tokens", value: result.hits.length },
            { label: "Platform", value: mitreResults?.matches?.[0]?.technique || tpl.technique.platform.split("/")[0] },
            { label: "Tactic", value: mitreResults?.matches?.[0]?.tactic || tpl.technique.tactic },
          ]}
        />

        {/* MITRE Mapping + Evidence side-by-side */}
        <TwoColumnOutput
          ratio="1:1"
          left={
            <Panel title="MITRE ATT&CK mapping" icon={Crosshair} collapsible storageKey="ba.panel.detection.mitre" defaultCollapsed actions={
              mitreResults ? <button onClick={clearMitre} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground"><RotateCcw className="h-3 w-3" /> clear</button> : undefined
            }>
              {mitreLoading ? (
                <div className="flex items-center gap-2 py-4 text-mono ba-text-sm text-muted-foreground">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> mapping to MITRE ATT&CK...
                </div>
              ) : mitreError ? (
                <p className="text-mono ba-text-sm text-destructive">{mitreError}</p>
              ) : mitreResults && mitreResults.matches && mitreResults.matches.length > 0 ? (
                <div className="space-y-3">
                  {mitreResults.matches.map((m: MitreMatch) => (
                    <div key={m.technique_id} className="rounded border border-border/50 bg-background/30 p-2">
                      <div className="flex items-center justify-between">
                        <span className="text-mono ba-text-sm font-semibold text-foreground">{m.technique_id}</span>
                        <Chip tone={m.confidence === "high" ? "destructive" : m.confidence === "medium" ? "warning" : "default"}>{m.confidence}</Chip>
                      </div>
                      <p className="mt-0.5 ba-text-base text-foreground/90">{m.technique}</p>
                      <p className="text-[11px] text-muted-foreground">{m.tactic}</p>
                      {m.matched_keywords && m.matched_keywords.length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {m.matched_keywords.map((kw: string) => (
                            <Chip key={kw} tone="info">{kw}</Chip>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                  {mitreResults.note && (
                    <p className="ba-text-2xs text-muted-foreground italic">{mitreResults.total_matches} technique(s) mapped · {mitreResults.note}</p>
                  )}
                </div>
              ) : (
                <p className="py-2 text-mono ba-text-sm text-muted-foreground">Click "evaluate" to map rule + event text against MITRE ATT&CK.</p>
              )}
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
        <Panel title="IOCs in event" icon={Hash} priority="secondary" meta={`${iocs.ips.length + iocs.urls.length + iocs.hashes.length} total`} collapsible storageKey="ba.panel.detection.iocs" defaultCollapsed>
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
          <div className="mt-2 flex flex-wrap gap-1.5">
            {iocs.ips.length > 0 && (
              <button onClick={() => { iocs.ips.forEach((v) => locker.add({ value: v, type: "ipv4", source: "/detection" })); toast(`Added ${iocs.ips.length} IPs to locker`); }}
                className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground"
              >+ IPs ({iocs.ips.length})</button>
            )}
            {iocs.urls.length > 0 && (
              <button onClick={() => { iocs.urls.forEach((v) => locker.add({ value: v, type: "url", source: "/detection" })); toast(`Added ${iocs.urls.length} URLs to locker`); }}
                className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground"
              >+ URLs ({iocs.urls.length})</button>
            )}
            {iocs.hashes.length > 0 && (
              <button onClick={() => { iocs.hashes.forEach((v) => locker.add({ value: v, type: v.length === 32 ? "md5" : v.length === 40 ? "sha1" : v.length === 64 ? "sha256" : "unknown", source: "/detection" })); toast(`Added ${iocs.hashes.length} hashes to locker`); }}
                className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground"
              >+ Hashes ({iocs.hashes.length})</button>
            )}
          </div>
        </CollapsibleSection>

        {/* Report */}
        <Panel title="Report (markdown)" priority="secondary" collapsible defaultCollapsed actions={
          <div className="flex items-center gap-1">
            <button onClick={() => { const md = genReport(tpl, result, rule); navigator.clipboard.writeText(md); }} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground"><Copy className="h-3 w-3" /> copy</button>
            <button onClick={() => { const md = genReport(tpl, result, rule); const blob = new Blob([md], { type: "text/markdown" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `detection-${tpl.technique.id}-${Date.now()}.md`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> md</button>
          </div>
        }>
          <pre className="max-h-48 overflow-auto rounded bg-background/60 p-3 text-mono ba-text-sm text-foreground/90">{genReport(tpl, result, rule)}</pre>
        </Panel>

          <div id="ids-engine">{/* IDS Rule Generator (from IdsBuilder essence) */}
          <Panel title="IDS Rule Generator" icon={ShieldAlert} priority="secondary" meta="Snort/Suricata" collapsible>
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">template</span>
                <select
                  value={idsSelected || ""}
                  onChange={(e) => setIdsSelected(e.target.value)}
                  className="rounded border border-divider-strong bg-background/60 px-2 py-1 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50"
                >
                  {idsTemplates && Object.keys(idsTemplates).map((k) => (
                    <option key={k} value={k}>{k}</option>
                  ))}
                </select>
              </div>
              <div className="grid gap-2 grid-cols-[1fr_2fr_80px_60px]">
                <input value={idsMsg} onChange={(e) => setIdsMsg(e.target.value)} placeholder="msg: Trojan activity detected" className="rounded border border-divider-strong bg-background/40 px-2 py-1.5 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground/40 focus:border-primary/50" />
                <input value={idsContent} onChange={(e) => setIdsContent(e.target.value)} placeholder="content:|evil.exe|" className="rounded border border-divider-strong bg-background/40 px-2 py-1.5 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground/40 focus:border-primary/50" />
                <input value={idsSid} onChange={(e) => setIdsSid(e.target.value)} placeholder="sid" className="rounded border border-divider-strong bg-background/40 px-2 py-1.5 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground/40 focus:border-primary/50" />
                <select value={idsPriority} onChange={(e) => setIdsPriority(e.target.value)} className="rounded border border-divider-strong bg-background/60 px-2 py-1.5 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50">
                  {["1","2","3","4"].map((p) => <option key={p} value={p}>prio {p}</option>)}
                </select>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={handleIdsBuild} disabled={idsBuildLoading || (!idsMsg && !idsContent)} className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-3 py-1 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20 disabled:opacity-40">
                  {idsBuildLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Wand2 className="h-3 w-3" />}
                  {idsBuildLoading ? "building..." : "generate"}
                </button>
                <button onClick={() => setIdsShowPanel(!idsShowPanel)} className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-foreground">{idsShowPanel ? "hide" : "show"} preview</button>
              </div>
              {idsShowPanel && idsRule && (
                <div className="rounded border border-border/50 bg-background/60 p-3">
                  <pre className="overflow-x-auto text-mono ba-text-sm leading-relaxed text-foreground/90 whitespace-pre-wrap">{idsRule}</pre>
                  <button onClick={() => { navigator.clipboard.writeText(idsRule); setIdsCopied(true); setTimeout(() => setIdsCopied(false), 1200); }} className="mt-2 inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-0.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-foreground">
                    {idsCopied ? <><Check className="h-3 w-3" /> copied</> : <><Copy className="h-3 w-3" /> copy rule</>}
                  </button>
                </div>
              )}
            </div>
          </Panel>
          </div>

        <SendToRow targets={[
          { label: "MITRE Coverage", to: "/mitre", icon: ArrowRight },
          { label: "SOC Guide", to: "/guide", icon: ShieldAlert },
          { label: "Case Notebook", to: "/case", icon: Database, onClick: () => sendToCase({ body: genReport(tpl, result, rule), source: "/detection", kind: "evidence" }) },
        ]} />


      </div>
      </OutputFilter>
      )}
      </>
    </PageShell>
  );
}
