import { ScrollText, FileSearch, Terminal } from "lucide-react";
import { type Severity } from "@/lib/severity";

export type Format = "sigma" | "yara" | "kql";

export const FMT_ICONS = { sigma: ScrollText, yara: FileSearch, kql: Terminal } as const;

export function autoDetectFmt(text: string): Format | null {
  if (/^title:/m.test(text) && /^detection:/m.test(text)) return "sigma";
  if (/^rule\s/m.test(text) && /^\s{2}meta:/m.test(text)) return "yara";
  if (/\b(where\s|project\b|summarize\b)/i.test(text)) return "kql";
  return null;
}

export type Tpl = {
  rule: string;
  event: string;
  matcher: (event: string) => { hit: boolean; hits: string[] };
  technique: { id: string; name: string; tactic: string; platform: string; source: string };
  severity: Severity;
};

export type MitreMatch = { technique_id: string; technique: string; tactic: string; confidence: string; matched_keywords?: string[] };
export type MitreResult = { total_matches: number; matches: MitreMatch[]; note?: string };
export type GenResult = { sigma_yaml?: string; mitre_mapping?: { matches?: MitreMatch[] }; _show?: boolean };

export const TEMPLATES: Record<Format, Tpl> = {
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
    technique: { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution", platform: "Strings / memory", source: "Strings / memory" },
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
    technique: { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution", platform: "Defender XDR", source: "DeviceProcessEvents" },
    severity: "high",
  },
};

export const SYNTAX: Record<Format, { kw: RegExp; str: RegExp; comment: RegExp }> = {
  sigma: { kw: /\b(title|id|status|logsource|product|category|detection|selection|condition|tags|level|description|author|references)\b/g, str: /'[^']*'|"[^"]*"/g, comment: /#.*$/gm },
  yara: { kw: /\b(rule|meta|strings|condition|ascii|wide|nocase|all|any|of|them|and|or|not)\b/g, str: /"[^"]*"/g, comment: /\/\/.*$/gm },
  kql: { kw: /\b(where|project|order by|desc|asc|has_any|has|contains|extend|summarize|count|by|let|datatable)\b/g, str: /"[^"]*"/g, comment: /\/\/.*$/gm },
};

export function highlight(src: string, fmt: Format, matches: string[]) {
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

export function extractIocs(text: string): { ips: string[]; urls: string[]; hashes: string[] } {
  return {
    ips: Array.from(new Set(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [])),
    urls: Array.from(new Set(text.match(/https?:\/\/[^\s"']+/g) ?? [])),
    hashes: Array.from(new Set(text.match(/\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b/g) ?? [])),
  };
}

export function genReport(tpl: Tpl, result: { hit: boolean; hits: string[] }, rule: string): string {
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

export type SavedRule = { id: string; name: string; format: Format; rule: string; event: string; created: number; updated: number; tags: string[] };
const RULES_KEY = "ba.detection.rules.v2";

export function loadRules(): SavedRule[] {
  try { return JSON.parse(localStorage.getItem(RULES_KEY) || "[]"); } catch { return []; }
}
export function saveRules(r: SavedRule[]) {
  try { localStorage.setItem(RULES_KEY, JSON.stringify(r)); } catch {}
}
export function genId() { return crypto.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`; }

export type ValidationMsg = { type: "error" | "warning"; msg: string; line?: number };
export function validateRule(rule: string, fmt: Format): ValidationMsg[] {
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

export type RuleField = { key: string; value: string };
export function analyzeRule(rule: string, fmt: Format): RuleField[] {
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
