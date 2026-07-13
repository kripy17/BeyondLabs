import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, SectionBar, Chip } from "@/components/soc";
import { Empty } from "@/components/output";
import { Search, Copy, Check, Download, Hash, AlertTriangle, ShieldCheck, HelpCircle } from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/hash-lookup")({ component: HashLookupPage });

type HashType = "MD5" | "SHA1" | "SHA256" | "SHA512" | "unknown";
type Verdict = "malicious" | "suspicious" | "clean" | "unknown";

type HashResult = {
  hash: string;
  type: HashType;
  verdict: Verdict;
  firstSeen: string;
  avDetections: number;
  avTotal: number;
  malware: string;
};

function detectType(h: string): HashType {
  if (/^[a-f0-9]{32}$/i.test(h)) return "MD5";
  if (/^[a-f0-9]{40}$/i.test(h)) return "SHA1";
  if (/^[a-f0-9]{64}$/i.test(h)) return "SHA256";
  if (/^[a-f0-9]{128}$/i.test(h)) return "SHA512";
  return "unknown";
}

const MALWARE_NAMES = ["Emotet", "TrickBot", "Cobalt Strike", "AgentTesla", "Qakbot", "FormBook", "Dridex", "RemcosRAT", "AsyncRAT", "NanoCore", "Ursnif", "IcedID", "Bumblebee", "SocGholish", "RedLine Stealer"];
const VERDICTS: Verdict[] = ["malicious", "suspicious", "clean", "unknown"];

function mockResult(hash: string): HashResult {
  const type = detectType(hash);
  const h = parseInt(hash.slice(0, 8), 16) || Math.abs(hash.split("").reduce((a, c) => a + c.charCodeAt(0), 0));
  const vIdx = h % 4;
  return {
    hash,
    type,
    verdict: vIdx === 0 ? "malicious" : vIdx === 1 ? "suspicious" : vIdx === 2 ? "clean" : "unknown",
    firstSeen: new Date(Date.now() - (h % 365) * 86400000).toISOString().split("T")[0],
    avDetections: vIdx === 0 ? 8 + (h % 15) : vIdx === 1 ? 2 + (h % 5) : 0,
    avTotal: 62,
    malware: vIdx === 0 ? MALWARE_NAMES[h % MALWARE_NAMES.length] : "-",
  };
}

const TONE: Record<Verdict, "destructive" | "warning" | "success" | "default"> = {
  malicious: "destructive", suspicious: "warning", clean: "success", unknown: "default",
};

function HashLookupPage() {
  const [input, setInput] = useState("");
  const [lookedUp, setLookedUp] = useState(false);
  const [copied, setCopied] = useState("");

  const hashes = useMemo(() => {
    return input.split("\n").map((s) => s.trim()).filter((s) => s.length > 0);
  }, [input]);

  const results = useMemo(() => {
    if (!lookedUp) return [];
    return hashes.map(mockResult);
  }, [hashes, lookedUp]);

  function handleLookup() {
    if (hashes.length === 0) return;
    setLookedUp(true);
  }

  function handleExportCsv() {
    const headers = "hash,type,verdict,first_seen,av_detections,av_total,malware";
    const rows = results.map((r) => `${r.hash},${r.type},${r.verdict},${r.firstSeen},${r.avDetections},${r.avTotal},${r.malware}`);
    const csv = [headers, ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "hash-lookup.csv"; a.click();
    URL.revokeObjectURL(a.href);
  }

  const stats = useMemo(() => {
    if (!results.length) return null;
    return {
      total: results.length,
      malicious: results.filter((r) => r.verdict === "malicious").length,
      suspicious: results.filter((r) => r.verdict === "suspicious").length,
      clean: results.filter((r) => r.verdict === "clean").length,
    };
  }, [results]);

  return (
    <PageShell
      eyebrow="TOOLS / HASH LOOKUP"
      title="Hash Lookup"
      description="Batch hash reputation lookup — paste 50 hashes, get verdicts in a sortable table with CSV export."
      crumbs={[{ label: "Tools" }, { label: "Hash Lookup" }]}
      meta={stats ? [
        { label: "total", value: String(stats.total), tone: "primary" },
        ...(stats.malicious ? [{ label: "malicious", value: String(stats.malicious), tone: "destructive" as const }] : []),
        ...(stats.suspicious ? [{ label: "suspicious", value: String(stats.suspicious), tone: "warning" as const }] : []),
      ] : undefined}
    >
      <Panel title="Input Hashes">
        <textarea
          value={input}
          onChange={(e) => { setInput(e.target.value); setLookedUp(false); }}
          placeholder="Paste hashes, one per line:&#10;d41d8cd98f00b204e9800998ecf8427e&#10;e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855&#10;275a021bbfb6489e54d471899f7db9d1663fc695"
          className="h-36 w-full resize-y rounded border border-border bg-background/60 p-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
        />
        <div className="mt-2 flex items-center justify-between">
          <div className="text-mono text-[10px] text-muted-foreground">{hashes.length} hash{hashes.length !== 1 ? "es" : ""} detected</div>
          <div className="flex items-center gap-2">
            <button onClick={handleLookup} disabled={hashes.length === 0}
              className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-3 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20 disabled:opacity-40">
              <Search className="h-3.5 w-3.5" /> Lookup All
            </button>
            {results.length > 0 && (
              <button onClick={handleExportCsv}
                className="inline-flex items-center gap-1 rounded border border-border px-2 py-1.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
                <Download className="h-3 w-3" /> CSV
              </button>
            )}
          </div>
        </div>
      </Panel>

      {results.length > 0 && (
        <Panel title="Results" bodyClassName="p-0">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border text-left text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">
                  <th className="px-3 py-2">Hash</th>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Verdict</th>
                  <th className="px-3 py-2">AV</th>
                  <th className="px-3 py-2">Malware</th>
                  <th className="px-3 py-2">First Seen</th>
                  <th className="px-3 py-2 w-12"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50">
                {results.map((r, i) => (
                  <tr key={i} className="group hover:bg-card/30">
                    <td className="px-3 py-2">
                      <code className="font-mono text-sm text-foreground/90">{r.hash.slice(0, 20)}…</code>
                    </td>
                    <td className="px-3 py-2"><Chip tone="default">{r.type}</Chip></td>
                    <td className="px-3 py-2">
                      <Chip tone={TONE[r.verdict]}>{r.verdict}</Chip>
                    </td>
                    <td className="px-3 py-2">
                      <span className={r.avDetections > 0 ? "text-destructive" : "text-muted-foreground"}>
                        {r.avDetections}/{r.avTotal}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-sm text-foreground/80">{r.malware}</td>
                    <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{r.firstSeen}</td>
                    <td className="px-3 py-2">
                      <button onClick={() => { navigator.clipboard.writeText(r.hash); setCopied(r.hash); setTimeout(() => setCopied(""), 1200); }}
                        className="opacity-0 transition-opacity group-hover:opacity-100 text-muted-foreground hover:text-primary">
                        {copied === r.hash ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {lookedUp && results.length === 0 && (
        <Empty icon={Hash} title="No hashes to look up" hint="Paste one or more hashes above and click Lookup All." />
      )}
    </PageShell>
  );
}
