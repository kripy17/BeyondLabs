import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, Chip, SendToRow } from "@/components/soc";
import { Empty } from "@/components/output";
import { Search, Copy, Check, Download, Hash, AlertTriangle, ExternalLink, Filter, Database } from "lucide-react";
import { toast } from "sonner";
import { pushTimelineEvent } from "@/lib/timeline";
import { useLocker } from "@/lib/locker";
import { copyText } from "@/lib/copy";
import { sendToCase } from "@/lib/handoff";
import { usePanelNav } from "@/lib/usePanelNav";

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

function validateHash(h: string): { valid: boolean; reason?: string } {
  if (h.length < 32) return { valid: false, reason: "Too short for any hash type" };
  if (h.length > 128) return { valid: false, reason: "Too long for any hash type" };
  if (!/^[a-f0-9]+$/i.test(h)) return { valid: false, reason: "Contains non-hex characters" };
  return { valid: true };
}

const MALWARE_NAMES = ["Emotet", "TrickBot", "Cobalt Strike", "AgentTesla", "Qakbot", "FormBook", "Dridex", "RemcosRAT", "AsyncRAT", "NanoCore", "Ursnif", "IcedID", "Bumblebee", "SocGholish", "RedLine Stealer"];
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

function VerdictBar({ detections, total }: { detections: number; total: number }) {
  const pct = total > 0 ? (detections / total) * 100 : 0;
  const color = pct > 30 ? "bg-destructive" : pct > 5 ? "bg-warning" : "bg-success";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 rounded-full bg-border/50">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${Math.min(pct, 100)}%` }} />
      </div>
      <span className={detections > 0 ? "text-destructive" : "text-muted-foreground"}>
        {detections}/{total}
      </span>
    </div>
  );
}

function HashLookupPage() {
  const locker = useLocker();
  const [input, setInput] = useState("");
  const [lookedUp, setLookedUp] = useState(false);
  const [copied, setCopied] = useState("");
  const [copyAllVerdict, setCopyAllVerdict] = useState<Verdict | null>(null);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape" && lookedUp) { setInput(""); setLookedUp(false); }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [lookedUp]);

  const hashes = useMemo(() => {
    return input.split("\n").map((s) => s.trim()).filter((s) => s.length > 0);
  }, [input]);

  const validHashes = useMemo(() => {
    return hashes.filter(h => validateHash(h).valid);
  }, [hashes]);

  const invalidHashes = useMemo(() => {
    return hashes.filter(h => !validateHash(h).valid).map(h => ({ hash: h, reason: validateHash(h).reason! }));
  }, [hashes]);

  const typeBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const h of hashes) {
      const t = detectType(h);
      counts[t] = (counts[t] || 0) + 1;
    }
    return counts;
  }, [hashes]);

  const results = useMemo(() => {
    if (!lookedUp) return [];
    return validHashes.map(mockResult);
  }, [validHashes, lookedUp]);

  const items = results;
  const { index: selectedIndex } = usePanelNav(items, {
    onCopy: (item) => copyText(item.hash),
    onAttach: (item) => sendToCase({ body: JSON.stringify(item), source: "/hash-lookup", kind: "evidence" }),
  });

  function handleLookup() {
    if (validHashes.length === 0) return;
    setLookedUp(true);
    pushTimelineEvent({ source: "hash-lookup", verb: "looked-up", detail: `Looked up ${validHashes.length} hash${validHashes.length > 1 ? "es" : ""}`, result: `${validHashes.filter(h => mockResult(h).verdict === "malicious").length} malicious` });
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
    const malicious = results.filter((r) => r.verdict === "malicious").length;
    const suspicious = results.filter((r) => r.verdict === "suspicious").length;
    const clean = results.filter((r) => r.verdict === "clean").length;
    return { total: results.length, malicious, suspicious, clean };
  }, [results]);

  function copyAllByVerdict(verdict: Verdict) {
    const texts = results.filter(r => r.verdict === verdict).map(r => r.hash);
    if (texts.length === 0) { toast("No hashes with this verdict"); return; }
    copyText(texts.join("\n"));
    setCopyAllVerdict(verdict);
    setTimeout(() => setCopyAllVerdict(null), 1200);
    toast(`Copied ${texts.length} ${verdict} hashes`);
  }

  return (
    <PageShell
      eyebrow="TOOLS / HASH LOOKUP"
      title="Hash Lookup"
      description="Batch hash reputation lookup — paste hashes, get verdicts in a sortable table with CSV export."
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
        <div className="mt-2 flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-3 text-mono text-[10px] text-muted-foreground">
            <span>{hashes.length} hash{hashes.length !== 1 ? "es" : ""}</span>
            {hashes.length > 0 && (
              <>
                <span className="text-border/60">·</span>
                {Object.entries(typeBreakdown).map(([type, count]) => (
                  <span key={type}>{count} {type}</span>
                ))}
              </>
            )}
            {invalidHashes.length > 0 && (
              <>
                <span className="text-border/60">·</span>
                <span className="text-warning flex items-center gap-1">
                  <AlertTriangle className="h-3 w-3" /> {invalidHashes.length} invalid
                </span>
              </>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button onClick={handleLookup} disabled={validHashes.length === 0}
              className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-3 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20 disabled:opacity-40">
              <Search className="h-3.5 w-3.5" /> Lookup All
            </button>
            {results.length > 0 && (
              <button onClick={() => { results.forEach(r => locker.add({ value: r.hash, type: r.type.toLowerCase() as any, source: "/hash-lookup" })); toast(`Added ${results.length} hashes to locker`); }}
                className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-primary">
                <Database className="h-3 w-3" /> all to locker
              </button>
            )}
            {results.length > 0 && (
              <button onClick={handleExportCsv}
                className="inline-flex items-center gap-1 rounded border border-border px-2 py-1.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
                <Download className="h-3 w-3" /> CSV
              </button>
            )}
          </div>
        </div>
        {invalidHashes.length > 0 && !lookedUp && (
          <div className="mt-2 space-y-0.5">
            {invalidHashes.slice(0, 3).map(({ hash, reason }) => (
              <div key={hash} className="flex items-center gap-1 text-mono text-[10px] text-warning">
                <AlertTriangle className="h-2.5 w-2.5" />
                <span className="truncate">{hash}</span>
                <span className="text-muted-foreground">— {reason}</span>
              </div>
            ))}
            {invalidHashes.length > 3 && (
              <div className="text-mono text-[10px] text-muted-foreground">…and {invalidHashes.length - 3} more</div>
            )}
          </div>
        )}
      </Panel>

      {results.length > 0 && stats && (
        <>
          <div className="flex items-center gap-2 px-1">
            {(["malicious", "suspicious", "clean", "unknown"] as Verdict[]).map((v) => {
              const count = stats[v as keyof typeof stats] as number;
              if (!count) return null;
              return (
                <button key={v} onClick={() => copyAllByVerdict(v)}
                  className="flex items-center gap-1 rounded border border-border/60 bg-card/30 px-2 py-0.5 text-mono text-[10px] text-muted-foreground hover:text-foreground transition-colors"
                  title={`Copy all ${v} hashes`}>
                  <Filter className="h-2.5 w-2.5" />
                  <Chip tone={TONE[v]}>{count} {v}</Chip>
                  {copyAllVerdict === v && <Check className="h-2.5 w-2.5 text-success" />}
                </button>
              );
            })}
          </div>

          <Panel title="Results" bodyClassName="p-0">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border text-left text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">
                    <th className="px-3 py-2">Hash</th>
                    <th className="px-3 py-2">Type</th>
                    <th className="px-3 py-2">Verdict</th>
                    <th className="px-3 py-2">AV Detection</th>
                    <th className="px-3 py-2">Malware</th>
                    <th className="px-3 py-2">First Seen</th>
                    <th className="px-3 py-2 w-20"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50">
                    {results.map((r, i) => (
                    <tr key={i} className={`group hover:bg-card/30${selectedIndex === i ? " bg-primary/5" : ""}`}>
                      <td className="px-3 py-2">
                        <code className="font-mono text-sm text-foreground/90">{r.hash.slice(0, 20)}…</code>
                      </td>
                      <td className="px-3 py-2"><Chip tone="default">{r.type}</Chip></td>
                      <td className="px-3 py-2">
                        <Chip tone={TONE[r.verdict]}>{r.verdict}</Chip>
                      </td>
                      <td className="px-3 py-2">
                        <VerdictBar detections={r.avDetections} total={r.avTotal} />
                      </td>
                      <td className="px-3 py-2 font-mono text-sm text-foreground/80">{r.malware}</td>
                      <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{r.firstSeen}</td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                          <button onClick={() => { locker.add({ value: r.hash, type: r.type.toLowerCase() as any, source: "/hash-lookup" }); toast("Added to locker"); }}
                            className="grid h-6 w-6 place-items-center rounded text-muted-foreground hover:text-primary" title="Add to locker">
                            <Database className="h-3 w-3" />
                          </button>
                          <button onClick={() => { copyText(r.hash); setCopied(r.hash); setTimeout(() => setCopied(""), 1200); }}
                            className="grid h-6 w-6 place-items-center rounded text-muted-foreground hover:text-primary">
                            {copied === r.hash ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                          </button>
                          <a href={`https://www.virustotal.com/gui/search/${r.hash}`} target="_blank" rel="noopener noreferrer"
                            className="grid h-6 w-6 place-items-center rounded text-muted-foreground hover:text-primary"
                            title="Search on VirusTotal">
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="border-t border-border bg-card/30 px-3 py-1.5 text-right text-mono text-[10px] text-muted-foreground">
              {stats.malicious > 0
                ? `${stats.malicious}/${stats.total} malicious (${Math.round((stats.malicious / stats.total) * 100)}%)`
                : `${stats.total} hashes checked — all clear`
              }
            </div>
          </Panel>
        </>
      )}

      {lookedUp && results.length === 0 && (
        <Empty icon={Hash} title="No valid hashes to look up" hint="Paste one or more valid hashes above and click Lookup All. Supported: MD5, SHA1, SHA256, SHA512." />
      )}

      {lookedUp && results.length > 0 && (
        <SendToRow targets={[
          { label: "Detection Editor", to: "/detection", icon: Search },
          { label: "Case Notebook", to: "/case", icon: Hash },
        ]} />
      )}
    </PageShell>
  );
}
