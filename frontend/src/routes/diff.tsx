import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import ReactDiffViewer from "react-diff-viewer-continued";
import { PageShell } from "@/components/PageShell";
import { Panel, Chip, SendToRow } from "@/components/soc";
import { Code2, FileText, Monitor, ScrollText, Search, ArrowUpDown, AlertTriangle, Copy, Check, Database } from "lucide-react";
import { toast } from "sonner";
import { pushTimelineEvent } from "@/lib/timeline";
import { useLocker } from "@/lib/locker";
import { copyText } from "@/lib/copy";

export const Route = createFileRoute("/diff")({ component: DiffPage });

const SAMPLES: Record<string, { old: string; new: string }> = {
  "Nmap scans": {
    old: `PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http
443/tcp open  https
3306/tcp closed mysql
8080/tcp open  http-proxy`,
    new: `PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http
443/tcp open  https
3306/tcp open   mysql
8080/tcp closed http-proxy
8443/tcp open  https-alt`,
  },
  "Email headers": {
    old: `Received: from mail.evil.com (203.0.113.44)
  by mx.example.org with ESMTPS
SPF: fail
DKIM: fail
DMARC: fail
Reply-To: support@evil.com`,
    new: `Received: from mail.legit.com (198.51.100.22)
  by mx.example.org with ESMTPS
SPF: pass
DKIM: pass
DMARC: pass
Reply-To: support@legit.com`,
  },
  "JSON reports": {
    old: JSON.stringify({ version: "1.0", iocs: { ip: [], domain: [] }, verdict: "clean" }, null, 2),
    new: JSON.stringify({ version: "2.0", iocs: { ip: ["1.2.3.4"], domain: ["evil.com"] }, verdict: "malicious", mitre: ["T1566"] }, null, 2),
  },
};

function extractIOCs(text: string): { ips: string[]; domains: string[]; urls: string[]; hashes: string[] } {
  const ips = [...new Set(text.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || [])];
  const domains = [...new Set(text.match(/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g) || [])].filter(d => !d.startsWith("mail.") && !d.startsWith("mx."));
  const urls = [...new Set(text.match(/https?:\/\/[^\s)"']+/g) || [])];
  const hashes = [...new Set(text.match(/\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi) || [])];
  return { ips, domains, urls, hashes };
}

function DiffPage() {
  const locker = useLocker();
  const [oldText, setOldText] = useState("");
  const [newText, setNewText] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") setSearchQuery("");
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  function loadSample(key: string) {
    const s = SAMPLES[key];
    if (s) { setOldText(s.old); setNewText(s.new); pushTimelineEvent({ source: "diff", verb: "loaded", detail: key, result: "sample" }); }
  }

  const stats = useMemo(() => {
    if (!oldText && !newText) return null;
    const oldLines = oldText ? oldText.split("\n") : [];
    const newLines = newText ? newText.split("\n") : [];
    const added = newLines.filter((l) => !oldLines.includes(l)).length;
    const removed = oldLines.filter((l) => !newLines.includes(l)).length;
    const unchanged = newLines.filter((l) => oldLines.includes(l)).length;
    return { added, removed, unchanged, oldSize: oldText.length, newSize: newText.length, netChange: newText.length - oldText.length };
  }, [oldText, newText]);

  const oldIocs = useMemo(() => extractIOCs(oldText), [oldText]);
  const newIocs = useMemo(() => extractIOCs(newText), [newText]);

  const newIps = newIocs.ips.filter(ip => !oldIocs.ips.includes(ip));
  const newDomains = newIocs.domains.filter(d => !oldIocs.domains.includes(d));
  const newHashes = newIocs.hashes.filter(h => !oldIocs.hashes.includes(h));

  useEffect(() => {
    if (stats && stats.added + stats.removed > 0) pushTimelineEvent({ source: "diff", verb: "compared", detail: `${stats.added} added, ${stats.removed} removed`, result: `${newIps.length + newDomains.length + newHashes.length} new IOCs` });
  }, [stats]);

  const filteredOldText = useMemo(() => {
    if (!searchQuery.trim()) return oldText;
    return oldText.split("\n").filter(l => l.toLowerCase().includes(searchQuery.toLowerCase())).join("\n");
  }, [oldText, searchQuery]);

  const filteredNewText = useMemo(() => {
    if (!searchQuery.trim()) return newText;
    return newText.split("\n").filter(l => l.toLowerCase().includes(searchQuery.toLowerCase())).join("\n");
  }, [newText, searchQuery]);

  return (
    <PageShell
      eyebrow="TOOLS / DIFF"
      title="Diff View"
      description="Side-by-side comparison for artifacts — nmap scans, email headers, Sigma rules, JSON blobs. Highlights IOCs added or removed."
      crumbs={[{ label: "Tools" }, { label: "Diff" }]}
      actions={
        <div className="flex items-center gap-1.5">
          {Object.keys(SAMPLES).map((k) => (
            <button key={k} onClick={() => loadSample(k)}
              className="inline-flex items-center gap-1 rounded border border-border bg-card/40 px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:border-primary/40 hover:text-primary">
              <FileText className="h-3 w-3" /> {k}
            </button>
          ))}
        </div>
      }
    >
      <div className="grid grid-cols-2 gap-4">
        <Panel title="Original" icon={Code2}>
          <textarea
            value={oldText}
            onChange={(e) => setOldText(e.target.value)}
            placeholder="Paste original content..."
            className="h-64 w-full resize-y rounded border border-border bg-background/60 p-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
          />
        </Panel>
        <Panel title="Changed" icon={ScrollText}>
          <textarea
            value={newText}
            onChange={(e) => setNewText(e.target.value)}
            placeholder="Paste modified content..."
            className="h-64 w-full resize-y rounded border border-border bg-background/60 p-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
          />
        </Panel>
      </div>

      {(oldText || newText) && stats && (
        <>
          <div className="flex items-center gap-3 px-1">
            <div className="flex items-center gap-1 text-mono text-[10px] text-muted-foreground">
              <span className="inline-block h-2.5 w-5 rounded bg-[rgba(34,197,94,0.2)]" />
              <span className="text-success">+{stats.added}</span> added
            </div>
            <div className="flex items-center gap-1 text-mono text-[10px] text-muted-foreground">
              <span className="inline-block h-2.5 w-5 rounded bg-[rgba(239,68,68,0.2)]" />
              <span className="text-destructive">-{stats.removed}</span> removed
            </div>
            <span className="text-mono text-[10px] text-muted-foreground">
              {stats.unchanged} unchanged · {stats.netChange > 0 ? "+" : ""}{stats.netChange} bytes net
            </span>
            <div className="ml-auto flex items-center gap-2">
              {searchQuery && (
                <span className="text-mono text-[10px] text-muted-foreground">
                  Filtering: "{searchQuery}"
                </span>
              )}
              <div className="relative">
                <Search className="absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground/60" />
                <input
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search diff…"
                  className="w-40 rounded border border-border bg-background/40 py-1 pl-6 pr-2 font-mono text-[11px] text-foreground outline-none placeholder:text-muted-foreground/50"
                />
              </div>
            </div>
          </div>

          {(newIps.length > 0 || newDomains.length > 0 || newHashes.length > 0) && (
            <div className="rounded border border-warning/30 bg-warning/5 px-3 py-2">
              <div className="flex items-center gap-1.5 text-mono text-[10px] uppercase tracking-widest text-warning mb-1.5">
                <AlertTriangle className="h-3 w-3" /> New IOCs in changed version
              </div>
              <div className="flex flex-wrap gap-2">
                {newIps.slice(0, 5).map(ip => <Chip key={ip} tone="destructive" actions={<button onClick={() => { locker.add({ value: ip, type: "ip", source: "/diff" }); toast("Added IP to locker"); }} className="grid h-3.5 w-3.5 place-items-center text-muted-foreground hover:text-primary"><Database className="h-3 w-3" /></button>}>{ip}</Chip>)}
                {newDomains.slice(0, 5).map(d => <Chip key={d} tone="warning" actions={<button onClick={() => { locker.add({ value: d, type: "domain", source: "/diff" }); toast("Added domain to locker"); }} className="grid h-3.5 w-3.5 place-items-center text-muted-foreground hover:text-primary"><Database className="h-3 w-3" /></button>}>{d}</Chip>)}
                {newHashes.slice(0, 3).map(h => <Chip key={h} tone="destructive" actions={<button onClick={() => { locker.add({ value: h, type: "hash", source: "/diff" }); toast("Added hash to locker"); }} className="grid h-3.5 w-3.5 place-items-center text-muted-foreground hover:text-primary"><Database className="h-3 w-3" /></button>}>{h.slice(0, 16)}…</Chip>)}
                {(newIps.length + newDomains.length + newHashes.length) > 13 && (
                  <Chip tone="default">+{newIps.length + newDomains.length + newHashes.length - 13} more</Chip>
                )}
              </div>
            </div>
          )}

          <Panel
            title="Diff"
            icon={Monitor}
            actions={
              <button onClick={() => { copyText(JSON.stringify({ added: newText, removed: oldText, stats }, null, 2)); setCopied(true); setTimeout(() => setCopied(false), 1200); }}
                className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
                {copied ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> export</>}
              </button>
            }
          >
            <div className="overflow-auto rounded border border-border/50 [&_*]:!font-mono [&_*]:!text-[12px]">
              <ReactDiffViewer
                oldValue={filteredOldText}
                newValue={filteredNewText}
                splitView={true}
                showDiffOnly={false}
                leftTitle="Original"
                rightTitle="Changed"
                styles={{
                  variables: { dark: { diffViewerBackground: "transparent", addedBackground: "rgba(34,197,94,0.08)", removedBackground: "rgba(239,68,68,0.08)", addedGutterBackground: "rgba(34,197,94,0.12)", removedGutterBackground: "rgba(239,68,68,0.12)", gutterBackground: "transparent", gutterColor: "#666", addedColor: "#4ade80", removedColor: "#f87171", diffViewerColor: "#ccc", emptyLineBackground: "rgba(0,0,0,0.05)", wordAddedBackground: "rgba(34,197,94,0.2)", wordRemovedBackground: "rgba(239,68,68,0.2)" } },
                }}
              />
            </div>
          </Panel>
        </>
      )}

      {!oldText && !newText && (
        <div className="flex flex-col items-center gap-2 py-12 text-mono text-sm text-muted-foreground">
          <ArrowUpDown className="h-8 w-8 opacity-40" />
          <p>Paste two versions of an artifact above</p>
          <p className="text-[10px]">Or load a sample — see what changed between good and bad</p>
        </div>
      )}

      {stats && (newIps.length + newDomains.length + newHashes.length) > 0 && (
        <div className="mt-4">
          <SendToRow targets={[
            { label: "Case Notebook", to: "/case", icon: Database },
            { label: "Hash Lookup", to: "/hash-lookup", icon: Search },
          ]} />
        </div>
      )}
    </PageShell>
  );
}
