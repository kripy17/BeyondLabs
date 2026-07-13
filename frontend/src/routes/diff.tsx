import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import ReactDiffViewer from "react-diff-viewer-continued";
import { PageShell } from "@/components/PageShell";
import { Panel, Chip } from "@/components/soc";
import { Code2, FileText, Monitor, ScrollText } from "lucide-react";

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

function DiffPage() {
  const [oldText, setOldText] = useState("");
  const [newText, setNewText] = useState("");

  function loadSample(key: string) {
    const s = SAMPLES[key];
    if (s) { setOldText(s.old); setNewText(s.new); }
  }

  return (
    <PageShell
      eyebrow="TOOLS / DIFF"
      title="Diff View"
      description="Side-by-side comparison for artifacts — nmap scans, email headers, Sigma rules, JSON blobs"
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

      {(oldText || newText) && (
        <Panel title="Diff" icon={Monitor}>
          <div className="overflow-auto rounded border border-border/50 [&_*]:!font-mono [&_*]:!text-[12px]">
            <ReactDiffViewer
              oldValue={oldText}
              newValue={newText}
              splitView={true}
              showDiffOnly={false}
              leftTitle="Original"
              rightTitle="Changed"
              styles={{
                variables: { dark: { diffViewerBackground: "transparent", addedBackground: "rgba(34,197,94,0.08)", removedBackground: "rgba(239,68,68,0.08)", addedGutterBackground: "rgba(34,197,94,0.12)", removedGutterBackground: "rgba(239,68,68,0.12)", gutterBackground: "transparent", gutterColor: "#666", addedColor: "#4ade80", removedColor: "#f87171", diffViewerColor: "#ccc", emptyLineBackground: "rgba(0,0,0,0.05)", wordAddedBackground: "rgba(34,197,94,0.2)", wordRemovedBackground: "rgba(239,68,68,0.2)" } },
              }}
            />
          </div>
          <div className="mt-2 flex items-center gap-2 text-mono text-[10px] text-muted-foreground">
            <span className="flex items-center gap-1"><span className="inline-block h-2.5 w-5 rounded bg-[rgba(34,197,94,0.2)]" /> additions</span>
            <span className="flex items-center gap-1"><span className="inline-block h-2.5 w-5 rounded bg-[rgba(239,68,68,0.2)]" /> deletions</span>
          </div>
        </Panel>
      )}
    </PageShell>
  );
}
