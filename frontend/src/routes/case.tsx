import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { SectionBar, Panel, Chip, ResultBanner, KeyFields, Empty, SendToRow, EvidenceCard, IocInventory } from "@/components/soc/Workspace";
import { Notebook, Plus, Copy, ArrowRight, Database, ShieldAlert, Download, Hash } from "lucide-react";

export const Route = createFileRoute("/case")({ component: CasePage });

type Entry = { id: number; ts: string; kind: "note" | "evidence" | "decision" | "action"; body: string };

function genReport(title: string, tags: string[], entries: Entry[]): string {
  return [
    `# ${title}`,
    `**Tags:** ${tags.join(", ") || "—"}`,
    `**Exported:** ${new Date().toISOString()}`,
    "", "## Timeline",
    ...entries.map((e) => `- [${e.ts}] **${e.kind}**: ${e.body}`),
    "", `---\n*${entries.length} entries*`,
  ].join("\n");
}

function extractIocs(entries: Entry[]): { ips: string[]; urls: string[]; hashes: string[] } {
  const text = entries.map((e) => e.body).join("\n");
  return {
    ips: Array.from(new Set(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [])),
    urls: Array.from(new Set(text.match(/https?:\/\/[^\s"']+/g) ?? [])),
    hashes: Array.from(new Set(text.match(/\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b/g) ?? [])),
  };
}

function CasePage() {
  const [title, setTitle] = useState("");
  const [tags, setTags] = useState<string[]>([]);
  const [entries, setEntries] = useState<Entry[]>([]);
  const [draft, setDraft] = useState("");
  const [kind, setKind] = useState<Entry["kind"]>("note");

  const add = () => {
    if (!draft.trim()) return;
    setEntries((e) => [...e, { id: e.length + 1, ts: new Date().toTimeString().slice(0, 5), kind, body: draft.trim() }]);
    setDraft("");
  };

  const iocs = useMemo(() => extractIocs(entries), [entries]);
  const report = genReport(title, tags, entries);
  const evidenceCount = entries.filter((e) => e.kind === "evidence").length;
  const decisionCount = entries.filter((e) => e.kind === "decision").length;
  const actionCount = entries.filter((e) => e.kind === "action").length;
  const findings = useMemo(() => {
    const f: { sev: "destructive" | "warning" | "info"; title: string; reason: string; action: string }[] = [];
    if (tags.some((t) => /phish|malware|c2|ransom/i.test(t))) f.push({ sev: "destructive", title: "Malicious classification", reason: `Tags indicate malicious activity: ${tags.filter((t) => /phish|malware|c2|ransom/i.test(t)).join(", ")}`, action: "Escalate to incident lead; begin containment." });
    if (actionCount > 0) f.push({ sev: "warning", title: `${actionCount} remediation action(s) logged`, reason: "Containment steps have been taken. Verify completion and effectiveness.", action: "Follow up within 24h to confirm remediation." });
    if (evidenceCount === 0) f.push({ sev: "info", title: "No evidence entries", reason: "Case lacks raw evidence — consider adding forensic artifacts.", action: "Collect logs, screenshots, or email source into the timeline." });
    if (entries.length >= 5) f.push({ sev: "info", title: `Case has ${entries.length} entries`, reason: "Well-documented timeline reduces ambiguity during handoff.", action: "Continue logging until case closure." });
    if (!f.length) f.push({ sev: "info", title: "Case opened", reason: "Timeline started — continue documenting findings.", action: "Add evidence entries as analysis progresses." });
    return f;
  }, [tags, actionCount, evidenceCount, entries.length]);

  return (
    <PageShell
      eyebrow="CASE / NOTEBOOK"
      title="Case Notebook"
      description="Append-only timeline that captures evidence, decisions, and actions in one place."
      crumbs={[{ label: "Case" }]}
    >
      <ResultBanner
        badge="case_open"
        caseId={title.split(" ")[0]}
        title={title}
        subtitle={`tags: ${tags.join(", ") || "—"}`}
        metrics={[
          { label: "Entries", value: entries.length, tone: "primary" },
          { label: "Evidence", value: evidenceCount },
          { label: "Decisions", value: decisionCount, tone: "warning" },
          { label: "Actions", value: actionCount, tone: "success" },
        ]}
      />

      <div className="grid gap-3 md:grid-cols-2">
        {findings.map((f, i) => (
          <EvidenceCard key={i} severity={f.sev} title={f.title} reason={f.reason} action={f.action} limitation="Case assessment based on tags and entry distribution." />
        ))}
      </div>

      <SectionBar id="IN" label="Intake · new entry" />
      <Panel>
        <div className="flex flex-wrap items-center gap-2 mb-2">
          {(["note", "evidence", "decision", "action"] as Entry["kind"][]).map((k) => (
            <button key={k} onClick={() => setKind(k)} className={"rounded border px-2 py-1 text-mono text-[10px] uppercase tracking-widest " + (kind === k ? "border-primary bg-primary/15 text-primary" : "border-border text-muted-foreground hover:text-foreground")}>{k}</button>
          ))}
        </div>
        <textarea value={draft} onChange={(e) => setDraft(e.target.value)} rows={3} placeholder="What did you observe / decide / do?" className="w-full resize-y rounded bg-background/60 p-2 text-mono text-[12px] text-foreground outline-none" />
        <div className="mt-2 flex justify-end">
          <button onClick={add} className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono text-[10px] uppercase text-primary"><Plus className="h-3 w-3" /> append</button>
        </div>
      </Panel>

      <SectionBar id="OT" label="Output · timeline" meta={`${entries.length} entries`} />
      <Panel title="Case timeline" icon={Notebook} bodyClassName="p-0">
        {entries.length === 0 ? <div className="p-4"><Empty title="No entries yet" /></div> : (
          <ul className="divide-y divide-border/50">
            {entries.map((e) => (
              <li key={e.id} className="flex gap-3 px-4 py-2.5">
                <div className="w-12 shrink-0 text-mono text-[10px] text-muted-foreground">{e.ts}</div>
                <div className="w-20 shrink-0"><Chip tone={e.kind === "evidence" ? "primary" : e.kind === "decision" ? "warning" : e.kind === "action" ? "success" : "default"}>{e.kind}</Chip></div>
                <div className="flex-1 text-[12px] text-foreground/90">{e.body}</div>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <div className="grid gap-3 lg:grid-cols-[2fr_1fr]">
        <Panel title="Case metadata">
          <KeyFields items={[
            { label: "Title", value: title, tone: "primary" },
            { label: "Tags", value: tags.join(", ") },
            { label: "Opened", value: "today 10:42" },
            { label: "State", value: "active", tone: "warning" },
          ]} />
        </Panel>
        <Panel title="IOCs in case" icon={Hash} meta={`${iocs.ips.length + iocs.urls.length + iocs.hashes.length} total`}>
          <KeyFields items={[
            { label: "IPs", value: iocs.ips.length ? iocs.ips.join(", ") : "—" },
            { label: "URLs", value: iocs.urls.length ? iocs.urls.join(", ") : "—" },
            { label: "Hashes", value: iocs.hashes.length ? iocs.hashes.join(", ") : "—" },
          ]} />
        </Panel>
      </div>

      <IocInventory groups={[
        { kind: "IPv4", items: iocs.ips, tone: "warning" },
        { kind: "URL", items: iocs.urls, tone: "warning" },
        { kind: "Hash", items: iocs.hashes, tone: "warning" },
      ]} onSendTo={() => {}} />

      <Panel title="Report (markdown)" actions={
        <div className="flex items-center gap-1">
          <button onClick={() => navigator.clipboard.writeText(report)} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground"><Copy className="h-3 w-3" /> copy</button>
          <button onClick={() => { const blob = new Blob([report], { type: "text/markdown" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `case-${Date.now()}.md`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> md</button>
        </div>
      }>
        <pre className="max-h-72 overflow-auto rounded bg-background/60 p-3 text-mono text-[11px] text-foreground/90">{report}</pre>
      </Panel>

      <SendToRow targets={[
        { label: "Detection", to: "/detection", icon: ShieldAlert },
        { label: "MITRE Coverage", to: "/mitre", icon: ArrowRight },
        { label: "Logs & Alerts", to: "/logs", icon: Database },
      ]} />
    </PageShell>
  );
}
