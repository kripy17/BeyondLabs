import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { SectionBar, Panel, Chip, ResultBanner, KeyFields, Empty, SendToRow } from "@/components/soc/Workspace";
import {
  Notebook, Plus, Copy, Download, Trash2, FileText, Tag, X,
  ArrowRight, Database, ShieldAlert, Pencil, Check, Search, FolderOpen,
} from "lucide-react";

export const Route = createFileRoute("/case")({ component: CasePage });

type EntryKind = "note" | "evidence" | "decision" | "action" | "ioc";
type Entry = { id: string; ts: string; kind: EntryKind; body: string };
type Case = {
  id: string;
  title: string;
  tags: string[];
  createdAt: string;
  state: "active" | "closed";
  entries: Entry[];
};

const LS_KEY = "ba.cases.v2";
const LS_ACTIVE = "ba.cases.active";

const KIND_TONE: Record<EntryKind, "default" | "primary" | "warning" | "success" | "destructive"> = {
  note: "default", evidence: "primary", decision: "warning", action: "success", ioc: "destructive",
};

function loadCases(): Case[] {
  try { const raw = localStorage.getItem(LS_KEY); return raw ? JSON.parse(raw) as Case[] : []; }
  catch { return []; }
}
function saveCases(list: Case[]) {
  try { localStorage.setItem(LS_KEY, JSON.stringify(list)); } catch { /* noop */ }
}
function newId(prefix: string) {
  return `${prefix}-${Math.random().toString(36).slice(2, 8)}`;
}
function newCaseTitle() {
  const d = new Date();
  const yy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  return `BA-${yy}${mm}${dd}-${hh}${mi}`;
}

function CasePage() {
  const [cases, setCases] = useState<Case[]>([]);
  const [activeId, setActiveId] = useState<string>("");
  const [draft, setDraft] = useState("");
  const [kind, setKind] = useState<EntryKind>("note");
  const [editingTitle, setEditingTitle] = useState(false);
  const [titleDraft, setTitleDraft] = useState("");
  const [tagDraft, setTagDraft] = useState("");
  const [search, setSearch] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const list = loadCases();
    if (list.length === 0) {
      const c: Case = { id: newId("c"), title: newCaseTitle(), tags: [], createdAt: new Date().toISOString(), state: "active", entries: [] };
      setCases([c]); setActiveId(c.id); saveCases([c]);
      return;
    }
    setCases(list);
    const remembered = localStorage.getItem(LS_ACTIVE);
    setActiveId(remembered && list.some(c => c.id === remembered) ? remembered : list[0].id);
  }, []);

  useEffect(() => { if (cases.length) saveCases(cases); }, [cases]);
  useEffect(() => { if (activeId) try { localStorage.setItem(LS_ACTIVE, activeId); } catch {/* noop */} }, [activeId]);

  const active = cases.find(c => c.id === activeId);

  const filteredCases = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return cases;
    return cases.filter(c =>
      c.title.toLowerCase().includes(q) ||
      c.tags.some(t => t.toLowerCase().includes(q)) ||
      c.entries.some(e => e.body.toLowerCase().includes(q)),
    );
  }, [cases, search]);

  function updateActive(fn: (c: Case) => Case) {
    setCases(prev => prev.map(c => c.id === activeId ? fn(c) : c));
  }

  function addEntry() {
    if (!draft.trim() || !active) return;
    const e: Entry = { id: newId("e"), ts: new Date().toISOString(), kind, body: draft.trim() };
    updateActive(c => ({ ...c, entries: [...c.entries, e] }));
    setDraft("");
  }

  function removeEntry(id: string) {
    updateActive(c => ({ ...c, entries: c.entries.filter(e => e.id !== id) }));
  }

  function addTag() {
    const t = tagDraft.trim().toLowerCase().replace(/\s+/g, "-");
    if (!t || !active || active.tags.includes(t)) { setTagDraft(""); return; }
    updateActive(c => ({ ...c, tags: [...c.tags, t] }));
    setTagDraft("");
  }
  function removeTag(t: string) { updateActive(c => ({ ...c, tags: c.tags.filter(x => x !== t) })); }

  function createCase() {
    const c: Case = { id: newId("c"), title: newCaseTitle(), tags: [], createdAt: new Date().toISOString(), state: "active", entries: [] };
    setCases(prev => [c, ...prev]); setActiveId(c.id);
  }
  function deleteCase(id: string) {
    if (!confirm("Delete this case? This cannot be undone.")) return;
    const remaining = cases.filter(c => c.id !== id);
    setCases(remaining);
    if (remaining.length === 0) createCase();
    else if (id === activeId) setActiveId(remaining[0].id);
  }
  function toggleClosed() {
    updateActive(c => ({ ...c, state: c.state === "active" ? "closed" : "active" }));
  }

  const markdown = useMemo(() => {
    if (!active) return "";
    const lines: string[] = [];
    lines.push(`# ${active.title}`);
    lines.push("");
    lines.push(`- **id:** \`${active.id}\``);
    lines.push(`- **opened:** ${active.createdAt}`);
    lines.push(`- **state:** ${active.state}`);
    lines.push(`- **tags:** ${active.tags.length ? active.tags.map(t => `\`${t}\``).join(", ") : "_none_"}`);
    lines.push(`- **entries:** ${active.entries.length}`);
    lines.push("");
    lines.push("## Timeline");
    lines.push("");
    if (active.entries.length === 0) lines.push("_no entries yet_");
    active.entries.forEach(e => {
      lines.push(`- \`${e.ts}\` **[${e.kind}]** ${e.body}`);
    });
    return lines.join("\n");
  }, [active]);

  const counts = useMemo(() => {
    const c: Record<EntryKind, number> = { note: 0, evidence: 0, decision: 0, action: 0, ioc: 0 };
    active?.entries.forEach(e => { c[e.kind] += 1; });
    return c;
  }, [active]);

  async function copyMd() {
    try { await navigator.clipboard.writeText(markdown); setCopied(true); setTimeout(() => setCopied(false), 1400); } catch {/* noop */}
  }
  function download() {
    const blob = new Blob([markdown], { type: "text/markdown;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${active?.title ?? "case"}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <PageShell
      eyebrow="CASE / NOTEBOOK"
      title="Case Notebook"
      description="Append-only timelines you build yourself. Nothing is pre-populated. Cases are persisted in this browser."
      crumbs={[{ label: "Case" }]}
      meta={[
        { label: "cases", value: String(cases.length), tone: "primary" },
        { label: "active", value: cases.filter(c => c.state === "active").length + "" },
      ]}
      actions={
        <button onClick={createCase} className="inline-flex items-center gap-1.5 rounded-md border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono text-[10px] uppercase tracking-widest text-primary hover:bg-primary/20">
          <Plus className="h-3 w-3" /> new case
        </button>
      }
    >
      {active && (
        <ResultBanner
          badge={active.state === "active" ? "case_open" : "case_closed"}
          caseId={active.id}
          title={active.title}
          subtitle={active.tags.length ? `tags · ${active.tags.join(" · ")}` : "no tags yet"}
          metrics={[
            { label: "Entries", value: active.entries.length, tone: "primary" },
            { label: "Evidence", value: counts.evidence },
            { label: "Decisions", value: counts.decision, tone: "warning" },
            { label: "Actions", value: counts.action, tone: "success" },
            { label: "IOCs", value: counts.ioc, tone: "destructive" },
          ]}
        />
      )}

      <div className="grid gap-4 grid-cols-[minmax(0,18rem)_minmax(0,1fr)]">
        <div className="space-y-3 sticky top-16 self-start">
          <Panel bodyClassName="p-0">
            <div className="border-b border-border p-2">
              <div className="relative">
                <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="search cases…"
                  className="w-full rounded-md border border-border bg-background/60 py-1.5 pl-7 pr-2 text-mono text-[11px] text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
                />
              </div>
            </div>
            <nav className="max-h-[calc(100vh-20rem)] overflow-auto p-1.5">
              {filteredCases.length === 0 && (
                <div className="p-4 text-center text-mono text-[10.5px] uppercase text-muted-foreground">no matches</div>
              )}
              <ul className="space-y-1">
                {filteredCases.map(c => {
                  const isActive = c.id === activeId;
                  return (
                    <li key={c.id}>
                      <button
                        onClick={() => setActiveId(c.id)}
                        className={
                          "group flex w-full items-start gap-2 rounded-md border px-2 py-2 text-left transition-colors " +
                          (isActive ? "border-primary/50 bg-primary/10" : "border-transparent hover:border-border hover:bg-card/60")
                        }
                      >
                        <FolderOpen className={"mt-0.5 h-3.5 w-3.5 shrink-0 " + (isActive ? "text-primary" : "text-muted-foreground")} />
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-2">
                            <span className="truncate text-mono text-[11px] uppercase tracking-widest text-foreground/90">{c.title}</span>
                            <Chip tone={c.state === "active" ? "warning" : "default"}>{c.state}</Chip>
                          </div>
                          <div className="mt-0.5 flex items-center gap-2 text-mono text-[10px] text-muted-foreground">
                            <span>{c.entries.length} entries</span>
                            {c.tags[0] && <><span>·</span><span className="truncate">{c.tags.slice(0, 2).join(", ")}</span></>}
                          </div>
                        </div>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </nav>
          </Panel>
        </div>

        <div className="min-w-0 space-y-4">
          {!active ? (
            <Empty title="No case selected" hint="Create a new case or pick one from the sidebar." />
          ) : (
            <>
              <Panel>
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Case title</div>
                    {editingTitle ? (
                      <div className="mt-1 flex items-center gap-2">
                        <input
                          autoFocus
                          value={titleDraft}
                          onChange={e => setTitleDraft(e.target.value)}
                          onKeyDown={e => { if (e.key === "Enter") { updateActive(c => ({ ...c, title: titleDraft.trim() || c.title })); setEditingTitle(false); } if (e.key === "Escape") setEditingTitle(false); }}
                          className="min-w-0 flex-1 rounded border border-border bg-background/60 px-2 py-1 text-mono text-[13px] text-foreground outline-none focus:border-primary/50"
                        />
                        <button onClick={() => { updateActive(c => ({ ...c, title: titleDraft.trim() || c.title })); setEditingTitle(false); }} className="rounded border border-success/50 bg-success/10 px-2 py-1 text-mono text-[10px] uppercase text-success"><Check className="h-3 w-3" /></button>
                      </div>
                    ) : (
                      <button onClick={() => { setTitleDraft(active.title); setEditingTitle(true); }} className="group mt-1 flex items-center gap-2 text-left">
                        <span className="text-mono text-[13.5px] text-foreground">{active.title}</span>
                        <Pencil className="h-3 w-3 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
                      </button>
                    )}
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      {active.tags.map(t => (
                        <span key={t} className="inline-flex items-center gap-1 rounded border border-border bg-background/60 px-1.5 py-0.5 text-mono text-[10px] text-foreground/85">
                          <Tag className="h-2.5 w-2.5 text-primary/70" /> {t}
                          <button onClick={() => removeTag(t)} className="text-muted-foreground hover:text-destructive"><X className="h-2.5 w-2.5" /></button>
                        </span>
                      ))}
                      <input
                        value={tagDraft}
                        onChange={e => setTagDraft(e.target.value)}
                        onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); addTag(); } }}
                        placeholder="add tag…"
                        className="rounded border border-dashed border-border/70 bg-background/40 px-1.5 py-0.5 text-mono text-[10px] text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
                      />
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <button onClick={toggleClosed} className="inline-flex items-center gap-1 rounded border border-border bg-card/40 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:border-primary/50 hover:text-primary">
                      {active.state === "active" ? "close case" : "re-open"}
                    </button>
                    <button onClick={() => deleteCase(active.id)} className="inline-flex items-center gap-1 rounded border border-border bg-card/40 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:border-destructive/50 hover:text-destructive">
                      <Trash2 className="h-3 w-3" /> delete
                    </button>
                  </div>
                </div>
              </Panel>

              <SectionBar id="IN" label="Intake · new entry" />
              <Panel>
                <div className="mb-2 flex flex-wrap items-center gap-1.5">
                  {(["note", "evidence", "decision", "action", "ioc"] as EntryKind[]).map(k => (
                    <button
                      key={k}
                      onClick={() => setKind(k)}
                      className={"rounded border px-2 py-1 text-mono text-[10px] uppercase tracking-widest " + (kind === k ? "border-primary bg-primary/15 text-primary" : "border-border text-muted-foreground hover:text-foreground")}
                    >{k}</button>
                  ))}
                </div>
                <textarea
                  value={draft}
                  onChange={e => setDraft(e.target.value)}
                  onKeyDown={e => { if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); addEntry(); } }}
                  rows={3}
                  placeholder="What did you observe / decide / do? (⌘/Ctrl + Enter to append)"
                  className="w-full resize-y rounded border border-border/60 bg-background/60 p-2 text-mono text-[12px] text-foreground outline-none focus:border-primary/50"
                />
                <div className="mt-2 flex items-center justify-between">
                  <span className="text-mono text-[10px] text-muted-foreground">{draft.length} chars</span>
                  <button
                    onClick={addEntry}
                    disabled={!draft.trim()}
                    className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono text-[10px] uppercase text-primary disabled:opacity-40"
                  >
                    <Plus className="h-3 w-3" /> append
                  </button>
                </div>
              </Panel>

              <SectionBar id="OT" label="Timeline" meta={`${active.entries.length} entries`} />
              <Panel title="Case timeline" icon={Notebook} bodyClassName="p-0">
                {active.entries.length === 0 ? (
                  <div className="p-4"><Empty title="No entries yet" hint="Append your first observation, decision, or IOC above." /></div>
                ) : (
                  <ul className="divide-y divide-border/50">
                    {[...active.entries].reverse().map(e => {
                      const d = new Date(e.ts);
                      const short = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
                      return (
                        <li key={e.id} className="group grid grid-cols-[70px_100px_1fr_auto] items-start gap-3 px-4 py-2.5">
                          <div className="text-mono text-[10px] text-muted-foreground" title={e.ts}>{short}</div>
                          <div><Chip tone={KIND_TONE[e.kind]}>{e.kind}</Chip></div>
                          <div className="whitespace-pre-wrap text-[12px] text-foreground/90">{e.body}</div>
                          <button
                            onClick={() => removeEntry(e.id)}
                            className="opacity-0 transition-opacity group-hover:opacity-100 text-muted-foreground hover:text-destructive"
                            title="Delete entry"
                          >
                            <Trash2 className="h-3 w-3" />
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </Panel>

              <Panel title="Case metadata">
                <KeyFields items={[
                  { label: "ID", value: active.id, tone: "primary" },
                  { label: "Opened", value: new Date(active.createdAt).toLocaleString() },
                  { label: "State", value: active.state, tone: active.state === "active" ? "warning" : "default" },
                  { label: "Entries", value: active.entries.length, tone: "primary" },
                ]} />
              </Panel>

              <Panel
                title="Report (markdown)"
                icon={FileText}
                actions={
                  <>
                    <button onClick={copyMd} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground">
                      {copied ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> copy</>}
                    </button>
                    <button onClick={download} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground">
                      <Download className="h-3 w-3" /> .md
                    </button>
                  </>
                }
              >
                <pre className="max-h-80 overflow-auto rounded bg-background/60 p-3 text-mono text-[11px] text-foreground/90">{markdown}</pre>
              </Panel>

              <SendToRow targets={[
                { label: "Detection", to: "/detection", icon: ShieldAlert },
                { label: "MITRE Coverage", to: "/mitre", icon: ArrowRight },
                { label: "Logs & Alerts", to: "/logs", icon: Database },
              ]} />
            </>
          )}
        </div>
      </div>
    </PageShell>
  );
}
