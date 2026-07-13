import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import { takePendingCaseEntry } from "@/lib/handoff";
import { pushTimelineEvent } from "@/lib/timeline";
import { useLocker, guessType } from "@/lib/locker";
import { PageShell } from "@/components/PageShell";
import { SectionBar, Panel, Chip, SendToRow } from "@/components/soc";
import { ResultBanner, KeyFields, Empty } from "@/components/output";
import { CopyAsDropdown } from "@/components/CopyAsDropdown";
import {
  Notebook, Plus, Copy, Download, Trash2, FileText, Tag, X,
  ArrowRight, Database, ShieldAlert, Pencil, Check, Search, FolderOpen, ClipboardList,
  StickyNote, Siren, GitBranch, Crosshair, Activity, MessageSquare,
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
const KIND_ICON: Record<EntryKind, typeof StickyNote> = {
  note: StickyNote, evidence: Search, decision: GitBranch, action: Crosshair, ioc: Siren,
};
const KIND_COLOR: Record<EntryKind, string> = {
  note: "bg-muted-foreground/40", evidence: "bg-primary/60", decision: "bg-warning/60", action: "bg-success/60", ioc: "bg-destructive/60",
};

function loadCases(): Case[] {
  try { const raw = localStorage.getItem(LS_KEY); return raw ? JSON.parse(raw) as Case[] : []; }
  catch { return []; }
}
function saveCases(list: Case[]) {
  try {
    const serialized = JSON.stringify(list);
    if (serialized.length > 5_000_000) { toast.error("Case data too large to save"); return; }
    localStorage.setItem(LS_KEY, serialized);
  } catch {
    toast.error("Failed to save cases — storage may be full");
  }
}
function newId(prefix: string) {
  return `${prefix}-${crypto.randomUUID().slice(0, 8)}`;
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

function autoDetectKind(text: string): EntryKind {
  if (!text.trim()) return "note";
  if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(text) || /https?:\/\//.test(text) || /\b[a-f0-9]{32}\b/i.test(text) || /\b[a-f0-9]{40}\b/i.test(text) || /\b[a-f0-9]{64}\b/i.test(text)) return "ioc";
  if (/^(decision|verdict|conclusion):/im.test(text)) return "decision";
  if (/^(action|todo|investigate|escalate):/im.test(text)) return "action";
  if (/\b(analysis|found|detected|evidence|observed):/im.test(text)) return "evidence";
  return "note";
}

type TemplateDef = {
  id: string;
  label: string;
  icon: import("lucide-react").LucideIcon;
  entries: { kind: EntryKind; body: string }[];
};
const CASE_TEMPLATES: TemplateDef[] = [
  {
    id: "phishing", label: "Phishing Triage", icon: ShieldAlert,
    entries: [
      { kind: "evidence", body: "## Header Analysis\n- **From:** \n- **Reply-To:** \n- **SPF:** \n- **DKIM:** \n- **DMARC:**" },
      { kind: "evidence", body: "## URL Analysis\n- **Original:** \n- **Redirect:** \n- **VT:**" },
      { kind: "evidence", body: "## Attachment\n- **Name:** \n- **Hash:** \n- **VT ratio:**" },
      { kind: "decision", body: "**Verdict:** [malicious / suspicious / benign]" },
      { kind: "action", body: "**Action:** [block sender / delete / escalate]" },
    ],
  },
  {
    id: "ransomware", label: "Ransomware Triage", icon: Siren,
    entries: [
      { kind: "evidence", body: "## Access\n- **Method:** \n- **Source IP:** \n- **User:**" },
      { kind: "evidence", body: "## Affected\n- **Hosts:** \n- **Count:**" },
      { kind: "evidence", body: "## Ransom Note\n- **File:** \n- **Contact:**" },
      { kind: "evidence", body: "## IOCs\n- **Hashes:** \n- **C2 IPs:** \n- **Registry:**" },
      { kind: "decision", body: "**Verdict:** [confirmed / suspicious / FP]" },
      { kind: "action", body: "**Action:** [isolate / block IOCs / notify]" },
    ],
  },
  {
    id: "suspicious-login", label: "Suspicious Login", icon: Activity,
    entries: [
      { kind: "evidence", body: "## Event\n- **Time:** \n- **User:** \n- **Source IP:** \n- **Geo:** \n- **UA:**" },
      { kind: "evidence", body: "## Risk\n- **Same IP before:** \n- **Impossible travel:** \n- **Known malicious IP:**" },
      { kind: "decision", body: "**Verdict:** [compromised / suspicious / valid]" },
      { kind: "action", body: "**Action:** [reset password / block IP / escalate]" },
    ],
  },
];

function CasePage() {
  const locker = useLocker();
  const [cases, setCases] = useState<Case[]>([]);
  const [activeId, setActiveId] = useState<string>("");
  const [draft, setDraft] = useState("");
  const [kind, setKind] = useState<EntryKind>("note");
  const kindRef = useRef(kind);
  kindRef.current = kind;
  const [editingTitle, setEditingTitle] = useState(false);
  const [titleDraft, setTitleDraft] = useState("");
  const [tagDraft, setTagDraft] = useState("");
  const [search, setSearch] = useState("");
  const [copied, setCopied] = useState(false);
  const [entryFilter, setEntryFilter] = useState("");
  const [copiedEntryId, setCopiedEntryId] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [templateOpen, setTemplateOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<"timeline" | "notebook">("timeline");
  const [notebookMd, setNotebookMd] = useState("");
  const [showHandoff, setShowHandoff] = useState(false);
  const [annotations, setAnnotations] = useState<Record<string, string>>({});
  const [annotatingEntry, setAnnotatingEntry] = useState<string | null>(null);
  const [annotationDraft, setAnnotationDraft] = useState("");

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") { setTemplateOpen(false); setShowHandoff(false); setAnnotatingEntry(null); }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  const active = cases.find(c => c.id === activeId);

  const filteredEntries = useMemo(() => {
    if (!active) return [];
    const q = entryFilter.trim().toLowerCase();
    if (!q) return active.entries;
    return active.entries.filter(e =>
      e.body.toLowerCase().includes(q) || e.kind.toLowerCase().includes(q),
    );
  }, [active, entryFilter]);

  async function copyEntryBody(id: string, body: string) {
    try { await navigator.clipboard.writeText(body); setCopiedEntryId(id); setTimeout(() => setCopiedEntryId(null), 1000); } catch { /* noop */ }
  }

  useEffect(() => {
    const list = loadCases();
    let nextCases = list;
    let nextActiveId = "";

    if (list.length === 0) {
      const c: Case = { id: newId("c"), title: newCaseTitle(), tags: [], createdAt: new Date().toISOString(), state: "active", entries: [] };
      nextCases = [c];
      nextActiveId = c.id;
    } else {
      const remembered = localStorage.getItem(LS_ACTIVE);
      nextActiveId = remembered && list.some(c => c.id === remembered) ? remembered : list[0].id;
    }

    const pending = takePendingCaseEntry();
    if (pending) {
      const ts = new Date().toISOString();
      const body = pending.source ? `[from ${pending.source}] ${pending.body}` : pending.body;
      const entry: Entry = { id: newId("e"), ts, kind: pending.kind as EntryKind, body };
      nextCases = nextCases.map(c => c.id === nextActiveId ? { ...c, entries: [...c.entries, entry] } : c);
    }

    setCases(nextCases);
    setActiveId(nextActiveId);
    saveCases(nextCases);
  }, []);

  useEffect(() => { if (cases.length) saveCases(cases); }, [cases]);
  useEffect(() => { if (activeId) try { localStorage.setItem(LS_ACTIVE, activeId); } catch {/* noop */} }, [activeId]);

  useEffect(() => {
    if (kindRef.current === "note") setKind(autoDetectKind(draft));
  }, [draft]);

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
    pushTimelineEvent({ source: "case", verb: kind === "ioc" ? "added-ioc" : "added-entry", detail: `Added ${kind} to case: ${active.title}`, result: draft.trim().slice(0, 60) });
  }

  function removeEntry(id: string, _body: string) {
    const caseId = activeId;
    if (!active) return;
    const snapshot = active.entries.find(e => e.id === id);
    setCases(prev => prev.map(c => c.id === caseId ? { ...c, entries: c.entries.filter(e => e.id !== id) } : c));
    if (snapshot) {
      toast("Entry deleted", {
        action: {
          label: "Undo",
          onClick: () => { setCases(prev => prev.map(c => c.id === caseId ? { ...c, entries: [...c.entries, snapshot] } : c)); },
        },
      });
    }
  }

  function applyTemplate(tpl: TemplateDef) {
    if (!active) return;
    updateActive(c => {
      const newEntries = tpl.entries.map((e, i) => ({
        id: newId("e"),
        ts: new Date(Date.now() + i * 1000).toISOString(),
        kind: e.kind,
        body: e.body,
      }));
      return { ...c, entries: [...c.entries, ...newEntries] };
    });
    setTemplateOpen(false);
    toast.success(`Template "${tpl.label}" applied`);
    pushTimelineEvent({ source: "case", verb: "applied-template", detail: `Applied template "${tpl.label}" to ${active?.title ?? "?"}`, result: `${tpl.entries.length} entries` });
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
    pushTimelineEvent({ source: "case", verb: "created", detail: `Created case: ${c.title}`, target: c.id });
  }
  function deleteCase(id: string) {
    const caseToDelete = cases.find(c => c.id === id);
    if (!caseToDelete) return;
    const remaining = cases.filter(c => c.id !== id);
    setCases(remaining);
    if (remaining.length === 0) createCase();
    else if (id === activeId) setActiveId(remaining[0].id);

    toast(`Case "${caseToDelete.title}" deleted`, {
      action: {
        label: "Undo",
        onClick: () => {
          setCases(prev => {
            if (prev.some(c => c.id === caseToDelete.id)) return prev;
            return [...prev, caseToDelete].sort((a, b) =>
              new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
            );
          });
          setActiveId(caseToDelete.id);
        },
      },
    });
  }
  function toggleClosed() {
    updateActive(c => ({ ...c, state: c.state === "active" ? "closed" : "active" }));
  }

  const caseJson = useMemo(() => {
    if (!active) return "";
    return JSON.stringify({ version: "1.0", ts: new Date().toISOString(), case: active }, null, 2);
  }, [active]);

  const beyondcaseExport = useMemo(() => {
    if (!active) return "";
    return JSON.stringify({
      version: 1,
      exportedAt: new Date().toISOString(),
      case: active,
    }, null, 2);
  }, [active]);

  const handoffReport = useMemo(() => {
    if (!active) return "";
    const lines: string[] = [];
    lines.push(`# Handoff Report: ${active.title}`);
    lines.push(`**Case ID:** \`${active.id}\``);
    lines.push(`**Status:** ${active.state}`);
    lines.push(`**Generated:** ${new Date().toISOString()}`);
    lines.push("");
    lines.push("---");
    lines.push("## 1. Summary");
    lines.push(`Total entries: ${active.entries.length}`);
    lines.push("");
    const byKindH: Record<EntryKind, number> = { note: 0, evidence: 0, decision: 0, action: 0, ioc: 0 };
    active.entries.forEach(e => { if (byKindH[e.kind] !== undefined) byKindH[e.kind]++; });
    for (const [k, v] of Object.entries(byKindH)) { if (v) lines.push(`- **${k}**: ${v} entries`); }
    lines.push("");
    lines.push("## 2. IOCs");
    const iocTextH = active.entries.filter(e => e.kind === "ioc").map(e => e.body).join("\n");
    const ips = [...new Set(iocTextH.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || [])];
    const urls = [...new Set(iocTextH.match(/https?:\/\/[^\s)"']+/g) || [])];
    const hashes32 = [...new Set(iocTextH.match(/\b[a-f0-9]{32}\b/ig) || [])];
    const hashes64 = [...new Set(iocTextH.match(/\b[a-f0-9]{64}\b/ig) || [])];
    if (ips.length) { lines.push("### IP Addresses"); ips.forEach(ip => lines.push(`- \`${ip}\``)); }
    if (urls.length) { lines.push("### URLs"); urls.forEach(u => lines.push(`- \`${u}\``)); }
    if (hashes32.length) { lines.push("### Hashes (MD5/SHA1)"); hashes32.forEach(h => lines.push(`- \`${h}\``)); }
    if (hashes64.length) { lines.push("### Hashes (SHA256)"); hashes64.forEach(h => lines.push(`- \`${h}\``)); }
    lines.push("");
    const decActions = active.entries.filter(e => e.kind === "decision" || e.kind === "action");
    if (decActions.length) {
      lines.push("## 3. Decisions & Actions");
      decActions.forEach(d => lines.push(`- **${d.kind}:** ${d.body}`));
      lines.push("");
    }
    lines.push("## 4. Timeline");
    for (const section of ["evidence", "decision", "action", "ioc", "note"] as EntryKind[]) {
      const items = active.entries.filter(e => e.kind === section);
      if (!items.length) continue;
      lines.push(`### ${section.charAt(0).toUpperCase() + section.slice(1)}`);
      items.forEach(e => {
        const d = new Date(e.ts);
        lines.push(`- \`${d.toLocaleString()}\` ${e.body}`);
      });
      lines.push("");
    }
    lines.push("---");
    lines.push(`*Report generated by BeyondLabs at ${new Date().toISOString()}*`);
    return lines.join("\n");
  }, [active]);

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
    if (active.entries.length === 0) {
      lines.push("_no entries yet_");
      return lines.join("\n");
    }
    lines.push("## Summary");
    const byKind: Record<string, string[]> = { note: [], evidence: [], decision: [], action: [], ioc: [] };
    active.entries.forEach(e => { (byKind[e.kind] ??= []).push(e.body); });
    lines.push(`| Kind | Count |`);
    lines.push(`|------|-------|`);
    for (const [k, items] of Object.entries(byKind)) {
      if (items.length) lines.push(`| **${k}** | ${items.length} |`);
    }
    lines.push("");
    const iocEntries = active.entries.filter(e => e.kind === "ioc");
    if (iocEntries.length) {
      lines.push("## Extracted IOCs");
      const iocs: string[] = [];
      const ipRe = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
      const urlRe = /https?:\/\/[^\s)"']+/g;
      const hashRe = /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/ig;
      iocEntries.forEach(e => {
        (e.body.match(ipRe) || []).forEach(m => { if (!iocs.includes(m)) iocs.push(m); });
        (e.body.match(urlRe) || []).forEach(m => { if (!iocs.includes(m)) iocs.push(m); });
        (e.body.match(hashRe) || []).forEach(m => { if (!iocs.includes(m)) iocs.push(m); });
      });
      if (iocs.length) iocs.forEach(io => lines.push(`- \`${io}\``));
      lines.push("");
    }
    lines.push("## Timeline");
    for (const section of ["evidence", "decision", "action", "ioc", "note"] as EntryKind[]) {
      const items = active.entries.filter(e => e.kind === section);
      if (!items.length) continue;
      lines.push(`### ${section.charAt(0).toUpperCase() + section.slice(1)}`);
      items.forEach(e => {
        const d = new Date(e.ts);
        const short = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
        lines.push(`- \`${short}\` ${e.body}`);
      });
      lines.push("");
    }
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
  function downloadHtml() {
    if (!active) return;
    const entries = [...active.entries].reverse();
    const rows = entries.map((e: Entry) => {
      const d = new Date(e.ts);
      const ts = d.toLocaleString();
      return `<tr>
        <td style="padding:6px 8px;white-space:nowrap;color:#888;font-family:monospace;font-size:11px">${ts}</td>
        <td style="padding:6px 8px"><span style="display:inline-block;padding:1px 8px;border-radius:3px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;font-family:monospace;background:${KIND_COLOR[e.kind].replace("bg-", "#").replace("/60", "30")};color:${KIND_COLOR[e.kind].replace("bg-", "#").replace("/60", "")}">${e.kind}</span></td>
        <td style="padding:6px 8px;font-family:monospace;font-size:13px;color:#ddd;white-space:pre-wrap">${e.body.replace(/</g, "&lt;")}</td>
      </tr>`;
    }).join("\n");
    const iocEntries = active.entries.filter(e => e.kind === "ioc");
    const iocs: string[] = [];
    const ipRe = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
    const urlRe = /https?:\/\/[^\s)"']+/g;
    const hashRe = /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/ig;
    iocEntries.forEach(e => {
      (e.body.match(ipRe) || []).forEach((m: string) => { if (!iocs.includes(m)) iocs.push(m); });
      (e.body.match(urlRe) || []).forEach((m: string) => { if (!iocs.includes(m)) iocs.push(m); });
      (e.body.match(hashRe) || []).forEach((m: string) => { if (!iocs.includes(m)) iocs.push(m); });
    });
    const iocHtml = iocs.length ? iocs.map((io: string) => `<code style="display:inline-block;background:#1a1a2e;border:1px solid #2a2a3e;border-radius:3px;padding:2px 8px;margin:2px 4px;font-size:11px;color:#f88">${io.replace(/</g, "&lt;")}</code>`).join(" ") : "<em>none</em>";
    const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>${active.title} - Case Report</title><style>
      body{background:#0d0d1a;color:#ccc;font-family:-apple-system,BlinkMacSystemFont,sans-serif;padding:40px;max-width:900px;margin:0 auto;line-height:1.5}
      h1{color:#fff;font-size:20px;letter-spacing:0.05em;font-weight:600}
      h2{color:#aaa;font-size:14px;text-transform:uppercase;letter-spacing:0.12em;margin-top:32px}
      .meta{display:flex;gap:24px;flex-wrap:wrap;font-size:12px;color:#888;margin:16px 0 32px}
      .meta dt{font-weight:600;color:#666;font-size:10px;text-transform:uppercase;letter-spacing:0.1em}
      .meta dd{margin:2px 0 0 0;color:#ccc;font-family:monospace}
      table{border-collapse:collapse;width:100%;font-size:13px}
      th{text-align:left;padding:6px 8px;border-bottom:1px solid #2a2a3e;color:#666;font-size:10px;text-transform:uppercase;letter-spacing:0.1em;font-weight:600}
      td{border-bottom:1px solid #1a1a2e}
      .footer{margin-top:48px;font-size:10px;color:#555;border-top:1px solid #1a1a2e;padding-top:16px}
</style></head><body>
      <h1>${active.title}</h1>
      <dl class="meta"><div><dt>Case ID</dt><dd>${active.id}</dd></div><div><dt>Opened</dt><dd>${new Date(active.createdAt).toLocaleString()}</dd></div><div><dt>State</dt><dd>${active.state}</dd></div><div><dt>Entries</dt><dd>${active.entries.length}</dd></div>${active.tags.length ? `<div><dt>Tags</dt><dd>${active.tags.join(", ")}</dd></div>` : ""}</dl>
      <h2>Extracted IOCs</h2><p>${iocHtml}</p>
      <h2>Timeline (${active.entries.length} entries)</h2>
      <table><thead><tr><th>Timestamp</th><th>Kind</th><th>Body</th></tr></thead><tbody>${rows}</tbody></table>
      <div class="footer">Generated by BeyondLabs · ${new Date().toISOString()}</div>
</body></html>`;
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${active.title}.html`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function handleImport(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target?.result as string);
        if (!data.version || !data.case || !data.case.id || !data.case.title || !Array.isArray(data.case.entries)) {
          toast.error("Invalid beyondcase file");
          return;
        }
        setCases(prev => {
          if (prev.some(c => c.id === data.case.id)) {
            toast.warning("A case with this ID already exists");
            return prev;
          }
          toast.success("Case imported");
          return [data.case, ...prev];
        });
      } catch {
        toast.error("Failed to parse file");
      }
    };
    reader.readAsText(file);
    e.target.value = "";
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
        <button onClick={createCase} className="inline-flex items-center gap-1.5 rounded-md border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
          <Plus className="h-3 w-3" /> new case
        </button>
      }
    >
      {active && (
        <div className="pointer-events-none select-none">
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
        </div>
      )}

      <div className="grid gap-4 grid-cols-[minmax(0,18rem)_minmax(0,1fr)]">
        <div className="space-y-3 sticky top-16 self-start">
          <Panel bodyClassName="p-0" priority="secondary">
            <div className="border-b border-border p-2">
              <div className="relative">
                <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="search cases…"
                  className="w-full rounded-md border border-border bg-background/60 py-1.5 pl-7 pr-2 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
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
                            <span className="truncate text-mono ba-text-sm uppercase tracking-widest text-foreground/90">{c.title}</span>
                            <Chip tone={c.state === "active" ? "warning" : "default"}>{c.state}</Chip>
                          </div>
                          <div className="mt-0.5 flex items-center gap-2 text-mono ba-text-2xs text-muted-foreground">
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
                    <div className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">Case title</div>
                    {editingTitle ? (
                      <div className="mt-1 flex items-center gap-2">
                        <input
                          autoFocus
                          value={titleDraft}
                          onChange={e => setTitleDraft(e.target.value)}
                          onKeyDown={e => { if (e.key === "Enter") { updateActive(c => ({ ...c, title: titleDraft.trim() || c.title })); setEditingTitle(false); } if (e.key === "Escape") setEditingTitle(false); }}
                          className="min-w-0 flex-1 rounded border border-border bg-background/60 px-2 py-1 text-mono ba-text-base text-foreground outline-none focus:border-primary/50"
                        />
                        <button onClick={() => { updateActive(c => ({ ...c, title: titleDraft.trim() || c.title })); setEditingTitle(false); }} aria-label="Confirm title" className="rounded border border-success/50 bg-success/10 px-2 py-1 text-mono ba-text-2xs uppercase text-success"><Check className="h-3 w-3" /></button>
                      </div>
                    ) : (
                      <button onClick={() => { setTitleDraft(active.title); setEditingTitle(true); }} className="group mt-1 flex items-center gap-2 text-left">
                        <span className="text-mono text-[13.5px] text-foreground">{active.title}</span>
                        <Pencil className="h-3 w-3 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
                      </button>
                    )}
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      {active.tags.map(t => (
                        <span key={t} className="inline-flex items-center gap-1 rounded border border-border bg-background/60 px-1.5 py-0.5 text-mono ba-text-2xs text-foreground/85">
                          <Tag className="h-2.5 w-2.5 text-primary/70" /> {t}
                          <button onClick={() => removeTag(t)} aria-label="Remove tag" className="text-muted-foreground hover:text-destructive"><X className="h-2.5 w-2.5" /></button>
                        </span>
                      ))}
                      <input
                        value={tagDraft}
                        onChange={e => setTagDraft(e.target.value)}
                        onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); addTag(); } }}
                        placeholder="add tag…"
                        className="rounded border border-dashed border-divider-strong bg-background/40 px-1.5 py-0.5 text-mono ba-text-2xs text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
                      />
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <button onClick={toggleClosed} className="inline-flex items-center gap-1 rounded border border-border bg-card/40 px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:border-primary/50 hover:text-primary">
                      {active.state === "active" ? "close case" : "re-open"}
                    </button>
                    <button onClick={() => deleteCase(active.id)} className="inline-flex items-center gap-1 rounded border border-border bg-card/40 px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:border-destructive/50 hover:text-destructive">
                      <Trash2 className="h-3 w-3" /> delete
                    </button>
                  </div>
                </div>
              </Panel>

              <Panel title="Templates" priority="secondary" icon={ClipboardList}
                actions={
                  <button onClick={() => setTemplateOpen(o => !o)} className="text-mono ba-text-2xs uppercase tracking-widest text-primary">
                    {templateOpen ? "collapse" : "expand"}
                  </button>
                }
              >
                {templateOpen ? (
                  <div className="space-y-1.5">
                    {CASE_TEMPLATES.map(tpl => (
                      <button key={tpl.id} onClick={() => applyTemplate(tpl)}
                        className="group flex w-full items-center gap-2 rounded border border-border/60 bg-background/40 px-2 py-1.5 text-left transition-colors hover:border-primary/40 hover:bg-primary/5"
                      >
                        <tpl.icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground group-hover:text-primary" />
                        <div className="min-w-0 flex-1">
                          <div className="text-mono ba-text-sm text-foreground/90">{tpl.label}</div>
                          <div className="text-mono ba-text-2xs text-muted-foreground">{tpl.entries.length} entries</div>
                        </div>
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="text-mono ba-text-2xs text-muted-foreground/70">Apply a pre-populated checklist template</div>
                )}
              </Panel>

              <SectionBar id="IN" label="Intake · new entry" />
              <Panel>
                <div className="mb-2 flex flex-wrap items-center gap-1.5">
                  {(["note", "evidence", "decision", "action", "ioc"] as EntryKind[]).map(k => (
                    <button
                      key={k}
                      onClick={() => setKind(k)}
                      className={"rounded border px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest " + (kind === k ? "border-primary bg-primary/15 text-primary" : "border-border text-muted-foreground hover:text-foreground")}
                    >{k}</button>
                  ))}
                </div>
                <textarea
                  value={draft}
                  onChange={e => setDraft(e.target.value)}
                  onKeyDown={e => { if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); addEntry(); } }}
                  rows={3}
                  placeholder="What did you observe / decide / do? (⌘/Ctrl + Enter to append)"
                  className="w-full resize-y rounded border border-divider-strong bg-background/60 p-2 text-mono ba-text-base text-foreground outline-none focus:border-primary/50"
                />
                <div className="mt-2 flex items-center justify-between">
                  <span className="text-mono ba-text-2xs text-muted-foreground">{draft.length} chars</span>
                  <button
                    onClick={addEntry}
                    disabled={!draft.trim()}
                    className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2.5 py-1 text-mono ba-text-2xs uppercase text-primary disabled:opacity-40"
                  >
                    <Plus className="h-3 w-3" /> append
                  </button>
                </div>
              </Panel>

              {/* IOC extraction summary */}
              {active.entries.some(e => e.kind === "ioc") && (
                <Panel title="Extracted IOCs" icon={Siren} priority="secondary"
                  headerAction={
                    <button onClick={() => { active.entries.filter(e => e.kind === "ioc").forEach(e => locker.add({ value: e.body, type: guessType(e.body), source: "/case" })); toast("All IOCs added to locker"); }}
                      className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:text-primary"><Database className="h-3 w-3" /> all to locker</button>
                  }>
                  {(() => {
                    const allText = active.entries.filter(e => e.kind === "ioc").map(e => e.body).join("\n");
                    const iocRx = { "IPs": /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, "URLs": /https?:\/\/[^\s)"']+/g, "Hashes 32": /\b[a-f0-9]{32}\b/ig, "Hashes 40": /\b[a-f0-9]{40}\b/ig, "Hashes 64": /\b[a-f0-9]{64}\b/ig };
                    return Object.entries(iocRx).map(([k, rx]) => {
                      const matches = allText.match(rx);
                      if (!matches) return null;
                      const unique = [...new Set(matches)];
                      return unique.length > 0 ? (
                        <div key={k} className="mb-2 last:mb-0">
                          <div className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground mb-1">{k} ({unique.length})</div>
                          <div className="flex flex-wrap gap-1">
                            {unique.slice(0, 10).map((v, i) => <Chip key={i} tone="destructive">{v}</Chip>)}
                            {unique.length > 10 && <Chip tone="default">+{unique.length - 10} more</Chip>}
                          </div>
                        </div>
                      ) : null;
                    }).filter(Boolean);
                  })()}
                </Panel>
              )}

              <div className="flex items-center gap-1 border-b border-border pb-1 mb-2">
                {(["timeline", "notebook"] as const).map(tab => (
                  <button key={tab} onClick={() => setActiveTab(tab)}
                    className={"rounded px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest " + (activeTab === tab ? "border border-primary/50 bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground")}
                  >{tab === "timeline" ? `Timeline (${active.entries.length})` : "Notebook"}</button>
                ))}
              </div>

              {activeTab === "timeline" ? (
                <>
              <SectionBar id="OT" label="Timeline" meta={`${active.entries.length} entries`}
                action={
                  <div className="flex items-center gap-1">
                    {(["", "note", "evidence", "decision", "action", "ioc"] as const).map(k => (
                      <button key={k} onClick={() => setEntryFilter(entryFilter === k ? "" : k)}
                        className={"rounded px-1.5 py-0.5 text-mono ba-text-2xs uppercase tracking-widest " + (entryFilter === k ? "border border-primary/50 bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground")}>
                        {k || "all"}
                      </button>
                    ))}
                  </div>
                }
              />
              <Panel title="Case timeline" icon={Notebook} bodyClassName="p-0">
                {active.entries.length === 0 ? (
                  <div className="p-4"><Empty title="No entries yet" hint="Append your first observation, decision, or IOC above." /></div>
                ) : (
                  <>
                    <ul className="divide-y divide-border/50">
                      {[...filteredEntries].reverse().map(e => {
                      const d = new Date(e.ts);
                      const short = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
                      const Icon = KIND_ICON[e.kind];
                      const annotation = annotations[e.id];
                      return (
                        <li key={e.id} className="group px-4 py-2.5">
                          <div className="grid grid-cols-[70px_100px_1fr_auto] items-start gap-3">
                            <div className="flex items-center gap-2">
                              <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${KIND_COLOR[e.kind]}`} />
                              <div className="text-mono ba-text-2xs text-muted-foreground" title={e.ts}>{short}</div>
                            </div>
                            <div className="flex items-center gap-1">
                              <Icon className={`h-3 w-3 ${KIND_COLOR[e.kind].replace("bg-", "text-").replace("/60", "/70")}`} />
                              <Chip tone={KIND_TONE[e.kind]}>{e.kind}</Chip>
                            </div>
                            <div className="whitespace-pre-wrap ba-text-base text-foreground/90">{e.body}</div>
                            <div className="flex items-center gap-1">
                              <button onClick={() => { setAnnotatingEntry(annotatingEntry === e.id ? null : e.id); setAnnotationDraft(annotations[e.id] || ""); }}
                                className={"opacity-0 transition-opacity group-hover:opacity-100 " + (annotation ? "text-warning" : "text-muted-foreground hover:text-primary")} title="Annotate entry">
                                <MessageSquare className="h-3 w-3" />
                              </button>
                              {e.kind === "ioc" ? (
                                <div className="flex items-center gap-0.5">
                                  <button onClick={() => { locker.add({ value: e.body, type: guessType(e.body), source: "/case" }); toast("Added to locker"); }}
                                    className="opacity-0 transition-opacity group-hover:opacity-100 text-muted-foreground hover:text-primary" title="Add to IOC locker">
                                    <Database className="h-3 w-3" />
                                  </button>
                                  <CopyAsDropdown value={e.body} label={e.body} />
                                </div>
                              ) : (
                                <button onClick={() => copyEntryBody(e.id, e.body)}
                                  className="opacity-0 transition-opacity group-hover:opacity-100 text-muted-foreground hover:text-primary" title="Copy entry">
                                  {copiedEntryId === e.id ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                                </button>
                              )}
                              <button onClick={() => removeEntry(e.id, e.body)}
                                className="opacity-0 transition-opacity group-hover:opacity-100 text-muted-foreground hover:text-destructive" title="Delete entry">
                                <Trash2 className="h-3 w-3" />
                              </button>
                            </div>
                          </div>
                          {annotatingEntry === e.id && (
                            <div className="ml-[70px] mt-2 flex items-start gap-2">
                              <input
                                autoFocus
                                value={annotationDraft}
                                onChange={e => setAnnotationDraft(e.target.value)}
                                placeholder="Add a note to this entry…"
                                className="min-w-0 flex-1 rounded border border-divider-strong bg-background/40 px-2 py-1 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50"
                              />
                              <button onClick={() => { setAnnotations(prev => ({ ...prev, [e.id]: annotationDraft })); setAnnotatingEntry(null); }}
                                className="rounded border border-primary/30 bg-primary/10 px-2 py-1 text-mono ba-text-2xs uppercase text-primary hover:bg-primary/20">save</button>
                            </div>
                          )}
                          {annotation && annotatingEntry !== e.id && (
                            <div className="ml-[70px] mt-1 border-l-2 border-warning/40 pl-2">
                              <span className="text-mono ba-text-2xs text-warning/80">annotation: </span>
                              <span className="text-mono ba-text-sm text-foreground/70">{annotation}</span>
                            </div>
                          )}
                        </li>
                      );
                    })}
                    </ul>
                  </>
                )}
              </Panel>
                </>
              ) : (
                <Panel title="Investigation Notebook" icon={Notebook}>
                  <textarea
                    value={notebookMd}
                    onChange={e => setNotebookMd(e.target.value)}
                    rows={12}
                    placeholder={"Write investigation notes in markdown...\n\n# Observations\n- \n\n# Analysis\n- \n\n# Next Steps\n- "}
                    className="w-full resize-y rounded border border-divider-strong bg-background/60 p-3 text-mono ba-text-sm text-foreground outline-none focus:border-primary/50 mb-3"
                  />
                  <div className="rounded border border-border/60 bg-background/30 p-3">
                    {notebookMd.split('\n').map((line, i) => {
                      if (line.startsWith('# ')) return <h1 key={i} className="text-base font-semibold text-foreground mt-2 mb-1">{line.slice(2)}</h1>;
                      if (line.startsWith('## ')) return <h2 key={i} className="text-sm font-semibold text-foreground/90 mt-2 mb-1">{line.slice(3)}</h2>;
                      if (line.startsWith('### ')) return <h3 key={i} className="text-xs font-semibold text-foreground/80 mt-1.5 mb-0.5">{line.slice(4)}</h3>;
                      if (line.startsWith('- ')) return <li key={i} className="text-mono ba-text-sm text-foreground/80 ml-4 list-disc">{line.slice(2)}</li>;
                      if (line.trim() === '') return <br key={i} />;
                      return <p key={i} className="text-mono ba-text-sm text-foreground/80 my-0.5">{line}</p>;
                    })}
                  </div>
                </Panel>
              )}

              <Panel title="Case metadata" priority="secondary">
                <KeyFields items={[
                  { label: "ID", value: active.id, tone: "primary" },
                  { label: "Opened", value: new Date(active.createdAt).toLocaleString() },
                  { label: "State", value: active.state, tone: active.state === "active" ? "warning" : "default" },
                  { label: "Entries", value: active.entries.length, tone: "primary" },
                ]} />
              </Panel>

              <Panel
                title="Report (markdown)" priority="secondary"
                icon={FileText}
                actions={
                  <>
                    <button onClick={copyMd} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
                      {copied ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> copy</>}
                    </button>
                    <button onClick={download} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
                      <Download className="h-3 w-3" /> .md
                    </button>
                    <button onClick={downloadHtml} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
                      <Download className="h-3 w-3" /> .html
                    </button>
                    <button onClick={() => { const blob = new Blob([caseJson], { type: "application/json" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `${active?.title ?? "case"}.json`; a.click(); }} className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-0.5 text-mono ba-text-2xs uppercase text-primary hover:bg-primary/20">
                      <Download className="h-3 w-3" /> .json
                    </button>
                    <button onClick={() => { const blob = new Blob([beyondcaseExport], { type: "application/json" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `${active?.title ?? "case"}.beyondcase.json`; a.click(); }} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
                      <Download className="h-3 w-3" /> .beyondcase
                    </button>
                    <input ref={fileInputRef} type="file" accept=".json" className="hidden" onChange={handleImport} />
                    <button onClick={() => fileInputRef.current?.click()} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
                      <FolderOpen className="h-3 w-3" /> import
                    </button>
                  </>
                }
              >
                <pre className="max-h-80 overflow-auto rounded bg-background/60 p-3 text-mono ba-text-sm text-foreground/90">{markdown}</pre>
              </Panel>

              <Panel title="Handoff Report (L2/IR)" priority="secondary" icon={ClipboardList}
                actions={
                  <button onClick={() => setShowHandoff(o => !o)} className="text-mono ba-text-2xs uppercase tracking-widest text-primary">
                    {showHandoff ? "hide" : "show"}
                  </button>
                }
              >
                {showHandoff ? (
                  <>
                    <pre className="max-h-96 overflow-auto rounded bg-background/60 p-3 text-mono ba-text-sm text-foreground/90 whitespace-pre-wrap">{handoffReport}</pre>
                    <div className="mt-2 flex items-center gap-2">
                      <button onClick={async () => { try { await navigator.clipboard.writeText(handoffReport); toast.success("Handoff report copied"); } catch {} }}
                        className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
                        <Copy className="h-3 w-3" /> copy
                      </button>
                      <button onClick={() => { const blob = new Blob([handoffReport], { type: "text/markdown" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `${active?.title ?? "case"}-handoff.md`; a.click(); }}
                        className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
                        <Download className="h-3 w-3" /> .md
                      </button>
                    </div>
                  </>
                ) : (
                  <div className="text-mono ba-text-2xs text-muted-foreground/70">Consolidated L2/IR handoff report with IOC summary, decisions, and timeline</div>
                )}
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
