import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, Chip } from "@/components/soc";
import { Empty } from "@/components/output";
import { Bookmark, Search, Plus, Copy, Check, Download, Upload, Trash2, Pencil, X, Save } from "lucide-react";
import { toast } from "sonner";
import { pushTimelineEvent } from "@/lib/timeline";
import { copyText } from "@/lib/copy";

export const Route = createFileRoute("/snippets")({ component: SnippetsPage });

type Snippet = { id: string; name: string; category: string; content: string; tags: string[] };
type Editable = { id: string } | null;

const LS_KEY = "ba.snippets.v2";
const CATEGORIES = ["SIEM", "Sigma", "Regex", "Notes"] as const;

const SEED: Snippet[] = [
  { id: "seed-1", name: "Failed logins (last 24h)", category: "SIEM", content: "index=windows event=4625 earliest=-24h\n| stats count by src_ip, user\n| where count > 5", tags: ["auth", "brute-force"] },
  { id: "seed-2", name: "Port scan detection", category: "SIEM", content: "index=network dest_port=*\n| stats dc(dest_port) as ports by src_ip\n| where ports > 25", tags: ["network", "recon"] },
  { id: "seed-3", name: "DNS query spike", category: "SIEM", content: "index=dns earliest=-1h\n| stats count by query\n| where count > 100\n| sort -count", tags: ["dns", "c2"] },
  { id: "seed-4", name: "PowerShell encoded command", category: "Sigma", content: "title: Suspicious PowerShell -EncodedCommand\nid: 6f1f0c20-1111-4444-8888-123456789abc\ndetection:\n  selection:\n    EventID: 4104\n    ScriptBlockText|contains: '-EncodedCommand'\n  condition: selection", tags: ["powershell", "execution"] },
  { id: "seed-5", name: "Suspicious rundll32 execution", category: "Sigma", content: "title: Suspicious rundll32 Execution\nid: a1b2c3d4-5555-4444-8888-123456789abc\ndetection:\n  selection:\n    Image|endswith: '\\rundll32.exe'\n    CommandLine|contains: 'javascript:'\n  condition: selection", tags: ["lolbin", "defense-evasion"] },
  { id: "seed-6", name: "Certutil download", category: "Sigma", content: "title: Certutil Download\nid: b2c3d4e5-6666-4444-8888-123456789abc\ndetection:\n  selection:\n    CommandLine|contains|all:\n      - 'certutil'\n      - '-urlcache'\n      - '-f'\n  condition: selection", tags: ["lolbin", "download"] },
  { id: "seed-7", name: "Extract URLs from text", category: "Regex", content: "\\b(?:hxxps?|https?):\\/\\/[^\\s)>\"']+", tags: ["ioc", "url"] },
  { id: "seed-8", name: "Extract IPv4 addresses", category: "Regex", content: "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", tags: ["ioc", "ip"] },
  { id: "seed-9", name: "Extract email addresses", category: "Regex", content: "\\b[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}\\b", tags: ["ioc", "email"] },
  { id: "seed-10", name: "Initial triage checklist", category: "Notes", content: "## Initial Triage\n1. Identify trigger / alert source\n2. Extract all IOCs (URLs, IPs, hashes, domains)\n3. Check SPF/DKIM/DMARC (phishing)\n4. Run URL analysis\n5. Check hashes against known malware\n6. Timeline the events\n7. Determine scope (single user vs org-wide)\n8. Draft initial findings", tags: ["checklist", "triage"] },
  { id: "seed-11", name: "Phishing analysis checklist", category: "Notes", content: "## Phishing Analysis\n1. Inspect email headers (From, Reply-To, Return-Path)\n2. Check Authentication-Results (SPF, DKIM, DMARC)\n3. Trace Received chain\n4. Extract and analyze all URLs\n5. Check attachments in sandbox\n6. Identify brand impersonation\n7. Check for urgency / coercion language\n8. Determine verdict: phishing / suspicious / clean", tags: ["checklist", "phishing"] },
];

function loadAll(): Snippet[] {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return SEED;
    const user: Snippet[] = JSON.parse(raw);
    return [...SEED.filter((s) => !user.some((u) => u.id === s.id)), ...user];
  } catch { return SEED; }
}
function saveAll(snippets: Snippet[]) {
  const user = snippets.filter((s) => !s.id.startsWith("seed-"));
  localStorage.setItem(LS_KEY, JSON.stringify(user));
}

function newId() { return `snip-${crypto.randomUUID().slice(0, 8)}`; }

function SnippetsPage() {
  const [snippets, setSnippets] = useState<Snippet[]>(loadAll);
  const [search, setSearch] = useState("");
  const [catFilter, setCatFilter] = useState<string>("all");
  const [editing, setEditing] = useState<Editable>(null);
  const [editName, setEditName] = useState("");
  const [editCategory, setEditCategory] = useState<string>("SIEM");
  const [editContent, setEditContent] = useState("");
  const [editTags, setEditTags] = useState("");
  const [copied, setCopied] = useState("");

  useEffect(() => { saveAll(snippets); }, [snippets]);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape" && editing) { setEditing(null); e.preventDefault(); }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [editing]);

  const filtered = useMemo(() => {
    let s = snippets;
    if (catFilter !== "all") s = s.filter((sn) => sn.category === catFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      s = s.filter((sn) =>
        sn.name.toLowerCase().includes(q) ||
        sn.content.toLowerCase().includes(q) ||
        sn.tags.some((t) => t.includes(q))
      );
    }
    return s;
  }, [snippets, catFilter, search]);

  const startEdit = (sn?: Snippet) => {
    if (sn) { setEditing({ id: sn.id }); setEditName(sn.name); setEditCategory(sn.category); setEditContent(sn.content); setEditTags(sn.tags.join(", ")); }
    else { setEditing({ id: "" }); setEditName(""); setEditCategory("SIEM"); setEditContent(""); setEditTags(""); }
  };

  const saveEdit = useCallback(() => {
    if (!editName.trim() || !editContent.trim()) return;
    const tags = editTags.split(",").map((t) => t.trim()).filter(Boolean);
    if (editing?.id) {
      setSnippets((prev) => prev.map((s) => s.id === editing.id ? { ...s, name: editName.trim(), category: editCategory, content: editContent, tags } : s));
      pushTimelineEvent({ source: "snippets", verb: "updated", detail: `Edited snippet: ${editName.trim()}`, result: editCategory });
    } else {
      const id = newId();
      setSnippets((prev) => [...prev, { id, name: editName.trim(), category: editCategory, content: editContent, tags }]);
      pushTimelineEvent({ source: "snippets", verb: "created", detail: `Created snippet: ${editName.trim()}`, target: id, result: editCategory });
    }
    setEditing(null);
  }, [editName, editCategory, editContent, editTags, editing]);

  const copyText = (id: string, text: string) => {
    copyText(text);
    setCopied(id);
    setTimeout(() => setCopied(""), 1200);
  };

  const deleteSnip = useCallback((id: string) => {
    if (id.startsWith("seed-")) return;
    const snip = snippets.find((s) => s.id === id);
    setSnippets((prev) => prev.filter((s) => s.id !== id));
    if (snip) {
      pushTimelineEvent({ source: "snippets", verb: "deleted", detail: `Deleted snippet: ${snip.name}`, result: snip.category });
      toast("Snippet deleted", {
        action: {
          label: "Undo",
          onClick: () => { setSnippets((prev) => [...prev, snip]); },
        },
      });
    }
  }, [snippets]);

  const exportAll = () => {
    const userOnly = snippets.filter((s) => !s.id.startsWith("seed-"));
    const blob = new Blob([JSON.stringify(userOnly, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `snippets-${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  const importSnippets = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const imported: Snippet[] = JSON.parse(text);
        if (!Array.isArray(imported)) throw new Error("invalid");
        setSnippets((prev) => {
          const existing = new Map(prev.map((s) => [s.id, s]));
          for (const sn of imported) {
            const id = sn.id && !sn.id.startsWith("seed-") ? sn.id : newId();
            existing.set(id, { ...sn, id });
          }
          return Array.from(existing.values());
        });
      } catch { toast.error("Invalid import file"); }
    };
    input.click();
  };

  return (
    <PageShell
      eyebrow="LIBRARY"
      title="Saved Queries & Snippets"
      description="SIEM queries, Sigma rules, SOC regex, and investigation checklists — saved locally."
      crumbs={[{ label: "Library" }, { label: "Snippets" }]}
      actions={
        <div className="flex items-center gap-1.5">
          <button onClick={importSnippets} className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground">
            <Upload className="h-3 w-3" /> import
          </button>
          <button onClick={exportAll} className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground">
            <Download className="h-3 w-3" /> export
          </button>
          <button onClick={() => startEdit()} className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-primary hover:bg-primary/20">
            <Plus className="h-3 w-3" /> new
          </button>
        </div>
      }
    >
      <div className="flex items-center gap-2 mb-3">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground/60" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search snippets…"
            className="h-8 w-full rounded border border-border bg-background/60 pl-8 pr-2 text-mono text-[11px] text-foreground outline-none placeholder:text-muted-foreground/50 focus:border-primary/50"
          />
        </div>
        <div className="flex gap-1">
          {["all", ...CATEGORIES].map((c) => (
            <button key={c} onClick={() => setCatFilter(c)}
              className={"rounded border px-2 py-1 text-mono text-[10px] uppercase tracking-widest " + (catFilter === c ? "border-primary bg-primary/15 text-primary" : "border-border text-muted-foreground hover:text-foreground")}
            >{c}</button>
          ))}
        </div>
      </div>

      {editing && (
        <Panel title={editing.id ? "Edit snippet" : "New snippet"} icon={Bookmark} meta="fill in all fields">
          <div className="space-y-2">
            <input value={editName} onChange={(e) => setEditName(e.target.value)} placeholder="Name" className="h-8 w-full rounded border border-border bg-background/60 px-2 text-mono text-[11px] text-foreground outline-none focus:border-primary/50" />
            <select value={editCategory} onChange={(e) => setEditCategory(e.target.value)} className="h-8 w-full rounded border border-border bg-background/60 px-2 text-mono text-[10px] uppercase tracking-widest text-foreground outline-none focus:border-primary/50">
              {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
            <textarea value={editContent} onChange={(e) => setEditContent(e.target.value)} placeholder="Content" rows={6} className="w-full rounded border border-border bg-background/60 p-2 text-mono text-[11px] text-foreground outline-none focus:border-primary/50 font-mono" />
            <input value={editTags} onChange={(e) => setEditTags(e.target.value)} placeholder="Tags (comma-separated)" className="h-8 w-full rounded border border-border bg-background/60 px-2 text-mono text-[11px] text-foreground outline-none focus:border-primary/50" />
            <div className="flex gap-2">
              <button onClick={saveEdit} className="inline-flex items-center gap-1 rounded border border-success/50 bg-success/10 px-3 py-1 text-mono text-[10px] uppercase tracking-widest text-success hover:bg-success/20">
                <Save className="h-3 w-3" /> save
              </button>
              <button onClick={() => setEditing(null)} className="inline-flex items-center gap-1 rounded border border-border px-3 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground">
                <X className="h-3 w-3" /> cancel
              </button>
            </div>
          </div>
        </Panel>
      )}

      {filtered.length === 0 ? (
        <Empty icon={Bookmark} title="No snippets" hint={search || catFilter !== "all" ? "Try a different filter." : "Create your first snippet using the + new button above."} />
      ) : (
        <div className="grid gap-2 grid-cols-2">
          {filtered.map((sn) => (
            <div key={sn.id} className="rounded border border-border/50 bg-card/30 px-3 py-2.5 hover:border-primary/30 transition-colors group">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-mono ba-text-sm font-semibold text-foreground truncate">{sn.name}</span>
                    <Chip tone={sn.category === "SIEM" ? "info" : sn.category === "Sigma" ? "primary" : sn.category === "Regex" ? "warning" : "default"}>{sn.category}</Chip>
                  </div>
                  {sn.tags.length > 0 && (
                    <div className="mt-0.5 flex flex-wrap gap-1">
                      {sn.tags.map((t) => <span key={t} className="text-mono text-[9px] uppercase tracking-widest text-muted-foreground/60">#{t}</span>)}
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-0.5 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button onClick={() => copyText(sn.id, sn.content)} className="grid h-6 w-6 place-items-center rounded text-muted-foreground hover:text-foreground hover:bg-card/60" title="Copy">
                    {copied === sn.id ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                  </button>
                  {!sn.id.startsWith("seed-") && (
                    <>
                      <button onClick={() => startEdit(sn)} className="grid h-6 w-6 place-items-center rounded text-muted-foreground hover:text-foreground hover:bg-card/60" title="Edit">
                        <Pencil className="h-3 w-3" />
                      </button>
                      <button onClick={() => deleteSnip(sn.id)} className="grid h-6 w-6 place-items-center rounded text-muted-foreground hover:text-destructive hover:bg-destructive/10" title="Delete">
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </>
                  )}
                </div>
              </div>
              <pre className="mt-1.5 max-h-[120px] overflow-auto rounded bg-background/40 p-1.5 text-mono text-[10px] leading-relaxed text-foreground/70 whitespace-pre-wrap">{sn.content}</pre>
            </div>
          ))}
        </div>
      )}
    </PageShell>
  );
}
