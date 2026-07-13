import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, Chip } from "@/components/soc";
import { Search, Copy, Check, Save, Trash2 } from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/regex-playground")({ component: RegexPlaygroundPage });

const SOC_PATTERNS: { label: string; pattern: string; flags: string; sample: string }[] = [
  { label: "Extract IPv4", pattern: "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b", flags: "g", sample: "Connection from 192.168.1.1 to 10.0.0.1 on port 443" },
  { label: "Extract URLs", pattern: "https?://[^\\s)\"'<>]+", flags: "g", sample: "Visit https://example.com/login?ref=abc or http://evil.org/payload.ps1" },
  { label: "Extract Hashes", pattern: "\\b[a-f0-9]{32}\\b|\\b[a-f0-9]{40}\\b|\\b[a-f0-9]{64}\\b", flags: "gi", sample: "MD5: d41d8cd98f00b204e9800998ecf8427e SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
  { label: "Extract Emails", pattern: "[\\w.+-]+@[\\w-]+\\.[\\w.-]+", flags: "g", sample: "Contact admin@example.org or support@evil-host.ru for details" },
  { label: "Extract Base64", pattern: "(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", flags: "g", sample: "Token: ZXNjaGFsb25neXN0ZW1zIGFyZSBjb29s base64 encoded data" },
  { label: "Extract Domains", pattern: "\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}\\b", flags: "g", sample: "Visit evil-host.ru or sub.domain.example.org for more info" },
  { label: "Common Log Format", pattern: "^(\\S+)\\s+\\S+\\s+\\S+\\s+\\[([^\\]]+)\\]\\s+\"([^\"]+)\"\\s+(\\d{3})\\s+(\\d+|-)$", flags: "gm", sample: "192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] \"GET /index.html HTTP/1.1\" 200 2326" },
  { label: "Extract JWT", pattern: "eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+", flags: "g", sample: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNrvP5rQj1wGvR6QqVvX5J7kLxQm4vN3bG8FhYI" },
  { label: "Extract Windows Paths", pattern: "[A-Za-z]:\\\\(?:[\\w. -]+\\\\)*[\\w. -]+", flags: "g", sample: "File dropped at C:\\Users\\Public\\malware.exe and D:\\temp\\payload.dll" },
  { label: "Extract CVEs", pattern: "CVE-\\d{4}-\\d{4,7}", flags: "gi", sample: "Exploits: CVE-2024-1234, CVE-2023-45678 affecting Apache and Nginx" },
];

const SAVED_KEY = "ba.regex.saved";

function RegexPlaygroundPage() {
  const [input, setInput] = useState("");
  const [pattern, setPattern] = useState("");
  const [flags, setFlags] = useState("g");
  const [saved, setSaved] = useState<{ label: string; pattern: string; flags: string }[]>(() => {
    try { return JSON.parse(localStorage.getItem(SAVED_KEY) || "[]"); } catch { return []; }
  });
  const [copiedIdx, setCopiedIdx] = useState(-1);

  useEffect(() => { localStorage.setItem(SAVED_KEY, JSON.stringify(saved)); }, [saved]);

  const matches = useMemo(() => {
    if (!pattern.trim() || !input) return null;
    try {
      const re = new RegExp(pattern, flags);
      const m: { full: string; groups: string[]; index: number }[] = [];
      let match: RegExpExecArray | null;
      while ((match = re.exec(input)) !== null) {
        m.push({ full: match[0], groups: match.slice(1), index: match.index });
        if (!re.global) break;
      }
      return m;
    } catch {
      return null;
    }
  }, [input, pattern, flags]);

  const highlighted = useMemo(() => {
    if (!pattern.trim() || !input || !matches) return input;
    const parts: { text: string; highlight: boolean }[] = [];
    let last = 0;
    for (const m of matches) {
      if (m.index > last) parts.push({ text: input.slice(last, m.index), highlight: false });
      parts.push({ text: m.full, highlight: true });
      last = m.index + m.full.length;
    }
    if (last < input.length) parts.push({ text: input.slice(last), highlight: false });
    return parts;
  }, [input, pattern, matches]);

  function loadPreset(p: typeof SOC_PATTERNS[0]) {
    setPattern(p.pattern);
    setFlags(p.flags);
    setInput(p.sample);
  }

  function saveCustom() {
    const label = prompt("Name this pattern:");
    if (!label || !pattern.trim()) return;
    setSaved((prev) => [...prev.filter((s) => s.label !== label), { label, pattern, flags }]);
    toast("Pattern saved");
  }

  function removeSaved(label: string) {
    setSaved((prev) => prev.filter((s) => s.label !== label));
  }

  return (
    <PageShell
      eyebrow="TOOLS / REGEX"
      title="Regex Playground"
      description="Test and build SOC regex patterns against sample data. Preloaded with common IOC and log parsing patterns."
      crumbs={[{ label: "Tools" }, { label: "Regex" }]}
    >
      <div className="grid grid-cols-[280px_1fr] gap-4">
        <div className="space-y-3">
          <Panel title="SOC Patterns" priority="secondary" bodyClassName="p-0">
            <div className="divide-y divide-border/50">
              {SOC_PATTERNS.map((p) => (
                <button key={p.label} onClick={() => loadPreset(p)}
                  className="w-full px-3 py-2 text-left hover:bg-card/40 transition-colors">
                  <div className="text-mono ba-text-sm text-foreground/90">{p.label}</div>
                  <div className="mt-0.5 font-mono text-[10px] text-muted-foreground truncate">{p.pattern}</div>
                </button>
              ))}
            </div>
          </Panel>
          {saved.length > 0 && (
            <Panel title="Saved Patterns" priority="secondary" bodyClassName="p-0">
              <div className="divide-y divide-border/50">
                {saved.map((s) => (
                  <div key={s.label} className="flex items-center gap-1 px-3 py-2">
                    <button onClick={() => { setPattern(s.pattern); setFlags(s.flags); }} className="flex-1 text-left">
                      <div className="text-mono ba-text-sm text-foreground/90">{s.label}</div>
                    </button>
                    <button onClick={() => removeSaved(s.label)} className="text-muted-foreground hover:text-destructive"><Trash2 className="h-3 w-3" /></button>
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </div>

        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <input
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              placeholder="Enter regex pattern..."
              className="flex-1 rounded border border-border bg-background/60 px-3 py-2 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
            />
            <input
              value={flags}
              onChange={(e) => setFlags(e.target.value)}
              placeholder="flags"
              className="w-16 rounded border border-border bg-background/60 px-2 py-2 font-mono text-sm text-foreground outline-none focus:border-primary/50"
            />
            <button onClick={saveCustom} disabled={!pattern.trim()}
              className="inline-flex items-center gap-1 rounded border border-border px-2 py-2 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground disabled:opacity-40">
              <Save className="h-3 w-3" /> Save
            </button>
          </div>

          <Panel title="Test Input">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Paste text to test against..."
              className="h-40 w-full resize-y rounded border border-border bg-background/60 p-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
            />
          </Panel>

          {matches && (
            <Panel
              title={`Matches (${matches.length})`}
              actions={
                <button onClick={() => { navigator.clipboard.writeText(JSON.stringify(matches, null, 2)); setCopiedIdx(0); setTimeout(() => setCopiedIdx(-1), 1200); }}
                  className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
                  {copiedIdx === 0 ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> export</>}
                </button>
              }
            >
              <div className="rounded border border-border/50 bg-background/40 p-3 font-mono text-sm leading-relaxed text-foreground/90 whitespace-pre-wrap">
                {highlighted.map((p, i) => p.highlight
                  ? <mark key={i} className="rounded bg-warning/30 text-warning px-0.5">{p.text}</mark>
                  : <span key={i}>{p.text}</span>
                )}
              </div>
              {matches.length > 0 && (
                <div className="mt-3 space-y-1">
                  {matches.map((m, i) => (
                    <div key={i} className="flex items-start gap-2 rounded border border-border/50 bg-background/30 px-3 py-1.5">
                      <Chip tone="primary">#{i + 1}</Chip>
                      <div className="min-w-0 flex-1">
                        <code className="block truncate font-mono text-sm text-foreground/90">{m.full}</code>
                        {m.groups.length > 0 && (
                          <div className="mt-0.5 flex flex-wrap gap-1">
                            {m.groups.map((g, gi) => g !== undefined && (
                              <span key={gi} className="rounded border border-border/30 bg-background/40 px-1 py-0.5 font-mono text-[10px] text-muted-foreground">${gi + 1}: {g}</span>
                            ))}
                          </div>
                        )}
                      </div>
                      <span className="shrink-0 font-mono text-[10px] text-muted-foreground">{m.index}</span>
                    </div>
                  ))}
                </div>
              )}
            </Panel>
          )}

          {!matches && pattern.trim() && (
            <div className="rounded border border-dashed border-border bg-card/40 p-6 text-center">
              <div className="text-mono text-sm text-muted-foreground">No matches found</div>
            </div>
          )}
        </div>
      </div>
    </PageShell>
  );
}
