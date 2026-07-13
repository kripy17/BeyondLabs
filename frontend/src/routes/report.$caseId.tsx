import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { ArrowLeft, Printer, Globe, Link2, Fingerprint, AlertTriangle, CheckCircle, FileText, Activity, HelpCircle, Database } from "lucide-react";
import { useLocker } from "@/lib/locker";
import { toast } from "sonner";

export const Route = createFileRoute("/report/$caseId")({ component: ReportPage });

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

function loadCases(): Case[] {
  try {
    const raw = localStorage.getItem(LS_KEY);
    return raw ? JSON.parse(raw) as Case[] : [];
  } catch {
    return [];
  }
}

function iocIcon(body: string) {
  if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(body)) return { icon: Globe, label: "IP" };
  if (/https?:\/\//.test(body)) return { icon: Link2, label: "URL" };
  if (/\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/i.test(body)) return { icon: Fingerprint, label: "Hash" };
  return { icon: HelpCircle, label: "IOC" };
}

function kindColor(kind: EntryKind): string {
  switch (kind) {
    case "note": return "var(--color-muted-foreground)";
    case "evidence": return "var(--color-primary)";
    case "decision": return "var(--color-warning)";
    case "action": return "var(--color-success)";
    case "ioc": return "var(--color-destructive)";
  }
}

function kindBg(kind: EntryKind): string {
  switch (kind) {
    case "note": return "var(--color-muted)";
    case "evidence": return "color-mix(in srgb, var(--color-primary) 15%, transparent)";
    case "decision": return "color-mix(in srgb, var(--color-warning) 15%, transparent)";
    case "action": return "color-mix(in srgb, var(--color-success) 15%, transparent)";
    case "ioc": return "color-mix(in srgb, var(--color-destructive) 15%, transparent)";
  }
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function daysSince(iso: string): number {
  return Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
}

const KIND_LABEL: Record<EntryKind, string> = {
  note: "Note", evidence: "Evidence", decision: "Decision", action: "Action", ioc: "IOC",
};

function ReportPage() {
  const { caseId } = Route.useParams();
  const navigate = useNavigate();
  const locker = useLocker();
  const [reportCase, setReportCase] = useState<Case | null>(null);

  useEffect(() => {
    const all = loadCases();
    setReportCase(all.find((c) => c.id === caseId) ?? null);
  }, [caseId]);

  if (!reportCase) {
    return (
      <div className="report report--not-found">
        <style>{reportCss}</style>
        <div className="report-body">
          <div className="report-empty">
            <AlertTriangle className="report-empty-icon" />
            <h1>Case not found</h1>
            <p>The case <code>{caseId}</code> does not exist or has been deleted.</p>
            <button className="report-btn report-btn--back" onClick={() => navigate({ to: "/case" })}>
              <ArrowLeft className="report-btn-icon" /> Back to cases
            </button>
          </div>
        </div>
      </div>
    );
  }

  const c = reportCase;
  const counts: Record<EntryKind, number> = { note: 0, evidence: 0, decision: 0, action: 0, ioc: 0 };
  c.entries.forEach((e) => { counts[e.kind]++; });

  const sorted = [...c.entries].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
  const iocEntries = c.entries.filter((e) => e.kind === "ioc");
  const evidenceEntries = c.entries.filter((e) => e.kind === "evidence");

  const age = daysSince(c.createdAt);

  return (
    <div className="report">
      <style>{reportCss}</style>

      <div className="report-toolbar no-print">
        <button className="report-btn report-btn--back" onClick={() => navigate({ to: "/case" })}>
          <ArrowLeft className="report-btn-icon" /> Back to case
        </button>
        <button className="report-btn report-btn--print" onClick={() => window.print()}>
          <Printer className="report-btn-icon" /> Print / Save PDF
        </button>
      </div>

      <div className="report-body">
        <header className="report-header">
          <div className="report-header-top">
            <h1 className="report-title">{c.title}</h1>
            <span className={`report-state report-state--${c.state}`}>{c.state}</span>
          </div>
          <div className="report-header-meta">
            <span>Created: {formatDate(c.createdAt)}</span>
            <span className="report-sep">|</span>
            <span>ID: {c.id}</span>
            <span className="report-sep">|</span>
            <span>Age: {age} day{age !== 1 ? "s" : ""}</span>
          </div>
          {c.tags.length > 0 && (
            <div className="report-tags">
              {c.tags.map((t) => (
                <span key={t} className="report-tag">{t}</span>
              ))}
            </div>
          )}
        </header>

        <section className="report-section">
          <h2 className="report-section-title">
            <FileText className="report-section-icon" /> Summary
          </h2>
          <table className="report-table">
            <thead>
              <tr>
                <th>Kind</th>
                <th>Count</th>
                <th>% of total</th>
              </tr>
            </thead>
            <tbody>
              {(Object.entries(counts) as [EntryKind, number][]).map(([kind, count]) => (
                <tr key={kind}>
                  <td>
                    <span className="report-kind-badge" style={{ color: kindColor(kind), background: kindBg(kind) }}>
                      {KIND_LABEL[kind]}
                    </span>
                  </td>
                  <td>{count}</td>
                  <td>{c.entries.length > 0 ? ((count / c.entries.length) * 100).toFixed(1) : "0.0"}%</td>
                </tr>
              ))}
              <tr className="report-table-total">
                <td><strong>Total</strong></td>
                <td><strong>{c.entries.length}</strong></td>
                <td>100%</td>
              </tr>
            </tbody>
          </table>
        </section>

        {iocEntries.length > 0 && (
          <section className="report-section">
            <h2 className="report-section-title">
              <Activity className="report-section-icon" /> IOC Summary
              <span className="report-section-count">{iocEntries.length}</span>
            </h2>
            <table className="report-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {iocEntries.map((e) => {
                  const { icon: Icon, label } = iocIcon(e.body);
                  const iocType = label === "IP" ? "ipv4" : label === "URL" ? "url" : label === "Hash" ? (e.body.length === 32 ? "md5" : e.body.length === 40 ? "sha1" : e.body.length === 64 ? "sha256" : "unknown") : "unknown";
                  return (
                    <tr key={e.id}>
                      <td>
                        <span className="report-ioc-type">
                          <Icon className="report-ioc-icon" /> {label}
                        </span>
                      </td>
                      <td><code className="report-code">{e.body}</code></td>
                      <td className="report-mono">
                        <span>{formatDate(e.ts)}</span>
                        <button onClick={() => { locker.add({ value: e.body, type: iocType as any, source: "/report" }); toast("Added to locker"); }} className="report-locker-btn" title="Add to IOC locker">
                          <Database className="report-locker-icon" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </section>
        )}

        <section className="report-section">
          <h2 className="report-section-title">
            <Activity className="report-section-icon" /> Timeline
            <span className="report-section-count">{c.entries.length}</span>
          </h2>

          {sorted.length === 0 ? (
            <p className="report-empty-text">No entries recorded.</p>
          ) : (
            <div className="report-timeline">
              {sorted.map((e, i) => {
                const prev = i > 0 ? sorted[i - 1] : null;
                const prevDate = prev ? new Date(prev.ts).toDateString() : null;
                const currDate = new Date(e.ts).toDateString();
                const showDate = currDate !== prevDate;
                return (
                  <div key={e.id} className="report-timeline-entry">
                    {showDate && (
                      <div className="report-timeline-date">
                        <span>{new Date(e.ts).toLocaleDateString(undefined, { weekday: "short", year: "numeric", month: "short", day: "numeric" })}</span>
                      </div>
                    )}
                    <div className="report-timeline-item">
                      <div className="report-timeline-marker" style={{ background: kindColor(e.kind) }} />
                      <div className="report-timeline-body">
                        <div className="report-timeline-head">
                          <span className="report-kind-badge" style={{ color: kindColor(e.kind), background: kindBg(e.kind) }}>
                            {KIND_LABEL[e.kind]}
                          </span>
                          <span className="report-timeline-time">{formatDate(e.ts)}</span>
                        </div>
                        <div className="report-timeline-text">{e.body}</div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {evidenceEntries.length > 0 && (
          <section className="report-section">
            <h2 className="report-section-title">
              <CheckCircle className="report-section-icon" /> Evidence
              <span className="report-section-count">{evidenceEntries.length}</span>
            </h2>
            <div className="report-evidence-list">
              {evidenceEntries.map((e) => (
                <div key={e.id} className="report-evidence-item">
                  <div className="report-evidence-meta">
                    <span className="report-kind-badge" style={{ color: kindColor("evidence"), background: kindBg("evidence") }}>
                      Evidence
                    </span>
                    <span className="report-evidence-time">{formatDate(e.ts)}</span>
                  </div>
                  <div className="report-evidence-body">{e.body}</div>
                </div>
              ))}
            </div>
          </section>
        )}

        <footer className="report-footer">
          <p>Generated by BeyondLabs Case Report · {new Date().toISOString()}</p>
        </footer>
      </div>
    </div>
  );
}

const reportCss = `
  .report {
    background: var(--color-background);
    color: var(--color-foreground);
    font-family: var(--ba-font-family, system-ui, sans-serif);
    min-height: 100vh;
    line-height: 1.6;
  }
  .report--not-found {
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .report-body {
    max-width: 960px;
    margin: 0 auto;
    padding: 2rem 1.5rem;
  }
  .report-empty {
    text-align: center;
    padding: 4rem 2rem;
    color: var(--color-muted-foreground);
  }
  .report-empty-icon {
    width: 2.5rem;
    height: 2.5rem;
    margin: 0 auto 1rem;
    color: var(--color-destructive);
  }
  .report-empty h1 {
    font-size: 1.25rem;
    font-weight: 600;
    margin: 0 0 0.5rem;
    color: var(--color-foreground);
  }
  .report-empty p {
    font-size: 0.875rem;
    margin: 0 0 1.5rem;
  }
  .report-empty code {
    background: var(--color-card);
    padding: 0.1em 0.3em;
    border-radius: 3px;
    font-size: 0.85em;
  }
  .report-empty-text {
    color: var(--color-muted-foreground);
    font-style: italic;
  }

  /* Toolbar */
  .report-toolbar {
    position: sticky;
    top: 0;
    z-index: 50;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    padding: 0.75rem 1.5rem;
    background: color-mix(in srgb, var(--color-background) 95%, transparent);
    backdrop-filter: blur(8px);
    border-bottom: 1px solid var(--color-border);
  }
  .report-btn {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.45rem 0.9rem;
    border-radius: 6px;
    border: 1px solid var(--color-border);
    background: var(--color-card);
    color: var(--color-foreground);
    font-family: var(--ba-font-family, system-ui, sans-serif);
    font-size: 0.8125rem;
    cursor: pointer;
    transition: all 0.15s;
  }
  .report-btn:hover {
    border-color: var(--color-primary);
    color: var(--color-primary);
  }
  .report-btn-icon {
    width: 1rem;
    height: 1rem;
  }

  /* Header */
  .report-header {
    margin-bottom: 2rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid var(--color-border);
  }
  .report-header-top {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 0.5rem;
  }
  .report-title {
    font-size: 1.75rem;
    font-weight: 700;
    margin: 0;
    line-height: 1.2;
    letter-spacing: -0.02em;
  }
  .report-state {
    display: inline-flex;
    align-items: center;
    padding: 0.15rem 0.6rem;
    border-radius: 9999px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .report-state--active {
    background: color-mix(in srgb, var(--color-warning) 20%, transparent);
    color: var(--color-warning);
    border: 1px solid color-mix(in srgb, var(--color-warning) 30%, transparent);
  }
  .report-state--closed {
    background: color-mix(in srgb, var(--color-muted-foreground) 15%, transparent);
    color: var(--color-muted-foreground);
    border: 1px solid var(--color-border);
  }
  .report-header-meta {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    color: var(--color-muted-foreground);
    flex-wrap: wrap;
  }
  .report-sep {
    color: var(--color-border);
  }
  .report-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    margin-top: 0.75rem;
  }
  .report-tag {
    display: inline-flex;
    align-items: center;
    padding: 0.15rem 0.55rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 500;
    background: color-mix(in srgb, var(--color-primary) 12%, transparent);
    color: var(--color-primary);
    border: 1px solid color-mix(in srgb, var(--color-primary) 20%, transparent);
    text-transform: lowercase;
    font-family: var(--ba-font-family, monospace);
  }

  /* Sections */
  .report-section {
    margin-bottom: 2rem;
  }
  .report-section-title {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 1.1rem;
    font-weight: 600;
    margin: 0 0 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--color-border);
  }
  .report-section-icon {
    width: 1.1rem;
    height: 1.1rem;
    color: var(--color-primary);
  }
  .report-section-count {
    margin-left: auto;
    font-size: 0.75rem;
    font-weight: 500;
    color: var(--color-muted-foreground);
    background: var(--color-card);
    padding: 0.1rem 0.5rem;
    border-radius: 9999px;
    border: 1px solid var(--color-border);
  }

  /* Tables */
  .report-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
  }
  .report-table th {
    text-align: left;
    padding: 0.5rem 0.75rem;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--color-muted-foreground);
    border-bottom: 2px solid var(--color-border);
    font-weight: 600;
  }
  .report-table td {
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--color-border);
    vertical-align: middle;
  }
  .report-table tbody tr:hover {
    background: color-mix(in srgb, var(--color-card) 50%, transparent);
  }
  .report-table-total td {
    border-top: 2px solid var(--color-border);
    font-weight: 600;
  }

  /* Kind badge */
  .report-kind-badge {
    display: inline-flex;
    align-items: center;
    padding: 0.15rem 0.55rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    white-space: nowrap;
  }

  /* IOC */
  .report-ioc-type {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 0.8rem;
    font-weight: 500;
  }
  .report-ioc-icon {
    width: 0.85rem;
    height: 0.85rem;
  }
  .report-code {
    font-family: var(--ba-font-family, monospace);
    font-size: 0.8125rem;
    background: var(--color-card);
    padding: 0.1em 0.3em;
    border-radius: 3px;
    word-break: break-all;
  }
  .report-mono {
    font-family: var(--ba-font-family, monospace);
    font-size: 0.75rem;
    color: var(--color-muted-foreground);
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .report-locker-btn {
    display: inline-flex;
    align-items: center;
    padding: 0.15rem 0.3rem;
    border: 1px solid var(--color-border);
    border-radius: 3px;
    background: transparent;
    cursor: pointer;
    opacity: 0.5;
    transition: opacity 0.15s;
    color: var(--color-muted-foreground);
  }
  .report-locker-btn:hover { opacity: 1; color: var(--color-primary); }
  .report-locker-icon { width: 0.75rem; height: 0.75rem; }

  /* Timeline */
  .report-timeline {
    position: relative;
  }
  .report-timeline::before {
    content: "";
    position: absolute;
    left: 0.5rem;
    top: 0;
    bottom: 0;
    width: 2px;
    background: var(--color-border);
  }
  .report-timeline-entry {
    position: relative;
  }
  .report-timeline-date {
    position: relative;
    z-index: 1;
    margin: 1rem 0 0.5rem 1.5rem;
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--color-muted-foreground);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .report-timeline-date span {
    background: var(--color-background);
    padding: 0 0.5rem;
  }
  .report-timeline-item {
    display: flex;
    gap: 0.75rem;
    padding: 0.4rem 0 0.4rem 0;
  }
  .report-timeline-marker {
    width: 0.75rem;
    height: 0.75rem;
    border-radius: 50%;
    flex-shrink: 0;
    margin-top: 0.3rem;
    margin-left: 0.125rem;
    border: 2px solid var(--color-background);
    z-index: 1;
  }
  .report-timeline-body {
    flex: 1;
    min-width: 0;
  }
  .report-timeline-head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.2rem;
  }
  .report-timeline-time {
    font-size: 0.75rem;
    color: var(--color-muted-foreground);
    font-family: var(--ba-font-family, monospace);
  }
  .report-timeline-text {
    font-size: 0.875rem;
    white-space: pre-wrap;
    word-break: break-word;
    color: var(--color-foreground);
    line-height: 1.6;
  }

  /* Evidence */
  .report-evidence-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .report-evidence-item {
    border: 1px solid var(--color-border);
    border-radius: 8px;
    padding: 1rem;
    background: var(--color-card);
  }
  .report-evidence-meta {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.5rem;
  }
  .report-evidence-time {
    font-size: 0.75rem;
    color: var(--color-muted-foreground);
    font-family: var(--ba-font-family, monospace);
  }
  .report-evidence-body {
    font-size: 0.875rem;
    white-space: pre-wrap;
    word-break: break-word;
    line-height: 1.65;
  }

  /* Footer */
  .report-footer {
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--color-border);
    text-align: center;
    font-size: 0.75rem;
    color: var(--color-muted-foreground);
  }

  /* Print */
  @media print {
    @page {
      margin: 0.75in;
      size: A4;
    }
    body {
      font-size: 11pt;
      line-height: 1.5;
    }
    .no-print {
      display: none !important;
    }
    a[href]::after {
      content: none !important;
    }
    .report-toolbar {
      display: none !important;
    }
    .report-body {
      padding: 0;
      max-width: none;
    }
    .report-timeline::before {
      background: #ccc;
    }
    .report-table th {
      border-bottom-color: #999;
    }
    .report-table td {
      border-bottom-color: #ddd;
    }
    .report-section-title {
      border-bottom-color: #999;
    }
    .report-header {
      border-bottom-color: #999;
    }
    .report-evidence-item {
      break-inside: avoid;
    }
  }
`;
