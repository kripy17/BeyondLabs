import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { pushTimelineEvent } from "@/lib/timeline";
import { useRecentInputs } from "@/lib/use-recent-inputs";
import { PageShell } from "@/components/PageShell";
import { ToolShell, type ToolState } from "@/components/soc/ToolShell";
import { IntakeCard, SectionBar, Panel, SendToRow, Chip, IocInventory } from "@/components/soc";
import { KeyFields, Empty, EvidenceCard, ResultBanner, PhishingVerdictSkeleton } from "@/components/output";
import { PreviewBadge } from "@/components/PreviewBadge";
import { takePendingArtifact, sendArtifact } from "@/lib/handoff";
import { analyzeFullEmail, safeAnalyzeUrl } from "@/api/backend";
import { toast } from "sonner";
import { refang, defang, scanSecrets } from "@/lib/ioc-patterns";
import { useLocker, type LockerItem } from "@/lib/locker";
import { Mail, ShieldAlert, ShieldCheck, Link2, Database, CheckCircle2, XCircle, MinusCircle, AlertTriangle, FileText, Hash, Crosshair, Download, Key, FlaskConical, Activity } from "lucide-react";
import { ExplainThisButton } from "@/components/ExplainThis";
import {
  SAMPLES, RX, SENDER_TLDS, BRAND_KEYWORDS,
  type AuthState,
  getDomain, detectAuth, extractBody, extractHeaders,
  detectAttachments, detectLookalike, analyzeUrls,
  genMarkdown, genJsonExport, htmlToText, genBodySignals, buildFromApi,
} from "@/data/phishing";

export const Route = createFileRoute("/phishing")({ component: PhishingPage });

function AuthTile({ name, state }: { name: string; state: AuthState }) {
  const cfg =
    state === "pass" ? { Icon: CheckCircle2, cls: "border-success/50 bg-success/10 text-success", label: "PASS" } :
    state === "fail" ? { Icon: XCircle, cls: "border-destructive/50 bg-destructive/10 text-destructive", label: "FAIL" } :
    state === "softfail" ? { Icon: AlertTriangle, cls: "border-warning/50 bg-warning/10 text-warning", label: "SOFTFAIL" } :
                       { Icon: MinusCircle, cls: "border-border bg-card/40 text-muted-foreground", label: "\u2014" };
  const { Icon, cls, label } = cfg;
  return (
    <div className={"flex items-center justify-between gap-2 rounded-md border px-3 py-2 " + cls}>
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4" />
        <span className="text-mono ba-text-sm uppercase tracking-widest">{name}</span>
      </div>
      <span className="text-mono ba-text-sm font-semibold tabular-nums">{label}</span>
    </div>
  );
}

function EmptyPreview() {
  const cards = [
    ["Sender Identity", "From, Reply-To, Return-Path, display-name mismatches"],
    ["Header Authentication", "SPF, DKIM, DMARC, Received path, auth results"],
    ["Extracted URLs", "Visible text, actual href, defanged targets"],
    ["Lure Signals", "Urgency, credential request, brand impersonation"],
    ["Case Findings", "Report-ready summary, limitations, next steps"],
  ];
  return (
    <Panel title="Awaiting Analysis" icon={FlaskConical} meta="expected output structure" priority="secondary">
      <div className="grid gap-3 grid-cols-2 sm:grid-cols-3">
        {cards.map(([title, text]) => (
          <div key={title} className="rounded-md border border-dashed border-divider-strong bg-card/30 p-3">
            <div className="text-mono text-[10px] font-semibold uppercase tracking-widest text-foreground/80">{title}</div>
            <p className="mt-1 text-[11px] text-muted-foreground">{text}</p>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function ScoreGauge({ score, maxScore, label }: { score: number; maxScore: number; label: string }) {
  const pct = maxScore > 0 ? Math.min(100, Math.round((score / maxScore) * 100)) : 0;
  const tone = pct >= 60 ? "destructive" : pct >= 30 ? "warning" : "success";
  const color = tone === "destructive" ? "bg-destructive" : tone === "warning" ? "bg-warning" : "bg-success";
  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-2 rounded-full bg-card/60 overflow-hidden">
        <div className={"h-full transition-all " + color} style={{ width: `${pct}%` }} />
      </div>
      <span className={"text-mono ba-text-sm font-semibold tabular-nums " + (tone === "destructive" ? "text-destructive" : tone === "warning" ? "text-warning" : "text-success")}>{score}/{maxScore}</span>
      <span className="text-mono text-[9px] uppercase tracking-widest text-muted-foreground">{label}</span>
    </div>
  );
}

function PhishingPage() {
  const pendingRef = useRef(takePendingArtifact());
  const [input, setInput] = useState(() => {
    const p = pendingRef.current;
    return p?.kind === "email" || p?.kind === "raw" || p?.kind === "ioc" ? (p.value ?? "") : "";
  });
  const [loading, setLoading] = useState<string | null>(null);
  const [notice, setNotice] = useState<string>("");
  const [runs, setRuns] = useState(() => pendingRef.current ? 1 : 0);
  const [apiResult, setApiResult] = useState<Record<string, any> | null>(null);
  const navigate = useNavigate();
  const locker = useLocker();
  const [iocDefanged, setIocDefanged] = useState(true);
  const recentInputs = useRecentInputs("phishing");
  const has = input.trim().length > 0;
  const committed = runs > 0 && has;

  useEffect(() => {
    if (pendingRef.current && input) {
      setNotice(`Loaded ${pendingRef.current.kind} from ${pendingRef.current.source}`);
      pendingRef.current = null;
    }
  }, [input]);

  useEffect(() => {
    if (input.trim()) recentInputs.push(input);
  }, [runs, input, recentInputs]);

  const flashNotice = (msg: string) => {
    setNotice(msg);
    setTimeout(() => setNotice(""), 3000);
  };

  const data = useMemo(() => {
    if (!committed) return null;

    const apiData = buildFromApi(apiResult, input, committed);
    if (apiData) return apiData;

    const refanged = refang(input);
    const spf = detectAuth(input, "spf");
    const dkim = detectAuth(input, "dkim");
    const dmarc = detectAuth(input, "dmarc");
    const fromLine = (input.match(/From:\s*(.+)/i)?.[1] ?? "").trim();
    const replyLine = (input.match(/Reply-To:\s*(.+)/i)?.[1] ?? "").trim();
    const pathLine = (input.match(/Return-Path:\s*(.+)/i)?.[1] ?? "").trim();
    const fromDomain = getDomain(fromLine);
    const replyDomain = getDomain(replyLine);
    const replyMismatch = !!(fromDomain && replyDomain && fromDomain !== replyDomain);
    const defangedUrl = /hxxps?:\/\/|\[\.\]/i.test(input);
    const urgency = /urgent|immediately|within \d+h|suspend|today|asap|before my flight/i.test(input);

    const body = extractBody(input);
    const headers = extractHeaders(input);
    const bodyLower = body.toLowerCase();
    const subject = (input.match(/Subject:\s*(.+)/i)?.[1] ?? "").toLowerCase();
    const brandMatch = BRAND_KEYWORDS.find(b => bodyLower.includes(b) || subject.includes(b));

    const hasForm = /<form/i.test(body) || /<input.*type=["']?(?:text|password|email)["' ]/i.test(body);
    const hasPasswordField = /<input.*type=["']?password["' ]/i.test(body) || /password/i.test(bodyLower);
    const hasHtmlForm = /<form\s/i.test(body);
    const hasAttachment = detectAttachments(input);
    const envelopeFlags = detectLookalike(fromLine, replyLine, pathLine);
    const hasLookalike = envelopeFlags.length > 0;

    const emailUniq = <T,>(a: T[]) => Array.from(new Set(a));
    const iocs = (() => {
      const urls = emailUniq((refanged.match(RX.URL) ?? []).map((u: string) => defang(u)));
      const emails = emailUniq(refanged.match(RX.Email) ?? []);
      const ips = emailUniq(refanged.match(RX.IPv4) ?? []);
      const md5 = emailUniq(refanged.match(RX.MD5)?.filter((h: string) => h.length === 32) ?? []);
      const sha256 = emailUniq(refanged.match(RX.SHA256) ?? []);
      const cve = emailUniq(refanged.match(RX.CVE) ?? []);
      const attack = emailUniq(refanged.match(RX.ATTACK) ?? []);
      const domains = emailUniq(
        (refanged.match(RX.Domain) ?? [])
          .filter((d: string) => !ips.includes(d) && !emails.some((e: string) => e.toLowerCase().includes(d.toLowerCase())))
          .map((d: string) => defang(d))
      );
      return { urls, domains, ips, hashes: [...md5, ...sha256], emails, cve, attack };
    })();

    const secrets = scanSecrets(body || input);

    const urlAnalysis = iocs.urls.length ? analyzeUrls(iocs.urls) : [];

    const findings = [
      spf === "fail" && { sev: "destructive" as const, t: "SPF authentication failed", r: "Sender server is not authorised for the domain.", a: "Treat the From: address as untrusted." },
      spf === "softfail" && { sev: "warning" as const, t: "SPF soft-fail", r: "Sending IP is not in the SPF record but policy is permissive (~all).", a: "Tighten SPF policy and inspect originating IP." },
      dmarc === "fail" && { sev: "destructive" as const, t: "DMARC alignment failed", r: "Sender policy denies delivery — likely spoof.", a: "Quarantine similar messages at the gateway." },
      dkim === "fail" && { sev: "warning" as const, t: "DKIM signature not validated", r: "Body integrity not guaranteed.", a: "Pivot on Received: hops for true source." },
      dkim === "softfail" && { sev: "info" as const, t: "DKIM soft-fail / neutral", r: "Selector responded but signature did not cleanly verify.", a: "Confirm key rotation on the sending domain." },
      replyMismatch && { sev: "warning" as const, t: "Reply-To masquerades as sender", r: "Reply traffic diverts to a different lookalike domain.", a: "Block both domains and notify the user." },
      defangedUrl && { sev: "info" as const, t: "Defanged URL detected", r: "Indicator was sanitised by the submitter.", a: "Re-fang in Safe URL Analyzer, never click directly." },
      urgency && { sev: "info" as const, t: "Urgency / coercion language", r: "Social-engineering pressure tactic.", a: "Include in user training and report draft." },
      hasForm && { sev: "destructive" as const, t: "HTML form in email body", r: "Email contains a form — credential harvesting risk.", a: "Verify form action URL and inspect in Phishing Triage." },
      hasPasswordField && { sev: "destructive" as const, t: "Password field in email", r: "Body contains password input — likely credential harvesting.", a: "Escalate; do not submit credentials." },
      hasAttachment.hasAttachments && { sev: "warning" as const, t: "Email carries attachments", r: hasAttachment.detail.length ? hasAttachment.detail.join("; ") : "Multipart content detected.", a: "Submit to Attachment Triage before opening." },
      fromDomain && SENDER_TLDS.has(fromDomain.split(".").pop() || "") && { sev: "warning" as const, t: "Sender TLD is high-risk", r: `Sender domain uses suspicious TLD .${fromDomain.split(".").pop()}`, a: "Investigate domain registration in OSINT." },
      hasLookalike && { sev: "warning" as const, t: "Envelope domain mismatch", r: envelopeFlags.join("; "), a: "Verify sender identity out-of-band." },
      brandMatch && spf === "fail" && { sev: "destructive" as const, t: `Brand impersonation: ${brandMatch}`, r: `Message references '${brandMatch}' while authentication fails.`, a: "Verify sender out-of-band." },
      brandMatch && spf !== "fail" && { sev: "warning" as const, t: `Brand reference: ${brandMatch}`, r: `Message references '${brandMatch}' in body or subject.`, a: "Verify legitimacy with sender." },
      ...genBodySignals(body, iocs),
    ].filter(Boolean) as { sev: "destructive" | "warning" | "info"; t: string; r: string; a: string }[];

    const breakdown = [
      { signal: "SPF",             weight: spf === "fail" ? 30 : spf === "softfail" ? 12 : 0,     state: spf },
      { signal: "DMARC",           weight: dmarc === "fail" ? 30 : dmarc === "softfail" ? 10 : 0, state: dmarc },
      { signal: "DKIM",            weight: dkim === "fail" ? 10 : dkim === "softfail" ? 4 : 0,    state: dkim },
      { signal: "Reply-To mismatch", weight: replyMismatch ? 15 : 0, state: replyMismatch ? "fail" as const : "pass" as const },
      { signal: "Defanged URL",    weight: defangedUrl ? 10 : 0,    state: defangedUrl ? "fail" as const : "pass" as const },
      { signal: "Urgency / coercion", weight: urgency ? 10 : 0,     state: urgency ? "fail" as const : "pass" as const },
      { signal: "HTML form",       weight: hasForm ? 25 : 0,        state: hasForm ? "fail" as const : "pass" as const },
      { signal: "Password field",  weight: hasPasswordField ? 25 : 0, state: hasPasswordField ? "fail" as const : "pass" as const },
      { signal: "Attachments",     weight: hasAttachment.hasAttachments ? 10 : 0, state: hasAttachment.hasAttachments ? "fail" as const : "pass" as const },
      { signal: "Sender TLD risk", weight: fromDomain && SENDER_TLDS.has(fromDomain.split(".").pop() || "") ? 10 : 0, state: "fail" as const },
      { signal: "Envelope mismatch", weight: hasLookalike ? 15 : 0, state: hasLookalike ? "fail" as const : "pass" as const },
      { signal: "Brand impersonation", weight: brandMatch && (spf === "fail" || dmarc === "fail") ? 30 : 0, state: "fail" as const },
    ];
    const destructiveCount = findings.filter((f) => f.sev === "destructive").length;
    const warningCount = findings.filter((f) => f.sev === "warning").length;
    const verdict = destructiveCount > 0 || (spf === "fail" && dmarc === "fail") ? "Likely Phishing" : warningCount > 0 || spf === "softfail" || dmarc === "softfail" ? "Suspicious" : "Inconclusive";
    const tone = destructiveCount > 0 || (spf === "fail" && dmarc === "fail") ? "destructive" as const : warningCount > 0 ? "warning" as const : "success" as const;

    const mitre = [] as { id: string; name: string; source: string }[];
    const seen = new Set<string>();
    const addMitre = (id: string, name: string, source: string) => { if (!seen.has(id)) { seen.add(id); mitre.push({ id, name, source }); } };
    if (spf === "fail" || dmarc === "fail") addMitre("T1566", "Phishing", "auth");
    if (hasForm || hasPasswordField) addMitre("T1566", "Phishing: Credential Harvesting", "body");
    if (hasAttachment.hasAttachments) addMitre("T1204", "User Execution", "attachment");
    if (iocs.cve.length) addMitre("T1190", "Exploit Public-Facing Application", "ioc");
    if (iocs.attack.length) for (const a of iocs.attack) addMitre(a, "Technique referenced", "ioc");

    return { spf, dkim, dmarc, replyMismatch, defangedUrl, urgency, findings, verdict, tone, breakdown, body, headers, hasForm, hasPasswordField, hasHtmlForm, hasAttachment, envelopeFlags, hasLookalike, iocs, secrets, urlAnalysis, mitre, fromDomain, fromLine, replyLine, pathLine, brandMatch };
  }, [committed, input, apiResult]);

  const pushedPhishRef = useRef("");
  useEffect(() => {
    if (data?.verdict && pushedPhishRef.current !== data.verdict + runs) {
      pushedPhishRef.current = data.verdict + runs;
      pushTimelineEvent({ source: "phishing", verb: "analyzed", detail: `Phishing analysis: ${data.verdict} risk`, result: `${data.findings.length} findings` });
    }
  }, [data, runs]);

  const handoff = (kind: string, value: string, to: string) => {
    sendArtifact({ kind, value, source: "/phishing" });
    navigate({ to });
  };

  const state: ToolState = loading ? "parsing" : !has ? "idle" : !data ? "idle" : "ready";

  const run = async () => {
    if (loading || !has) return;
    setRuns((r) => r + 1);
    setLoading("analysing");
    setNotice("");
    try {
      const body = extractBody(input);
      const headers = extractHeaders(input);
      const response = await analyzeFullEmail(headers, body, true);
      setApiResult(response);
    } catch (e: any) {
      setApiResult(null);
      toast.error(e?.message || "Analysis failed", { description: e?.suggestion });
    }
    try {
      const refanged = refang(input);
      const urls = Array.from(new Set(refanged.match(RX.URL) ?? [])).slice(0, 3);
      if (urls.length > 0) {
        await Promise.all(urls.map((url) =>
          safeAnalyzeUrl({
            url,
            allow_live_fetch: true,
            max_redirects: 3,
            timeout_seconds: 6,
            allow_private_targets: false,
          }).catch(() => null)
        ));
      }
      flashNotice("Analysis complete");
      toast.success("Phishing analysis complete");
    } catch (e: any) {
      flashNotice("Analysis completed (partial)");
      toast.error(e?.message || "Analysis completed with errors", { description: e?.suggestion });
    } finally {
      setLoading(null);
    }
  };

  const clear = useCallback(() => { setInput(""); setRuns(0); setNotice(""); setApiResult(null); }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") clear();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [clear]);

  return (
    <PageShell
      eyebrow="TRIAGE / PHISHING"
      title="Phishing Triage"
      description="Static-only inspection of email envelope, auth results, body, and embedded indicators. No links followed."
      crumbs={[{ label: "Triage" }, { label: "Phishing" }]}
      jumps={[{ label: "URL Analysis", to: "/url" }, { label: "Detection", to: "/detection" }]}
    >
      <ToolShell
        icon={Mail}
        title="Phishing Triage"
        purpose="Static analysis of email envelope, authentication and body lures."
        state={state}
        canRun={has && !loading}
        onRun={run}
        onClear={clear}
        intake={
          <>
            <SectionBar id="IN" label="Intake · raw email source" meta="paste full source incl. headers" />
            <IntakeCard
              icon={Mail}
              title="Email Source"
              value={input}
              onChange={setInput}
              onPaste={(t) => { setInput(t); setRuns((r) => r + 1); }}
              samples={[
                { key: "lure", label: "Credential lure", hint: "spf/dkim/dmarc fail" },
                { key: "bec", label: "BEC wire request", hint: "lookalike domain, attachment" },
                { key: "invoice", label: "Invoice / portal", hint: "all auth pass, attachment" },
                { key: "html", label: "HTML form phish", hint: "form, password field, secrets" },
                { key: "suspicious_invoice", label: "Suspicious invoice", hint: "overdue payment lure" },
                { key: "account_alert", label: "Account alert", hint: "security alert + spoofed sender" },
              ]}
              onLoadSample={(key) => {
                const s = SAMPLES[key as keyof typeof SAMPLES] ?? SAMPLES.lure;
                setInput(s);
                setRuns((r) => r + 1);
              }}
              onFile={(txt) => { setInput(txt); setRuns((r) => r + 1); }}
              fileAccept=".eml,.txt,.msg,.log"
              run={{ label: "analyse", icon: ShieldAlert, hint: "\u2318\u21B5", onClick: run, disabled: !has || !!loading }}
              onClear={clear}
              rows={10}
              placeholder="[WAITING_FOR_INPUT]\n\nPaste raw email source including headers — or drop a .eml file."
              notice={notice || undefined}
            />
            {recentInputs.items.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 rounded border border-border/50 bg-card/30 px-2.5 py-1.5">
                <span className="text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground/70">recent</span>
                {recentInputs.items.slice(0, 8).map((item, i) => (
                  <button key={i} onClick={() => { setInput(item); setRuns((r) => r + 1); recentInputs.push(item); }}
                    className="max-w-[160px] truncate rounded border border-border/40 bg-background/40 px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground transition-colors hover:border-primary/40 hover:text-primary"
                    title={item}
                  >{item.slice(0, 40)}{item.length > 40 ? "…" : ""}</button>
                ))}
                {recentInputs.items.length > 8 && <span className="text-mono ba-text-3xs text-muted-foreground/50">+{recentInputs.items.length - 8} more</span>}
                <button onClick={() => recentInputs.clear()} className="ml-auto text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground/50 hover:text-destructive">clear</button>
              </div>
            )}
          </>
        }
        output={
          loading ? <PhishingVerdictSkeleton /> : !data ? (
            has ? <Empty icon={ShieldAlert} title="Press analyse or paste to run" hint="Paste the full email source above to compute the risk verdict." /> : <EmptyPreview />
          ) : (
            <div className="space-y-4">

              <div className="pointer-events-none select-none">
                <ResultBanner
                  sticky
                  tone={data.tone === "destructive" ? "destructive" : data.tone === "warning" ? "warning" : "default"}
                  badge={data.tone === "destructive" ? "likely phishing" : data.tone === "warning" ? "suspicious" : "inconclusive"}
                  caseId={`BA-PH-${String(data.findings.length).padStart(2, "0")}`}
                  title={data.verdict}
                  subtitle="Authentication snapshot computed from the message's Authentication-Results header."
                  reasons={data.findings.slice(0, 3).map((f: { t: string }) => f.t)}
                  metrics={[
                    { label: "Findings", value: data.findings.length, tone: data.findings.length > 0 ? "warning" : "success" },
                    { label: "SPF",   value: data.spf.toUpperCase(),   tone: data.spf === "fail" ? "destructive" : data.spf === "softfail" ? "warning" : data.spf === "pass" ? "success" : "default" },
                    { label: "DKIM",  value: data.dkim.toUpperCase(),  tone: data.dkim === "fail" ? "destructive" : data.dkim === "softfail" ? "warning" : data.dkim === "pass" ? "success" : "default" },
                    { label: "DMARC", value: data.dmarc.toUpperCase(), tone: data.dmarc === "fail" ? "destructive" : data.dmarc === "softfail" ? "warning" : data.dmarc === "pass" ? "success" : "default" },
                  ]}
                />
              </div>

              <Panel title="Authentication detail" icon={ShieldCheck} meta="SPF \u00B7 DKIM \u00B7 DMARC" actions={<PreviewBadge />}>
                <div className="grid gap-2 grid-cols-3">
                  <AuthTile name="SPF" state={data.spf} />
                  <AuthTile name="DKIM" state={data.dkim} />
                  <AuthTile name="DMARC" state={data.dmarc} />
                </div>
              </Panel>

              <Panel title="Auth Chain" icon={ShieldCheck} meta="SPF · DKIM · DMARC chain-of-trust"
                actions={<ExplainThisButton kind="email" input={input} />}
              >
                <div className="flex items-center gap-2">
                  <Chip tone={data.spf === "pass" ? "success" : data.spf === "fail" ? "destructive" : data.spf === "softfail" ? "warning" : "default"}>SPF: {data.spf.toUpperCase()}</Chip>
                  <Chip tone={data.dkim === "pass" ? "success" : data.dkim === "fail" ? "destructive" : data.dkim === "softfail" ? "warning" : "default"}>DKIM: {data.dkim.toUpperCase()}</Chip>
                  <Chip tone={data.dmarc === "pass" ? "success" : data.dmarc === "fail" ? "destructive" : data.dmarc === "softfail" ? "warning" : "default"}>DMARC: {data.dmarc.toUpperCase()}</Chip>
                </div>
              </Panel>

              <Panel title="Sender Identity" icon={ShieldCheck}>
                <KeyFields items={[
                  { label: "From", value: data.fromLine || "\u2014" },
                  { label: "Reply-To", value: data.replyLine || "\u2014", tone: data.replyMismatch ? "warning" : "default" },
                  { label: "Return-Path", value: data.pathLine || "\u2014" },
                  { label: "Subject", value: (input.match(/Subject:\s*(.+)/i)?.[1] ?? "\u2014").trim() },
                  { label: "Sender TLD", value: data.fromDomain ? `.${data.fromDomain.split(".").pop()}` : "\u2014", tone: data.fromDomain && SENDER_TLDS.has(data.fromDomain.split(".").pop() || "") ? "warning" : "default" },
                  { label: "Authentication", value: data.spf === "fail" || data.dmarc === "fail" ? "FAIL" : data.spf === "softfail" || data.dmarc === "softfail" || data.dkim === "softfail" ? "SOFTFAIL" : "pass", tone: data.spf === "fail" || data.dmarc === "fail" ? "destructive" : data.spf === "softfail" || data.dmarc === "softfail" || data.dkim === "softfail" ? "warning" : "success" },
                   ...(data.hasAttachment.hasAttachments ? [{ label: "Attachment", value: data.hasAttachment.detail.join("; "), tone: "warning" as const }] : []),
                ]} />
              </Panel>

              {/* Body content */}
              {data.body && (
                <Panel title="Email Body" icon={FileText} meta={data.hasHtmlForm ? "contains HTML" : "plain text"}>
                  {data.hasHtmlForm ? (
                    <pre className="max-h-[280px] overflow-auto rounded border border-border/50 bg-background/60 p-2.5 text-mono ba-text-sm leading-relaxed text-foreground/80 whitespace-pre-wrap">{data.body}</pre>
                  ) : (
                    <pre className="max-h-[200px] overflow-auto rounded border border-border/50 bg-background/60 p-2.5 text-mono ba-text-sm leading-relaxed text-foreground/80 whitespace-pre-wrap">{data.body}</pre>
                  )}
                  {data.hasHtmlForm && (
                    <details className="mt-1">
                      <summary className="cursor-pointer text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground">plain text extract ({htmlToText(data.body).length} chars)</summary>
                      <pre className="mt-1 max-h-[160px] overflow-auto rounded border border-divider-soft bg-background/40 p-2 text-mono ba-text-sm text-foreground/80 whitespace-pre-wrap">{htmlToText(data.body)}</pre>
                    </details>
                  )}
                </Panel>
              )}

              {/* Delivery path */}
              {(() => {
                const hops = Array.from(input.matchAll(/Received:\s*from\s+(\S+)\s*(?:\(([^)]+)\))?(?:\s+by\s+(\S+))?(?:\s+with\s+(\S+))?/gi)).map((m) => ({
                  from: m[1],
                  ip: m[2] ?? "",
                  by: m[3] ?? "",
                  protocol: m[4] ?? "",
                }));
                const classifyHop = (host: string): { label: string; tone: "primary" | "info" | "warning" | "destructive" } => {
                  const h = host.toLowerCase();
                  if (h.includes("mx") || h.includes("mail")) return { label: "MX", tone: "info" };
                  if (h.includes("edge")) return { label: "edge", tone: "warning" };
                  if (h.includes("gateway") || h.includes("gw")) return { label: "gateway", tone: "destructive" };
                  return { label: "relay", tone: "primary" };
                };
                const protoTone = (p: string): "primary" | "info" | "warning" | "success" | "destructive" => {
                  const v = p.toLowerCase();
                  if (v === "esmtpsa") return "warning";
                  if (v === "esmtps") return "info";
                  if (v === "esmtp") return "primary";
                  return "primary";
                };
                return (
                  <Panel title="Delivery Path" meta={`${hops.length} hop${hops.length === 1 ? "" : "s"}`} priority="secondary" collapsible storageKey="ba.panel.phish.delivery" defaultCollapsed>
                    {hops.length === 0 ? (
                      <p className="text-mono ba-text-sm text-muted-foreground">No Received: hops found.</p>
                    ) : (
                      <ol className="relative space-y-0">
                        {hops.map((h, i) => {
                          const cls = classifyHop(h.from);
                          return (
                            <li key={i}>
                              <div className="relative flex items-start gap-3 pb-1">
                                {i < hops.length - 1 && (
                                  <span className="absolute left-[7px] top-4 bottom-0 w-px bg-divider-strong" aria-hidden />
                                )}
                                <div className="relative flex flex-col items-center pt-0.5">
                                  <span className="grid h-3 w-3 shrink-0 place-items-center rounded-full bg-primary ring-2 ring-background" />
                                </div>
                                <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5 py-0.5">
                                  <Chip tone="primary">hop {hops.length - i}</Chip>
                                  <code className="text-mono ba-text-sm text-foreground/90">{h.from}</code>
                                  {h.ip && <span className="text-mono text-[10px] text-muted-foreground">({h.ip})</span>}
                                  {h.protocol && <Chip tone={protoTone(h.protocol)}>{h.protocol}</Chip>}
                                  <Chip tone={cls.tone}>{cls.label}</Chip>
                                </div>
                              </div>
                              {i < hops.length - 1 && (
                                <div className="flex items-center gap-2 pl-[7px] pb-1">
                                  <span className="text-mono text-[10px] text-muted-foreground/40">↓</span>
                                  <span className="h-px flex-1 bg-divider-soft" />
                                </div>
                              )}
                            </li>
                          );
                        })}
                      </ol>
                    )}
                  </Panel>
                );
              })()}

              {/* URL analysis */}
              {data.urlAnalysis.length > 0 && (
                <Panel title="URL Deep Analysis" icon={Link2} meta={`${data.urlAnalysis.length} URL${data.urlAnalysis.length === 1 ? "" : "s"}`} priority="secondary">
                  <div className="space-y-2">
                    {data.urlAnalysis.map((u: any, i: number) => (
                      <div key={i} className="flex flex-wrap items-center gap-2 rounded border border-border/50 bg-card/40 px-3 py-2">
                        <code className="min-w-0 flex-1 truncate text-mono ba-text-sm text-foreground/90">{defang(u.value)}</code>
                        <div className="flex flex-wrap items-center gap-1">
                          {u.badges.length === 0 && <Chip tone="success">clean</Chip>}
                          {u.badges.map((b: any, j: number) => (
                            <Chip key={j} tone={b.tone}>{b.label}</Chip>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}

              {/* Secrets in body */}
              {data.secrets.length > 0 && (
                <Panel title="Secrets Detected in Body" icon={Key} meta={`${data.secrets.length} potential exposure`} priority="secondary">
                  <div className="space-y-1.5">
                    {data.secrets.map((s: any, i: number) => (
                      <div key={i} className="flex items-center justify-between gap-2 rounded border border-destructive/30 bg-destructive/5 px-2.5 py-1.5">
                        <span className="text-mono text-[10px] uppercase tracking-widest text-destructive">{s.type}</span>
                        <code className="text-mono ba-text-sm text-foreground/80">{s.value}</code>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}

              {/* IOC inventory */}
              {data.iocs && (
                <>
                  <label className="inline-flex items-center gap-2 cursor-pointer mb-2">
                    <input
                      type="checkbox"
                      checked={iocDefanged}
                      onChange={(e) => setIocDefanged(e.target.checked)}
                      className="sr-only"
                    />
                    <span className={`relative inline-block h-5 w-9 rounded-full transition-colors ${iocDefanged ? "bg-primary" : "bg-muted-foreground/30"}`}>
                      <span className={`absolute left-0.5 top-0.5 h-4 w-4 rounded-full bg-background transition-transform ${iocDefanged ? "translate-x-4" : "translate-x-0"}`} />
                    </span>
                    <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">{iocDefanged ? "defanged" : "refanged"}</span>
                  </label>
                  <SectionBar id="IO" label="IOC inventory" meta="urls · domains · ips · hashes · emails · cve · attack" priority="secondary" />
                  <div className="flex flex-wrap gap-1.5 mb-2">
                    {(Object.entries(data.iocs) as [string, string[]][]).filter(([, v]) => v.length > 0).map(([k, v]) => (
                      <button
                        key={k}
                        onClick={() => { const t = k === "urls" ? "url" : k === "ips" ? "ipv4" : k === "hashes" ? "sha256" : k === "domains" ? "domain" : k === "emails" ? "email" : k === "cve" ? "cve" : k === "attack" ? "mitre-attack" : "unknown"; v.forEach((item: string) => locker.add({ value: item, type: t as LockerItem["type"], source: "/phishing", note: "" })); flashNotice(`Added ${v.length} ${k} to locker`); }}
                        className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1 text-mono text-[9px] uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground transition-colors"
                      >
                        + {k} ({v.length})
                      </button>
                    ))}
                  </div>
                  <IocInventory
                    onSendTo={(kind, value) => {
                      const map: Record<string, string> = { urls: "/url", domains: "/recon", ips: "/recon", hashes: "/attachment", emails: "/recon", cve: "/detection", attack: "/detection" };
                      handoff(kind.toLowerCase(), value, map[kind.toLowerCase()] ?? "/case");
                    }}
                    groups={[
                      { kind: "urls", items: data.iocs.urls.map(iocDefanged ? defang : refang), tone: "destructive" },
                      { kind: "domains", items: data.iocs.domains.map(iocDefanged ? defang : refang), tone: "warning" },
                      { kind: "ips", items: data.iocs.ips.map(iocDefanged ? defang : refang), tone: "info" },
                      { kind: "hashes", items: data.iocs.hashes.map(iocDefanged ? defang : refang), tone: "primary" },
                      { kind: "emails", items: data.iocs.emails.map(iocDefanged ? defang : refang), tone: "success" },
                      ...(data.iocs.cve.length ? [{ kind: "cve" as const, items: data.iocs.cve.map(iocDefanged ? defang : refang), tone: "destructive" as const }] : []),
                      ...(data.iocs.attack.length ? [{ kind: "attack" as const, items: data.iocs.attack.map(iocDefanged ? defang : refang), tone: "destructive" as const }] : []),
                    ]}
                  />
                </>
              )}

              {/* MITRE */}
              {data.mitre.length > 0 && (
                <Panel title="MITRE ATT&CK Mapping" icon={Crosshair} meta={`${data.mitre.length} technique${data.mitre.length === 1 ? "" : "s"}`} priority="secondary" collapsible storageKey="ba.panel.phish.mitre" defaultCollapsed>
                  <div className="grid gap-2 grid-cols-3">
                    {data.mitre.map((m: any, i: number) => (
                      <div key={i} className="flex items-center gap-2.5 rounded border border-border/50 bg-card/40 px-3 py-2">
                        <span className="grid h-7 w-7 place-items-center rounded border border-destructive/40 bg-destructive/10">
                          <Crosshair className="h-3.5 w-3.5 text-destructive" />
                        </span>
                        <div>
                          <div className="text-mono text-[10px] font-semibold uppercase tracking-widest text-destructive">{m.id}</div>
                          <div className="text-mono ba-text-sm text-foreground/80">{m.name}</div>
                        </div>
                        <Chip tone="info">{m.source}</Chip>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}

              {/* Scoring breakdown table */}
              <SectionBar id="TA" label="Technical · scoring breakdown" meta={`score computed from ${data.breakdown.filter((b: any) => b.weight > 0).length} signal(s)`} priority="raw" />
              <Panel icon={Activity} title="Signal weights" meta="how the risk score was assembled" priority="secondary">
                {(() => { const totalScore = data.breakdown.reduce((a: number, b: any) => a + (b.state === "pass" ? 0 : b.weight), 0); const maxScore = data.breakdown.reduce((a: number, b: any) => a + b.weight, 0); return <ScoreGauge score={totalScore} maxScore={maxScore} label="risk score" />; })()}
                <div className="mt-3 overflow-x-auto rounded border border-border/50">
                  <table className="w-full text-mono text-[11.5px]">
                    <thead className="bg-background/40 text-[10px] uppercase tracking-widest text-muted-foreground">
                      <tr>
                        <th className="px-2 py-1 text-left">signal</th>
                        <th className="px-2 py-1 text-left">state</th>
                        <th className="px-2 py-1 text-left">contribution</th>
                        <th className="px-2 py-1 text-left">share</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.breakdown.map((b: any, i: number) => {
                        const wt = b.state === "pass" ? 0 : b.weight;
                        const totalWt = data.breakdown.reduce((a: number, x: any) => a + (x.state === "pass" ? 0 : x.weight), 0);
                        const pct = totalWt > 0 ? Math.round((wt / totalWt) * 100) : 0;
                        const tone = b.state === "fail" ? "destructive" : b.state === "softfail" ? "warning" : "default";
                        return (
                          <tr key={i} className={"border-t border-divider-soft " + (i % 2 ? "bg-background/20" : "")}>
                            <td className="px-2 py-1.5 text-foreground/90">{b.signal}</td>
                            <td className="px-2 py-1.5"><Chip tone={tone as "destructive" | "warning" | "default"}>{b.state}</Chip></td>
                            <td className="px-2 py-1.5 text-foreground/90">+{wt}</td>
                            <td className="px-2 py-1.5">
                              <div className="flex items-center gap-2">
                                <div className="h-1.5 w-24 overflow-hidden rounded bg-background/60">
                                  <div className={"h-full " + (wt === 0 ? "bg-muted-foreground/30" : tone === "destructive" ? "bg-destructive/70" : tone === "warning" ? "bg-warning/70" : "bg-primary/70")} style={{ width: `${pct}%` }} />
                                </div>
                                <span className="text-muted-foreground">{pct}%</span>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </Panel>

              {/* Evidence cards */}
              <SectionBar id="EV" label="Evidence cards" meta="reason · limitation · action" />
              <div className="grid gap-3 grid-cols-2">
                {data.findings.length === 0 ? <Empty title="No suspicious patterns triggered" hint="Phishing Triage scans email headers and body for SPF/DKIM/DMARC failures, suspicious sender addresses, deceptive links, and urgency language. Try pasting a full email source (headers + body)." /> : data.findings.map((f: { sev: "destructive" | "warning" | "info"; t: string; r: string; a: string }, i: number) => (
                  <EvidenceCard key={i} severity={f.sev} title={f.t} reason={f.r} action={f.a} limitation="Heuristic — confirm against gateway logs and user report." />
                ))}
              </div>



              {/* Raw panels */}
              <div className="grid gap-3 grid-cols-2">
                <Panel icon={ShieldCheck} title="Authentication-Results · raw" meta="parsed verbatim" priority="raw" collapsible storageKey="ba.panel.phish.authraw" defaultCollapsed>
                  <pre className="overflow-x-auto rounded border border-border/50 bg-background/60 p-2.5 text-mono ba-text-sm text-foreground/85 whitespace-pre-wrap">
                    {(input.match(/Authentication-Results:[^\n]*(?:\n\s+[^\n]+)*/gi) ?? ["— none found —"]).join("\n\n")}
                  </pre>
                </Panel>
                <Panel icon={Hash} title="Message identifiers" meta="for de-duplication & search" priority="secondary" collapsible storageKey="ba.panel.phish.msgid" defaultCollapsed>
                  <KeyFields items={[
                    { label: "Message-ID",     value: (input.match(/Message-ID:\s*<([^>]+)>/i)?.[1] ?? "—") },
                    { label: "X-Mailer",       value: (input.match(/X-Mailer:\s*(.+)/i)?.[1]?.trim() ?? "—") },
                    { label: "Date",           value: (input.match(/^Date:\s*(.+)$/im)?.[1]?.trim() ?? "—") },
                    { label: "MIME-Version",   value: (input.match(/MIME-Version:\s*(.+)/i)?.[1]?.trim() ?? "—") },
                    { label: "Content-Type",   value: (input.match(/Content-Type:\s*([^;\n]+)/i)?.[1]?.trim() ?? "—") },
                  ]} />
                </Panel>
              </div>

              <Panel icon={FileText} title="Raw headers" meta="everything before the first blank line" priority="raw" actions={<PreviewBadge label="verbatim" />} collapsible storageKey="ba.panel.phish.rawheaders" defaultCollapsed>
                <pre className="max-h-[320px] overflow-auto rounded border border-border/50 bg-background/60 p-2.5 text-mono text-[10.5px] leading-relaxed text-foreground/80 whitespace-pre-wrap">
                  {extractHeaders(input) || "— empty —"}
                </pre>
              </Panel>

              {/* Export + Handoff */}
              <div className="grid gap-3 grid-cols-[200px_1fr]">
                <Panel title="Export" icon={Download} priority="secondary">
                  <button
                    onClick={() => {
                      const md = genMarkdown(input, data, data.iocs);
                      const blob = new Blob([md], { type: "text/markdown" });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a"); a.href = url; a.download = `phishing-report-${Date.now()}.md`; a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="group inline-flex w-full items-center justify-center gap-2 rounded border border-primary/50 bg-primary/10 px-3 py-2 text-mono text-[10px] uppercase tracking-widest text-primary transition-all hover:bg-primary/20"
                  >
                    <Download className="h-3.5 w-3.5" /> MD
                  </button>
                  <button
                    onClick={() => {
                      const json = genJsonExport(data, data.iocs);
                      const blob = new Blob([json], { type: "application/json" });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a"); a.href = url; a.download = `phishing-report-${Date.now()}.json`; a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="mt-1 group inline-flex w-full items-center justify-center gap-2 rounded border border-divider-strong bg-card/40 px-3 py-2 text-mono text-[10px] uppercase tracking-widest text-muted-foreground transition-all hover:bg-card/70 hover:text-foreground"
                  >
                    <Download className="h-3.5 w-3.5" /> JSON
                  </button>
                </Panel>
                <SendToRow targets={[
                  { label: "Safe URL Analyzer", to: "/url", icon: Link2 },
                  { label: "Attachment Triage", to: "/attachment", icon: FileText },
                  { label: "Detection & MITRE", to: "/detection", icon: ShieldAlert },
                  { label: "Logs & Alerts", to: "/logs", icon: Database },
                ]} />
              </div>
            </div>
          )
        }
      />
    </PageShell>
  );
}


