import { useEffect, useMemo, useState } from "react"
import { BookOpen, Clipboard, FileCode2, ShieldCheck } from "lucide-react"
import { buildIdsRule, explainIdsRule, getIdsRuleTemplates } from "../../api/backend"
import IdsRuleBuilderForm from "../../components/ids/IdsRuleBuilderForm"
import IdsRuleOutput from "../../components/ids/IdsRuleOutput"
import IdsTemplateLibrary from "../../components/ids/IdsTemplateLibrary"
import { WorkbenchHeader, WorkbenchPage, WorkbenchPanel } from "../../components/layout/WorkbenchShell"
import { copyText, DEFAULT_IDS_RULE, normalizeIdsPayload, reviewIdsRule, templatesFromBackend } from "../../lib/idsRuleEngine"
import { downloadText } from "../../lib/domUtils"

const MODES = [
  { id: "build", label: "Build from fields", icon: FileCode2, description: "Draft a Snort or Suricata rule from structured inputs." },
  { id: "explain", label: "Explain existing rule", icon: Clipboard, description: "Paste a rule and review options, warnings, and tuning notes." },
  { id: "templates", label: "Template library", icon: BookOpen, description: "Load common defensive starting points into the builder." },
]

const SAMPLE_RULE = 'alert tcp any any -> any 80 (msg:"SQL injection attempt"; content:"union select"; nocase; http_uri; classtype:web-application-attack; sid:1000001; rev:1;)'

const LOG_QUERY_PROFILES = {
  web: { label: "Web access", description: "HTTP access logs, proxy events, WAF hits, and app gateway telemetry.", fields: [["src_ip", "Source IP"], ["method", "Method"], ["path", "Path contains"], ["status", "Status"], ["user_agent", "User agent"]], defaults: { method: "GET", status: "500", path: "/admin" } },
  auth: { label: "Auth logs", description: "Linux sshd, Windows logon, VPN, IAM, and identity events.", fields: [["username", "Username"], ["src_ip", "Source IP"], ["result", "Result"], ["service", "Service"], ["host", "Host"]], defaults: { result: "failed", service: "sshd" } },
  dns: { label: "DNS logs", description: "Resolver, DNS firewall, and passive DNS query telemetry.", fields: [["query", "Query/domain"], ["record_type", "Record type"], ["rcode", "Response code"], ["client_ip", "Client IP"]], defaults: { record_type: "A", rcode: "NXDOMAIN" } },
  firewall: { label: "Firewall", description: "Firewall, security group, IDS flow, and deny/allow records.", fields: [["src_ip", "Source IP"], ["dst_ip", "Destination IP"], ["dst_port", "Destination port"], ["action", "Action"], ["protocol", "Protocol"]], defaults: { action: "deny", protocol: "tcp", dst_port: "3389" } },
  email: { label: "Email security", description: "MTA logs, DMARC aggregate/failure reports, spam filter, and mail gateway events.", fields: [["from", "Envelope from"], ["to", "Recipient"], ["src_ip", "Source IP"], ["status", "Status"], ["action", "Action taken"]], defaults: { action: "reject", status: "550" } },
  windows: { label: "Windows events", description: "Security EventLog (4625, 4688, 4720, 7045) and Sysmon process/network events.", fields: [["event_id", "Event ID"], ["account", "Account name"], ["process", "Process/Image"], ["src_ip", "Source IP"], ["host", "Hostname"]], defaults: { event_id: "4625", account: "Administrator" } },
  cloud: { label: "Cloud / SaaS logs", description: "CloudTrail, audit logs, AWS GuardDuty, GCP Security Command Center, O365 audit.", fields: [["source", "Cloud/Service"], ["event_name", "Event name"], ["user", "User/ARN"], ["src_ip", "Source IP"], ["status", "Status"]], defaults: { source: "AWS", status: "FAILURE", event_name: "ConsoleLogin" } },
}

const PROFILE_MITRE_MAP = {
  web: { id: "T1190", name: "Exploit Public-Facing Application" },
  auth: { id: "T1110", name: "Brute Force" },
  dns: { id: "T1071.004", name: "DNS" },
  firewall: { id: "T1046", name: "Network Service Discovery" },
  email: { id: "T1566", name: "Phishing" },
  windows: { id: "T1078", name: "Valid Accounts" },
  cloud: { id: "T1530", name: "Data from Cloud Storage" },
}

function buildLogQueries(profile, fields = {}) {
  const entries = Object.entries(fields).filter(([, value]) => String(value || "").trim()).map(([key, value]) => [key, String(value).replaceAll('"', '\\"').trim()])
  const spl = entries.length ? `index=* sourcetype=${profile} ${entries.map(([key, value]) => `${key}="${value}"`).join(" ")}` : `index=* sourcetype=${profile}`
  const kql = entries.length ? entries.map(([key, value]) => `${key}: "${value}"`).join(" and ") : "*"
  const sigma = [
    "title: BeyondArch Detection Query",
    `description: ${LOG_QUERY_PROFILES[profile]?.description || profile} log search`,
    `logsource:`,
    `  product: ${profile}`,
    "detection:",
    "  selection:",
    ...(entries.length ? entries.map(([key, value]) => `    ${key}: "${value}"`) : ["    event: *"]),
    "  condition: selection",
    "fields:",
    ...(entries.length ? entries.map(([key]) => `  - ${key}`) : ["  - _raw"]),
    "falsepositives:",
    "  - Review before promotion",
    `level: medium`,
  ].join("\n")
  return { spl, kql, sigma }
}

function DetectionQueryBuilder({ setNotice }) {
  const [profile, setProfile] = useState("web")
  const [fields, setFields] = useState(() => ({ ...LOG_QUERY_PROFILES.web.defaults }))
  const spec = LOG_QUERY_PROFILES[profile] || LOG_QUERY_PROFILES.web
  const queries = useMemo(() => buildLogQueries(profile, fields), [fields, profile])

  function choose(nextProfile) {
    setProfile(nextProfile)
    setFields({ ...(LOG_QUERY_PROFILES[nextProfile]?.defaults || {}) })
  }

  function update(key, value) {
    setFields((current) => ({ ...current, [key]: value }))
  }

  function copyAllQueries() {
    const text = Object.entries(queries).map(([label, value]) => `=== ${label.toUpperCase()} ===\n${value}`).join("\n\n")
    copyText(text, "All queries", setNotice)
  }

  function downloadQueries() {
    const text = Object.entries(queries).map(([label, value]) => `=== ${label.toUpperCase()} ===\n${value}`).join("\n\n")
    downloadText(`beyondarch-${profile}-queries.txt`, text, "text/plain")
    setNotice?.("Queries downloaded.")
  }

  return (
    <WorkbenchPanel className="ba-detection-query-panel">
      <div className="ba-detection-query-head">
        <div>
          <p className="ba-workbench-eyebrow">Log query builder</p>
          <h2>Build investigation queries beside the rule draft</h2>
          <p>{spec.description}</p>
        </div>
        <div className="ba-detection-query-tabs">
          {Object.entries(LOG_QUERY_PROFILES).map(([key, item]) => (
            <button key={key} type="button" className={profile === key ? "is-active" : ""} onClick={() => choose(key)}>{item.label} <span className="ba-chip ba-status-info">MITRE: {PROFILE_MITRE_MAP[key]?.id}</span></button>
          ))}
        </div>
      </div>
      <div className="ba-detection-query-grid">
        <section className="ba-detection-query-fields">
          {spec.fields.map(([key, label]) => (
            <label key={key}>
              <span>{label}</span>
              <input value={fields[key] || ""} onChange={(event) => update(key, event.target.value)} placeholder={key} />
            </label>
          ))}
        </section>
        <section className="ba-detection-query-output">
          {PROFILE_MITRE_MAP[profile] ? (
            <div className="mb-2 text-[11px] font-semibold tracking-wide text-cyan-400">
              MITRE ATT&amp;CK: {PROFILE_MITRE_MAP[profile].id} — {PROFILE_MITRE_MAP[profile].name}
            </div>
          ) : null}
          {Object.entries(queries).map(([label, value]) => (
            <article key={label}>
              <div><strong>{label.toUpperCase()}</strong><button type="button" onClick={() => copyText(value, label.toUpperCase(), setNotice)}>Copy</button></div>
              <pre>{value}</pre>
            </article>
          ))}
          <div className="mt-3 flex flex-wrap gap-2 border-t border-white/10 pt-3">
            <button type="button" className="ba-button-ghost rounded-lg px-2.5 py-1.5 text-[11px] font-black" onClick={copyAllQueries}>Copy all queries</button>
            <button type="button" className="ba-button-ghost rounded-lg px-2.5 py-1.5 text-[11px] font-black" onClick={downloadQueries}>Download .txt</button>
          </div>
        </section>
      </div>
    </WorkbenchPanel>
  )
}


const IDS_PREFILL_KEY = "beyondarch.ids.prefill"
const PENDING_ARTIFACT_KEY = "beyondarch.pendingArtifact"

function consumeIdsPrefill() {
  try {
    const direct = window.localStorage.getItem(IDS_PREFILL_KEY) || ""
    if (direct) {
      window.localStorage.removeItem(IDS_PREFILL_KEY)
      return direct
    }
    const raw = window.localStorage.getItem(PENDING_ARTIFACT_KEY)
    if (!raw) return ""
    const artifact = JSON.parse(raw)
    if (artifact?.target !== "ids-builder") return ""
    const value = artifact?.value ? String(artifact.value) : ""
    if (!value.trim()) return ""
    window.localStorage.removeItem(PENDING_ARTIFACT_KEY)
    return value
  } catch {
    return ""
  }
}

export default function IdsBuilderPage({ setPage }) {
  const [incomingPrefill] = useState(() => consumeIdsPrefill())
  const [mode, setMode] = useState(incomingPrefill ? "explain" : "build")
  const [form, setForm] = useState(DEFAULT_IDS_RULE)
  const [generated, setGenerated] = useState(null)
  const [explainInput, setExplainInput] = useState(incomingPrefill || SAMPLE_RULE)
  const [explained, setExplained] = useState(null)
  const [templates, setTemplates] = useState([])
  const [templateLoading, setTemplateLoading] = useState(false)
  const [loading, setLoading] = useState(false)
  const [notice, setNotice] = useState(incomingPrefill ? "Loaded draft context from Detection & MITRE." : "")

  useEffect(() => {
    let active = true
    async function loadTemplates() {
      setTemplateLoading(true)
      try {
        const response = await getIdsRuleTemplates()
        if (active) setTemplates(templatesFromBackend(response))
      } catch {
        if (active) setTemplates(templatesFromBackend(null))
      } finally {
        if (active) setTemplateLoading(false)
      }
    }
    loadTemplates()
    return () => { active = false }
  }, [])

  const activeResult = mode === "explain" ? explained : generated
  const activeRule = mode === "explain"
    ? explained?.input || explainInput
    : generated?.rule || ""
  const review = useMemo(() => reviewIdsRule({ payload: form, rule: activeRule, result: activeResult }), [form, activeRule, activeResult])

  async function generateRule() {
    setLoading(true)
    setNotice("")
    try {
      const payload = normalizeIdsPayload(form)
      const data = await buildIdsRule(payload)
      setGenerated(data)
      setMode("build")
      setNotice("IDS rule draft generated. Validate locally before production use.")
    } catch (error) {
      setGenerated({ error: error?.message || "Could not generate IDS rule." })
      setNotice("IDS rule generation failed.")
    } finally {
      setLoading(false)
    }
  }

  async function explainRule() {
    if (!explainInput.trim()) {
      setNotice("Paste an IDS rule before explaining.")
      return
    }
    setLoading(true)
    setNotice("")
    try {
      const data = await explainIdsRule(explainInput.trim())
      setExplained(data)
      setMode("explain")
      setNotice(data?.parsed === false ? "Rule could not be parsed. Check syntax." : "IDS rule explained.")
    } catch (error) {
      setExplained({ parsed: false, error: error?.message || "Could not explain IDS rule.", input: explainInput })
      setNotice("IDS rule explanation failed.")
    } finally {
      setLoading(false)
    }
  }

  function useTemplate(template) {
    setForm(normalizeIdsPayload(template.data))
    setGenerated(null)
    setMode("build")
    setNotice(`${template.name} loaded into builder.`)
  }

  function resetBuilder() {
    setForm(DEFAULT_IDS_RULE)
    setGenerated(null)
    setNotice("Builder reset.")
  }

  return (
    <WorkbenchPage className="ba-ids-rule-page ba-page-enter">
      <WorkbenchHeader
        eyebrow="Detection engineering"
        title="Detection Workspace"
        subtitle="Draft Snort / Suricata rules, explain existing signatures, build log queries, and hand off detection evidence."
        icon={ShieldCheck}
        chips={[{ label: "Rules", tone: "info" }, { label: "Query builder", tone: "ready" }, { label: "case handoff", tone: "warning" }]}
      />

      {notice ? <p className="ba-info-banner text-sm">{notice}</p> : null}

      <section className="ba-detection-mode-row">
        {MODES.map((item) => {
          const Icon = item.icon
          return (
            <button
              key={item.id}
              type="button"
              className={`ba-ids-mode-card ${mode === item.id ? "is-active" : ""}`}
              onClick={() => setMode(item.id)}
            >
              <span><Icon className="h-4 w-4" />{item.label}</span>
              <small>{item.description}</small>
            </button>
          )
        })}
      </section>

      <div className="ba-detection-workspace-grid">
        <WorkbenchPanel className="ba-detection-build-panel">
          {mode === "build" ? (
            <IdsRuleBuilderForm value={form} onChange={setForm} onGenerate={generateRule} onReset={resetBuilder} loading={loading} />
          ) : null}

          {mode === "explain" ? (
            <div className="space-y-3">
              <section className="ba-ids-builder-section rounded-2xl border border-white/10 bg-black/40 p-4">
                <div className="ba-ids-section-copy">
                  <p className="text-sm font-black text-zinc-100">Explain existing rule</p>
                  <p className="mt-1 text-xs leading-5 text-zinc-400">Paste a Snort/Suricata-style rule to parse options, validation notes, tuning guidance, and mapping hints.</p>
                </div>
                <label className="min-w-0 space-y-2">
                  <span className="ba-field-label">IDS rule</span>
                  <textarea
                    className="ba-input min-h-40 font-mono text-xs"
                    value={explainInput}
                    onChange={(event) => setExplainInput(event.target.value)}
                    placeholder={SAMPLE_RULE}
                  />
                </label>
              </section>
              <div className="flex flex-wrap gap-2">
                <button type="button" className="ba-button-primary rounded-xl px-4 py-2 text-sm font-black" onClick={explainRule}>{loading ? "Explaining…" : "Explain rule"}</button>
                <button type="button" className="ba-button-secondary rounded-xl px-4 py-2 text-sm font-bold" onClick={() => copyText(explainInput, "Rule", setNotice)}>Copy input</button>
              </div>
            </div>
          ) : null}

          {mode === "templates" ? <IdsTemplateLibrary templates={templates} onUseTemplate={useTemplate} loading={templateLoading} /> : null}
        </WorkbenchPanel>

        <WorkbenchPanel className="ba-detection-output-panel">
          <IdsRuleOutput
            rule={activeRule}
            result={activeResult}
            review={review}
            mode={mode}
            setNotice={setNotice}
            setPage={setPage}
          />
        </WorkbenchPanel>
      </div>

      <DetectionQueryBuilder setNotice={setNotice} />
    </WorkbenchPage>
  )
}
