import { useState, useEffect } from "react"
import { Clipboard, Play, Terminal, AlertTriangle, Wrench, ShieldCheck, RefreshCcw } from "lucide-react"
import { getHackingtoolCategories, runHackingtoolTool } from "../../api/backend"
import { WorkbenchPage, WorkbenchPanel } from "../../components/layout/WorkbenchShell"
import { copyText } from "../../lib/domUtils.js"

const DUPLICATE_TOOL_IDS = new Set(["nmap", "theharvester", "amass", "maigret"])

function filterUnique(categories) {
  return categories.map((cat) => ({
    ...cat,
    tools: (cat.tools || []).filter((t) => !DUPLICATE_TOOL_IDS.has(t.id)),
  })).filter((cat) => cat.tools.length > 0)
}

function toolHint(toolId) {
  const hints = {
    sqlmap: "SQL injection detection & exploitation",
    hydra: "Online password brute-force",
    searchsploit: "Local exploit-db search",
    metasploit: "Metasploit framework console",
    foremost: "File carving toolkit",
    dnsrecon: "DNS enumeration & brute-force",
    recon_ng: "Reconnaissance framework",
    whatweb: "Web technology detection",
    wpscan: "WordPress vulnerability scanner",
    wfuzz: "Web application fuzzer",
    crunch: "Wordlist generator",
    cewl: "Custom wordlist from URL content",
    aircrack_ng: "Wireless security assessment",
    apktool: "Android APK reverse engineering",
    testdisk: "Data recovery & partition repair",
  }
  return hints[toolId]
}

function ToolCard({ cat, tool, active, onSelect }) {
  return (
    <button type="button" onClick={() => onSelect(cat, tool)}
      className={`ht-tool-card ${active ? "active" : ""}`}>
      <p className="ht-tool-card-name">{tool.name}</p>
      {tool.description ? <p className="ht-tool-card-desc">{tool.description}</p> : null}
      {toolHint(tool.id) ? <p className="ht-tool-card-hint">{toolHint(tool.id)}</p> : null}
    </button>
  )
}

function Field({ label, value }) {
  return (
    <div className="ht-field">
      <p className="ht-field-label">{label}</p>
      <p className="ht-field-value">{value}</p>
    </div>
  )
}

export default function HackingToolsPage() {
  const [categories, setCategories] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [selectedCat, setSelectedCat] = useState(null)
  const [selectedTool, setSelectedTool] = useState(null)
  const [target, setTarget] = useState("")
  const [args, setArgs] = useState("")
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState(null)
  const [notice, setNotice] = useState("")

  useEffect(() => { load() }, [])

  async function load() {
    setLoading(true)
    setError("")
    try {
      const data = await getHackingtoolCategories()
      setCategories(filterUnique(data.categories || []))
    } catch (err) {
      setError(`Failed to load categories: ${err.message}`)
      setNotice(`Failed to load categories: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  function selectTool(cat, tool) {
    setSelectedCat(cat)
    setSelectedTool(tool)
    setResult(null)
  }

  function clearSelection() {
    setSelectedCat(null)
    setSelectedTool(null)
    setResult(null)
    setTarget("")
    setArgs("")
    setNotice("")
  }

  async function runTool() {
    if (!selectedTool || !target.trim()) { setNotice("Select a tool and enter a target first."); return }
    setRunning(true)
    setNotice(`Running ${selectedTool.name}...`)
    try {
      const resp = await runHackingtoolTool({ categoryId: selectedCat.id, toolId: selectedTool.id, target: target.trim(), args: args.trim() })
      setResult(resp)
      setNotice(resp?.error ? `${selectedTool.name} returned an error.` : `${selectedTool.name} finished.`)
    } catch (err) {
      setResult({ error: err.message })
      setNotice(`Tool failed: ${err.message}`)
    } finally {
      setRunning(false)
    }
  }

  const hasCat = categories.length > 0

  return (
    <WorkbenchPage className="ht-page">
      <WorkbenchPanel className="ht-workbench">
        <div className="ht-hero">
          <div className="ht-hero-row">
            <div className="ht-hero-main">
              <div className="ht-hero-title-row">
                <Wrench className="ht-hero-icon" />
                <h1 className="ht-hero-title">Offensive <span className="ht-hero-accent">Toolbox</span></h1>
              </div>
              <p className="ht-hero-sub">Web attack, forensics, wireless, exploit, reverse engineering, and other Kali/security tools. Tools with dedicated pages are excluded.</p>
            </div>
            <div className="ht-hero-badge">
              <div className="ht-hero-led" />
              <span>LOCAL WRAPPER</span>
            </div>
          </div>
        </div>

        {error ? (
          <div className="ht-error">
            <AlertTriangle />
            <p className="ht-error-text">{error}</p>
          </div>
        ) : null}

        {!hasCat && !loading && !error ? (
          <div className="ht-empty">
            <Wrench className="ht-empty-icon" />
            <h3 className="ht-empty-title">No tools loaded</h3>
            <p className="ht-empty-desc">Click <strong>Load tools</strong> to fetch available categories from the backend.</p>
            <div className="ht-empty-chips">
              <span className="ht-badge ht-badge-info">Category browser</span>
              <span className="ht-badge ht-badge-warning">Run controls</span>
              <span className="ht-badge">Terminal output</span>
            </div>
          </div>
        ) : null}

        {hasCat ? (
          <div className="ht-section">
            <div className="ht-section-head">
              <div>
                <p className="ht-section-eyebrow"><Wrench />Select a tool</p>
                <h2 className="ht-section-title">Tool browser</h2>
                <p className="ht-section-desc">Pick a category, then choose a tool to configure and run.</p>
              </div>
              <div style={{ display: "flex", gap: "0.4rem" }}>
                {selectedTool && <button className="ht-btn-secondary" onClick={clearSelection}>Clear</button>}
                <button className="ht-load-btn" disabled={loading} onClick={load}>
                  <RefreshCcw />
                  {loading ? "Loading\u2026" : hasCat ? `${categories.length} categories` : "Load tools"}
                </button>
              </div>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
              {categories.map((cat) => {
                const isActive = selectedCat?.id === cat.id
                return (
                  <details key={cat.id} open={isActive} className="ht-details">
                    <summary>
                      <div className="ht-details-row">
                        <div>
                          <p className="ht-details-name">{cat.name}</p>
                          {cat.description ? <p className="ht-details-desc">{cat.description}</p> : null}
                        </div>
                        <span className="ht-details-count">{cat.tools?.length || 0}</span>
                      </div>
                    </summary>
                    <div className="ht-details-grid">
                      {cat.tools?.map((tool) => (
                        <ToolCard key={tool.id} cat={cat} tool={tool} active={selectedTool?.id === tool.id} onSelect={selectTool} />
                      ))}
                    </div>
                  </details>
                )
              })}
            </div>
          </div>
        ) : null}

        {selectedTool && hasCat ? (
          <div className="ht-section">
            <div className="ht-run-grid">
              <div style={{ display: "flex", flexDirection: "column", gap: "0.65rem" }}>
                <div>
                  <p className="ht-section-eyebrow active"><ShieldCheck />Explicit run</p>
                  <h2 className="ht-section-title">{selectedTool.name}</h2>
                  <p className="ht-section-desc">{selectedTool.description || `Category: ${selectedCat?.name}`}</p>
                </div>

                <label className="ht-input-label">
                  Target
                  <input className="ht-input" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="Domain, IP, or URL" style={{ marginTop: "0.35rem" }} />
                </label>
                <label className="ht-input-label">
                  Additional arguments <span className="ht-input-opt">(optional)</span>
                  <input className="ht-input" value={args} onChange={(e) => setArgs(e.target.value)} placeholder="e.g. -v --timeout 30" style={{ marginTop: "0.35rem" }} />
                </label>

                <button className="ht-btn-run" disabled={running || !target.trim()} onClick={runTool}>
                  <Play />
                  {running ? "Running\u2026" : `Run ${selectedTool.name}`}
                </button>

                {result ? (
                  result.error ? (
                    <div className="ht-result-error">
                      <p className="ht-result-error-label">Error</p>
                      <p className="ht-result-error-text">{result.error}</p>
                    </div>
                  ) : (
                    <div className="ht-result-ok">
                      <p className="ht-result-ok-label">Result</p>
                      <p className="ht-result-ok-text">
                        {result.exit_code === 0 ? "Tool completed successfully." : `Finished with exit code ${result.exit_code}.`}
                      </p>
                    </div>
                  )
                ) : null}
              </div>

              <aside className="ht-sidebar">
                <div>
                  <p className="ht-sidebar-hd"><ShieldCheck />Controls</p>
                  <p className="ht-sidebar-text">Explicit run \u2014 no automatic execution. Only execute against owned or authorized targets.</p>
                </div>
                <div className="ht-sidebar-chips">
                  <span className="ht-badge ht-badge-warning">EXPLICIT RUN</span>
                  <span className="ht-badge">LOCAL WRAPPER</span>
                  <span className="ht-badge ht-badge-info">NO AUTO EXEC</span>
                </div>
                <Field label="Selected tool" value={selectedTool.name} />
                <Field label="Category" value={selectedCat?.name || ""} />
                {target && <Field label="Target" value={target} />}
                <Field label="Tool state" value={running ? "Running" : result ? "Complete" : "Ready"} />
              </aside>
            </div>
          </div>
        ) : null}

        {selectedTool && hasCat ? (
          <details className="ht-term">
            <summary>
              <div className="ht-term-hd">
                <div className="ht-term-hd-l">
                  <Terminal />
                  <span className="ht-term-hd-label">Terminal log</span>
                </div>
                <div className="ht-term-hd-r">
                  {result ? (
                    <button className="ht-btn-sm"
                      onClick={(e) => {
                        e.stopPropagation()
                        copyText(
                          [result.command || "", result.stdout || "", result.stderr ? `\n[stderr]\n${result.stderr}` : "", result.error ? `\n[error]\n${result.error}` : ""].filter(Boolean).join("\n"),
                          setNotice, "Terminal output"
                        )
                      }}>
                      <Clipboard />Copy
                    </button>
                  ) : null}
                  <span className="ht-term-hd-collapsed">collapsed</span>
                </div>
              </div>
            </summary>
            <pre className="ht-term-pre">
              {result
                ? [result.command || "", result.stdout || "", result.stderr ? `\n[stderr]\n${result.stderr}` : "", result.error ? `\n[error]\n${result.error}` : ""].filter(Boolean).join("\n")
                : "Run a tool to view terminal output."}
            </pre>
          </details>
        ) : null}

        {notice ? <div className="ht-notice">{notice}</div> : null}
      </WorkbenchPanel>
    </WorkbenchPage>
  )
}
