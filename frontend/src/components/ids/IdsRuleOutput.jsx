import { Clipboard, Download, ExternalLink, FileText } from "lucide-react"
import IdsRuleExplanation from "./IdsRuleExplanation"
import IdsRuleWarnings from "./IdsRuleWarnings"
import { buildIdsMarkdown, copyText, downloadText, makeDetectionPrefill } from "../../lib/idsRuleEngine"
import SendToActions from "../investigation/SendToActions"
import AnalystOutputCard from "../investigation/AnalystOutputCard"

export default function IdsRuleOutput({ rule, result, review, mode, setNotice, setPage }) {
  const markdown = buildIdsMarkdown({ rule, result, review, mode })

  function sendToCyberChef() {
    try {
      window.localStorage.setItem("beyondarch.pendingArtifact", JSON.stringify({
        target: "cyberchef",
        type: "text",
        value: rule,
        source: "ids-rule-builder",
        created_at: new Date().toISOString(),
      }))
      setNotice?.("Rule sent to CyberChef input.")
      setPage?.("cyberchef")
    } catch {
      setNotice?.("Could not write CyberChef handoff to local storage.")
    }
  }

  function sendToDetection() {
    try {
      window.localStorage.setItem("beyondarch.detection.prefill", makeDetectionPrefill({ rule, result, review }))
      setNotice?.("Rule context sent to Detection & MITRE.")
      setPage?.("detection-mitre")
    } catch {
      setNotice?.("Could not write Detection & MITRE handoff to local storage.")
    }
  }

  if (!rule && !result) {
    return (
      <section className="ba-utility-output-card">
        <h3>Generated Rule</h3>
        <p className="mt-2 text-sm leading-6 text-zinc-400">Build a rule from fields, explain an existing rule, or load a template to start review.</p>
      </section>
    )
  }

  return (
    <div className="space-y-4">
      {result?.error ? <p className="ba-info-banner text-sm">{result.error}</p> : null}

      <section className="ba-utility-output-card">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3>Generated Rule</h3>
            <p className="mt-1 text-xs text-zinc-400">Draft only. Validate locally before production use.</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {result?.profile ? <span className="rounded-md border border-white/10 bg-black/30 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-zinc-400">Profile: {result.profile}</span> : null}
              <span className="rounded-md border border-white/10 bg-black/30 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-zinc-400">Mode: {mode}</span>
              {review?.mitre?.length > 0 ? review.mitre.map((m) => <span key={m.id} className="rounded-md border border-cyan-700/30 bg-cyan-950/30 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-cyan-300">MITRE: {m.id} ({m.name})</span>) : null}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <button type="button" className="ba-button-ghost rounded-lg px-2 py-1 text-xs font-bold" onClick={() => copyText(rule, "Rule", setNotice)}><Clipboard className="mr-1 inline h-3.5 w-3.5" />Copy rule</button>
            <button type="button" className="ba-button-ghost rounded-lg px-2 py-1 text-xs font-bold" onClick={() => downloadText("beyondarch-ids-rule.rules", `${rule}\n`, "text/plain")}><Download className="mr-1 inline h-3.5 w-3.5" />.rules</button>
            <button type="button" className="ba-button-ghost rounded-lg px-2 py-1 text-xs font-bold" onClick={() => downloadText("beyondarch-ids-review.md", markdown, "text/markdown")}><FileText className="mr-1 inline h-3.5 w-3.5" />Review</button>
          </div>
        </div>
        <pre className="ba-code-block ba-utility-code whitespace-pre-wrap break-words text-sm leading-6">{rule || "No rule parsed."}</pre>
        <div className="mt-3 flex flex-wrap gap-2">
          <button type="button" className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={sendToDetection}><ExternalLink className="mr-2 inline h-4 w-4" />Send to Detection & MITRE</button>
          <button type="button" className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={sendToCyberChef}><ExternalLink className="mr-2 inline h-4 w-4" />Send content to CyberChef</button>
        </div>
        <div className="mt-3">
          <SendToActions
            payload={{ type: "detection_rule", title: "Detection rule draft", value: markdown, summary: review?.summary || rule, tags: ["detection", "ids", "rule"] }}
            source="Detection Workspace"
            setPage={setPage}
            compact
          />
        </div>
      </section>

      <AnalystOutputCard
        title="Rule output quality"
        verdict={review?.warnings?.length ? "needs tuning" : "draft rule"}
        confidence="static rule review"
        summary={(review?.coverage || [])[0] || "Validate this rule with positive and negative samples before production deployment."}
        evidence={(review?.coverage || []).concat((review?.mitre || []).map((item) => `${item.id} ${item.name}: ${item.reason}`)).slice(0, 5)}
        limitations={(review?.warnings || []).concat("Generated/explained rule output is a draft and may create false positives.").slice(0, 5)}
        nextActions={[...(review?.tuning || []).slice(0, 2), "Test against sample logs before enabling.", "Send validated behavior to Detection & MITRE or the case report."]}
        metrics={[
          ["Rule chars", rule?.length || 0],
          ["Warnings", review?.warnings?.length || 0],
          ["Mode", mode],
        ]}
      />

      <IdsRuleExplanation result={result} review={review} />
      <IdsRuleWarnings review={review} />

      <details className="ba-ds-panel p-4">
        <summary className="cursor-pointer text-sm font-bold text-zinc-100">Advanced / raw details</summary>
        <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap rounded-xl bg-black/40 p-3 text-xs text-zinc-300">{JSON.stringify({ result, review }, null, 2)}</pre>
      </details>
    </div>
  )
}
