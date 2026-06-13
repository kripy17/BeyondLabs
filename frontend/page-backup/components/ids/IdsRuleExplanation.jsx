export default function IdsRuleExplanation({ result, review }) {
  const explanation = result?.explanation || []
  const parsed = result?.parsed_rule
  return (
    <section className="ba-utility-output-card space-y-4">
      <div>
        <h3>Rule explanation</h3>
        <p className="mt-1 text-sm leading-6 text-zinc-400">Plain-English detection context, tuning notes, false-positive checks, and ATT&CK hints.</p>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <InfoList title="What it detects" items={explanation.slice(0, 3)} empty="Generate or explain a rule to see detection meaning." />
        <InfoList title="Tuning notes" items={review?.tuning || []} />
        <InfoList title="False-positive risks" items={review?.falsePositive || []} />
        <InfoList title="Coverage" items={review?.coverage || []} />
      </div>

      <div className="ba-card" style={{ borderColor: "var(--clr-border)" }}>
        <div className="ba-output-section-head" style={{ marginBottom: ".65rem" }}>
          <p className="ba-output-section-eyebrow">MITRE / detection context</p>
        </div>
        <div className="grid gap-2 md:grid-cols-2">
          {(review?.mitre || []).map((item) => (
            <article key={item.id} className="ba-card">
              <div className="flex flex-wrap gap-2">
                <span className="ba-tag-violet">{item.id}</span>
                <span className="ba-tag-zinc">candidate</span>
              </div>
              <h4 className="mt-2 text-sm font-black text-zinc-100">{item.name}</h4>
              <p className="mt-1 text-xs text-zinc-400">{item.tactic}</p>
              <p className="mt-2 text-xs leading-5 text-zinc-300">{item.reason}</p>
            </article>
          ))}
        </div>
        <p className="mt-3 text-xs leading-5 text-zinc-500">These are mapping hints only. Confirm adversary behavior with telemetry before assigning ATT&CK techniques in a report.</p>
      </div>

      {parsed ? (
        <details className="ba-final-details">
          <summary>Parsed options</summary>
          <pre className="ba-pre-block">{JSON.stringify(parsed, null, 2)}</pre>
        </details>
      ) : null}
    </section>
  )
}

function InfoList({ title, items = [], empty = "No notes yet." }) {
  return (
    <div className="ba-ds-panel p-4">
      <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">{title}</p>
      <div className="mt-3 space-y-2">
        {items.length ? items.map((item) => <p key={item} className="text-sm leading-6 text-zinc-300">• {item}</p>) : <p className="text-sm text-zinc-500">{empty}</p>}
      </div>
    </div>
  )
}
