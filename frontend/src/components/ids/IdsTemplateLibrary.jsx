import { FileText } from "lucide-react"

export default function IdsTemplateLibrary({ templates, onUseTemplate, loading }) {
  return (
    <div className="space-y-4">
      <div className="ba-ds-panel p-4">
        <p className="text-sm font-black text-zinc-100">Template library</p>
        <p className="mt-1 text-sm leading-6 text-zinc-400">Templates fill the builder only. They are starting points for lab validation, not production-ready signatures.</p>
      </div>
      {loading ? <p className="ba-empty-state">Loading IDS templates…</p> : null}
      <div className="grid gap-3 md:grid-cols-2">
        {templates.map((template) => (
          <article key={template.id} className="ba-ids-template-card ba-ds-panel p-4">
            <div className="flex items-start justify-between gap-3">
              <span className="rounded-xl border border-cyan-400/20 bg-cyan-400/10 p-2 text-cyan-200"><FileText className="h-4 w-4" /></span>
              <button type="button" className="ba-button-secondary rounded-xl px-3 py-2 text-xs font-black" onClick={() => onUseTemplate(template)}>Use template</button>
            </div>
            <h3 className="mt-3 text-base font-black text-zinc-100">{template.name}</h3>
            <p className="mt-2 text-sm leading-6 text-zinc-400">{template.description}</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {(template.tags || []).map((tag) => <span key={tag} className="ba-chip ba-status-info">{tag}</span>)}
            </div>
            <pre className="mt-3 max-h-28 overflow-hidden whitespace-pre-wrap rounded-xl border border-white/10 bg-black/30 p-3 text-[11px] leading-5 text-zinc-400">{template.data?.msg || "IDS template"}\ncontent: {template.data?.content || template.data?.pcre || "custom"}</pre>
          </article>
        ))}
      </div>
    </div>
  )
}
