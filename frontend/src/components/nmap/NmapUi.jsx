
export function NmapMetricGrid({ fields = [] }) {
  const filtered = fields.filter(([, value]) => value !== undefined && value !== null && String(value).trim() !== "" && String(value).trim() !== "0")
  if (!filtered.length) return null
  return (
    <div className="ba-metric-grid">
      {filtered.map(([label, value]) => (
        <article key={label}>
          <p>{label}</p>
          <strong>{value}</strong>
        </article>
      ))}
    </div>
  )
}

export function NmapTerminalPane({ raw }) {
  return (
    <section className="rounded-2xl border border-emerald-400/15 bg-black p-4 shadow-[inset_0_0_32px_rgba(16,185,129,0.08)]">
      <div className="mb-3 flex items-center justify-between gap-3 border-b border-emerald-400/10 pb-2">
        <div className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 rounded-full bg-rose-400" />
          <span className="h-2.5 w-2.5 rounded-full bg-amber-300" />
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
        </div>
        <span className="font-mono text-[0.68rem] font-bold uppercase tracking-[0.16em] text-emerald-300">nmap terminal</span>
      </div>
      {raw ? (
        <pre className="max-h-[34rem] overflow-auto whitespace-pre-wrap font-mono text-xs leading-5 text-emerald-300">{raw}</pre>
      ) : (
        <div className="flex min-h-[18rem] items-center justify-center rounded-xl border border-emerald-400/10 bg-emerald-400/5 p-4 text-center font-mono text-sm text-emerald-200/80">
          Run Nmap to view the raw terminal transcript here.
        </div>
      )}
    </section>
  )
}

export function NmapServiceTable({ ports = [], onSend }) {
  if (!ports.length) return <p className="ba-empty-state">No open ports parsed yet.</p>
  return (
    <div className="overflow-auto rounded-2xl border border-white/10">
      <table className="w-full min-w-[760px] text-left text-sm">
        <thead className="bg-black/40 text-xs uppercase tracking-[0.14em] text-zinc-400">
          <tr>
            <th className="p-3">Port</th>
            <th className="p-3">Service</th>
            <th className="p-3">Category</th>
            <th className="p-3">Version / product</th>
            <th className="p-3">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-white/10">
          {ports.map((port) => {
            const detail = [port.product, port.version, port.extrainfo].filter(Boolean).join(" ")
            return (
              <tr key={`${port.protocol}-${port.port}-${port.service}`}>
                <td className="p-3 font-mono text-zinc-100">{port.port}/{port.protocol}</td>
                <td className="p-3 font-black text-zinc-100">{port.service}</td>
                <td className="p-3"><span className="ba-tag-cyan">{port.category || "service"}</span></td>
                <td className="break-words p-3 text-zinc-300">
                  <div>{detail || "—"}</div>
                  {port.exposureNote ? <div className="mt-1 text-xs leading-5 text-zinc-400">{port.exposureNote}</div> : null}
                </td>
                <td className="p-3">
                  {onSend ? (
                    <div className="flex flex-wrap gap-2">
                      <button type="button" className="rounded-lg border border-white/10 px-2 py-1 text-xs font-bold text-zinc-200 hover:border-cyan-300/50 hover:text-cyan-100" onClick={() => onSend(port, "recon-exposure")}>Recon</button>
                      <button type="button" className="rounded-lg border border-white/10 px-2 py-1 text-xs font-bold text-zinc-200 hover:border-cyan-300/50 hover:text-cyan-100" onClick={() => onSend(port, "detection-mitre")}>Detection</button>
                    </div>
                  ) : "—"}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
