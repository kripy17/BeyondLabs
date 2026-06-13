import { ChevronDown, Play, RotateCcw, SlidersHorizontal } from "lucide-react"

const ENGINES = ["snort", "suricata"]
const ACTIONS = ["alert", "log", "pass", "drop"]
const PROTOCOLS = ["tcp", "udp", "icmp", "http", "dns", "tls"]
const CLASSTYPES = [
  "web-application-attack",
  "attempted-recon",
  "trojan-activity",
  "policy-violation",
  "misc-activity",
  "attempted-admin",
]

export default function IdsRuleBuilderForm({ value, onChange, onGenerate, onReset, loading }) {
  const setField = (key, nextValue) => onChange({ ...value, [key]: nextValue })
  const setCheck = (key, checked) => onChange({ ...value, [key]: checked })

  return (
    <div className="space-y-3">
      <BuilderSection
        title="Rule intent"
        description="Choose the engine and describe the behavior this draft should alert on. Keep the message analyst-readable."
      >
        <div className="grid gap-3 md:grid-cols-3">
          <SelectField label="Engine" value={value.engine} onChange={(next) => setField("engine", next)} options={ENGINES} />
          <SelectField label="Action" value={value.action} onChange={(next) => setField("action", next)} options={ACTIONS} />
          <SelectField label="Protocol" value={value.protocol} onChange={(next) => setField("protocol", next)} options={PROTOCOLS} />
        </div>
        <TextField label="Message" value={value.msg} onChange={(next) => setField("msg", next)} placeholder="Possible suspicious HTTP activity" />
      </BuilderSection>

      <BuilderSection
        title="Traffic scope"
        description="Scope the rule to the network path you expect. Avoid broad any-any matching unless you are still exploring."
      >
        <div className="grid gap-3 md:grid-cols-[1fr_0.7fr_0.7fr_1fr_0.7fr]">
          <TextField label="Source IP" value={value.src_ip} onChange={(next) => setField("src_ip", next)} placeholder="any or $HOME_NET" />
          <TextField label="Source port" value={value.src_port} onChange={(next) => setField("src_port", next)} placeholder="any" />
          <SelectField label="Direction" value={value.direction} onChange={(next) => setField("direction", next)} options={["->", "<>"]} />
          <TextField label="Destination IP" value={value.dst_ip} onChange={(next) => setField("dst_ip", next)} placeholder="any or $EXTERNAL_NET" />
          <TextField label="Destination port" value={value.dst_port} onChange={(next) => setField("dst_port", next)} placeholder="80" />
        </div>
      </BuilderSection>

      <BuilderSection
        title="Match logic"
        description="Use a stable content string or PCRE. HTTP modifiers should match where the evidence appears."
      >
        <div className="grid gap-3 md:grid-cols-2">
          <TextField label="Content match" value={value.content} onChange={(next) => setField("content", next)} placeholder="union select" />
          <TextField label="PCRE" value={value.pcre} onChange={(next) => setField("pcre", next)} placeholder="/pattern/i" />
        </div>
        <div className="grid gap-2 sm:grid-cols-3">
          <CheckField label="nocase" checked={value.nocase} onChange={(checked) => setCheck("nocase", checked)} />
          <CheckField label="http_uri" checked={value.http_uri} onChange={(checked) => setCheck("http_uri", checked)} />
          <CheckField label="http_header" checked={value.http_header} onChange={(checked) => setCheck("http_header", checked)} />
        </div>
      </BuilderSection>

      <details className="ba-ds-panel p-4">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-sm font-black text-zinc-100">
          <span className="flex items-center gap-2"><SlidersHorizontal className="h-4 w-4 text-cyan-300" />Advanced rule metadata</span>
          <ChevronDown className="h-4 w-4 text-zinc-400" />
        </summary>
        <div className="mt-4 space-y-3">
          <div className="grid gap-3 md:grid-cols-5">
            <TextField label="Flow" value={value.flow} onChange={(next) => setField("flow", next)} placeholder="to_server,established" />
            <SelectField label="Classtype" value={value.classtype} onChange={(next) => setField("classtype", next)} options={CLASSTYPES} allowCustom />
            <TextField label="Priority" value={value.priority} onChange={(next) => setField("priority", next)} placeholder="2" />
            <TextField label="SID" value={value.sid} onChange={(next) => setField("sid", next)} placeholder="1000001" />
            <TextField label="Rev" value={value.rev} onChange={(next) => setField("rev", next)} placeholder="1" />
          </div>
          <TextField
            label="Extra options"
            textarea
            value={value.extra_options}
            onChange={(next) => setField("extra_options", next)}
            placeholder="metadata:service http\nreference:url,example.com"
          />
        </div>
      </details>

      <div className="flex flex-wrap gap-2">
        <button type="button" className="ba-button-primary rounded-xl px-4 py-2 text-sm font-black" onClick={onGenerate}>
          <Play className="mr-2 inline h-4 w-4" />{loading ? "Generating…" : "Generate rule"}
        </button>
        <button type="button" className="ba-button-secondary rounded-xl px-4 py-2 text-sm font-bold" onClick={onReset}>
          <RotateCcw className="mr-2 inline h-4 w-4" />Reset
        </button>
      </div>
    </div>
  )
}

function BuilderSection({ title, description, children }) {
  return (
    <section className="ba-ids-builder-section ba-ds-panel p-4">
      <div className="ba-ids-section-copy">
        <p className="text-sm font-black text-zinc-100">{title}</p>
        <p className="mt-1 text-xs leading-5 text-zinc-400">{description}</p>
      </div>
      <div className="min-w-0 space-y-3">{children}</div>
    </section>
  )
}

function TextField({ label, value, onChange, placeholder = "", textarea = false }) {
  const props = {
    className: `ba-input ${textarea ? "min-h-24 font-mono text-xs" : ""}`,
    value,
    placeholder,
    onChange: (event) => onChange(event.target.value),
  }
  return (
    <label className="space-y-2">
      <span className="ba-field-label">{label}</span>
      {textarea ? <textarea {...props} /> : <input {...props} />}
    </label>
  )
}

function SelectField({ label, value, onChange, options, allowCustom = false }) {
  return (
    <label className="space-y-2">
      <span className="ba-field-label">{label}</span>
      <select className="ba-input" value={value} onChange={(event) => onChange(event.target.value)}>
        {allowCustom && value && !options.includes(value) ? <option value={value}>{value}</option> : null}
        {options.map((option) => <option key={option} value={option}>{option}</option>)}
      </select>
    </label>
  )
}

function CheckField({ label, checked, onChange }) {
  return (
    <label className="ba-check-row ba-ds-panel px-3 py-2 text-sm text-zinc-200">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      {label}
    </label>
  )
}
