import {
  containsPredicate,
  countByField,
  dedupeEventsBy,
  eventFieldValue,
  filterEvents,
  numericPredicate,
  regexPredicate,
  sortEvents,
  topNByField,
} from "./eventAlgorithms.js"

const FIELD_ALIASES = {
  _time: "timestamp",
  time: "timestamp",
  username: "user",
  user_name: "user",
  src: "source_ip",
  src_ip: "source_ip",
  clientip: "source_ip",
  client_ip: "source_ip",
  dst: "destination_ip",
  dst_ip: "destination_ip",
  dest: "destination_ip",
  dest_ip: "destination_ip",
  dpt: "destination_port",
  dest_port: "destination_port",
  status: "status_code",
  uri: "uri_path",
  url_path: "uri_path",
  process: "process_name",
  proc: "process_name",
  _raw: "raw",
  raw: "raw",
}

const SEVERITY_RANK = { info: 1, low: 2, medium: 3, high: 4, critical: 5 }
const SEARCH_META_FIELDS = new Set(["index", "source", "sourcetype", "host", "earliest", "latest"])

function deriveTimestamp(event = {}) {
  const direct = event.timestamp || event._time || event.time || event.date || event.datetime || event.TimeCreated || event['@timestamp'] || ""
  if (direct) return String(direct)
  const text = String(event.raw || event.message || event.headline || "")
  const iso = text.match(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/)?.[0]
  if (iso) return iso
  const apache = text.match(/\[(\d{1,2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]/)?.[1]
  if (apache) return apache
  const syslog = text.match(/\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b/)?.[1]
  if (syslog) return syslog
  const loose = text.match(/\b(\d{2}:\d{2}(?::\d{2})?(?:[+-]\d{2}:?\d{2})?)\b/)?.[1]
  return loose || ""
}

function timeParts(value = "") {
  const parsed = Date.parse(value)
  if (Number.isNaN(parsed)) {
    const hour = String(value).match(/\b(\d{2}):(\d{2})(?::\d{2})?/)
    return { date: "", date_hour: hour?.[1] || "", date_minute: hour ? `${hour[1]}:${hour[2]}` : "", time_bucket: hour ? `${hour[1]}:00` : "" }
  }
  const d = new Date(parsed)
  const yyyy = d.getFullYear()
  const mm = String(d.getMonth() + 1).padStart(2, "0")
  const dd = String(d.getDate()).padStart(2, "0")
  const hh = String(d.getHours()).padStart(2, "0")
  const mi = String(d.getMinutes()).padStart(2, "0")
  return { date: `${yyyy}-${mm}-${dd}`, date_hour: hh, date_minute: `${hh}:${mi}`, time_bucket: `${yyyy}-${mm}-${dd} ${hh}:00` }
}

export function normalizeEvent(event = {}, index = 0) {
  const derivedTime = deriveTimestamp(event)
  const parts = timeParts(derivedTime)
  return {
    id: event.id || event.event_id || `event-${index + 1}`,
    event_id: event.event_id || index + 1,
    index: event.index || "main",
    timestamp: derivedTime,
    _time: derivedTime,
    ingest_time: event.ingest_time || new Date().toISOString(),
    date: event.date || parts.date,
    date_hour: event.date_hour || parts.date_hour,
    date_minute: event.date_minute || parts.date_minute,
    time_bucket: event.time_bucket || parts.time_bucket || "unknown",
    source: event.source || "pasted_logs",
    sourcetype: event.sourcetype || event.source_type || "generic_text",
    category: event.category || "generic",
    event_type: event.event_type || "generic",
    severity: event.severity || "info",
    host: event.host || "",
    user: event.user || event.username || "",
    source_ip: event.source_ip || event.src_ip || "",
    src_ip: event.source_ip || event.src_ip || "",
    destination_ip: event.destination_ip || event.dest_ip || "",
    dest_ip: event.destination_ip || event.dest_ip || "",
    destination_port: event.destination_port || event.dest_port || "",
    dest_port: event.destination_port || event.dest_port || "",
    process_name: event.process_name || event.process || "",
    parent_process: event.parent_process || "",
    command_line: event.command_line || "",
    method: event.method || "",
    uri_path: event.uri_path || event.path || "",
    path: event.uri_path || event.path || "",
    status_code: event.status_code || event.status || "",
    status: event.status_code || event.status || "",
    action: event.action || "",
    outcome: event.outcome || "",
    user_agent: event.user_agent || "",
    message: event.message || event.headline || event.raw || "",
    headline: event.headline || event.message || event.raw || "Event",
    why_it_matters: event.why_it_matters || "Review this event in context with adjacent timeline and extracted fields.",
    next_check: event.next_check || "Correlate timestamp, source, user, host, and surrounding activity.",
    mitre_candidates: event.mitre_candidates || [],
    iocs: event.iocs || {},
    raw: event.raw || event.message || JSON.stringify(event),
    matched_rule: event.matched_rule || "",
  }
}

function canonical(field = "") {
  return FIELD_ALIASES[field] || field
}

function stripQuotes(value = "") {
  return String(value).trim().replace(/^['"]|['"]$/g, "")
}

function fieldValue(event, field) {
  const value = eventFieldValue(event, canonical(field))
  if (Array.isArray(value)) return value.join(",")
  if (value && typeof value === "object") return JSON.stringify(value)
  return String(value ?? "")
}

function wildcardToRegExp(pattern = "") {
  const escaped = String(pattern).replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")
  return new RegExp(`^${escaped}$`, "i")
}

function valueMatches(current, expected) {
  const want = stripQuotes(expected)
  const have = String(current ?? "")
  if (want === "*") return have !== "" && have !== "null" && have !== "undefined"
  if (want.includes("*")) return wildcardToRegExp(want).test(have)
  return have.toLowerCase() === want.toLowerCase()
}

function severityCompare(current, operator, expected) {
  const left = SEVERITY_RANK[String(current || "").toLowerCase()] || 0
  const right = SEVERITY_RANK[String(expected || "").toLowerCase()] || 0
  if (operator === ">=") return left >= right
  if (operator === "<=") return left <= right
  if (operator === ">") return left > right
  if (operator === "<") return left < right
  return false
}

function applyWhere(rows, expression) {
  const text = expression.trim()

  let match = text.match(/^like\(([^,]+),\s*['"]?(.+?)['"]?\)$/i)
  if (match) {
    const field = canonical(match[1].trim())
    const pattern = stripQuotes(match[2]).replaceAll("%", "*")
    return rows.filter((event) => valueMatches(fieldValue(event, field), pattern))
  }

  match = text.match(/^match\(([^,]+),\s*['"]?(.+?)['"]?\)$/i)
  if (match) {
    const predicate = regexPredicate(canonical(match[1].trim()), stripQuotes(match[2]))
    return predicate ? filterEvents(rows, [predicate]) : rows
  }

  match = text.match(/^isnotnull\(([^)]+)\)$/i)
  if (match) return rows.filter((event) => fieldValue(event, match[1].trim()) !== "")
  match = text.match(/^isnull\(([^)]+)\)$/i)
  if (match) return rows.filter((event) => fieldValue(event, match[1].trim()) === "")

  return applySearchExpression(rows, text)
}

function tokenizeSearch(text = "") {
  const tokens = []
  const re = /([\w_.-]+\s+IN\s*\([^)]*\)|[\w_.-]+\s*(?:>=|<=|!=|=|>|<)\s*"[^"]*"|[\w_.-]+\s*(?:>=|<=|!=|=|>|<)\s*'[^']*'|[\w_.-]+\s*(?:>=|<=|!=|=|>|<)\s*[^\s]+|"[^"]+"|'[^']+'|\(|\)|\bAND\b|\bOR\b|\bNOT\b|\S+)/gi
  let match
  while ((match = re.exec(text))) tokens.push(match[0].trim())
  return tokens.filter(Boolean)
}

function eventMatchesComparison(event, token) {
  let match = token.match(/^([\w_.-]+)\s+IN\s*\(([^)]*)\)$/i)
  if (match) {
    const field = canonical(match[1])
    const options = match[2].split(/\s*,\s*/).map(stripQuotes).filter(Boolean)
    return options.some((value) => valueMatches(fieldValue(event, field), value))
  }

  match = token.match(/^([\w_.-]+)\s*(>=|<=|!=|=|>|<)\s*(.+)$/)
  if (!match) return null
  const [, rawField, operator, rawValue] = match
  const field = canonical(rawField)
  const expected = stripQuotes(rawValue)

  if (field === "severity" && [">=", "<=", ">", "<"].includes(operator)) {
    return severityCompare(event.severity, operator, expected)
  }

  const current = fieldValue(event, field)
  if (operator === "=") return valueMatches(current, expected)
  if (operator === "!=") return !valueMatches(current, expected)

  const predicate = numericPredicate(field, operator, expected)
  return predicate ? predicate(event) : true
}

function eventMatchesTerm(event, token) {
  const term = stripQuotes(token)
  if (!term || term === "*" || /^index\s*=/.test(term)) return true
  const comparison = eventMatchesComparison(event, term)
  if (comparison !== null) return comparison
  const haystack = `${event.raw || ""} ${event.message || ""} ${event.headline || ""}`.toLowerCase()
  return haystack.includes(term.toLowerCase())
}

function applySearchExpression(events, expression = "") {
  const cleaned = expression.replace(/^search\s+/i, "").trim()
  if (!cleaned || cleaned === "*" || /^index\s*=\S+$/i.test(cleaned)) return events

  if (cleaned.includes(" contains ")) {
    const [field, value] = cleaned.split(/\s+contains\s+/i).map((item) => stripQuotes(item))
    return filterEvents(events, [containsPredicate(canonical(field), value)])
  }

  const orParts = cleaned.split(/\s+OR\s+/i).map((part) => part.trim()).filter(Boolean)
  if (orParts.length > 1) {
    const seen = new Set()
    const merged = []
    for (const part of orParts) {
      const rows = applySearchExpression(events, part)
      for (const row of rows) {
        const key = row.id || row.event_id || JSON.stringify(row)
        if (!seen.has(key)) {
          seen.add(key)
          merged.push(row)
        }
      }
    }
    return merged
  }

  const tokens = tokenizeSearch(cleaned).filter((token) => !["AND", "(" , ")"].includes(token.toUpperCase()))
  let negateNext = false
  return events.filter((event) => {
    for (const token of tokens) {
      if (token.toUpperCase() === "NOT") {
        negateNext = true
        continue
      }
      if (/^(earliest|latest)=/i.test(token)) continue
      const matched = eventMatchesTerm(event, token)
      const ok = negateNext ? !matched : matched
      negateNext = false
      if (!ok) return false
    }
    return true
  })
}

function applyTimeRange(events, expression) {
  const match = expression.match(/^timerange\s+(.+)\s+to\s+(.+)$/i)
  if (!match) return events
  const [, start, end] = match
  const startTime = Date.parse(start.trim())
  const endTime = Date.parse(end.trim())
  if (Number.isNaN(startTime) || Number.isNaN(endTime)) return events
  return events.filter((event) => {
    const eventTime = Date.parse(fieldValue(event, "timestamp"))
    return !Number.isNaN(eventTime) && eventTime >= startTime && eventTime <= endTime
  })
}

function applyRelativeTime(events, range) {
  if (range === "all") return events
  const minutes = { "15m": 15, "1h": 60, "24h": 1440 }[range]
  if (!minutes) return events
  const times = events.map((event) => Date.parse(event.timestamp)).filter((value) => !Number.isNaN(value))
  if (!times.length) return events
  const max = Math.max(...times)
  const min = max - minutes * 60 * 1000
  return events.filter((event) => {
    const time = Date.parse(event.timestamp)
    return Number.isNaN(time) || time >= min
  })
}

function splitFields(text = "") {
  return text.split(/[\s,]+/).map((field) => canonical(field.trim())).filter(Boolean)
}

function statsCountBy(rows, fields) {
  if (!fields.length) return [{ count: rows.length }]
  const map = new Map()
  rows.forEach((event) => {
    const keyValues = fields.map((field) => fieldValue(event, field) || "N/A")
    const key = keyValues.join("¦")
    if (!map.has(key)) {
      const row = Object.fromEntries(fields.map((field, index) => [field, keyValues[index]]))
      row.count = 0
      map.set(key, row)
    }
    map.get(key).count += 1
  })
  return [...map.values()].sort((a, b) => b.count - a.count)
}

function timechart(rows, splitField = "severity") {
  const buckets = new Map()
  rows.forEach((event) => {
    const bucket = event.time_bucket || (event.timestamp ? event.timestamp.slice(0, 16) : "unknown")
    const split = fieldValue(event, splitField) || "events"
    if (!buckets.has(bucket)) buckets.set(bucket, { time_bucket: bucket, count: 0 })
    const row = buckets.get(bucket)
    row.count += 1
    row[split] = (row[split] || 0) + 1
  })
  return [...buckets.values()].sort((a, b) => String(a.time_bucket).localeCompare(String(b.time_bucket)))
}

function renameFields(rows, expression) {
  const match = expression.match(/^rename\s+([\w_.-]+)\s+AS\s+([\w_.-]+)$/i)
  if (!match) return rows
  const [, oldField, newField] = match
  const oldKey = canonical(oldField)
  return rows.map((row) => {
    const next = { ...row }
    next[newField] = next[oldKey]
    delete next[oldKey]
    return next
  })
}

export function executeSiemQuery(events = [], query = "", options = {}) {
  let rows = applyRelativeTime(events.map(normalizeEvent), options.timeRange || "all")
  let tableFields = null
  let stats = null
  let visualization = null
  const steps = (query || "search *").split("|").map((step) => step.trim()).filter(Boolean)

  for (const step of steps) {
    const lower = step.toLowerCase()
    if (lower.startsWith("search ")) {
      rows = applySearchExpression(rows, step)
    } else if (lower.startsWith("where ")) {
      rows = applyWhere(rows, step.slice(6).trim())
    } else if (lower.includes(" contains ")) {
      rows = applySearchExpression(rows, step)
    } else if (lower.startsWith("regex ")) {
      const [, field, pattern] = step.match(/^regex\s+([\w_.-]+)\s+(.+)$/i) || []
      if (field && pattern) rows = filterEvents(rows, [regexPredicate(canonical(field), stripQuotes(pattern))])
    } else if (lower.startsWith("table ")) {
      tableFields = splitFields(step.slice(6))
    } else if (lower.startsWith("fields ")) {
      tableFields = splitFields(step.slice(7)).filter((field) => !field.startsWith("-"))
    } else if (lower.startsWith("stats ")) {
      const byMatch = step.match(/\bby\s+(.+)$/i)
      const fields = byMatch ? splitFields(byMatch[1]) : []
      stats = statsCountBy(rows, fields)
      rows = stats
    } else if (lower.startsWith("timechart")) {
      const [, field = "severity"] = step.match(/^timechart\s+count(?:\s+by\s+([\w_.-]+))?/i) || []
      stats = timechart(rows, canonical(field))
      visualization = "timechart"
      rows = stats
    } else if (lower.startsWith("top ")) {
      const byMatch = step.match(/^top\s+(?:(\d+)\s+by\s+)?([\w_.-]+)$/i) || step.match(/^top\s+(?:limit=(\d+)\s+)?([\w_.-]+)$/i)
      if (byMatch) {
        const limit = Number(byMatch[1]) || 10
        const field = byMatch[2]
        stats = topNByField(rows, canonical(field), limit)
        rows = stats
      }
    } else if (lower.startsWith("rare ")) {
      const match = step.match(/^rare\s+(?:(\d+)\s+by\s+)?([\w_.-]+)$/i) || step.match(/^rare\s+(?:limit=(\d+)\s+)?([\w_.-]+)$/i)
      if (match) {
        const limit = Number(match[1]) || 10
        const field = canonical(match[2])
        stats = sortEvents(countByField(rows, field), "count", "asc").slice(0, limit)
        rows = stats
      }
    } else if (lower.startsWith("sort ")) {
      const body = step.slice(5).trim()
      const splunk = body.match(/^(-)?\s*([\w_.-]+)(?:\s+(asc|desc))?$/i)
      if (splunk) rows = sortEvents(rows, canonical(splunk[2]), splunk[1] ? "desc" : (splunk[3] || "asc"))
    } else if (lower.startsWith("limit ") || lower.startsWith("head ")) {
      rows = rows.slice(0, Number(step.replace(/^(limit|head)\s+/i, "").trim()) || 50)
    } else if (lower.startsWith("tail ")) {
      rows = rows.slice(-(Number(step.slice(5).trim()) || 50))
    } else if (lower === "reverse") {
      rows = [...rows].reverse()
    } else if (lower.startsWith("dedup ")) {
      const field = canonical(step.slice(6).trim())
      rows = dedupeEventsBy(rows, field)
    } else if (lower.startsWith("timerange ")) {
      rows = applyTimeRange(rows, step)
    } else if (lower.startsWith("rename ")) {
      rows = renameFields(rows, step)
    } else if (!SEARCH_META_FIELDS.has(lower)) {
      rows = applySearchExpression(rows, step)
    }
  }

  return {
    query,
    matched_events: rows,
    table_fields: tableFields,
    stats,
    visualization,
    count: rows.length,
    executed_at: new Date().toISOString(),
    limitations: "Local SPL-like subset supports field=value, wildcards, NOT/OR, contains, regex, where like/isnotnull, table/fields, stats count by, top, rare, sort, head/tail, dedup, timerange, and timechart count by.",
  }
}

export function createDetectionRuleFromQuery({ name, description, severity, query, mitre = [], threshold = 1, timeWindow = "5m" }) {
  return {
    id: crypto.randomUUID(),
    name: name || "Untitled detection rule",
    description: description || "Generated from SIEM Workspace query.",
    severity: severity || "medium",
    query,
    time_window: timeWindow,
    threshold,
    mitre_mapping: mitre,
    false_positive_notes: "Validate against baseline administrative and lab activity.",
    recommended_actions: ["Review matched events", "Correlate users/hosts/IPs", "Add confirmed evidence to case"],
    enabled: false,
    created_at: new Date().toISOString(),
  }
}
