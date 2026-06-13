export function eventFieldValue(event = {}, field = "") {
  const aliases = {
    username: "user",
    src_ip: "source_ip",
    dst_ip: "destination_ip",
    dest_ip: "destination_ip",
    raw: "raw",
  }
  const key = aliases[field] || field
  return event[key] ?? ""
}

export function compareEventValues(left, right, direction = "asc") {
  const multiplier = direction === "desc" ? -1 : 1
  const leftNumber = Number(left)
  const rightNumber = Number(right)

  if (!Number.isNaN(leftNumber) && !Number.isNaN(rightNumber)) {
    return (leftNumber - rightNumber) * multiplier
  }

  return String(left ?? "").localeCompare(String(right ?? "")) * multiplier
}

export function sortEvents(events = [], field = "timestamp", direction = "asc") {
  return [...events].sort((left, right) => (
    compareEventValues(eventFieldValue(left, field), eventFieldValue(right, field), direction)
  ))
}

export function groupEventsBy(events = [], field = "event_type") {
  return events.reduce((groups, event) => {
    const key = String(eventFieldValue(event, field) || "N/A")
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key).push(event)
    return groups
  }, new Map())
}

export function countByField(events = [], field = "event_type") {
  return Array.from(groupEventsBy(events, field).entries()).map(([value, rows]) => ({
    [field]: value,
    count: rows.length,
  }))
}

export function topNByField(events = [], field = "event_type", limit = 10) {
  return sortEvents(countByField(events, field), "count", "desc").slice(0, limit)
}

export function dedupeEventsBy(events = [], field = "id") {
  const seen = new Set()
  return events.filter((event) => {
    const value = String(eventFieldValue(event, field))
    if (seen.has(value)) return false
    seen.add(value)
    return true
  })
}

export function filterEvents(events = [], predicates = []) {
  const checks = predicates.filter(Boolean)
  if (!checks.length) return events
  return events.filter((event) => checks.every((predicate) => predicate(event)))
}

export function containsPredicate(field, value) {
  const needle = String(value ?? "").toLowerCase()
  if (!needle) return null
  return (event) => String(eventFieldValue(event, field)).toLowerCase().includes(needle)
}

export function equalityPredicate(field, expected, negate = false) {
  const wanted = String(expected ?? "").toLowerCase()
  return (event) => {
    const matched = String(eventFieldValue(event, field)).toLowerCase() === wanted
    return negate ? !matched : matched
  }
}

export function numericPredicate(field, operator, expected) {
  const expectedNumber = Number(expected)
  if (Number.isNaN(expectedNumber)) return null

  return (event) => {
    const currentNumber = Number(eventFieldValue(event, field))
    if (Number.isNaN(currentNumber)) return false
    if (operator === ">") return currentNumber > expectedNumber
    if (operator === "<") return currentNumber < expectedNumber
    if (operator === ">=") return currentNumber >= expectedNumber
    if (operator === "<=") return currentNumber <= expectedNumber
    return false
  }
}

export function regexPredicate(field, pattern) {
  try {
    const cleaned = String(pattern).replace(/^\/|\/$/g, "")
    const re = new RegExp(cleaned, "i")
    return (event) => re.test(String(eventFieldValue(event, field)))
  } catch {
    return null
  }
}

export function matchAnyPattern(text = "", patterns = []) {
  const haystack = String(text)
  return patterns.some((pattern) => {
    if (pattern instanceof RegExp) return pattern.test(haystack)
    return haystack.toLowerCase().includes(String(pattern).toLowerCase())
  })
}
