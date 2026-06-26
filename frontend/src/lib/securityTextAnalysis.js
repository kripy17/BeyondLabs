const SECRET_PATTERNS = [
  // ... pattern entries ...
]



function lineNumberForIndex(text, index) {
  return text.slice(0, index).split(/\r?\n/).length
}

export function redactSecret(value = "") {
  if (value.length <= 10) return `${value.slice(0, 2)}...`
  return `${value.slice(0, 4)}...${value.slice(-4)}`
}

export function entropy(value = "") {
  if (!value) return 0
  const counts = new Map()
  for (const char of value) counts.set(char, (counts.get(char) || 0) + 1)
  return [...counts.values()].reduce((score, count) => {
    const probability = count / value.length
    return score - (probability * Math.log2(probability))
  }, 0)
}

export function scanSecrets(text = "") {
  const findings = []
  const seen = new Set()

  for (const pattern of SECRET_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags)
    let match = regex.exec(text)
    while (match) {
      const raw = match[1] || match[0]
      const key = `${pattern.type}:${raw}`
      if (!seen.has(key)) {
        seen.add(key)
        findings.push({
          type: pattern.type,
          confidence: pattern.confidence,
          line: lineNumberForIndex(text, match.index),
          preview: redactSecret(raw),
          evidence: redactSecret(raw),
          remediation: pattern.advice,
          source: "local pattern scan",
          limitation: "Pattern-based secret detection. Validate before rotation, but treat likely real credentials cautiously.",
        })
      }
      match = regex.exec(text)
    }
  }

  const highEntropyRegex = /\b[A-Za-z0-9+/=_-]{32,}\b/g
  let entropyMatch = highEntropyRegex.exec(text)
  while (entropyMatch) {
    const value = entropyMatch[0]
    const score = entropy(value)
    if (score >= 4.4 && !seen.has(`High entropy string:${value}`)) {
      seen.add(`High entropy string:${value}`)
      findings.push({
        type: "High-entropy string",
        confidence: score >= 4.8 ? "Medium" : "Low",
        line: lineNumberForIndex(text, entropyMatch.index),
        preview: redactSecret(value),
        evidence: `entropy ${score.toFixed(2)}: ${redactSecret(value)}`,
        remediation: "Review whether this is a token, session value, encoded blob, or benign random identifier. Rotate if confirmed secret.",
        source: "local entropy scan",
        limitation: "Entropy is heuristic and can flag hashes, compressed data, IDs, or encoded text.",
      })
    }
    entropyMatch = highEntropyRegex.exec(text)
  }

  return findings.sort((a, b) => a.line - b.line || a.type.localeCompare(b.type))
}

export function secretMarkdown(findings = []) {
  const lines = ["## Secret Scan Findings"]
  if (!findings.length) {
    lines.push("- No secret-like patterns detected by local scanner.")
    return lines.join("\n")
  }

  findings.forEach((item) => {
    lines.push(`- Line ${item.line}: ${item.type} (${item.confidence} evidence) - ${item.preview}`)
    lines.push(`  - Remediation: ${item.remediation}`)
    lines.push(`  - Limitation: ${item.limitation}`)
  })
  return lines.join("\n")
}
