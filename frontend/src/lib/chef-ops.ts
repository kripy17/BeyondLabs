export type Cat = "favourites" | "ioc" | "encodings" | "web" | "data" | "text" | "hashing" | "triage";

export type Op = {
  id: string; label: string; category: Cat; description: string;
  placeholder?: string;
  run: (s: string, opts?: Record<string, any>) => string | Promise<string>;
};

export type RecipeStep = { id: string; operationId: string; options: Record<string, any> };

const td = new TextDecoder();
const te = new TextEncoder();

const defang = (v: string) => v.replaceAll("http://", "hxxp[:]//").replaceAll("https://", "hxxps[:]//").replaceAll(".", "[.]").replaceAll("@", "[@]");
const refang = (v: string) => v.replaceAll("hxxp[:]//", "http://").replaceAll("hxxps[:]//", "https://").replaceAll("[.]", ".").replaceAll("[@]", "@");
const uniq = (a: string[]) => Array.from(new Set(a));
const toBase64Url = (s: string) => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromBase64Url = (s: string) => { try { return decodeURIComponent(escape(atob(s.replace(/-/g, "+").replace(/_/g, "/")))); } catch { return "[decode error]"; } };

const RX = {
  url: /https?:\/\/[^\s"'<>]+/gi,
  ip:  /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g,
  em:  /\b[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+\b/g,
  ha:  /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g,
  dom: /\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}\b/g,
  cve: /\bCVE-\d{4}-\d{4,7}\b/gi,
  evt: /\b(?:4624|4625|4688|4672|1102|7045|4720|4726|4732)\b/g,
};

async function digest(algo: string, v: string) {
  const buf = await crypto.subtle.digest(algo, te.encode(v));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function extractIocRun(s: string, opts?: Record<string, any>) {
  const include = opts?.include ?? ["urls", "ips", "emails", "domains", "hashes"];
  const sec = (label: string, key: string, rx: RegExp) =>
    (include.includes(key) ? (s.match(rx) ?? []) : []).length > 0
      ? `${label} (${uniq(s.match(rx) ?? []).length})\n${uniq(s.match(rx) ?? []).map((i) => "  · " + i).join("\n")}` : "";
  const out = [
    sec("URLs",    "urls",    RX.url),
    sec("IPs",     "ips",     RX.ip),
    sec("Emails",  "emails",  RX.em),
    sec("Domains", "domains", RX.dom),
    sec("Hashes",  "hashes",  RX.ha),
  ].filter(Boolean);
  return out.length ? out.join("\n\n") : "No IOCs extracted.";
}

async function withBackendFallback(label: string, backend: () => Promise<string>, local: () => string): Promise<string> {
  try {
    const res = await backend();
    return `${res}\n\n[source: backend API]`;
  } catch (e: any) {
    const fallback = local();
    return `${fallback}\n\n[source: local fallback — backend unavailable (${e?.message ?? "unknown error"})]`;
  }
}

function toBase64Run(s: string, opts?: Record<string, any>) {
  let v = btoa(unescape(encodeURIComponent(s)));
  if (opts?.alphabet === "urlsafe") v = v.replace(/\+/g, "-").replace(/\//g, "_");
  if (opts?.padding === false) v = v.replace(/=+$/, "");
  if (opts?.lineLength) v = v.replace(new RegExp(`.{${opts.lineLength}}`, "g"), "$&\n").trimEnd();
  return v;
}
function fromBase64Run(s: string, opts?: Record<string, any>) {
  try {
    let c = opts?.keepWhitespace ? s : s.replace(/\s+/g, "");
    c = c.replace(/-/g, "+").replace(/_/g, "/").padEnd(c.length + ((4 - c.length % 4) % 4), "=");
    return decodeURIComponent(escape(atob(c)));
  } catch { return "[decode error]"; }
}
function toBinaryRun(s: string, opts?: Record<string, any>) {
  const d = opts?.delimiter ?? " "; const sep = d === "none" ? "" : d === "newline" ? "\n" : d;
  return Array.from(te.encode(s)).map((b) => b.toString(2).padStart(8, "0")).join(sep);
}
function unicodeEscapeRun(s: string, opts?: Record<string, any>) {
  return Array.from(s).map((c) => {
    const code = c.codePointAt(0)!;
    if (code < 128 && !opts?.allChars) return c;
    const hex = code.toString(16).padStart(4, "0");
    return opts?.uppercase ? `\\u${hex.toUpperCase()}` : `\\u${hex}`;
  }).join("");
}
function sortLinesRun(s: string, opts?: Record<string, any>) {
  const lines = s.split(/\r?\n/);
  const sorted = lines.sort((a, b) => opts?.caseSensitive ? a.localeCompare(b, undefined, { sensitivity: "case" }) : a.localeCompare(b, undefined, { sensitivity: "base" }));
  return (opts?.reverse ? sorted.reverse() : sorted).join("\n");
}
function regexExtractRun(s: string, opts?: Record<string, any>) {
  const types = opts?.types ?? ["ipv4", "urls", "emails", "hashes", "cves", "event_ids"];
  const block = (label: string, key: string, rx: RegExp) => {
    if (!types.includes(key)) return "";
    const items = uniq(s.match(rx) ?? []);
    return `${label} (${items.length})${items.length ? "\n" + items.map((i) => "  · " + i).join("\n") : ""}`;
  };
  return [
    block("ipv4",      "ipv4",      RX.ip),
    block("urls",      "urls",      RX.url),
    block("emails",    "emails",    RX.em),
    block("hashes",    "hashes",    RX.ha),
    block("cves",      "cves",      RX.cve),
    block("event_ids", "event_ids", RX.evt),
  ].filter(Boolean).join("\n\n");
}
async function parseUrlRun(s: string, _opts?: Record<string, any>): Promise<string> {
  return withBackendFallback("Parse URL",
    async () => { const r = await fetch("/api/tools/parse-url", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: s.trim() }) }); const d = await r.json(); return typeof d === "string" ? d : JSON.stringify(d, null, 2); },
    () => { const u = new URL(s.trim()); return `scheme:   ${u.protocol.replace(":", "")}\nhost:     ${u.hostname}\nport:     ${u.port || "(default)"}\npath:     ${u.pathname}\nquery:    ${u.search || "—"}\nfragment: ${u.hash || "—"}\n\nparams:\n${Array.from(u.searchParams.entries()).map(([k, v]) => `  ${k} = ${v}`).join("\n") || "  (none)"}`; }
  );
}
async function jwtDecodeRun(s: string, _opts?: Record<string, any>): Promise<string> {
  return withBackendFallback("JWT Decode",
    async () => { const r = await fetch("/api/tools/jwt-decode", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token: s.trim() }) }); const d = await r.json(); return typeof d === "string" ? d : JSON.stringify(d, null, 2); },
    () => { const [h, p] = s.trim().split("."); const dec = (x: string) => JSON.stringify(JSON.parse(atob(x.replace(/-/g, "+").replace(/_/g, "/").padEnd(x.length + ((4 - x.length % 4) % 4), "="))), null, 2); return `=== header ===\n${dec(h)}\n\n=== payload ===\n${dec(p)}\n\n[signature NOT verified]`; }
  );
}
async function timestampRun(s: string, _opts?: Record<string, any>): Promise<string> {
  return withBackendFallback("Timestamp",
    async () => { const r = await fetch("/api/tools/timestamp", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ value: s.trim() }) }); const d = await r.json(); return typeof d === "string" ? d : JSON.stringify(d, null, 2); },
    () => { const t = s.trim(); if (/^\d+$/.test(t)) { const n = Number(t); const ms = n < 1e12 ? n * 1000 : n; return `unix:  ${n}\niso:   ${new Date(ms).toISOString()}\nutc:   ${new Date(ms).toUTCString()}`; } const d = new Date(t); if (isNaN(+d)) return "[unparseable]"; return `iso:   ${d.toISOString()}\nunix:  ${Math.floor(+d / 1000)}\nepoch: ${+d}`; }
  );
}

const OPS: Op[] = [
  // IOC
  { id: "defang", label: "Defang", category: "ioc", description: "Make URLs, IPs, emails report-safe.", placeholder: "https://example.com\n8.8.8.8\nuser@example.com", run: defang },
  { id: "refang", label: "Refang", category: "ioc", description: "Convert defanged indicators back.", placeholder: "hxxps[:]//example[.]com\n8[.]8[.]8[.]8", run: refang },
  { id: "extract-iocs", label: "Extract IOCs", category: "ioc", description: "Pull URLs, IPs, domains, emails, hashes.", run: extractIocRun },
  { id: "extract-urls",    label: "Extract URLs",    category: "ioc", description: "Unique HTTP/S URLs.",                     run: (s) => uniq(s.match(RX.url) ?? []).join("\n") },
  { id: "extract-ips",     label: "Extract IPs",     category: "ioc", description: "Unique IPv4 addresses.",                  run: (s) => uniq(s.match(RX.ip)  ?? []).join("\n") },
  { id: "extract-domains", label: "Extract Domains", category: "ioc", description: "Unique domain-like tokens.",              run: (s) => uniq(s.match(RX.dom) ?? []).join("\n") },
  { id: "extract-emails",  label: "Extract Emails",  category: "ioc", description: "Unique email addresses.",                 run: (s) => uniq(s.match(RX.em)  ?? []).join("\n") },
  { id: "extract-hashes",  label: "Extract Hashes",  category: "ioc", description: "Unique MD5/SHA-1/SHA-256-looking hashes.",run: (s) => uniq(s.match(RX.ha)  ?? []).join("\n") },
  { id: "normalize-ioc-list", label: "Normalize IOC List", category: "ioc", description: "Trim, lowercase, dedupe, sort.", run: (s) => uniq(s.split(/\r?\n/).map((l) => l.trim().toLowerCase()).filter(Boolean)).sort().join("\n") },

  // Encodings
  { id: "to-base64",   label: "To Base64",   category: "encodings", description: "Encode text as Base64.",       placeholder: "admin:password", run: toBase64Run },
  { id: "from-base64", label: "From Base64", category: "encodings", description: "Decode Base64 text.",          placeholder: "YWRtaW46cGFzc3dvcmQ=", run: fromBase64Run },
  { id: "to-base64url",   label: "To Base64URL",   category: "encodings", description: "URL-safe Base64, no padding.",  placeholder: "admin:password", run: toBase64Url },
  { id: "from-base64url", label: "From Base64URL", category: "encodings", description: "Decode URL-safe Base64 (JWT, web tokens).", placeholder: "YWRtaW46cGFzc3dvcmQ", run: fromBase64Url },
  { id: "to-hex",      label: "To Hex",      category: "encodings", description: "Hex bytes.",                    run: (s, o) => { const d = o?.delimiter ?? " "; const c = o?.case ?? "lower"; const p = o?.prefix ?? ""; return Array.from(te.encode(s)).map((b) => { const h = b.toString(16).padStart(2, "0"); return p + (c === "upper" ? h.toUpperCase() : h); }).join(d === "none" ? "" : d === "colon" ? ":" : d); } },
  { id: "from-hex",    label: "From Hex",    category: "encodings", description: "Hex bytes back to text.",       placeholder: "48 65 6c 6c 6f", run: (s) => { try { const c = s.replace(/[^a-fA-F0-9]/g, ""); return td.decode(new Uint8Array(c.match(/.{1,2}/g)!.map((x) => parseInt(x, 16)))); } catch { return "[hex error]"; } } },
  { id: "to-binary",   label: "To Binary",   category: "encodings", description: "8-bit binary byte groups.",     run: toBinaryRun },
  { id: "from-binary", label: "From Binary", category: "encodings", description: "Binary back to text.",          run: (s) => { const m = s.match(/[01]{8}/g) ?? []; return td.decode(new Uint8Array(m.map((b) => parseInt(b, 2)))); } },
  { id: "to-charcode",   label: "To Charcode",   category: "encodings", description: "Text to decimal char codes.",     placeholder: "ABC", run: (s, o) => { const base = o?.base ?? 10; const sep = o?.delimiter ?? " "; return Array.from(s).map((c) => (c.codePointAt(0)!).toString(base)).join(sep); } },
  { id: "from-charcode", label: "From Charcode", category: "encodings", description: "Decimal char codes back to text.", placeholder: "65 66 67", run: (s, o) => { try { const base = o?.base ?? 10; const sep = o?.delimiter ?? /\s+/; return s.split(sep instanceof RegExp ? sep : new RegExp(sep)).map((c) => String.fromCodePoint(parseInt(c, base))).join(""); } catch { return "[charcode error]"; } } },
  { id: "url-encode",  label: "URL Encode",  category: "encodings", description: "Percent-encode for URLs.",      run: (s) => encodeURIComponent(s) },
  { id: "url-decode",  label: "URL Decode",  category: "encodings", description: "Decode percent-encoding.",      run: (s) => { try { return decodeURIComponent(s); } catch { return s; } } },
  { id: "html-encode", label: "HTML Encode", category: "encodings", description: "Escape HTML entities.",         run: (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;") },
  { id: "html-decode", label: "HTML Decode", category: "encodings", description: "Decode HTML entities.",         run: (s) => { const t = document.createElement("textarea"); t.innerHTML = s; return t.value; } },
  { id: "unicode-escape",   label: "Unicode Escape",   category: "encodings", description: "Non-ASCII to \\uXXXX.",          placeholder: "hello π",   run: unicodeEscapeRun },
  { id: "unicode-unescape", label: "Unicode Unescape", category: "encodings", description: "Decode \\uXXXX sequences.",        placeholder: "hello \\u03c0", run: (s: string) => s.replace(/\\u([0-9a-fA-F]{4})/g, (_, c) => String.fromCharCode(parseInt(c, 16))).replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, c) => String.fromCodePoint(parseInt(c, 16))) },
  { id: "rot13",       label: "ROT13",       category: "encodings", description: "Simple obfuscation review.",    run: (s, o) => { const n = o?.rotation ?? 13; return s.replace(/[a-zA-Z]/g, (c) => { const b = c <= "Z" ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - b + n) % 26) + b); }); } },

  // Web
  { id: "parse-url",  label: "Parse URL",  category: "web", description: "Break URL into parts.", placeholder: "https://example.com/login?u=test", run: parseUrlRun },
  { id: "jwt-decode", label: "JWT Decode", category: "web", description: "Decode header & payload (no signature verify).", placeholder: "eyJhbGciOi...", run: jwtDecodeRun },

  // Data
  { id: "json-pretty",        label: "JSON Beautify",      category: "data", description: "Pretty-print JSON.",                run: (s) => { try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return "[invalid JSON]"; } } },
  { id: "json-minify",        label: "JSON Minify",        category: "data", description: "Strip whitespace from JSON.",       run: (s) => { try { return JSON.stringify(JSON.parse(s)); } catch { return "[invalid JSON]"; } } },
  { id: "timestamp",          label: "Timestamp",          category: "data", description: "Unix ↔ ISO conversion.",            run: timestampRun },
  { id: "sort-lines",         label: "Sort Lines",         category: "data", description: "Sort lines alphabetically.",        run: sortLinesRun },
  { id: "unique-lines",       label: "Unique Lines",       category: "data", description: "Dedupe lines (first wins).",        run: (s, o) => { const lines = s.split(/\r?\n/); const fn = o?.caseSensitive ? (x: string) => x : (x: string) => x.toLowerCase(); const seen = new Set<string>(); return lines.filter((l) => { const k = fn(l); if (seen.has(k)) return false; seen.add(k); return true; }).join("\n"); } },
  { id: "remove-empty-lines", label: "Remove Empty Lines", category: "data", description: "Drop blank lines.",                 run: (s) => s.split(/\r?\n/).filter((l) => l.trim()).join("\n") },

  // Text
  { id: "uppercase",        label: "To Uppercase",     category: "text", description: "Convert to uppercase.",      run: (s) => s.toUpperCase() },
  { id: "lowercase",        label: "To Lowercase",     category: "text", description: "Convert to lowercase.",      run: (s) => s.toLowerCase() },
  { id: "reverse",          label: "Reverse",          category: "text", description: "Reverse the string.",        run: (s) => Array.from(s).reverse().join("") },
  { id: "trim-lines",       label: "Trim Lines",       category: "text", description: "Trim each line.",            run: (s) => s.split(/\r?\n/).map((l) => l.trim()).join("\n") },
  { id: "remove-whitespace",label: "Remove Whitespace",category: "text", description: "Strip all whitespace.",      run: (s) => s.replace(/\s+/g, "") },
  { id: "count",            label: "Count",            category: "text", description: "Chars · words · lines · bytes.", run: (s) => { const t = s.trim(); return `characters: ${Array.from(s).length}\nbytes_utf8: ${te.encode(s).length}\nwords:      ${t ? t.split(/\s+/).length : 0}\nlines:      ${s ? s.split(/\r?\n/).length : 0}`; } },
  { id: "escape-regex",     label: "Escape Regex",     category: "text", description: "Escape regex metacharacters.", run: (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") },
  { id: "regex-extract",    label: "Regex Extract",    category: "text", description: "Common SOC regex hits.",      run: regexExtractRun },
  { id: "regex-redact",     label: "Regex Redact",     category: "text", description: "Redact IPs/emails/URLs/hashes.", run: (s, o) => { const r = o?.replacement ?? "[REDACTED]"; return s.replace(RX.url, r).replace(RX.em, r).replace(RX.ip, r).replace(RX.ha, r); } },

  // Hashing
  { id: "hash-identify", label: "Hash Identify", category: "hashing", description: "Identify likely hash format(s).", run: (s) => {
    return s.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((h) => {
      const hex = /^[a-f0-9]+$/i.test(h);
      let t = "unknown", c = "low";
      if (/^\$2[aby]\$\d{2}\$/.test(h)) { t = "bcrypt"; c = "high"; }
      else if (/^\$argon2/i.test(h))    { t = "argon2"; c = "high"; }
      else if (/^\$1\$/.test(h)) { t = "md5crypt"; c = "high"; }
      else if (/^\$5\$/.test(h)) { t = "sha256crypt"; c = "high"; }
      else if (/^\$6\$/.test(h)) { t = "sha512crypt"; c = "high"; }
      else if (hex && h.length === 32)  { t = "MD5 / NTLM"; c = "medium"; }
      else if (hex && h.length === 40)  { t = "SHA1"; c = "high"; }
      else if (hex && h.length === 64)  { t = "SHA256"; c = "high"; }
      else if (hex && h.length === 128) { t = "SHA512"; c = "high"; }
      else if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(h)) { t = "JWT-like"; c = "medium"; }
      return `${h}\n  → ${t}  (${c})`;
    }).join("\n\n");
  }},
  { id: "sha1",   label: "SHA1",   category: "hashing", description: "SHA-1 hash.",   run: (s) => digest("SHA-1", s) },
  { id: "sha256", label: "SHA256", category: "hashing", description: "SHA-256 hash.", run: (s) => digest("SHA-256", s) },
  { id: "sha384", label: "SHA384", category: "hashing", description: "SHA-384 hash.", run: (s) => digest("SHA-384", s) },
  { id: "sha512", label: "SHA512", category: "hashing", description: "SHA-512 hash.", run: (s) => digest("SHA-512", s) },

  // Triage
  { id: "secret-scan", label: "Secret Scan", category: "triage", description: "Detect API keys, tokens, .env, high-entropy strings.", run: (s) => {
    const lines = s.split(/\r?\n/);
    const rules: { name: string; rx: RegExp }[] = [
      { name: "AWS access key",  rx: /\bAKIA[0-9A-Z]{16}\b/ },
      { name: "GitHub token",    rx: /\bghp_[A-Za-z0-9]{20,}\b/ },
      { name: "GitHub classic",  rx: /\bgho_[A-Za-z0-9_]{20,}\b/ },
      { name: "GitLab token",    rx: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },
      { name: "Slack token",     rx: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
      { name: "Discord webhook", rx: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/ },
      { name: "Stripe live key", rx: /\bsk_live_[A-Za-z0-9]{16,}\b/ },
      { name: "Stripe test key", rx: /\bsk_test_[A-Za-z0-9]{16,}\b/ },
      { name: "Private key PEM", rx: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
      { name: ".env assignment", rx: /^[A-Z][A-Z0-9_]+=[\S]+$/ },
      { name: "JWT token",       rx: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/ },
      { name: "Generic API key", rx: /\b[A-Za-z0-9_-]{32,}\b/ },
    ];
    function entropy(t: string): number {
      const freq: Record<string, number> = {}; for (const c of t) freq[c] = (freq[c] || 0) + 1;
      return -Object.values(freq).reduce((s, c) => { const p = c / t.length; return s + p * Math.log2(p); }, 0);
    }
    const hits: { line: number; name: string; preview: string; ent: number }[] = [];
    lines.forEach((l, i) => rules.forEach((r) => { if (r.rx.test(l)) hits.push({ line: i + 1, name: r.name, preview: l.trim().slice(0, 100), ent: 0 }); }));
    lines.forEach((l, i) => { const t = l.trim(); if (t.length >= 20 && !/^[A-Z][A-Z0-9_]+=/.test(t)) { const e = entropy(t); if (e >= 4.4 && !hits.some((h) => h.line === i + 1)) hits.push({ line: i + 1, name: "high entropy", preview: t.slice(0, 100), ent: e }); } });
    hits.sort((a, b) => a.line - b.line);
    const fmt = hits.map((h) => `L${h.line.toString().padStart(4)}  [${h.name.padEnd(16)}]  ${h.preview}${h.ent ? `  (entropy: ${h.ent.toFixed(2)})` : ""}`);
    return hits.length ? `${hits.length} finding(s):\n\n${fmt.join("\n")}` : "No secrets detected.";
  }},
  { id: "powershell-analyze", label: "PowerShell Analyze", category: "triage", description: "Decode & statically triage PowerShell (no execution).", placeholder: "powershell -NoP -EncodedCommand SQBFAFgA", run: async (s) => {
    const lo = s.toLowerCase();
    const encMatch = s.match(/(?:-enc(?:odedcommand)?\s+)([a-z0-9+/=_-]+)/i);
    let decoded = "";
    if (encMatch) {
      try { const c = encMatch[1].replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/"); const p = c.padEnd(c.length + ((4 - c.length % 4) % 4), "="); decoded = new TextDecoder("utf-16le").decode(Uint8Array.from(atob(p), (x) => x.charCodeAt(0))).replace(/\0/g, ""); } catch { decoded = "[decode failed]"; }
    }
    const flags = ["encodedcommand", "-enc", "-nop", "bypass", "hidden", "downloadstring", "invoke-expression", "iex", "frombase64string", "new-object net.webclient"].filter((f) => lo.includes(f));
    const localResult = `encoded_command: ${encMatch ? "yes" : "no"}${decoded ? `\ndecoded_preview: ${decoded.slice(0, 500)}` : ""}\nsuspicious_flags: ${flags.join(", ") || "none"}\n\n[ioc extraction from decoded payload may yield additional indicators — run Extract IOCs on output]`;
    try {
      const r = await fetch("/api/tools/powershell-analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ script: s.trim() }) });
      const d = await r.json();
      const backendStr = typeof d === "string" ? d : JSON.stringify(d, null, 2);
      return `${backendStr}\n\n[source: backend API]`;
    } catch {
      return `${localResult}\n\n[source: local — backend unavailable]`;
    }
  }},
  { id: "linux-auth-summary", label: "Linux Auth Summary", category: "triage", description: "Summarize auth/SSH log lines.", placeholder: "Jan 12 10:01:02 host sshd[123]: Failed password for invalid user admin from 8.8.8.8", run: (s) => {
    const lines = s.split(/\r?\n/).filter(Boolean);
    const ips = uniq(lines.flatMap((l) => l.match(RX.ip) ?? []));
    const invalid = uniq(lines.map((l) => l.match(/invalid user\s+(\S+)/i)?.[1]).filter((x): x is string => !!x));
    return `total_lines:       ${lines.length}\nfailed_password:  ${lines.filter((l) => /failed password/i.test(l)).length}\naccepted_login:   ${lines.filter((l) => /accepted (password|publickey)/i.test(l)).length}\ninvalid_users:    ${invalid.join(", ") || "none"}\nsource_ips:       ${ips.join(", ") || "none"}`;
  }},
  { id: "windows-cmdline-parse", label: "Windows Command Parse", category: "triage", description: "Parse executable, args, LOLBins, suspicious flags.", placeholder: "powershell.exe -NoP -W Hidden -enc SQBFAFgA", run: (s) => {
    const tokens = s.match(/"[^"]+"|'[^']+'|\S+/g) ?? [];
    const lo = s.toLowerCase();
    const lol = ["powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "wscript", "cscript", "certutil", "bitsadmin", "wmic"].filter((x) => lo.includes(x));
    const flags = ["-enc", "-encodedcommand", "-nop", "-w hidden", "-windowstyle hidden", "/c", "downloadstring", "iex", "bypass"].filter((x) => lo.includes(x));
    return `executable:       ${tokens[0] ?? ""}\ntokens:           ${tokens.length}\nlolbin_hits:      ${lol.join(", ") || "—"}\nsuspicious_flags: ${flags.join(", ") || "—"}\n\narguments:\n${tokens.slice(1).map((t) => "  " + t).join("\n")}`;
  }},
  { id: "user-agent-classify", label: "User-Agent Classify", category: "triage", description: "Browser / crawler / CLI / scanner.", placeholder: "Mozilla/5.0\ncurl/8.1\nsqlmap/1.7", run: (s) => s.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((ua) => {
    const lo = ua.toLowerCase();
    let t = "unknown";
    if (/sqlmap|nikto|nmap|masscan|nessus|burp/.test(lo)) t = "suspicious_scanner";
    else if (/curl|wget|httpie/.test(lo)) t = "cli_tool";
    else if (/python-requests|go-http-client|java|okhttp/.test(lo)) t = "library_client";
    else if (/bot|crawler|spider|slurp/.test(lo)) t = "crawler";
    else if (/mozilla|chrome|safari|firefox|edge/.test(lo)) t = "browser";
    return `${t.padEnd(20)}  ${ua}`;
  }).join("\n") },
];

export const OP_BY_ID = Object.fromEntries(OPS.map((o) => [o.id, o]));

export const DEFAULT_FAVS = ["defang", "refang", "extract-iocs", "from-base64", "url-decode", "sha256", "parse-url"];

export const CATEGORIES: { id: Cat; label: string }[] = [
  { id: "favourites", label: "Favourites" },
  { id: "ioc",        label: "IOC Safe Handling" },
  { id: "encodings",  label: "Encodings" },
  { id: "web",        label: "Web" },
  { id: "data",       label: "Data Format" },
  { id: "text",       label: "Text" },
  { id: "hashing",    label: "Hashing" },
  { id: "triage",     label: "Script Triage" },
];

export default OPS;
