import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { takePendingArtifact } from "@/lib/handoff";
import {
  ChefHat, Search, Star, X, GripVertical, Copy, Check, Eraser, Trash2,
  ArrowDown, ArrowUp, RotateCcw, FileDown, ChevronDown, ChevronRight, BookMarked,
  Clock, ArrowDownToLine, ArrowUpFromLine, Settings2, Upload, Download, Send, AlertTriangle,
} from "lucide-react";

export const Route = createFileRoute("/chef")({ component: ChefPage });


/* =================== Operations =================== */

type Cat = "favourites" | "ioc" | "encodings" | "web" | "data" | "text" | "hashing" | "triage";
type Op = {
  id: string; label: string; category: Cat; description: string;
  placeholder?: string;
  run: (s: string) => string | Promise<string>;
};

const td = new TextDecoder();
const te = new TextEncoder();

const defang = (v: string) => v.replaceAll("http://", "hxxp[:]//").replaceAll("https://", "hxxps[:]//").replaceAll(".", "[.]").replaceAll("@", "[@]");
const refang = (v: string) => v.replaceAll("hxxp[:]//", "http://").replaceAll("hxxps[:]//", "https://").replaceAll("[.]", ".").replaceAll("[@]", "@");
const uniq = (a: string[]) => Array.from(new Set(a));
const toBase64Url = (s: string) => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromBase64Url = (s: string) => { try { return decodeURIComponent(escape(atob(s.replace(/-/g, "+").replace(/_/g, "/")))); } catch { return "[decode error]"; } };
const toCharcode = (s: string) => Array.from(s).map((c) => String(c.codePointAt(0)!)).join(" ");
const fromCharcode = (s: string) => { try { return s.trim().split(/\s+/).map((c) => String.fromCodePoint(parseInt(c, 10))).join(""); } catch { return "[charcode error]"; } };
const unicodeEscape = (s: string) => Array.from(s).map((c) => { const code = c.codePointAt(0)!; return code < 128 ? c : `\\u${code.toString(16).padStart(4, "0")}`; }).join("");
const unicodeUnescape = (s: string) => s.replace(/\\u([0-9a-fA-F]{4})/g, (_, c) => String.fromCharCode(parseInt(c, 16))).replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, c) => String.fromCodePoint(parseInt(c, 16)));

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

const OPS: Op[] = [
  // IOC
  { id: "defang", label: "Defang", category: "ioc", description: "Make URLs, IPs, emails report-safe.", placeholder: "https://example.com\n8.8.8.8\nuser@example.com", run: defang },
  { id: "refang", label: "Refang", category: "ioc", description: "Convert defanged indicators back.", placeholder: "hxxps[:]//example[.]com\n8[.]8[.]8[.]8", run: refang },
  { id: "extract-iocs", label: "Extract IOCs", category: "ioc", description: "Pull URLs, IPs, domains, emails, hashes.", run: (s) => {
    const sec = (label: string, items: string[]) => items.length ? `${label} (${items.length})\n${items.map((i) => "  · " + i).join("\n")}` : "";
    const out = [
      sec("URLs",    uniq(s.match(RX.url) ?? [])),
      sec("IPs",     uniq(s.match(RX.ip)  ?? [])),
      sec("Emails",  uniq(s.match(RX.em)  ?? [])),
      sec("Domains", uniq(s.match(RX.dom) ?? [])),
      sec("Hashes",  uniq(s.match(RX.ha)  ?? [])),
    ].filter(Boolean);
    return out.length ? out.join("\n\n") : "No IOCs extracted.";
  }},
  { id: "extract-urls",    label: "Extract URLs",    category: "ioc", description: "Unique HTTP/S URLs.",                     run: (s) => uniq(s.match(RX.url) ?? []).join("\n") },
  { id: "extract-ips",     label: "Extract IPs",     category: "ioc", description: "Unique IPv4 addresses.",                  run: (s) => uniq(s.match(RX.ip)  ?? []).join("\n") },
  { id: "extract-domains", label: "Extract Domains", category: "ioc", description: "Unique domain-like tokens.",              run: (s) => uniq(s.match(RX.dom) ?? []).join("\n") },
  { id: "extract-emails",  label: "Extract Emails",  category: "ioc", description: "Unique email addresses.",                 run: (s) => uniq(s.match(RX.em)  ?? []).join("\n") },
  { id: "extract-hashes",  label: "Extract Hashes",  category: "ioc", description: "Unique MD5/SHA-1/SHA-256-looking hashes.",run: (s) => uniq(s.match(RX.ha)  ?? []).join("\n") },
  { id: "normalize-ioc-list", label: "Normalize IOC List", category: "ioc", description: "Trim, lowercase, dedupe, sort.", run: (s) => uniq(s.split(/\r?\n/).map((l) => l.trim().toLowerCase()).filter(Boolean)).sort().join("\n") },

  // Encodings
  { id: "to-base64",   label: "To Base64",   category: "encodings", description: "Encode text as Base64.",       placeholder: "admin:password", run: (s) => btoa(unescape(encodeURIComponent(s))) },
  { id: "from-base64", label: "From Base64", category: "encodings", description: "Decode Base64 text.",          placeholder: "YWRtaW46cGFzc3dvcmQ=", run: (s) => { try { return decodeURIComponent(escape(atob(s.trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/").padEnd(s.length + ((4 - s.length % 4) % 4), "=")))); } catch { return "[decode error]"; } } },
  { id: "to-base64url",   label: "To Base64URL",   category: "encodings", description: "URL-safe Base64, no padding.",  placeholder: "admin:password", run: toBase64Url },
  { id: "from-base64url", label: "From Base64URL", category: "encodings", description: "Decode URL-safe Base64 (JWT, web tokens).", placeholder: "YWRtaW46cGFzc3dvcmQ", run: fromBase64Url },
  { id: "to-hex",      label: "To Hex",      category: "encodings", description: "Hex bytes.",                    run: (s) => Array.from(te.encode(s)).map((b) => b.toString(16).padStart(2, "0")).join(" ") },
  { id: "from-hex",    label: "From Hex",    category: "encodings", description: "Hex bytes back to text.",       placeholder: "48 65 6c 6c 6f", run: (s) => { try { const c = s.replace(/[^a-fA-F0-9]/g, ""); return td.decode(new Uint8Array(c.match(/.{1,2}/g)!.map((x) => parseInt(x, 16)))); } catch { return "[hex error]"; } } },
  { id: "to-binary",   label: "To Binary",   category: "encodings", description: "8-bit binary byte groups.",     run: (s) => Array.from(te.encode(s)).map((b) => b.toString(2).padStart(8, "0")).join(" ") },
  { id: "from-binary", label: "From Binary", category: "encodings", description: "Binary back to text.",          run: (s) => { const m = s.match(/[01]{8}/g) ?? []; return td.decode(new Uint8Array(m.map((b) => parseInt(b, 2)))); } },
  { id: "to-charcode",   label: "To Charcode",   category: "encodings", description: "Text to decimal char codes.",     placeholder: "ABC", run: toCharcode },
  { id: "from-charcode", label: "From Charcode", category: "encodings", description: "Decimal char codes back to text.", placeholder: "65 66 67", run: fromCharcode },
  { id: "url-encode",  label: "URL Encode",  category: "encodings", description: "Percent-encode for URLs.",      run: (s) => encodeURIComponent(s) },
  { id: "url-decode",  label: "URL Decode",  category: "encodings", description: "Decode percent-encoding.",      run: (s) => { try { return decodeURIComponent(s); } catch { return s; } } },
  { id: "html-encode", label: "HTML Encode", category: "encodings", description: "Escape HTML entities.",         run: (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;") },
  { id: "html-decode", label: "HTML Decode", category: "encodings", description: "Decode HTML entities.",         run: (s) => { const t = document.createElement("textarea"); t.innerHTML = s; return t.value; } },
  { id: "unicode-escape",   label: "Unicode Escape",   category: "encodings", description: "Non-ASCII to \\uXXXX.",          placeholder: "hello π",   run: unicodeEscape },
  { id: "unicode-unescape", label: "Unicode Unescape", category: "encodings", description: "Decode \\uXXXX sequences.",        placeholder: "hello \\u03c0", run: unicodeUnescape },
  { id: "rot13",       label: "ROT13",       category: "encodings", description: "Simple obfuscation review.",    run: (s) => s.replace(/[a-zA-Z]/g, (c) => { const b = c <= "Z" ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b); }) },

  // Web
  { id: "parse-url",  label: "Parse URL",  category: "web", description: "Break URL into parts.", placeholder: "https://example.com/login?u=test", run: (s) => { try { const u = new URL(s.trim()); return `scheme:   ${u.protocol.replace(":", "")}\nhost:     ${u.hostname}\nport:     ${u.port || "(default)"}\npath:     ${u.pathname}\nquery:    ${u.search || "—"}\nfragment: ${u.hash || "—"}\n\nparams:\n${Array.from(u.searchParams.entries()).map(([k, v]) => `  ${k} = ${v}`).join("\n") || "  (none)"}`; } catch { return "[invalid URL]"; } } },
  { id: "jwt-decode", label: "JWT Decode", category: "web", description: "Decode header & payload (no signature verify).", placeholder: "eyJhbGciOi...", run: (s) => { try { const [h, p] = s.trim().split("."); const dec = (x: string) => JSON.stringify(JSON.parse(atob(x.replace(/-/g, "+").replace(/_/g, "/").padEnd(x.length + ((4 - x.length % 4) % 4), "="))), null, 2); return `=== header ===\n${dec(h)}\n\n=== payload ===\n${dec(p)}\n\n[signature NOT verified]`; } catch { return "[invalid JWT]"; } } },

  // Data
  { id: "json-pretty",        label: "JSON Beautify",      category: "data", description: "Pretty-print JSON.",                run: (s) => { try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return "[invalid JSON]"; } } },
  { id: "json-minify",        label: "JSON Minify",        category: "data", description: "Strip whitespace from JSON.",       run: (s) => { try { return JSON.stringify(JSON.parse(s)); } catch { return "[invalid JSON]"; } } },
  { id: "timestamp",          label: "Timestamp",          category: "data", description: "Unix ↔ ISO conversion.",            run: (s) => { const t = s.trim(); if (/^\d+$/.test(t)) { const n = Number(t); const ms = n < 1e12 ? n * 1000 : n; return `unix:  ${n}\niso:   ${new Date(ms).toISOString()}\nutc:   ${new Date(ms).toUTCString()}`; } const d = new Date(t); if (isNaN(+d)) return "[unparseable]"; return `iso:   ${d.toISOString()}\nunix:  ${Math.floor(+d / 1000)}\nepoch: ${+d}`; } },
  { id: "sort-lines",         label: "Sort Lines",         category: "data", description: "Sort lines alphabetically.",        run: (s) => s.split(/\r?\n/).sort((a, b) => a.localeCompare(b)).join("\n") },
  { id: "unique-lines",       label: "Unique Lines",       category: "data", description: "Dedupe lines (first wins).",        run: (s) => uniq(s.split(/\r?\n/)).join("\n") },
  { id: "remove-empty-lines", label: "Remove Empty Lines", category: "data", description: "Drop blank lines.",                 run: (s) => s.split(/\r?\n/).filter((l) => l.trim()).join("\n") },

  // Text
  { id: "uppercase",        label: "To Uppercase",     category: "text", description: "Convert to uppercase.",      run: (s) => s.toUpperCase() },
  { id: "lowercase",        label: "To Lowercase",     category: "text", description: "Convert to lowercase.",      run: (s) => s.toLowerCase() },
  { id: "reverse",          label: "Reverse",          category: "text", description: "Reverse the string.",        run: (s) => Array.from(s).reverse().join("") },
  { id: "trim-lines",       label: "Trim Lines",       category: "text", description: "Trim each line.",            run: (s) => s.split(/\r?\n/).map((l) => l.trim()).join("\n") },
  { id: "remove-whitespace",label: "Remove Whitespace",category: "text", description: "Strip all whitespace.",      run: (s) => s.replace(/\s+/g, "") },
  { id: "count",            label: "Count",            category: "text", description: "Chars · words · lines · bytes.", run: (s) => { const t = s.trim(); return `characters: ${Array.from(s).length}\nbytes_utf8: ${te.encode(s).length}\nwords:      ${t ? t.split(/\s+/).length : 0}\nlines:      ${s ? s.split(/\r?\n/).length : 0}`; } },
  { id: "escape-regex",     label: "Escape Regex",     category: "text", description: "Escape regex metacharacters.", run: (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") },
  { id: "regex-extract",    label: "Regex Extract",    category: "text", description: "Common SOC regex hits.",      run: (s) => {
    const block = (label: string, items: string[]) => `${label} (${items.length})${items.length ? "\n" + items.map((i) => "  · " + i).join("\n") : ""}`;
    return [
      block("ipv4",    uniq(s.match(RX.ip)  ?? [])),
      block("urls",    uniq(s.match(RX.url) ?? [])),
      block("emails",  uniq(s.match(RX.em)  ?? [])),
      block("hashes",  uniq(s.match(RX.ha)  ?? [])),
      block("cves",    uniq(s.match(RX.cve) ?? [])),
      block("event_ids", uniq(s.match(RX.evt) ?? [])),
    ].join("\n\n");
  }},
  { id: "regex-redact",     label: "Regex Redact",     category: "text", description: "Redact IPs/emails/URLs/hashes.", run: (s) => s.replace(RX.url, "[REDACTED]").replace(RX.em, "[REDACTED]").replace(RX.ip, "[REDACTED]").replace(RX.ha, "[REDACTED]") },

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
  { id: "secret-scan", label: "Secret Scan", category: "triage", description: "Detect API keys, tokens, .env assignments.", run: (s) => {
    const lines = s.split(/\r?\n/);
    const rules: { name: string; rx: RegExp }[] = [
      { name: "AWS access key",  rx: /\bAKIA[0-9A-Z]{16}\b/ },
      { name: "GitHub token",    rx: /\bghp_[A-Za-z0-9]{20,}\b/ },
      { name: "Stripe live key", rx: /\bsk_live_[A-Za-z0-9]{16,}\b/ },
      { name: "Stripe test key", rx: /\bsk_test_[A-Za-z0-9]{16,}\b/ },
      { name: "Slack token",     rx: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
      { name: "Private key PEM", rx: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
      { name: ".env assignment", rx: /^[A-Z][A-Z0-9_]+=[\S]+$/ },
      { name: "Generic API key", rx: /\b[A-Za-z0-9_-]{32,}\b/ },
    ];
    const hits: string[] = [];
    lines.forEach((l, i) => rules.forEach((r) => { if (r.rx.test(l)) hits.push(`L${i + 1}  [${r.name}]  ${l.trim().slice(0, 100)}`); }));
    return hits.length ? `${hits.length} potential secret(s):\n\n${hits.join("\n")}` : "No secrets detected.";
  }},
  { id: "powershell-analyze", label: "PowerShell Analyze", category: "triage", description: "Decode & statically triage PowerShell (no execution).", placeholder: "powershell -NoP -EncodedCommand SQBFAFgA", run: (s) => {
    const lo = s.toLowerCase();
    const encMatch = s.match(/(?:-enc(?:odedcommand)?\s+)([a-z0-9+/=_-]+)/i);
    let decoded = "";
    if (encMatch) {
      try { const c = encMatch[1].replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/"); const p = c.padEnd(c.length + ((4 - c.length % 4) % 4), "="); decoded = new TextDecoder("utf-16le").decode(Uint8Array.from(atob(p), (x) => x.charCodeAt(0))).replace(/\0/g, ""); } catch { decoded = "[decode failed]"; }
    }
    const flags = ["encodedcommand", "-enc", "-nop", "bypass", "hidden", "downloadstring", "invoke-expression", "iex", "frombase64string", "new-object net.webclient"].filter((f) => lo.includes(f));
    return `encoded_command: ${encMatch ? "yes" : "no"}${decoded ? `\ndecoded_preview: ${decoded.slice(0, 500)}` : ""}\nsuspicious_flags: ${flags.join(", ") || "none"}\n\n[ioc extraction from decoded payload may yield additional indicators — run Extract IOCs on output]`;
  }},
  { id: "linux-auth-summary", label: "Linux Auth Summary", category: "triage", description: "Summarize auth/SSH log lines.", placeholder: "Jan 12 10:01:02 host sshd[123]: Failed password for invalid user admin from 8.8.8.8", run: (s) => {
    const lines = s.split(/\r?\n/).filter(Boolean);
    const ips = uniq(lines.flatMap((l) => l.match(RX.ip) ?? []));
    const invalid = uniq(lines.map((l) => l.match(/invalid user\s+(\S+)/i)?.[1]).filter(Boolean));
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

const OP_BY_ID = Object.fromEntries(OPS.map((o) => [o.id, o]));

const DEFAULT_FAVS = ["defang", "refang", "extract-iocs", "from-base64", "url-decode", "sha256", "parse-url"];

const CATEGORIES: { id: Cat; label: string }[] = [
  { id: "favourites", label: "Favourites" },
  { id: "ioc",        label: "IOC Safe Handling" },
  { id: "encodings",  label: "Encodings" },
  { id: "web",        label: "Web" },
  { id: "data",       label: "Data Format" },
  { id: "text",       label: "Text" },
  { id: "hashing",    label: "Hashing" },
  { id: "triage",     label: "Script Triage" },
];

type Preset = { id: string; label: string; description: string; steps: string[]; sample: string };

const PRESETS: Preset[] = [
  { id: "url-decode-iocs", label: "URL Decode → Extract IOCs", description: "Decode an encoded URL or payload, then extract indicators.", steps: ["url-decode", "extract-iocs"], sample: "hxxps%3A%2F%2Flogin.example.com%2Fsecure%3Fnext%3Dhttp%253A%252F%252Fevil.example.net%252Fdrop.exe%20from%208.8.8.8" },
  { id: "base64-url-iocs", label: "Base64 Decode → Extract URLs", description: "Decode Base64 text, then isolate URLs.", steps: ["from-base64", "extract-urls"], sample: "U3VzcGljaW91cyBsaW5rOiBodHRwczovL2V4YW1wbGUuY29tL2xvZ2luP3U9dGVzdA==" },
  { id: "base64-powershell", label: "Base64 Decode → PowerShell Analyze", description: "Decode a Base64 command, then statically triage.", steps: ["from-base64", "powershell-analyze"], sample: "cG93ZXJzaGVsbCAtTm9QIC1XIEhpZGRlbiAtRW5jb2RlZENvbW1hbmQgU1FCRkFGZ0E=" },
  { id: "html-url-extract", label: "HTML Decode → Extract URLs", description: "Decode HTML entities from email or web text, then extract URLs.", steps: ["html-decode", "extract-urls"], sample: "Click &lt;a href=&quot;https://example.com/login?token=abc&quot;&gt;secure portal&lt;/a&gt;" },
  { id: "unicode-ioc-extract", label: "Unicode Unescape → Extract IOCs", description: "Decode escaped script text, then pull indicators.", steps: ["unicode-unescape", "extract-iocs"], sample: "\\u0068\\u0074\\u0074\\u0070\\u0073://example.com/login from 1.1.1.1" },
  { id: "json-ioc-review", label: "JSON Beautify → Extract IOCs", description: "Make JSON readable, then extract indicators from it.", steps: ["json-pretty", "extract-iocs"], sample: '{"event":"click","url":"https://example.com/login","src_ip":"8.8.8.8"}' },
  { id: "normalize-then-defang", label: "Normalize IOC List → Defang", description: "Clean an IOC list and make it report-safe.", steps: ["normalize-ioc-list", "defang"], sample: "  EXAMPLE.com\n8.8.8.8\nexample.com\nHTTPS://Example.com/login" },
  { id: "redact-then-defang", label: "Regex Redact → Defang", description: "Redact sensitive values, then defang remaining indicators.", steps: ["regex-redact", "defang"], sample: "User admin@example.com clicked https://example.com/login from 8.8.8.8" },
  { id: "jwt-decode", label: "JWT Decode", description: "Decode JWT header and payload (signature not verified).", steps: ["jwt-decode"], sample: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IktyaXNoIFBhdGVsIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature" },
  { id: "parse-url", label: "Parse URL", description: "Break a URL into host, path, query parameters.", steps: ["parse-url"], sample: "https://example.com/login?user=test&id=7" },
];

/* =================== Component =================== */

const FAVS_KEY = "beyondarch.chefFavs";
const RECIPE_KEY = "beyondarch.chefRecipe";
const LIBRARY_KEY = "beyondarch.chefLibrary";

type SavedBake = { id: string; name: string; recipe: string[]; ts: number };

function ChefPage() {
  const [input, setInput] = useState("");
  const [recipe, setRecipe] = useState<string[]>([]);
  const [output, setOutput] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [expandedCats, setExpandedCats] = useState<Set<string>>(new Set(["favourites"]));
  const [query, setQuery] = useState("");
  const [favs, setFavs] = useState<string[]>(DEFAULT_FAVS);
  const [copied, setCopied] = useState(false);
  const [dragIdx, setDragIdx] = useState<number | null>(null);
  const [library, setLibrary] = useState<SavedBake[]>([]);
  const [showLibrary, setShowLibrary] = useState(false);
  const [stepOptions, setStepOptions] = useState<Record<number, Record<string, any>>>({});
  const [expandedStep, setExpandedStep] = useState<number | null>(null);
  const [inputFileName, setInputFileName] = useState("");
  const [inputDrag, setInputDrag] = useState(false);
  const [secretScanOpen, setSecretScanOpen] = useState(false);
  const [autoBake, setAutoBake] = useState(true);
  const [baking, setBaking] = useState(false);
  const [stepOutputs, setStepOutputs] = useState<{label: string; output: string; status: string}[]>([]);
  const [stepDetailsOpen, setStepDetailsOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Hydrate persisted state + inbound handoff
  useEffect(() => {
    try {
      const f = localStorage.getItem(FAVS_KEY); if (f) setFavs(JSON.parse(f));
      const r = localStorage.getItem(RECIPE_KEY); if (r) setRecipe(JSON.parse(r));
      const l = localStorage.getItem(LIBRARY_KEY); if (l) setLibrary(JSON.parse(l));
    } catch {}
    const pending = takePendingArtifact();
    if (pending?.value) setInput(pending.value);
  }, []);

  // Persist favourites + active recipe
  useEffect(() => { try { localStorage.setItem(FAVS_KEY, JSON.stringify(favs)); } catch {} }, [favs]);
  useEffect(() => { try { localStorage.setItem(RECIPE_KEY, JSON.stringify(recipe)); } catch {} }, [recipe]);
  useEffect(() => { try { localStorage.setItem(LIBRARY_KEY, JSON.stringify(library)); } catch {} }, [library]);


  // Run pipeline — collects intermediate step outputs, respects autoBake toggle
  useEffect(() => {
    if (!autoBake) return;
    let cancelled = false;
    (async () => {
      try {
        let acc: string = input;
        const steps: {label: string; output: string; status: string}[] = [];
        for (const id of recipe) {
          if (cancelled) return;
          const op = OP_BY_ID[id];
          if (!op) continue;
          acc = await op.run(acc);
          if (!cancelled) steps.push({label: op.label, output: acc, status: "success"});
        }
        if (!cancelled) { setOutput(acc); setError(""); setStepOutputs(steps); }
      } catch (e: any) {
        if (!cancelled) {
          const msg = e?.message ?? "pipeline error";
          setStepOutputs((s) => [...s, {label: "error", output: msg, status: "failed"}]);
          setError(msg);
        }
      }
    })();
    return () => { cancelled = true; };
  }, [input, recipe, autoBake]);

  const manualBake = () => {
    if (!input || !recipe.length) return;
    setBaking(true);
    setStepOutputs([]);
    (async () => {
      try {
        let acc = input;
        const steps: {label: string; output: string; status: string}[] = [];
        for (const id of recipe) {
          const op = OP_BY_ID[id];
          if (!op) continue;
          acc = await op.run(acc);
          steps.push({label: op.label, output: acc, status: "success"});
        }
        setOutput(acc); setError(""); setStepOutputs(steps);
      } catch (e: any) {
        const msg = e?.message ?? "pipeline error";
        setStepOutputs((s) => [...s, {label: "error", output: msg, status: "failed"}]);
        setError(msg);
      } finally { setBaking(false); }
    })();
  };

  const toggleCategory = (id: string) => {
    setExpandedCats((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const addStep = (id: string) => setRecipe((r) => [...r, id]);
  const removeStep = (i: number) => setRecipe((r) => r.filter((_, idx) => idx !== i));
  const toggleFav = (id: string) => setFavs((f) => f.includes(id) ? f.filter((x) => x !== id) : [...f, id]);

  const onDragStart = (i: number) => setDragIdx(i);
  const onDragOver = (e: React.DragEvent, over: number) => {
    e.preventDefault();
    if (dragIdx === null || dragIdx === over) return;
    setRecipe((r) => {
      const copy = r.slice();
      const [m] = copy.splice(dragIdx, 1);
      copy.splice(over, 0, m);
      setDragIdx(over);
      return copy;
    });
  };

  const copy = () => { navigator.clipboard.writeText(output); setCopied(true); setTimeout(() => setCopied(false), 1200); };

  const loadPreset = (idOrSteps: string | string[]) => {
    if (Array.isArray(idOrSteps)) { setRecipe(idOrSteps); return; }
    const preset = PRESETS.find((p) => p.id === idOrSteps);
    if (!preset) { setRecipe([idOrSteps]); return; }
    setRecipe(preset.steps);
    if (preset.sample) setInput(preset.sample);
  };
  const clearAll = () => { setRecipe([]); setInput(""); };
  const saveBake = () => {
    const blob = new Blob([JSON.stringify({ input, recipe, output }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `chef-bake-${Date.now()}.json`; a.click(); URL.revokeObjectURL(url);
  };
  const saveToLibrary = () => {
    if (!recipe.length) return;
    const name = window.prompt("Name this recipe:", recipe.map((id) => OP_BY_ID[id]?.label ?? id).slice(0, 3).join(" → "));
    if (!name) return;
    setLibrary((l) => [{ id: crypto.randomUUID(), name, recipe: recipe.slice(), ts: Date.now() }, ...l].slice(0, 20));
  };

  const loadSample = () => {
    const firstId = recipe[0];
    const op = firstId ? OP_BY_ID[firstId] : null;
    if (op?.placeholder) setInput(op.placeholder);
    else setInput("https://example.com/login?user=test\n8.8.8.8\nuser@example.com");
  };
  const loadFile = (file: File | null) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => { setInput(reader.result as string); setInputFileName(file.name); };
    reader.readAsText(file);
  };
  const HANDOFF_TARGETS: Record<string, { label: string; page: string }> = {
    parser: { label: "Smart Parser", page: "/parser" },
    phishing: { label: "Phishing Triage", page: "/phishing" },
    recon: { label: "Recon & Exposure", page: "/recon" },
    detection: { label: "Detection & MITRE", page: "/detection" },
    logs: { label: "Logs & Alerts", page: "/logs" },
  };
  const sendOutputTo = (target: string) => {
    const route = HANDOFF_TARGETS[target];
    if (!route || !output) return;
    try {
      localStorage.setItem("beyondarch.pendingArtifact", JSON.stringify({ target: route.page.replace("/", ""), value: output, source: "CyberChef", type: "transform" }));
      window.location.href = route.page;
    } catch {}
  };

  const moveStep = (i: number, dir: -1 | 1) => {
    const j = i + dir;
    if (j < 0 || j >= recipe.length) return;
    setRecipe((r) => { const c = r.slice(); [c[i], c[j]] = [c[j], c[i]]; return c; });
  };
  const duplicateStep = (i: number) => setRecipe((r) => { const c = r.slice(); c.splice(i + 1, 0, r[i]); return c; });
  const updateStepOpts = (i: number, opts: Record<string, any>) => setStepOptions((s) => ({ ...s, [i]: { ...(s[i] || {}), ...opts } }));

  function StepOptionsForm({ idx, opId }: { idx: number; opId: string }) {
    const opts = stepOptions[idx] || {};
    if (opId === "to-hex") return (
      <div className="mt-2 grid grid-cols-3 gap-2 text-mono text-[10px] text-muted-foreground">
        <label>Delimiter <select value={opts.delimiter ?? ""} onChange={(e) => updateStepOpts(idx, { delimiter: e.target.value })} className="mt-0.5 w-full rounded border border-border/60 bg-background/60 px-1 py-0.5 text-[10px]"><option value="">None</option><option value=" ">Space</option><option value=":">Colon</option></select></label>
        <label>Case <select value={opts.case ?? "lower"} onChange={(e) => updateStepOpts(idx, { case: e.target.value })} className="mt-0.5 w-full rounded border border-border/60 bg-background/60 px-1 py-0.5 text-[10px]"><option value="lower">lower</option><option value="upper">UPPER</option></select></label>
        <label>Prefix <select value={opts.prefix ?? ""} onChange={(e) => updateStepOpts(idx, { prefix: e.target.value })} className="mt-0.5 w-full rounded border border-border/60 bg-background/60 px-1 py-0.5 text-[10px]"><option value="">None</option><option value="0x">0x</option></select></label>
      </div>
    );
    if (["to-charcode", "from-charcode"].includes(opId)) return (
      <div className="mt-2 flex flex-wrap gap-3 text-mono text-[10px] text-muted-foreground">
        <label>Base <select value={opts.base ?? 10} onChange={(e) => updateStepOpts(idx, { base: Number(e.target.value) })} className="rounded border border-border/60 bg-background/60 px-1 py-0.5 text-[10px]"><option value={10}>Decimal</option><option value={16}>Hex</option></select></label>
      </div>
    );
    if (opId === "rot13") return (
      <label className="mt-2 block text-mono text-[10px] text-muted-foreground">Rotation <input type="number" min={1} max={25} value={opts.rotation ?? 13} onChange={(e) => updateStepOpts(idx, { rotation: Number(e.target.value) })} className="ml-1 w-14 rounded border border-border/60 bg-background/60 px-1 py-0.5 text-[10px]" /></label>
    );
    if (["sort-lines", "unique-lines"].includes(opId)) return (
      <label className="mt-2 flex items-center gap-1 text-mono text-[10px] text-muted-foreground"><input type="checkbox" checked={!!opts.caseSensitive} onChange={(e) => updateStepOpts(idx, { caseSensitive: e.target.checked })} /> Case sensitive</label>
    );
    if (["sha1", "sha256", "sha384", "sha512"].includes(opId)) return (
      <label className="mt-2 block text-mono text-[10px] text-muted-foreground">Case <select value={opts.case ?? "lower"} onChange={(e) => updateStepOpts(idx, { case: e.target.value })} className="ml-1 rounded border border-border/60 bg-background/60 px-1 py-0.5 text-[10px]"><option value="lower">lower</option><option value="upper">UPPER</option></select></label>
    );
    return null;
  }

  return (
    <PageShell
      eyebrow="TOOLS / CYBERCHEF"
      title="CyberChef"
      description="Local-only encode, decode, extract, hash. Pick operations → drag into a recipe → input streams through into output."
      crumbs={[{ label: "Tools" }, { label: "CyberChef" }]}
    >
      {/* Preset bar */}
      <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card/40 px-3 py-2">
        <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">presets</span>
        {PRESETS.map((p) => (
          <button key={p.id} onClick={() => loadPreset(p.id)} className="rounded border border-border/70 bg-background/40 px-2 py-0.5 text-mono text-[10.5px] text-foreground/80 hover:border-primary/40 hover:text-primary">
            {p.label}
          </button>
        ))}
        <span className="ml-auto inline-flex items-center gap-2">
          <div className="relative">
            <button onClick={() => setShowLibrary((v) => !v)} className="inline-flex items-center gap-1 rounded border border-border bg-background/40 px-2 py-0.5 text-mono text-[10.5px] text-muted-foreground hover:text-foreground">
              <BookMarked className="h-3 w-3" /> library · {library.length}
            </button>
            {showLibrary && (
              <div className="absolute right-0 z-20 mt-1 w-72 rounded-md border border-border bg-card shadow-lg">
                <div className="border-b border-border/60 px-2 py-1.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">saved recipes</div>
                {library.length === 0 ? (
                  <div className="px-3 py-3 text-mono text-[11px] text-muted-foreground">No saved recipes yet — bake one and click <em>save to library</em>.</div>
                ) : (
                  <ul className="max-h-64 overflow-y-auto py-1">
                    {library.map((b) => (
                      <li key={b.id} className="group flex items-center gap-1 px-2 py-1 hover:bg-primary/5">
                        <button onClick={() => { loadPreset(b.recipe); setShowLibrary(false); }} className="min-w-0 flex-1 text-left">
                          <div className="truncate text-mono text-[11.5px] text-foreground/90">{b.name}</div>
                          <div className="truncate text-mono text-[10px] text-muted-foreground">{b.recipe.length} steps · {new Date(b.ts).toLocaleDateString()}</div>
                        </button>
                        <button onClick={() => setLibrary((l) => l.filter((x) => x.id !== b.id))} className="opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-destructive"><X className="h-3 w-3" /></button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
          <button onClick={saveToLibrary} disabled={!recipe.length} className="inline-flex items-center gap-1 rounded border border-border bg-background/40 px-2 py-0.5 text-mono text-[10.5px] text-muted-foreground hover:text-foreground disabled:opacity-40 disabled:cursor-not-allowed">
            <Star className="h-3 w-3" /> save to library
          </button>
          <button onClick={clearAll} className="inline-flex items-center gap-1 rounded border border-border bg-background/40 px-2 py-0.5 text-mono text-[10.5px] text-muted-foreground hover:text-foreground">
            <Eraser className="h-3 w-3" /> clear
          </button>
          <button onClick={saveBake} className="inline-flex items-center gap-1 rounded border border-border bg-background/40 px-2 py-0.5 text-mono text-[10.5px] text-muted-foreground hover:text-foreground">
            <FileDown className="h-3 w-3" /> export bake
          </button>
        </span>
      </div>


      {/* 3-pane CyberChef layout: Operations | Recipe | Input/Output stacked */}
      <div className="grid gap-3 lg:grid-cols-[240px_280px_minmax(0,1fr)]">

        {/* PANE 1 — Operations */}
        <aside className="flex h-[calc(100vh-260px)] min-h-[560px] flex-col overflow-hidden rounded-md border border-border bg-card/40">
          <div className="border-b border-border/60 px-2.5 py-2">
            <div className="flex items-center gap-1.5">
              <ChefHat className="h-3.5 w-3.5 text-primary" />
              <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">operations</span>
              <span className="ml-auto text-mono text-[10px] text-muted-foreground">{OPS.length}</span>
            </div>
            <div className="mt-1.5 flex items-center gap-1 rounded border border-border/60 bg-background/60 px-1.5">
              <Search className="h-3 w-3 text-muted-foreground" />
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="search…" className="flex-1 bg-transparent py-1 text-mono text-[11px] outline-none placeholder:text-muted-foreground/60" />
            </div>
          </div>
          {/* collapsible operation tree */}
          <div className="flex-1 overflow-y-auto p-1.5">
            {/* Recipes section */}
            <div className="mb-1">
              <button
                onClick={() => toggleCategory("recipes")}
                className="flex w-full items-center gap-1.5 rounded px-2 py-1.5 text-left text-mono text-[11px] font-bold uppercase tracking-widest text-foreground/80 hover:bg-primary/5"
              >
                {expandedCats.has("recipes") ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                Recipes
                <span className="ml-auto text-[10px] font-normal text-muted-foreground">{PRESETS.length}</span>
              </button>
              {expandedCats.has("recipes") && (
                <div className="ml-3 space-y-1 border-l border-border/40 py-1 pl-2">
                  {PRESETS.map((p) => (
                    <button
                      key={p.id}
                      onClick={() => loadPreset(p.id)}
                      className="w-full rounded border border-border/50 bg-background/30 px-2 py-1.5 text-left transition-colors hover:border-primary/40 hover:bg-primary/5"
                    >
                      <div className="truncate text-mono text-[11px] text-foreground/90">{p.label}</div>
                      <div className="line-clamp-2 text-mono text-[10px] text-muted-foreground">{p.description}</div>
                      <div className="mt-0.5 truncate text-mono text-[9px] text-primary/60">{p.steps.map((id) => OP_BY_ID[id]?.label ?? id).join(" → ")}</div>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Category sections */}
            {CATEGORIES.map((cat) => {
              const catOps = OPS.filter((o) => o.category === cat.id);
              const q = query.trim().toLowerCase();
              const visible = q ? catOps.filter((o) => o.label.toLowerCase().includes(q) || o.description.toLowerCase().includes(q)) : catOps;
              const isExpanded = expandedCats.has(cat.id);
              const showContent = q ? true : isExpanded;
              if (q && visible.length === 0) return null;
              return (
                <div key={cat.id} className="mb-1">
                  <button
                    onClick={() => toggleCategory(cat.id)}
                    className="flex w-full items-center gap-1.5 rounded px-2 py-1.5 text-left text-mono text-[11px] font-bold uppercase tracking-widest text-foreground/80 hover:bg-primary/5"
                  >
                    {showContent ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                    {cat.label}
                    <span className="ml-auto text-[10px] font-normal text-muted-foreground">{catOps.length}</span>
                  </button>
                  {showContent && (
                    <div className="ml-3 space-y-0.5 border-l border-border/40 py-1 pl-2">
                      {visible.map((op) => (
                        <div key={op.id} className="group flex items-stretch gap-1">
                          <button
                            onClick={() => addStep(op.id)}
                            onDoubleClick={() => addStep(op.id)}
                            title={op.description}
                            draggable
                            onDragStart={(e) => { e.dataTransfer.setData("text/op-id", op.id); e.dataTransfer.effectAllowed = "copy"; }}
                            className="flex-1 cursor-grab rounded border border-transparent px-2 py-1 text-left transition-colors hover:border-primary/40 hover:bg-primary/5"
                          >
                            <div className="flex items-center justify-between gap-1">
                              <span className="truncate text-mono text-[11px] text-foreground/90">{op.label}</span>
                              <span className="shrink-0 rounded border border-border/50 px-1 py-0.5 text-[9px] uppercase tracking-widest text-muted-foreground">{op.category}</span>
                            </div>
                            <div className="truncate text-mono text-[10px] text-muted-foreground">{op.description}</div>
                          </button>
                          <button
                            onClick={() => toggleFav(op.id)}
                            title={favs.includes(op.id) ? "Unfavourite" : "Favourite"}
                            className="px-1 text-muted-foreground hover:text-warning"
                          >
                            <Star className={"h-3.5 w-3.5 " + (favs.includes(op.id) ? "fill-warning text-warning" : "")} />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </aside>

        {/* PANE 2 — Recipe */}
        <section
          className="flex h-[calc(100vh-260px)] min-h-[560px] flex-col overflow-hidden rounded-md border border-border bg-card/40"
          onDragOver={(e) => { if (e.dataTransfer.types.includes("text/op-id")) { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; } }}
          onDrop={(e) => {
            const id = e.dataTransfer.getData("text/op-id");
            if (id && OP_BY_ID[id]) { e.preventDefault(); addStep(id); }
          }}
        >
            <div className="flex items-center justify-between border-b border-border/60 px-3 py-1.5">
              <div className="flex items-center gap-2">
                <span className="grid h-4 w-4 place-items-center rounded-sm border border-warning/40 bg-warning/10 text-warning"><Clock className="h-2.5 w-2.5" strokeWidth={2.5} /></span>
                <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">recipe · {recipe.length} step{recipe.length === 1 ? "" : "s"}</span>
              </div>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setAutoBake((v) => !v)}
                  className={"inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-mono text-[9px] uppercase tracking-widest " + (autoBake ? "bg-success/15 text-success" : "bg-muted/40 text-muted-foreground")}
                  title="Toggle automatic baking"
                >
                  auto {autoBake ? "on" : "off"}
                </button>
              <button onClick={() => { try { localStorage.setItem("beyondarch.chefRecipeSaved", JSON.stringify(recipe)); } catch {} }} disabled={!recipe.length} className="inline-flex items-center gap-1 text-mono text-[9px] uppercase tracking-widest text-muted-foreground hover:text-primary disabled:opacity-30" title="Save recipe to browser">save</button>
              <button onClick={() => { try { const r = localStorage.getItem("beyondarch.chefRecipeSaved"); if (r) setRecipe(JSON.parse(r)); } catch {} }} className="inline-flex items-center gap-1 text-mono text-[9px] uppercase tracking-widest text-muted-foreground hover:text-primary" title="Load saved recipe from browser">load</button>
              {recipe.length > 0 && (
                <button onClick={() => setRecipe([])} className="inline-flex items-center gap-1 text-mono text-[9px] uppercase tracking-widest text-muted-foreground hover:text-destructive">
                  <Trash2 className="h-3 w-3" /> clr
                </button>
              )}
            </div>
          </div>
          <div className="flex-1 overflow-y-auto p-2">
            {recipe.length === 0 ? (
              <div className="grid h-full place-items-center rounded border border-dashed border-border/60 px-3 py-6 text-center">
                <div>
                  <div className="text-mono text-[11px] text-muted-foreground">Drag an operation here, or click to add.</div>
                  <div className="mt-1 text-mono text-[10px] text-muted-foreground/70">Steps run top → bottom.</div>
                </div>
              </div>
            ) : (
              <ol className="space-y-1.5">
                {recipe.map((id, i) => {
                  const op = OP_BY_ID[id];
                  return (
                    <li
                      key={i}
                      draggable
                      onDragStart={() => onDragStart(i)}
                      onDragOver={(e) => onDragOver(e, i)}
                      onDragEnd={() => setDragIdx(null)}
                      className={"group relative rounded border bg-background/40 px-2 py-1.5 " + (dragIdx === i ? "border-primary/60 opacity-60" : "border-border/60 hover:border-primary/40")}
                    >
                      <div className="flex items-center gap-2">
                        <GripVertical className="h-3.5 w-3.5 cursor-grab text-muted-foreground" />
                        <span className="grid h-5 w-5 shrink-0 place-items-center rounded-sm bg-primary/15 text-mono text-[9px] font-bold text-primary">{i + 1}</span>
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-mono text-[11.5px] text-foreground/90">{op?.label ?? id}</div>
                          <div className="truncate text-mono text-[10px] text-muted-foreground">{op?.category ?? "—"}</div>
                        </div>
                        <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100">
                          <button onClick={() => moveStep(i, -1)} disabled={i === 0} title="Move up" className="rounded p-0.5 text-muted-foreground hover:text-primary disabled:opacity-30"><ArrowUp className="h-3 w-3" /></button>
                          <button onClick={() => moveStep(i, 1)} disabled={i === recipe.length - 1} title="Move down" className="rounded p-0.5 text-muted-foreground hover:text-primary disabled:opacity-30"><ArrowDown className="h-3 w-3" /></button>
                          <button onClick={() => duplicateStep(i)} title="Duplicate" className="rounded p-0.5 text-muted-foreground hover:text-primary"><Copy className="h-3 w-3" /></button>
                          <button onClick={() => setExpandedStep(expandedStep === i ? null : i)} title="Options" className={"rounded p-0.5 " + (expandedStep === i ? "text-primary" : "text-muted-foreground hover:text-primary")}><Settings2 className="h-3 w-3" /></button>
                          <button onClick={() => removeStep(i)} title="Remove" className="rounded p-0.5 text-muted-foreground hover:text-destructive"><X className="h-3 w-3" /></button>
                        </div>
                      </div>
                      {expandedStep === i && (
                        <div className="ml-7 border-t border-border/40 pt-1.5">
                          <StepOptionsForm idx={i} opId={id} />
                        </div>
                      )}
                    </li>
                  );
                })}
              </ol>
            )}
          </div>
          {/* recipe footer — show pipeline summary */}
          <div className="border-t border-border/60 px-3 py-1 text-mono text-[10px] text-muted-foreground">
            <span className="block truncate" title={recipe.map((id) => OP_BY_ID[id]?.label ?? id).join(" → ") || ""}>
              {recipe.length ? recipe.map((id) => OP_BY_ID[id]?.label ?? id).join(" → ") : "pipeline empty"}
            </span>
          </div>
        </section>

        {/* PANE 3 — Input + Output stacked */}
        <div className="grid h-[calc(100vh-260px)] min-h-[560px] grid-rows-2 gap-3">
          {/* Input */}
          <section
            className={"flex min-h-0 flex-col overflow-hidden rounded-md border bg-card/40 transition-colors " + (inputDrag ? "border-primary/60 bg-primary/5" : "border-border")}
            onDragOver={(e) => { e.preventDefault(); setInputDrag(true); }}
            onDragLeave={() => setInputDrag(false)}
            onDrop={(e) => { e.preventDefault(); setInputDrag(false); const f = e.dataTransfer.files?.[0]; if (f) loadFile(f); }}
          >
            <div className="flex items-center justify-between border-b border-border/60 px-3 py-1.5">
              <div className="flex items-center gap-2">
                <span className="grid h-4 w-4 place-items-center rounded-sm border border-primary/40 bg-primary/10 text-primary"><ArrowDownToLine className="h-2.5 w-2.5" strokeWidth={2.5} /></span>
                <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">input</span>
                {inputFileName && <span className="truncate text-mono text-[9px] text-muted-foreground/70 max-w-[120px]" title={inputFileName}>{inputFileName}</span>}
              </div>
              <div className="flex items-center gap-1.5 text-mono text-[10px] text-muted-foreground">
                <span>{input.length} chars</span>
                <span>·</span>
                <span>{input.split(/\r?\n/).length} lines</span>
                <button onClick={loadSample} title="Load sample input" className="rounded border border-border bg-background/60 px-1.5 py-0.5 uppercase tracking-widest hover:border-primary/40 hover:text-primary">sample</button>
                <button onClick={() => inputRef.current?.click()} title="Open file" className="rounded border border-border bg-background/60 px-1.5 py-0.5 uppercase tracking-widest hover:border-primary/40 hover:text-primary"><Upload className="h-3 w-3" /></button>
                <input ref={inputRef} type="file" onChange={(e) => loadFile(e.target.files?.[0] ?? null)} className="hidden" />
                <button onClick={() => setInput("")} title="Clear input" className="rounded border border-border bg-background/60 px-1.5 py-0.5 uppercase tracking-widest hover:border-destructive/50 hover:text-destructive">
                  <Eraser className="h-3 w-3" />
                </button>
              </div>
            </div>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={recipe.length ? OP_BY_ID[recipe[0]]?.placeholder ?? "Paste input here…" : "Paste input here, or drag a file."}
              className="flex-1 resize-none bg-transparent p-3 text-mono text-[12px] leading-relaxed text-foreground outline-none placeholder:text-muted-foreground/50"
              spellCheck={false}
            />
          </section>

          {/* Output */}
          <section className="flex min-h-0 flex-col overflow-hidden rounded-md border border-border bg-card/40">
            <div className="flex items-center justify-between border-b border-border/60 px-3 py-1.5">
              <div className="flex items-center gap-2">
                <span className="grid h-4 w-4 place-items-center rounded-sm border border-success/40 bg-success/10 text-success"><ArrowUpFromLine className="h-2.5 w-2.5" strokeWidth={2.5} /></span>
                <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">output</span>
                {error && <span className="rounded border border-destructive/50 bg-destructive/10 px-1.5 py-0.5 text-mono text-[9.5px] uppercase tracking-widest text-destructive">error</span>}
              </div>
              <div className="flex items-center gap-1.5 text-mono text-[10px] text-muted-foreground">
                {(input && !autoBake && (input || recipe.length)) && (
                  <button onClick={manualBake} disabled={baking} className="inline-flex items-center gap-1 rounded border border-primary/30 bg-primary/10 px-2 py-0.5 uppercase tracking-widest text-primary hover:bg-primary/20 disabled:opacity-50" title="Run pipeline manually">
                    {baking ? "..." : "run"}
                  </button>
                )}
                <span>{output.length} chars</span>
                <span>·</span>
                <span>{output.split(/\r?\n/).length} lines</span>
                <button onClick={copy} className="rounded border border-border bg-background/60 px-1.5 py-0.5 uppercase tracking-widest hover:border-primary/40 hover:text-primary">
                  {copied ? <><Check className="h-3 w-3" /></> : <><Copy className="h-3 w-3" /></>}
                </button>
                <button onClick={() => setInput(output)} title="Swap output → input" className="rounded border border-border bg-background/60 px-1.5 py-0.5 uppercase tracking-widest hover:border-primary/40 hover:text-primary">
                  <RotateCcw className="h-3 w-3" />
                </button>
                {/* More dropdown */}
                <div className="relative group">
                  <button className="rounded border border-border bg-background/60 px-1.5 py-0.5 uppercase tracking-widest hover:border-primary/40 hover:text-primary">more</button>
                  <div className="absolute right-0 z-20 mt-1 w-48 rounded-md border border-border bg-card py-1 shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-opacity">
                    <button onClick={() => { setInput(output); setOutput(""); }} className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-mono text-[11px] text-foreground/80 hover:bg-primary/5"><RotateCcw className="h-3 w-3" /> Swap I/O</button>
                    <button onClick={() => { const b = new Blob([output], { type: "text/plain" }); const u = URL.createObjectURL(b); const a = document.createElement("a"); a.href = u; a.download = "chef-output.txt"; a.click(); URL.revokeObjectURL(u); }} className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-mono text-[11px] text-foreground/80 hover:bg-primary/5"><Download className="h-3 w-3" /> Download</button>
                    <button onClick={() => setOutput("")} className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-mono text-[11px] text-foreground/80 hover:bg-primary/5"><Eraser className="h-3 w-3" /> Clear</button>
                  </div>
                </div>
                {/* Send to dropdown */}
                {output && (
                  <div className="relative group">
                    <button className="rounded border border-border bg-background/60 px-1.5 py-0.5 uppercase tracking-widest hover:border-primary/40 hover:text-primary"><Send className="h-3 w-3" /></button>
                    <div className="absolute right-0 z-20 mt-1 w-48 rounded-md border border-border bg-card py-1 shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-opacity">
                      {Object.entries(HANDOFF_TARGETS).map(([k, v]) => (
                        <button key={k} onClick={() => sendOutputTo(k)} className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-mono text-[11px] text-foreground/80 hover:bg-primary/5"><Send className="h-3 w-3" /> {v.label}</button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
            {error ? (
              <pre className="flex-1 overflow-auto whitespace-pre-wrap break-words p-3 text-mono text-[12px] text-destructive">{error}</pre>
            ) : output ? (
              <pre className="flex-1 overflow-auto whitespace-pre-wrap break-words p-3 text-mono text-[12px] leading-relaxed text-foreground">{output}</pre>
            ) : (
              <div className="grid flex-1 place-items-center p-6 text-center">
                <div>
                  <div className="text-mono text-[11px] text-muted-foreground">{recipe.length ? "Type or paste input." : "Add a recipe step, then paste input."}</div>
                  <div className="mt-1 text-mono text-[10px] text-muted-foreground/70">Everything runs locally in your browser.</div>
                </div>
              </div>
            )}
            {/* Transformation summary */}
            {output && !error && (
              <div className="border-t border-border/60 px-3 py-1 text-mono text-[10px] text-muted-foreground">
                {recipe.map((id) => OP_BY_ID[id]?.label ?? id).join(" → ") || "passthrough"}
              </div>
            )}
            {/* Step outputs */}
            {stepOutputs.length > 0 && (
              <div className="border-t border-border/60">
                <button
                  onClick={() => setStepDetailsOpen((v) => !v)}
                  className="flex w-full items-center gap-1.5 px-3 py-1 text-left text-mono text-[10px] text-muted-foreground hover:text-foreground"
                >
                  Step outputs ({stepOutputs.length}) {stepDetailsOpen ? "▲" : "▼"}
                </button>
                {stepDetailsOpen && (
                  <div className="max-h-36 overflow-y-auto border-t border-border/40">
                    {stepOutputs.map((s, i) => (
                      <div key={i} className={"border-b border-border/30 px-3 py-1.5 last:border-0 " + (s.status === "failed" ? "bg-destructive/5" : "")}>
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-mono text-[10px] font-bold text-foreground/80">{i + 1}. {s.label}</span>
                          <span className={"text-mono text-[9px] uppercase tracking-widest " + (s.status === "failed" ? "text-destructive" : "text-success")}>{s.status}</span>
                        </div>
                        <pre className="mt-1 max-h-20 overflow-auto whitespace-pre-wrap break-all rounded bg-background/60 p-1.5 text-mono text-[10px] text-foreground/70">{s.output}</pre>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
            {/* Secret scan collapsible */}
            {output && !error && (() => {
              const lines = output.split(/\r?\n/);
              const rules: { name: string; rx: RegExp }[] = [
                { name: "AWS key", rx: /\bAKIA[0-9A-Z]{16}\b/ },
                { name: "GitHub token", rx: /\bghp_[A-Za-z0-9]{20,}\b/ },
                { name: "Stripe key", rx: /\bsk_(live|test)_[A-Za-z0-9]{16,}\b/ },
                { name: "Private key PEM", rx: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
                { name: ".env assign", rx: /^[A-Z][A-Z0-9_]+=[\S]+$/ },
              ];
              const hits: string[] = [];
              lines.forEach((l, i) => rules.forEach((r) => { if (r.rx.test(l)) hits.push(`L${i+1} [${r.name}]`); }));
              return hits.length > 0 ? (
                <div className="border-t border-border/60">
                  <button onClick={() => setSecretScanOpen((v) => !v)} className="flex w-full items-center gap-1.5 px-3 py-1 text-left text-mono text-[10px] text-muted-foreground hover:text-warning">
                    <AlertTriangle className="h-3 w-3 text-warning" /> {hits.length} potential secret{hits.length === 1 ? "" : "s"} {secretScanOpen ? "▲" : "▼"}
                  </button>
                  {secretScanOpen && (
                    <div className="max-h-24 overflow-y-auto border-t border-border/40 px-3 py-1 text-mono text-[10px] text-muted-foreground">
                      {hits.map((h, i) => <div key={i}>{h}</div>)}
                    </div>
                  )}
                </div>
              ) : null;
            })()}
            <div className="flex items-center justify-between border-t border-border/60 px-3 py-1 text-mono text-[10px] text-muted-foreground">
              <span>{recipe.length} op{recipe.length === 1 ? "" : "s"} · local</span>
              <span>{error ? "halted" : output ? "baked" : "idle"}</span>
            </div>
          </section>
        </div>
      </div>
    </PageShell>
  );
}
