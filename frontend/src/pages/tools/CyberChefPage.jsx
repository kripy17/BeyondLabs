import { useEffect, useMemo, useRef, useState } from "react"
import {
  ArrowDown,
  ArrowUp,
  ChevronDown,
  ChevronRight,
  Copy,
  Download,
  Eraser,
  ChefHat,
  FolderOpen,
  Play,
  Save,
  Shuffle,
  Terminal,
  Trash2,
  Upload,
  Wrench,
  X
} from "lucide-react"
import SendToActions from "../../components/investigation/SendToActions"
import AnalystOutputCard from "../../components/investigation/AnalystOutputCard"
import { WorkbenchHeader, WorkbenchPage } from "../../components/layout/WorkbenchShell"
import { scanSecrets, secretMarkdown } from "../../lib/securityTextAnalysis"
import { addTimelineArtifact } from "../../lib/timelineStore"
import { buildCyberChefHandoff, CYBERCHEF_HANDOFF_TARGETS } from "../../lib/cyberchef/artifactRouting"
import {
  analyzePowerShell,
  convertTimestamp,
  decodeJwt,
  parseUrlUtility,
} from "../../api/backend"

const PENDING_ARTIFACT_KEY = "beyondarch.pendingArtifact"

const DEFAULT_FAVOURITES = ["defang", "refang", "extract-iocs", "secret-scan", "extract-urls", "extract-ips", "extract-hashes", "url-decode", "from-base64", "sha256", "powershell-analyze"]

const QUICK_RECIPE_PRESETS = [
  {
    id: "url-decode-iocs",
    label: "URL Decode -> Extract IOCs",
    operations: ["url-decode", "extract-iocs"],
    description: "Decode an encoded URL or payload, then extract indicators.",
    sample: "hxxps%3A%2F%2Flogin.example.com%2Fsecure%3Fnext%3Dhttp%253A%252F%252Fevil.example.net%252Fdrop.exe%20from%208.8.8.8",
  },
  {
    id: "base64-url-iocs",
    label: "Base64 Decode -> Extract URLs",
    operations: ["from-base64", "extract-urls"],
    description: "Decode Base64 text, then isolate URLs.",
    sample: "U3VzcGljaW91cyBsaW5rOiBodHRwczovL2V4YW1wbGUuY29tL2xvZ2luP3U9dGVzdA==",
  },
  {
    id: "base64-powershell",
    label: "Base64 Decode -> PowerShell Analyze",
    operations: ["from-base64", "powershell-analyze"],
    description: "Decode a Base64 command, then statically triage the script without execution.",
    sample: "cG93ZXJzaGVsbCAtTm9QIC1XIEhpZGRlbiAtRW5jb2RlZENvbW1hbmQgU1FCRkFGZ0E=",
  },
  {
    id: "html-url-extract",
    label: "HTML Decode -> Extract URLs",
    operations: ["html-decode", "extract-urls"],
    description: "Decode HTML entities from email or web text, then extract URLs.",
    sample: "Click &lt;a href=&quot;https://example.com/login?token=abc&quot;&gt;secure portal&lt;/a&gt;",
  },
  {
    id: "unicode-ioc-extract",
    label: "Unicode Unescape -> Extract IOCs",
    operations: ["unicode-unescape", "extract-iocs"],
    description: "Decode escaped script text, then pull indicators.",
    sample: "\\u0068\\u0074\\u0074\\u0070\\u0073://example.com/login from 1.1.1.1",
  },
  {
    id: "json-ioc-review",
    label: "JSON Beautify -> Extract IOCs",
    operations: ["json-pretty", "extract-iocs"],
    description: "Make JSON readable, then extract indicators from it.",
    sample: "{\"event\":\"click\",\"url\":\"https://example.com/login\",\"src_ip\":\"8.8.8.8\"}",
  },
  {
    id: "normalize-then-defang",
    label: "Normalize IOC List -> Defang",
    operations: ["normalize-ioc-list", "defang"],
    description: "Clean an IOC list and make it safe for reports or chat.",
    sample: "  EXAMPLE.com\n8.8.8.8\nexample.com\nHTTPS://Example.com/login",
  },
  {
    id: "redact-then-defang",
    label: "Regex Redact -> Defang",
    operations: ["regex-redact", "defang"],
    description: "Redact sensitive values, then make remaining indicators safe.",
    sample: "User admin@example.com clicked https://example.com/login from 8.8.8.8",
  },
  {
    id: "jwt-decode",
    label: "JWT Decode",
    operations: ["jwt-decode"],
    description: "Decode JWT header and payload. Signature trust is not verified.",
    sample: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IktyaXNoIFBhdGVsIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature",
  },
  {
    id: "parse-url",
    label: "Parse URL",
    operations: ["parse-url"],
    description: "Break a URL into host, path, query parameters, and related parts.",
    sample: "https://example.com/login?user=test&id=7",
  },
  {
    id: "hex-decode-extract",
    label: "Hex Decode -> Extract IOCs",
    operations: ["from-hex", "extract-iocs"],
    description: "Decode hex-encoded text, then extract indicators.",
    sample: "68747470733a2f2f6578616d706c652e636f6d2f6c6f67696e",
  },
  {
    id: "extract-ips-clean",
    label: "Extract IPs -> Sort -> Unique",
    operations: ["extract-ips", "sort-lines", "unique-lines"],
    description: "Pull unique sorted IP addresses from messy logs or blacklists.",
    sample: "10.0.0.2\n10.0.0.1\n10.0.0.1\n10.0.0.3",
  },
  {
    id: "extract-cves-sort",
    label: "Extract CVEs -> Sort -> Unique",
    operations: ["extract-cves", "sort-lines", "unique-lines"],
    description: "Pull unique sorted CVE references from advisory or changelog text.",
    sample: "CVE-2024-1234\nFixed CVE-2024-5678 and CVE-2024-1234\nCVE-2023-9999",
  },
  {
    id: "defang-normalize-ioc",
    label: "Defang -> Normalize IOCs",
    operations: ["defang", "normalize-ioc-list"],
    description: "Defang indicators then normalize the IOC list.",
    sample: "  http://example.com/login\nExample.com\nhttps://example.com\n",
  },
  {
    id: "base64-hex-decode",
    label: "Base64 -> Hex -> Decode",
    operations: ["from-base64", "from-hex"],
    description: "Decode Base64-wrapped hex payload (common in encoded scripts).",
    sample: "NDg2NTczNzA3Mzc0NzM3YTY1NzI3MzNhMmYyZjY1NzgyNjE2ZDcwNmMyZTY3NzI2Zg==",
  },
  {
    id: "url-decode-parse",
    label: "URL Decode -> Parse URL",
    operations: ["url-decode", "parse-url"],
    description: "Decode then structurally analyze a URL for phishing or C2 review.",
    sample: "https%3A%2F%2Fevil.example.com%2F%2Fgate.php%3Fid%3D1234",
  },
  {
    id: "timestamp-format",
    label: "Timestamp Convert",
    operations: ["timestamp"],
    description: "Convert epoch/unix timestamps to human-readable format.",
    sample: "1735689600\n1700000000",
  },
  {
    id: "powershell-defang-iocs",
    label: "PS Decode -> Extract IOCs -> Defang",
    operations: ["from-base64", "powershell-analyze", "extract-iocs", "defang"],
    description: "Decode Base64 PowerShell, triage the script, extract indicators, and defang them.",
    sample: "JHVybCA9ICJodHRwczovL2V4YW1wbGUuY29tL2Ryb3AuZXhlIjtfaW52b2tlLVdlYlJlcXVlc3QgJHVybCAtT3V0RmlsZSBDOlx0ZW1wX3BheWxvYWQuZXhl",
  },
  {
    id: "multi-base64-round",
    label: "Multi-layer Base64 Decode",
    operations: ["from-base64", "from-base64", "from-base64"],
    description: "Decode three layers of Base64 (common malware evasion pattern).",
    sample: "UjBsR09EbGhMMkIxWkdsdVp6MGlNakF5TlRZaUxDSmhiR2NpT2lKaGQj",
  },
]

const RECIPE_MITRE_MAP = {
  "url-decode-iocs": "T1595 (Active Scanning)",
  "base64-url-iocs": "T1059 (Command and Scripting Interpreter)",
  "base64-powershell": "T1059.001 (PowerShell)",
  "html-url-extract": "T1566 (Phishing)",
  "unicode-ioc-extract": "T1059 (Command and Scripting Interpreter)",
  "json-ioc-review": "T1595 (Active Scanning)",
  "jwt-decode": "T1078 (Valid Accounts)",
  "parse-url": "T1566 (Phishing)",
  "hex-decode-extract": "T1059 (Command and Scripting Interpreter)",
  "extract-ips-clean": "T1046 (Network Service Discovery)",
  "extract-cves-sort": "T1595 (Active Scanning)",
  "timestamp-format": "T1595 (Active Scanning)",
}

const BASE_CATEGORIES = [
  {
    id: "favourites",
    label: "Favourites",
    operations: DEFAULT_FAVOURITES,
  },
  {
    id: "all",
    label: "All Operations",
    operations: null,
  },
  {
    id: "ioc",
    label: "IOC Safe Handling",
    operations: ["defang", "refang", "extract-iocs", "extract-urls", "extract-ips", "extract-domains", "extract-emails", "extract-hashes", "normalize-ioc-list"],
  },
  {
    id: "encodings",
    label: "Encodings",
    operations: ["to-base64", "from-base64", "to-base64url", "from-base64url", "to-hex", "from-hex", "to-binary", "from-binary", "to-charcode", "from-charcode", "url-encode", "url-decode", "html-encode", "html-decode", "unicode-escape", "unicode-unescape", "rot13"],
  },
  {
    id: "web",
    label: "Web",
    operations: ["parse-url", "jwt-decode"],
  },
  {
    id: "data",
    label: "Data Format",
    operations: ["json-pretty", "json-minify", "timestamp", "sort-lines", "unique-lines", "remove-empty-lines"],
  },
  {
    id: "text",
    label: "Text",
    operations: ["uppercase", "lowercase", "reverse", "trim-lines", "remove-whitespace", "count", "escape-regex", "regex-extract", "regex-redact"],
  },
  {
    id: "hashing",
    label: "Hashing",
    operations: ["hash-identify", "sha1", "sha256", "sha384", "sha512"],
  },
  {
    id: "triage",
    label: "Script Triage",
    operations: ["secret-scan", "powershell-analyze", "windows-cmdline-parse", "linux-auth-summary", "user-agent-classify"],
  },
]

const OPERATIONS = [
  {
    id: "defang",
    label: "Defang",
    category: "ioc",
    description: "Make URLs, domains, IPs, and emails safe for reports, tickets, and chat.",
    placeholder: "https://example.com/login?user=test\nuser@example.com\n8.8.8.8",
  },
  {
    id: "refang",
    label: "Refang",
    category: "ioc",
    description: "Convert defanged indicators back into analyst-usable values.",
    placeholder: "hxxps[:]//example[.]com/login\nuser[@]example[.]com\n8[.]8[.]8[.]8",
  },
  {
    id: "extract-iocs",
    label: "Extract IOCs",
    category: "ioc",
    description: "Extract URLs, IPs, domains, emails, and MD5/SHA1/SHA256 hashes from text.",
    placeholder: "Suspicious URL https://example.com/login from 8.8.8.8 with hash 44d88612fea8a8f36de82e1278abb02f",
  },
  {
    id: "extract-urls",
    label: "Extract URLs",
    category: "ioc",
    description: "Return unique HTTP and HTTPS URLs from pasted text.",
    placeholder: "Click https://example.com/login and http://test.local/path",
  },
  {
    id: "extract-ips",
    label: "Extract IPs",
    category: "ioc",
    description: "Return unique IPv4 addresses from pasted text.",
    placeholder: "Failed login from 8.8.8.8 and 1.1.1.1",
  },
  {
    id: "extract-domains",
    label: "Extract Domains",
    category: "ioc",
    description: "Return unique domain-like values from pasted text.",
    placeholder: "Contact login.example.com or cdn.example.net",
  },
  {
    id: "extract-emails",
    label: "Extract Emails",
    category: "ioc",
    description: "Return unique email addresses from pasted text.",
    placeholder: "From: user@example.com Reply-To: admin@example.net",
  },
  {
    id: "extract-hashes",
    label: "Extract Hashes",
    category: "ioc",
    description: "Return unique MD5, SHA1, and SHA256-looking hashes from pasted text.",
    placeholder: "44d88612fea8a8f36de82e1278abb02f",
  },
  {
    id: "secret-scan",
    label: "Secret Scan",
    category: "triage",
    description: "Scan pasted code or text for API keys, private keys, GitHub tokens, AWS-like keys, .env assignments, and high-entropy strings.",
    placeholder: "API_KEY=sk_test_exampleexampleexample\nGITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
  },
  {
    id: "to-base64",
    label: "To Base64",
    category: "encodings",
    description: "Encode text as Base64.",
    placeholder: "admin:password",
  },
  {
    id: "from-base64",
    label: "From Base64",
    category: "encodings",
    description: "Decode Base64 text. Useful for suspicious payloads and command fragments.",
    placeholder: "YWRtaW46cGFzc3dvcmQ=",
  },
  {
    id: "to-base64url",
    label: "To Base64URL",
    category: "encodings",
    description: "Encode text as URL-safe Base64 without padding.",
    placeholder: "admin:password",
  },
  {
    id: "from-base64url",
    label: "From Base64URL",
    category: "encodings",
    description: "Decode URL-safe Base64, common in JWT segments and web tokens.",
    placeholder: "YWRtaW46cGFzc3dvcmQ",
  },
  {
    id: "to-hex",
    label: "To Hex",
    category: "encodings",
    description: "Convert text into hexadecimal bytes.",
    placeholder: "Hello",
  },
  {
    id: "from-hex",
    label: "From Hex",
    category: "encodings",
    description: "Convert hexadecimal bytes back to text.",
    placeholder: "48656c6c6f",
  },
  {
    id: "to-binary",
    label: "To Binary",
    category: "encodings",
    description: "Convert text to 8-bit binary byte groups.",
    placeholder: "Hello",
  },
  {
    id: "from-binary",
    label: "From Binary",
    category: "encodings",
    description: "Convert 8-bit binary byte groups back to text.",
    placeholder: "01001000 01100101 01101100 01101100 01101111",
  },
  {
    id: "to-charcode",
    label: "To Charcode",
    category: "encodings",
    description: "Convert text to decimal character codes.",
    placeholder: "ABC",
  },
  {
    id: "from-charcode",
    label: "From Charcode",
    category: "encodings",
    description: "Convert decimal character codes back to text.",
    placeholder: "65 66 67",
  },
  {
    id: "url-encode",
    label: "URL Encode",
    category: "encodings",
    description: "Percent-encode text for URL-safe transport.",
    placeholder: "https://example.com/login?a=1&b=test",
  },
  {
    id: "url-decode",
    label: "URL Decode",
    category: "encodings",
    description: "Decode percent-encoded URLs and parameters.",
    placeholder: "https%3A%2F%2Fexample.com%2Flogin%3Fa%3D1",
  },
  {
    id: "html-encode",
    label: "HTML Entity Encode",
    category: "encodings",
    description: "Encode HTML-sensitive characters as entities.",
    placeholder: '<script>alert("x")</script>',
  },
  {
    id: "html-decode",
    label: "HTML Entity Decode",
    category: "encodings",
    description: "Decode HTML entities found in emails, pages, or payloads.",
    placeholder: "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;",
  },
  {
    id: "unicode-escape",
    label: "Unicode Escape",
    category: "encodings",
    description: "Convert non-ASCII characters to JavaScript-style Unicode escapes.",
    placeholder: "hello π",
  },
  {
    id: "unicode-unescape",
    label: "Unicode Unescape",
    category: "encodings",
    description: "Decode JavaScript-style Unicode escape sequences.",
    placeholder: "hello \\u03c0",
  },
  {
    id: "rot13",
    label: "ROT13",
    category: "encodings",
    description: "Apply ROT13 substitution for simple obfuscation review.",
    placeholder: "uggcf://rknzcyr.pbz",
  },
  {
    id: "parse-url",
    label: "Parse URL",
    category: "web",
    description: "Break a URL into scheme, host, path, query values, and related parts.",
    placeholder: "https://example.com/login?user=test&id=7",
  },
  {
    id: "jwt-decode",
    label: "JWT Decode",
    category: "web",
    description: "Decode JWT header and payload. This does not verify signature trust.",
    placeholder: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature",
  },
  {
    id: "json-pretty",
    label: "JSON Beautify",
    category: "data",
    description: "Pretty-print JSON for readable notes and review.",
    placeholder: '{"event":"login","src_ip":"8.8.8.8"}',
  },
  {
    id: "json-minify",
    label: "JSON Minify",
    category: "data",
    description: "Remove whitespace from JSON while preserving its structure.",
    placeholder: '{\n  "event": "login",\n  "src_ip": "8.8.8.8"\n}',
  },
  {
    id: "timestamp",
    label: "Timestamp",
    category: "data",
    description: "Convert Unix timestamps and ISO datetime strings for timeline work.",
    placeholder: "1710000000",
  },
  {
    id: "sort-lines",
    label: "Sort Lines",
    category: "data",
    description: "Sort lines alphabetically.",
    placeholder: "beta\nalpha\ngamma",
  },
  {
    id: "unique-lines",
    label: "Unique Lines",
    category: "data",
    description: "Remove duplicate lines while preserving first-seen order.",
    placeholder: "8.8.8.8\n1.1.1.1\n8.8.8.8",
  },
  {
    id: "remove-empty-lines",
    label: "Remove Empty Lines",
    category: "data",
    description: "Remove blank lines from pasted text.",
    placeholder: "line one\n\nline two",
  },
  {
    id: "uppercase",
    label: "To Uppercase",
    category: "text",
    description: "Convert text to uppercase.",
    placeholder: "Hello World",
  },
  {
    id: "lowercase",
    label: "To Lowercase",
    category: "text",
    description: "Convert text to lowercase.",
    placeholder: "Hello World",
  },
  {
    id: "reverse",
    label: "Reverse",
    category: "text",
    description: "Reverse the full text string.",
    placeholder: "stressed",
  },
  {
    id: "trim-lines",
    label: "Trim Lines",
    category: "text",
    description: "Trim leading and trailing whitespace from every line.",
    placeholder: "  alpha  \n  beta  ",
  },
  {
    id: "remove-whitespace",
    label: "Remove Whitespace",
    category: "text",
    description: "Remove all whitespace characters.",
    placeholder: "a b\tc\nd",
  },
  {
    id: "count",
    label: "Count",
    category: "text",
    description: "Count characters, words, lines, and bytes.",
    placeholder: "one two\nthree",
  },
  {
    id: "escape-regex",
    label: "Escape Regex",
    category: "text",
    description: "Escape text so it can be safely pasted into a regular expression.",
    placeholder: "https://example.com/login?a=1",
  },
  {
    id: "regex-extract",
    label: "Regex Extract",
    category: "text",
    description: "Extract common SOC regex hits: IPv4s, URLs, emails, hashes, CVEs, and Windows Event IDs.",
    placeholder: "Alert from 8.8.8.8 hit https://example.com/login with CVE-2024-1234 and EventID 4625",
  },
  {
    id: "regex-redact",
    label: "Regex Redact",
    category: "text",
    description: "Redact common sensitive values such as IPs, emails, URLs, and hashes for sharing notes.",
    placeholder: "User admin@example.com clicked https://example.com/login from 8.8.8.8",
  },
  {
    id: "sha1",
    label: "SHA1",
    category: "hashing",
    description: "Generate a SHA-1 hash using browser crypto.",
    placeholder: "hello",
  },
  {
    id: "hash-identify",
    label: "Hash Identify",
    category: "hashing",
    description: "Identify likely hash formats by length, charset, and common prefixes.",
    placeholder: "44d88612fea8a8f36de82e1278abb02f\n$2b$12$abcdefghijklmnopqrstuuYj8Yjk9e9r5xDxEXAMPLEEXAMPLE",
  },
  {
    id: "sha256",
    label: "SHA256",
    category: "hashing",
    description: "Generate a SHA-256 hash using browser crypto.",
    placeholder: "hello",
  },
  {
    id: "sha384",
    label: "SHA384",
    category: "hashing",
    description: "Generate a SHA-384 hash using browser crypto.",
    placeholder: "hello",
  },
  {
    id: "sha512",
    label: "SHA512",
    category: "hashing",
    description: "Generate a SHA-512 hash using browser crypto.",
    placeholder: "hello",
  },
  {
    id: "powershell-analyze",
    label: "PowerShell Analyze",
    category: "triage",
    description: "Decode and statically review suspicious PowerShell commands. Commands are not executed.",
    placeholder: "powershell -NoP -EncodedCommand SQBFAFgA",
  },
  {
    id: "windows-cmdline-parse",
    label: "Windows Command Parse",
    category: "triage",
    description: "Parse a Windows command line into executable, arguments, suspicious flags, and LOLBin hints.",
    placeholder: 'powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA',
  },
  {
    id: "linux-auth-summary",
    label: "Linux Auth Summary",
    category: "triage",
    description: "Summarize Linux auth/SSH log lines for failed passwords, invalid users, accepted logins, and source IPs.",
    placeholder: "Jan 12 10:01:02 host sshd[123]: Failed password for invalid user admin from 8.8.8.8 port 44221 ssh2\nJan 12 10:03:10 host sshd[124]: Accepted password for root from 1.1.1.1 port 55910 ssh2",
  },
  {
    id: "user-agent-classify",
    label: "User-Agent Classify",
    category: "triage",
    description: "Classify common user-agent strings as browser, crawler, CLI tool, library, suspicious, or unknown.",
    placeholder: "Mozilla/5.0\ncurl/8.1.2\npython-requests/2.31\nsqlmap/1.7",
  },
  {
    id: "normalize-ioc-list",
    label: "Normalize IOC List",
    category: "triage",
    description: "Trim, lowercase, deduplicate, sort, and remove blank lines from IOC lists.",
    placeholder: "  EXAMPLE.com\n8.8.8.8\nexample.com\n\nHTTPS://Example.com/login",
  },
]

const OPERATION_BY_ID = Object.fromEntries(OPERATIONS.map((operation) => [operation.id, operation]))
const SAVED_RECIPE_KEY = "beyondarch_cyberchef_recipe_v1"
const SAVED_FAVOURITES_KEY = "beyondarch_cyberchef_favourites_v1"
const EMPTY_RECIPE_INPUT_PLACEHOLDER = "Paste input here, or drag and drop a file."
const EMPTY_RECIPE_OUTPUT_PLACEHOLDER = "Add recipe steps to preview the expected output."
const OUTPUT_PLACEHOLDER_BY_OPERATION = {
  defang: "hxxps[:]//example[.]com/login?user=test\nuser[@]example[.]com\n8[.]8[.]8[.]8",
  refang: "https://example.com/login\nuser@example.com\n8.8.8.8",
  "extract-iocs": "URLs\nhttps://example.com/login\n\nIPs\n8.8.8.8\n\nHashes\n44d88612fea8a8f36de82e1278abb02f",
  "extract-urls": "https://example.com/login\nhttp://test.local/path",
  "extract-ips": "8.8.8.8\n1.1.1.1",
  "extract-domains": "login.example.com\ncdn.example.net",
  "extract-emails": "user@example.com\nadmin@example.net",
  "extract-hashes": "44d88612fea8a8f36de82e1278abb02f",
  "secret-scan": "Line 1: API key-like value\nLine 2: GitHub token-like value",
  "to-base64": "YWRtaW46cGFzc3dvcmQ=",
  "from-base64": "admin:password",
  "to-base64url": "YWRtaW46cGFzc3dvcmQ",
  "from-base64url": "admin:password",
  "to-hex": "48656c6c6f",
  "from-hex": "Hello",
  "to-binary": "01001000 01100101 01101100 01101100 01101111",
  "from-binary": "Hello",
  "to-charcode": "65 66 67",
  "from-charcode": "ABC",
  "url-encode": "https%3A%2F%2Fexample.com%2Flogin%3Fa%3D1%26b%3Dtest",
  "url-decode": "https://example.com/login?a=1",
  "html-encode": "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;",
  "html-decode": "<script>alert(\"x\")</script>",
  "unicode-escape": "hello \\u03c0",
  "unicode-unescape": "hello pi",
  rot13: "https://example.com",
  "parse-url": "Scheme: https\nHost: example.com\nPath: /login\nQuery: user=test, id=7",
  "jwt-decode": "{\n  \"alg\": \"HS256\",\n  \"typ\": \"JWT\"\n}\n\n{\n  \"sub\": \"1234567890\",\n  \"name\": \"John Doe\"\n}",
  "json-pretty": "{\n  \"event\": \"login\",\n  \"src_ip\": \"8.8.8.8\"\n}",
  "json-minify": "{\"event\":\"login\",\"src_ip\":\"8.8.8.8\"}",
  timestamp: "2024-03-09T16:00:00.000Z",
  "sort-lines": "alpha\nbeta\ngamma",
  "unique-lines": "8.8.8.8\n1.1.1.1",
  "remove-empty-lines": "line one\nline two",
  uppercase: "HELLO WORLD",
  lowercase: "hello world",
  reverse: "desserts",
  "trim-lines": "alpha\nbeta",
  "remove-whitespace": "abcd",
  count: "Characters: 13\nWords: 3\nLines: 2",
  "escape-regex": "https:\\/\\/example\\.com\\/login\\?a=1",
  "regex-extract": "IPv4: 8.8.8.8\nURL: https://example.com/login\nCVE: CVE-2024-1234\nEvent ID: 4625",
  "regex-redact": "User [EMAIL] clicked [URL] from [IP]",
  "hash-identify": "44d88612fea8a8f36de82e1278abb02f -> MD5-like, 32 hex chars",
  sha1: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
  sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  sha384: "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f",
  sha512: "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
  "powershell-analyze": "Signals\n- No profile flag\n- EncodedCommand flag\n- Hidden window flag",
  "windows-cmdline-parse": "Executable: powershell.exe\nArguments: -NoP -W Hidden -EncodedCommand SQBFAFgA\nSignals: encoded command, hidden window",
  "linux-auth-summary": "Failed logins: 1\nInvalid users: admin\nSource IPs: 8.8.8.8",
  "user-agent-classify": "curl/8.1.2 -> CLI tool\npython-requests/2.31 -> automation library\nsqlmap/1.7 -> suspicious automation",
  "normalize-ioc-list": "8.8.8.8\nexample.com\nhttps://example.com/login",
}

function outputPlaceholderFor(operationId) {
  return OUTPUT_PLACEHOLDER_BY_OPERATION[operationId] || "Example output will appear here after baking."
}

function createRecipeStep(operationId, options = {}) {
  return {
    id: `${operationId}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    operationId,
    options,
  }
}

function getStepOperationId(step) {
  return typeof step === "string" ? step : step?.operationId
}

function getStepOptions(step) {
  return typeof step === "string" ? {} : step?.options || {}
}

function normalizeRecipeItems(importedRecipe) {
  if (!Array.isArray(importedRecipe)) return []

  return importedRecipe
    .map((item) => {
      const operationId = typeof item === "string" ? item : item?.operationId || item?.id || item?.operation
      if (!OPERATION_BY_ID[operationId]) return null
      return createRecipeStep(operationId, typeof item === "string" ? {} : item?.options || {})
    })
    .filter(Boolean)
}

function serializeRecipe(recipe) {
  return recipe.map((step) => ({
    operationId: getStepOperationId(step),
    options: getStepOptions(step),
  }))
}

function outputSignatureFor(input, recipe) {
  return JSON.stringify({
    input,
    recipe: serializeRecipe(recipe),
  })
}

function operationForInitialMode(initialMode) {
  const modeMap = {
    defang: "defang",
    "base64-decode": "from-base64",
    "base64-encode": "to-base64",
    "url-decode": "url-decode",
    "url-encode": "url-encode",
    "url-parse": "parse-url",
    jwt: "jwt-decode",
    timestamp: "timestamp",
    powershell: "powershell-analyze",
  }

  return modeMap[initialMode] || initialMode || "defang"
}

function defang(value) {
  return value
    .replaceAll("http://", "hxxp[:]//")
    .replaceAll("https://", "hxxps[:]//")
    .replaceAll(".", "[.]")
    .replaceAll("@", "[@]")
}

function refang(value) {
  return value
    .replaceAll("hxxp[:]//", "http://")
    .replaceAll("hxxps[:]//", "https://")
    .replaceAll("[.]", ".")
    .replaceAll("[@]", "@")
    .replace(/\b(\d{1,3})\[\.\](\d{1,3})\[\.\](\d{1,3})\[\.\](\d{1,3})\b/g, "$1.$2.$3.$4")
}

function toHex(value, options = {}) {
  const delimiter = options.delimiter || ""
  const casing = options.case || "lower"
  const prefix = options.prefix || ""
  const hex = Array.from(new TextEncoder().encode(value))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .map((item) => casing === "upper" ? item.toUpperCase() : item)

  return hex.map((item) => `${prefix}${item}`).join(delimiter)
}

function fromHex(value) {
  const cleaned = value.replace(/[^a-fA-F0-9]/g, "")
  if (cleaned.length % 2 !== 0) throw new Error("Hex input must contain an even number of characters.")

  const bytes = cleaned.match(/.{1,2}/g).map((item) => parseInt(item, 16))
  return new TextDecoder().decode(new Uint8Array(bytes))
}

function htmlEncode(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;")
}

function htmlDecode(value) {
  const textarea = document.createElement("textarea")
  textarea.innerHTML = value
  return textarea.value
}

function rot13(value, options = {}) {
  const rotation = Number(options.rotation || 13)
  return value.replace(/[a-zA-Z]/g, (char) => {
    const base = char <= "Z" ? 65 : 97
    return String.fromCharCode(((char.charCodeAt(0) - base + rotation) % 26) + base)
  })
}

function uniqueItems(items) {
  return [...new Set(items)]
}

function wrapText(value, lineLength) {
  const size = Number(lineLength || 0)
  if (!size || size < 1) return value
  return value.match(new RegExp(`.{1,${size}}`, "g"))?.join("\n") || value
}

function toBase64(value, options = {}) {
  let encoded = btoa(unescape(encodeURIComponent(value)))

  if (options.alphabet === "url") {
    encoded = encoded.replaceAll("+", "-").replaceAll("/", "_")
  }

  if (options.padding === false) {
    encoded = encoded.replace(/=+$/g, "")
  }

  return wrapText(encoded, options.lineLength)
}

function fromBase64(value, options = {}) {
  const compact = options.keepWhitespace ? value : value.replace(/\s+/g, "")
  const normalized = compact.trim().replaceAll("-", "+").replaceAll("_", "/")
  const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), "=")
  return decodeURIComponent(escape(atob(padded)))
}

function toBase64Url(value) {
  return toBase64(value, { alphabet: "url", padding: false })
}

function fromBase64Url(value) {
  return fromBase64(value)
}

function toBinary(value, options = {}) {
  const delimiter = options.delimiter ?? " "
  return Array.from(new TextEncoder().encode(value))
    .map((byte) => byte.toString(2).padStart(8, "0"))
    .join(delimiter)
}

function fromBinary(value) {
  const bytes = value.match(/[01]{8}/g) || []
  if (!bytes.length) throw new Error("Binary input must contain 8-bit byte groups.")

  return new TextDecoder().decode(new Uint8Array(bytes.map((byte) => parseInt(byte, 2))))
}

function toCharcode(value, options = {}) {
  const delimiter = options.delimiter ?? " "
  const base = Number(options.base || 10)

  return Array.from(value).map((char) => {
    const code = char.codePointAt(0)
    if (base === 16) return `${options.prefix === false ? "" : "0x"}${code.toString(16)}`
    return String(code)
  }).join(delimiter)
}

function fromCharcode(value, options = {}) {
  const base = Number(options.base || 10)
  const codes = base === 16
    ? value.match(/(?:0x)?[0-9a-fA-F]+/g) || []
    : value.match(/\d+/g) || []
  if (!codes.length) throw new Error("Charcode input must contain character codes.")

  return codes.map((code) => String.fromCodePoint(parseInt(code.replace(/^0x/i, ""), base))).join("")
}

function unicodeEscape(value, options = {}) {
  return Array.from(value)
    .map((char) => {
      const code = char.codePointAt(0)
      if (!options.allCharacters && code < 128) return char
      const hex = code.toString(16).padStart(4, "0")
      const formatted = options.uppercase ? hex.toUpperCase() : hex
      if (code <= 0xffff) return `\\u${formatted}`
      return `\\u{${options.uppercase ? code.toString(16).toUpperCase() : code.toString(16)}}`
    })
    .join("")
}

function unicodeUnescape(value) {
  return value
    .replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, code) => String.fromCodePoint(parseInt(code, 16)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, code) => String.fromCharCode(parseInt(code, 16)))
}

function sortLines(value, options = {}) {
  const lines = value.split(/\r?\n/)
  const sorted = lines.sort((a, b) => {
    const left = options.caseSensitive ? a : a.toLowerCase()
    const right = options.caseSensitive ? b : b.toLowerCase()
    return left.localeCompare(right)
  })

  return (options.reverse ? sorted.reverse() : sorted).join("\n")
}

function uniqueLines(value, options = {}) {
  const seen = new Set()
  const lines = []

  value.split(/\r?\n/).forEach((line) => {
    const key = options.caseSensitive ? line : line.toLowerCase()
    if (seen.has(key)) return
    seen.add(key)
    lines.push(line)
  })

  return lines.join("\n")
}

function removeEmptyLines(value) {
  return value.split(/\r?\n/).filter((line) => line.trim()).join("\n")
}

function trimLines(value) {
  return value.split(/\r?\n/).map((line) => line.trim()).join("\n")
}

function countText(value) {
  const trimmed = value.trim()

  return {
    characters: Array.from(value).length,
    bytes_utf8: new TextEncoder().encode(value).length,
    words: trimmed ? trimmed.split(/\s+/).length : 0,
    lines: value ? value.split(/\r?\n/).length : 0,
  }
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

function regexExtract(value, options = {}) {
  const patterns = {
    ipv4: /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g,
    urls: /https?:\/\/[^\s"'<>]+/gi,
    emails: /\b[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+\b/g,
    hashes: /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g,
    cves: /\bCVE-\d{4}-\d{4,7}\b/gi,
    windows_event_ids: /\b(?:4624|4625|4688|4672|1102|7045|4720|4726|4732)\b/g,
  }

  const selected = options.types || Object.keys(patterns)

  return Object.fromEntries(
    Object.entries(patterns).map(([key, pattern]) => [key, uniqueItems(value.match(pattern) || [])])
      .filter(([key]) => selected.includes(key))
  )
}

function regexRedact(value, options = {}) {
  const replacement = options.replacement || "[REDACTED]"

  return value
    .replace(/https?:\/\/[^\s"'<>]+/gi, replacement)
    .replace(/\b[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+\b/g, replacement)
    .replace(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g, replacement)
    .replace(/\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g, replacement)
}

async function hashText(value, algorithm, options = {}) {
  const digest = await crypto.subtle.digest(algorithm, new TextEncoder().encode(value))
  const hash = Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")

  return options.case === "upper" ? hash.toUpperCase() : hash
}

function identifyHashLocal(value = "") {
  return value.split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean)
    .map((hash) => {
      const lowered = hash.toLowerCase()
      const hex = /^[a-f0-9]+$/i.test(hash)
      let type = "Unknown / unsupported"
      let confidence = "Low"
      let reason = "No local length, charset, or prefix rule matched."

      if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(hash)) {
        type = "bcrypt"
        confidence = "High"
        reason = "bcrypt-style $2a/$2b/$2y prefix and length."
      } else if (/^\$argon2(?:id|i|d)\$/i.test(hash)) {
        type = "Argon2"
        confidence = "High"
        reason = "Argon2 prefix detected."
      } else if (/^\$pbkdf2/i.test(hash) || /pbkdf2/i.test(hash)) {
        type = "PBKDF2-like"
        confidence = "Medium"
        reason = "PBKDF2 marker detected."
      } else if (/^\$1\$/.test(hash)) {
        type = "Unix md5crypt"
        confidence = "High"
        reason = "$1$ Unix crypt prefix."
      } else if (/^\$5\$/.test(hash)) {
        type = "Unix sha256crypt"
        confidence = "High"
        reason = "$5$ Unix crypt prefix."
      } else if (/^\$6\$/.test(hash)) {
        type = "Unix sha512crypt"
        confidence = "High"
        reason = "$6$ Unix crypt prefix."
      } else if (hex && hash.length === 32) {
        type = "MD5 or NTLM-like"
        confidence = "Medium"
        reason = "32 hexadecimal characters. MD5 and NTLM are ambiguous without context."
      } else if (hex && hash.length === 40) {
        type = "SHA1"
        confidence = "High"
        reason = "40 hexadecimal characters."
      } else if (hex && hash.length === 56) {
        type = "SHA224"
        confidence = "High"
        reason = "56 hexadecimal characters."
      } else if (hex && hash.length === 64) {
        type = "SHA256"
        confidence = "High"
        reason = "64 hexadecimal characters."
      } else if (hex && hash.length === 96) {
        type = "SHA384"
        confidence = "High"
        reason = "96 hexadecimal characters."
      } else if (hex && hash.length === 128) {
        type = "SHA512"
        confidence = "High"
        reason = "128 hexadecimal characters."
      } else if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(hash)) {
        type = "JWT-like token"
        confidence = "Medium"
        reason = "Three Base64URL-like segments separated by dots."
      } else if (/^[A-Za-z0-9+/=_-]{24,}$/.test(hash)) {
        type = "Base64-looking value"
        confidence = "Low"
        reason = "Long Base64-like character set. May be encoded data rather than a hash."
      }

      return {
        input: hash,
        normalized: lowered,
        likely_type: type,
        confidence,
        reason,
        limitations: "Local format identification only. Hash type can be ambiguous without algorithm/source context.",
      }
    })
}

function extractIocsLocal(value, options = {}) {
  const urls = value.match(/https?:\/\/[^\s"'<>]+/gi) || []
  const ips = value.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g) || []
  const emails = value.match(/\b[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+\b/g) || []
  const hashes = value.match(/\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g) || []
  const domains = value.match(/\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}\b/g) || []
  const uniqueEmails = [...new Set(emails)]

  const result = {
    summary: {
      urls: new Set(urls).size,
      ips: new Set(ips).size,
      emails: uniqueEmails.length,
      domains: new Set(domains).size,
      hashes: new Set(hashes).size
    },
    iocs: {
      urls: [...new Set(urls)],
      ips: [...new Set(ips)],
      emails: uniqueEmails,
      domains: [...new Set(domains)].filter((domain) => !uniqueEmails.some((email) => email.endsWith(`@${domain}`))),
      hashes: [...new Set(hashes)]
    }
  }

  const include = options.include || ["urls", "ips", "emails", "domains", "hashes"]
  result.iocs = Object.fromEntries(Object.entries(result.iocs).filter(([key]) => include.includes(key)))
  result.summary = Object.fromEntries(Object.entries(result.summary).filter(([key]) => include.includes(key)))

  return result
}

function cyberChefMarkdownSummary({ sourceText, output, recipe, iocs, secrets }) {
  const recipeLabels = recipe.map((step) => OPERATION_BY_ID[getStepOperationId(step)]?.label || getStepOperationId(step))
  const lines = [
    "# CyberChef Analyst Summary",
    "",
    "## Summary",
    `- Recipe: ${recipeLabels.length ? recipeLabels.join(" -> ") : "Empty"}`,
    `- Input characters: ${sourceText.length}`,
    `- Output characters: ${output.length}`,
    "- Method: local/browser transformation pipeline where possible",
    "- Limitations: JWT decode does not verify trust/signature. Static triage helpers do not execute scripts or commands.",
    "",
    "## Extracted IOCs",
  ]

  Object.entries(iocs.iocs || {}).forEach(([type, values]) => {
    lines.push(`- ${type}: ${values.length ? values.join(", ") : "None"}`)
  })
  lines.push("", secretMarkdown(secrets))
  return lines.join("\n")
}

function extractSingleIocType(value, type, options = {}) {
  const iocs = extractIocsLocal(value, options).iocs
  return (iocs[type] || []).join("\n")
}

function parseWindowsCommandLine(value) {
  const tokens = value.match(/"[^"]+"|'[^']+'|\S+/g) || []
  const executable = tokens[0] || ""
  const lowered = value.toLowerCase()
  const lolbins = ["powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "wscript", "cscript", "certutil", "bitsadmin", "wmic"]
  const suspiciousFlags = ["-enc", "-encodedcommand", "-nop", "-w hidden", "-windowstyle hidden", "/c", "downloadstring", "iex", "bypass"]

  return {
    executable,
    arguments: tokens.slice(1),
    token_count: tokens.length,
    lolbin_hits: lolbins.filter((item) => lowered.includes(item)),
    suspicious_flags: suspiciousFlags.filter((item) => lowered.includes(item)),
    note: "Static parsing only. Review context before deciding maliciousness.",
  }
}

function summarizeLinuxAuth(value) {
  const lines = value.split(/\r?\n/).filter(Boolean)
  const ips = uniqueItems(lines.flatMap((line) => line.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g) || []))
  const invalidUsers = uniqueItems(lines.map((line) => line.match(/invalid user\s+(\S+)/i)?.[1]).filter(Boolean))

  return {
    total_lines: lines.length,
    failed_password: lines.filter((line) => /failed password/i.test(line)).length,
    accepted_login: lines.filter((line) => /accepted (password|publickey)/i.test(line)).length,
    invalid_user: lines.filter((line) => /invalid user/i.test(line)).length,
    root_mentions: lines.filter((line) => /\broot\b/i.test(line)).length,
    source_ips: ips,
    invalid_users: invalidUsers,
  }
}

function classifyUserAgents(value) {
  return value.split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((ua) => {
      const lowered = ua.toLowerCase()
      let type = "unknown"
      if (/sqlmap|nikto|nmap|masscan|acunetix|nessus|burp/.test(lowered)) type = "suspicious_scanner"
      else if (/curl|wget|httpie/.test(lowered)) type = "cli_tool"
      else if (/python-requests|go-http-client|java|okhttp|libwww/.test(lowered)) type = "library_client"
      else if (/bot|crawler|spider|slurp/.test(lowered)) type = "crawler"
      else if (/mozilla|chrome|safari|firefox|edge/.test(lowered)) type = "browser"

      return { user_agent: ua, type }
    })
}

function normalizeIocList(value) {
  return uniqueItems(
    value.split(/\r?\n/)
      .map((line) => line.trim().toLowerCase())
      .filter(Boolean)
  ).sort((a, b) => a.localeCompare(b)).join("\n")
}


function formatIocExtraction(value) {
  if (!value?.iocs || !value?.summary) return ""
  const labels = { urls: "URLs", ips: "IPs", emails: "Emails", domains: "Domains", hashes: "Hashes" }
  const sections = Object.entries(labels)
    .filter(([key]) => Array.isArray(value.iocs[key]) && value.iocs[key].length)
    .map(([key, label]) => [`${label} (${value.iocs[key].length})`, ...value.iocs[key].map((item) => `  - ${item}`)].join("\n"))
  if (!sections.length) return "No IOCs extracted."
  const total = Object.values(value.summary || {}).reduce((sum, count) => sum + Number(count || 0), 0)
  return [`Extracted IOCs: ${total}`, "", ...sections].join("\n")
}

function outputToText(value) {
  if (value === null || value === undefined) return ""
  if (typeof value === "string") return value
  if (typeof value === "number" || typeof value === "boolean") return String(value)
  if (typeof value.output === "string") return value.output
  if (typeof value.decoded === "string") return value.decoded
  if (typeof value.encoded === "string") return value.encoded
  if (typeof value.pretty === "string") return value.pretty
  if (typeof value.minified === "string") return value.minified
  const iocOutput = formatIocExtraction(value)
  if (iocOutput) return iocOutput
  return JSON.stringify(value, null, 2)
}

function localUrlTransform(value, action) {
  try {
    return action === "encode" ? encodeURIComponent(value) : decodeURIComponent(value)
  } catch (err) {
    throw new Error(`URL ${action} failed: ${err.message}`, { cause: err })
  }
}

function parseUrlLocal(value) {
  try {
    const parsed = new URL(value.trim())
    return {
      input: value.trim(),
      source: "browser URL parser",
      method: "local URL parsing",
      scheme: parsed.protocol.replace(":", ""),
      username: parsed.username || null,
      password_present: Boolean(parsed.password),
      host: parsed.hostname,
      port: parsed.port || null,
      path: parsed.pathname,
      query: Object.fromEntries(parsed.searchParams.entries()),
      fragment: parsed.hash ? parsed.hash.slice(1) : null,
      limitations: "Local parser only. It does not fetch the URL or perform reputation checks.",
    }
  } catch (err) {
    throw new Error(`URL parse failed: ${err.message}`, { cause: err })
  }
}

function decodeBase64UrlJson(segment) {
  const normalized = segment.replaceAll("-", "+").replaceAll("_", "/")
  const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), "=")
  return JSON.parse(decodeURIComponent(escape(atob(padded))))
}

function decodeJwtLocal(value) {
  const parts = value.trim().split(".")
  if (parts.length < 2) throw new Error("JWT must contain at least header and payload segments.")

  return {
    header: decodeBase64UrlJson(parts[0]),
    payload: decodeBase64UrlJson(parts[1]),
    signature_present: Boolean(parts[2]),
    verified: false,
    source: "browser decoder",
    method: "local Base64URL decode",
    limitations: "Decoded only. Signature trust is not verified.",
  }
}

function convertTimestampLocal(value) {
  const trimmed = value.trim()
  const numeric = Number(trimmed)
  const date = Number.isFinite(numeric)
    ? new Date((String(Math.trunc(numeric)).length <= 10 ? numeric * 1000 : numeric))
    : new Date(trimmed)

  if (Number.isNaN(date.getTime())) throw new Error("Timestamp input must be Unix seconds, Unix milliseconds, or a parseable date.")

  return {
    input: value,
    source: "browser Date",
    method: "local timestamp conversion",
    unix_seconds: Math.floor(date.getTime() / 1000),
    unix_milliseconds: date.getTime(),
    utc: date.toISOString(),
    local: date.toString(),
    limitations: "Local conversion only. Timezone display depends on the analyst workstation.",
  }
}

function analyzePowerShellLocal(value) {
  const lowered = value.toLowerCase()
  const encodedMatch = value.match(/(?:-enc(?:odedcommand)?\s+)([a-z0-9+/=_-]+)/i)
  let decoded_preview = null

  if (encodedMatch) {
    try {
      const compact = encodedMatch[1].replace(/\s+/g, "")
      const normalized = compact.replaceAll("-", "+").replaceAll("_", "/")
      const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), "=")
      const bytes = Uint8Array.from(atob(padded), (char) => char.charCodeAt(0))
      decoded_preview = new TextDecoder("utf-16le").decode(bytes).split(String.fromCharCode(0)).join("").slice(0, 2000)
    } catch {
      decoded_preview = "Encoded command detected, but local decode failed."
    }
  }

  const suspiciousPatterns = [
    "encodedcommand",
    "-enc",
    "-nop",
    "bypass",
    "hidden",
    "downloadstring",
    "invoke-expression",
    "iex",
    "frombase64string",
    "new-object net.webclient",
  ]

  return {
    source: "local static analyzer",
    method: "string pattern review",
    encoded_command_detected: Boolean(encodedMatch),
    decoded_preview,
    suspicious_flags: suspiciousPatterns.filter((pattern) => lowered.includes(pattern)),
    extracted_iocs: extractIocsLocal(`${value}\n${decoded_preview || ""}`).iocs,
    limitations: "Static analysis only. Commands are not executed and intent is not proven.",
  }
}

async function withBackendFallback(operationLabel, backendCall, localCall) {
  try {
    const result = await backendCall()
    return {
      source: "BeyondArch local backend",
      backend_used: true,
      result,
    }
  } catch (err) {
    const fallback = localCall()
    return {
      source: "browser local fallback",
      backend_used: false,
      backend_error: err.message || "Backend unavailable.",
      result: fallback,
      limitations: `${operationLabel} used browser fallback because the local backend was unavailable.`,
    }
  }
}

async function applyOperation(operationId, currentInput, options = {}) {
  switch (operationId) {
    case "defang":
      return defang(currentInput)
    case "refang":
      return refang(currentInput)
    case "extract-iocs":
      return extractIocsLocal(currentInput, options)
    case "extract-urls":
      return extractSingleIocType(currentInput, "urls", options)
    case "extract-ips":
      return extractSingleIocType(currentInput, "ips", options)
    case "extract-domains":
      return extractSingleIocType(currentInput, "domains", options)
    case "extract-emails":
      return extractSingleIocType(currentInput, "emails", options)
    case "extract-hashes":
      return extractSingleIocType(currentInput, "hashes", options)
    case "secret-scan":
      return {
        findings: scanSecrets(currentInput),
        source: "local browser scanner",
        method: "deterministic pattern and entropy review",
        limitations: "Pattern-based secret detection. Validate before rotation, but treat likely real credentials cautiously.",
      }
    case "to-base64":
      return toBase64(currentInput, options)
    case "from-base64":
      return fromBase64(currentInput, options)
    case "to-base64url":
      return toBase64Url(currentInput)
    case "from-base64url":
      return fromBase64Url(currentInput)
    case "to-hex":
      return toHex(currentInput, options)
    case "from-hex":
      return fromHex(currentInput)
    case "to-binary":
      return toBinary(currentInput, options)
    case "from-binary":
      return fromBinary(currentInput)
    case "to-charcode":
      return toCharcode(currentInput, options)
    case "from-charcode":
      return fromCharcode(currentInput, options)
    case "url-encode":
      return localUrlTransform(currentInput, "encode")
    case "url-decode":
      return localUrlTransform(currentInput, "decode")
    case "html-encode":
      return htmlEncode(currentInput)
    case "html-decode":
      return htmlDecode(currentInput)
    case "unicode-escape":
      return unicodeEscape(currentInput, options)
    case "unicode-unescape":
      return unicodeUnescape(currentInput)
    case "rot13":
      return rot13(currentInput, options)
    case "parse-url":
      return withBackendFallback("Parse URL", () => parseUrlUtility(currentInput), () => parseUrlLocal(currentInput))
    case "jwt-decode":
      return withBackendFallback("JWT Decode", () => decodeJwt(currentInput), () => decodeJwtLocal(currentInput))
    case "json-pretty":
      return JSON.stringify(JSON.parse(currentInput), null, 2)
    case "json-minify":
      return JSON.stringify(JSON.parse(currentInput))
    case "timestamp":
      return withBackendFallback("Timestamp", () => convertTimestamp(currentInput), () => convertTimestampLocal(currentInput))
    case "sort-lines":
      return sortLines(currentInput, options)
    case "unique-lines":
      return uniqueLines(currentInput, options)
    case "remove-empty-lines":
      return removeEmptyLines(currentInput)
    case "uppercase":
      return currentInput.toUpperCase()
    case "lowercase":
      return currentInput.toLowerCase()
    case "reverse":
      return Array.from(currentInput).reverse().join("")
    case "trim-lines":
      return trimLines(currentInput)
    case "remove-whitespace":
      return currentInput.replace(/\s+/g, "")
    case "count":
      return countText(currentInput)
    case "escape-regex":
      return escapeRegex(currentInput)
    case "regex-extract":
      return regexExtract(currentInput, options)
    case "regex-redact":
      return regexRedact(currentInput, options)
    case "hash-identify":
      return identifyHashLocal(currentInput)
    case "sha1":
      return hashText(currentInput, "SHA-1", options)
    case "sha256":
      return hashText(currentInput, "SHA-256", options)
    case "sha384":
      return hashText(currentInput, "SHA-384", options)
    case "sha512":
      return hashText(currentInput, "SHA-512", options)
    case "powershell-analyze":
      return withBackendFallback("PowerShell Analyze", () => analyzePowerShell(currentInput), () => analyzePowerShellLocal(currentInput))
    case "windows-cmdline-parse":
      return parseWindowsCommandLine(currentInput)
    case "linux-auth-summary":
      return summarizeLinuxAuth(currentInput)
    case "user-agent-classify":
      return classifyUserAgents(currentInput)
    case "normalize-ioc-list":
      return normalizeIocList(currentInput)
    default:
      throw new Error(`Unsupported operation: ${operationId}`)
  }
}

function iconButtonClass(active = false) {
  return active
    ? "ba-cyberchef-action is-active inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[11px] font-bold transition"
    : "ba-cyberchef-action inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[11px] font-bold transition"
}

function StepOptions({ operationId, options, onChange }) {
  if (["extract-iocs", "extract-urls", "extract-ips", "extract-domains", "extract-emails", "extract-hashes"].includes(operationId)) {
    const current = options.include || ["urls", "ips", "emails", "domains", "hashes"]
    const toggles = ["urls", "ips", "emails", "domains", "hashes"]

    return (
      <div className="mt-3 flex flex-wrap gap-2">
        {toggles.map((key) => (
          <label key={key} className="flex items-center gap-1 text-[11px] text-zinc-400">
            <input
              type="checkbox"
              checked={current.includes(key)}
              onChange={(event) => onChange({
                include: event.target.checked
                  ? [...current, key]
                  : current.filter((item) => item !== key)
              })}
            />
            {key}
          </label>
        ))}
      </div>
    )
  }

  if (operationId === "to-hex") {
    return (
      <div className="mt-3 grid gap-2 text-[11px] text-zinc-400">
        <label>
          Delimiter
          <select value={options.delimiter || ""} onChange={(event) => onChange({ delimiter: event.target.value })} className="ba-workbench-field mt-1 w-full rounded border px-2 py-1">
            <option value="">None</option>
            <option value=" ">Space</option>
            <option value=":">Colon</option>
            <option value="-">Dash</option>
          </select>
        </label>
        <label>
          Case
          <select value={options.case || "lower"} onChange={(event) => onChange({ case: event.target.value })} className="ba-workbench-field mt-1 w-full rounded border px-2 py-1">
            <option value="lower">lower</option>
            <option value="upper">UPPER</option>
          </select>
        </label>
        <label>
          Prefix
          <select value={options.prefix || ""} onChange={(event) => onChange({ prefix: event.target.value })} className="ba-workbench-field mt-1 w-full rounded border px-2 py-1">
            <option value="">None</option>
            <option value="0x">0x</option>
            <option value="\\x">\\x</option>
          </select>
        </label>
      </div>
    )
  }

  if (operationId === "to-base64") {
    return (
      <div className="mt-3 grid gap-2 text-[11px] text-zinc-400">
        <label>
          Alphabet
          <select value={options.alphabet || "standard"} onChange={(event) => onChange({ alphabet: event.target.value })} className="ba-workbench-field mt-1 w-full rounded border px-2 py-1">
            <option value="standard">Standard</option>
            <option value="url">URL safe</option>
          </select>
        </label>
        <label>
          Line length
          <input
            type="number"
            min="0"
            value={options.lineLength || 0}
            onChange={(event) => onChange({ lineLength: Number(event.target.value) })}
            className="ba-workbench-field mt-1 w-full rounded border px-2 py-1"
          />
        </label>
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={options.padding !== false} onChange={(event) => onChange({ padding: event.target.checked })} />
          Include padding
        </label>
      </div>
    )
  }

  if (operationId === "from-base64") {
    return (
      <div className="mt-3 flex flex-wrap gap-3 text-[11px] text-zinc-400">
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={!options.keepWhitespace} onChange={(event) => onChange({ keepWhitespace: !event.target.checked })} />
          Ignore whitespace
        </label>
      </div>
    )
  }

  if (operationId === "to-binary") {
    return (
      <label className="mt-3 block text-[11px] text-zinc-400">
        Delimiter
        <select value={options.delimiter ?? " "} onChange={(event) => onChange({ delimiter: event.target.value })} className="ba-workbench-field mt-1 w-full rounded border px-2 py-1">
          <option value=" ">Space</option>
          <option value="">None</option>
          <option value="-">Dash</option>
          <option value={"\n"}>New line</option>
        </select>
      </label>
    )
  }

  if (["to-charcode", "from-charcode"].includes(operationId)) {
    const base = Number(options.base || 10)

    return (
      <div className="mt-3 grid gap-2 text-[11px] text-zinc-400">
        <label>
          Base
          <select value={base} onChange={(event) => onChange({ base: Number(event.target.value) })} className="ba-workbench-field mt-1 w-full rounded border px-2 py-1">
            <option value={10}>Decimal</option>
            <option value={16}>Hex</option>
          </select>
        </label>
        {operationId === "to-charcode" && (
          <>
            <label>
              Delimiter
              <select value={options.delimiter ?? " "} onChange={(event) => onChange({ delimiter: event.target.value })} className="ba-workbench-field mt-1 w-full rounded border px-2 py-1">
                <option value=" ">Space</option>
                <option value=",">Comma</option>
                <option value="">None</option>
                <option value={"\n"}>New line</option>
              </select>
            </label>
            {base === 16 && (
              <label className="flex items-center gap-1">
                <input type="checkbox" checked={options.prefix !== false} onChange={(event) => onChange({ prefix: event.target.checked })} />
                Hex prefix
              </label>
            )}
          </>
        )}
      </div>
    )
  }

  if (operationId === "unicode-escape") {
    return (
      <div className="mt-3 flex flex-wrap gap-3 text-[11px] text-zinc-400">
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={!!options.allCharacters} onChange={(event) => onChange({ allCharacters: event.target.checked })} />
          Escape ASCII too
        </label>
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={!!options.uppercase} onChange={(event) => onChange({ uppercase: event.target.checked })} />
          Uppercase hex
        </label>
      </div>
    )
  }

  if (operationId === "rot13") {
    return (
      <label className="mt-3 block text-[11px] text-zinc-400">
        Rotation
        <input
          type="number"
          min="1"
          max="25"
          value={options.rotation || 13}
          onChange={(event) => onChange({ rotation: Number(event.target.value) })}
          className="ba-workbench-field mt-1 w-full rounded border px-2 py-1"
        />
      </label>
    )
  }

  if (["sort-lines", "unique-lines"].includes(operationId)) {
    return (
      <div className="mt-3 flex flex-wrap gap-3 text-[11px] text-zinc-400">
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={!!options.caseSensitive} onChange={(event) => onChange({ caseSensitive: event.target.checked })} />
          Case sensitive
        </label>
        {operationId === "sort-lines" && (
          <label className="flex items-center gap-1">
            <input type="checkbox" checked={!!options.reverse} onChange={(event) => onChange({ reverse: event.target.checked })} />
            Reverse
          </label>
        )}
      </div>
    )
  }

  if (operationId === "regex-extract") {
    const current = options.types || ["ipv4", "urls", "emails", "hashes", "cves", "windows_event_ids"]
    const types = ["ipv4", "urls", "emails", "hashes", "cves", "windows_event_ids"]

    return (
      <div className="mt-3 flex flex-wrap gap-2">
        {types.map((key) => (
          <label key={key} className="flex items-center gap-1 text-[11px] text-zinc-400">
            <input
              type="checkbox"
              checked={current.includes(key)}
              onChange={(event) => onChange({
                types: event.target.checked
                  ? [...current, key]
                  : current.filter((item) => item !== key)
              })}
            />
            {key}
          </label>
        ))}
      </div>
    )
  }

  if (["sha1", "sha256", "sha384", "sha512"].includes(operationId)) {
    return (
      <label className="mt-3 block text-[11px] text-zinc-400">
        Output case
        <select value={options.case || "lower"} onChange={(event) => onChange({ case: event.target.value })} className="ba-workbench-field mt-1 w-full rounded border px-2 py-1">
          <option value="lower">lower</option>
          <option value="upper">UPPER</option>
        </select>
      </label>
    )
  }

  if (operationId === "regex-redact") {
    return (
      <label className="mt-3 block text-[11px] text-zinc-400">
        Replacement
        <input
          value={options.replacement || "[REDACTED]"}
          onChange={(event) => onChange({ replacement: event.target.value })}
          className="ba-workbench-field mt-1 w-full rounded border px-2 py-1"
        />
      </label>
    )
  }

  return null
}

export default function CyberChefPage({ initialMode = "defang", setPage }) {
  const initialOperationId = operationForInitialMode(initialMode)
  const pendingArtifact = useMemo(() => {
    try {
      const raw = localStorage.getItem(PENDING_ARTIFACT_KEY)
      if (!raw) return null
      const artifact = JSON.parse(raw)
      if (!artifact?.value || artifact.target !== "cyberchef") return null
      localStorage.removeItem(PENDING_ARTIFACT_KEY)
      return artifact
    } catch {
      return null
    }
  }, [])
  const pendingRecipe = useMemo(() => {
    if (!Array.isArray(pendingArtifact?.suggested_recipe)) return null
    const normalized = pendingArtifact.suggested_recipe.filter((operationId) => OPERATION_BY_ID[operationId]).map((operationId) => createRecipeStep(operationId))
    return normalized.length ? normalized : null
  }, [pendingArtifact])
  const [selectedCategory, setSelectedCategory] = useState("favourites")
  const [selectedOperation, setSelectedOperation] = useState(() => pendingRecipe?.[0] ? getStepOperationId(pendingRecipe[0]) : initialOperationId)
  const [recipe, setRecipe] = useState(() => pendingRecipe || [])
  const [input, setInput] = useState(() => pendingArtifact?.value ? String(pendingArtifact.value) : "")
  const [output, setOutput] = useState("")
  const [steps, setSteps] = useState([])
  const [error, setError] = useState("")
  const [notice, setNotice] = useState(() => pendingArtifact ? `Loaded ${pendingArtifact.type || "artifact"} from ${pendingArtifact.source || "BeyondArch"}.` : "")
  const [outputState, setOutputState] = useState("empty")
  const [outputSignature, setOutputSignature] = useState("")
  const [loading, setLoading] = useState(false)
  const [autoBake, setAutoBake] = useState(true)
  const [wordWrap, setWordWrap] = useState(true)
  const [inputDragActive, setInputDragActive] = useState(false)
  const [inputFileName, setInputFileName] = useState(() => pendingArtifact ? `From ${pendingArtifact.source || "BeyondArch"}` : "")
  const [secretScanOpen, setSecretScanOpen] = useState(false)
  const [stepDetailsOpen, setStepDetailsOpen] = useState(false)
  const [expandedStepIds, setExpandedStepIds] = useState(() => new Set())
  const [search, setSearch] = useState("")
  const [dropIndex, setDropIndex] = useState(null)
  const [favourites, setFavourites] = useState(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(SAVED_FAVOURITES_KEY) || "null")
      return Array.isArray(saved) && saved.length ? saved.filter((operationId) => OPERATION_BY_ID[operationId]) : DEFAULT_FAVOURITES
    } catch {
      return DEFAULT_FAVOURITES
    }
  })
  const [favouritesDropActive, setFavouritesDropActive] = useState(false)
  const [expandedCategories, setExpandedCategories] = useState(() => new Set(["favourites"]))
  const recipePanelRef = useRef(null)
  const recipeDropHandledRef = useRef(false)
  const draggedOperationRef = useRef(null)
  const draggedRecipeIndexRef = useRef(null)
  const inputFileRef = useRef(null)

  const selectedOperationConfig = OPERATION_BY_ID[selectedOperation] || OPERATION_BY_ID.defang
  const inputPlaceholderOperationId = getStepOperationId(recipe[0]) || selectedOperation
  const outputPlaceholderOperationId = getStepOperationId(recipe[recipe.length - 1]) || selectedOperation
  const inputPlaceholder = recipe.length
    ? OPERATION_BY_ID[inputPlaceholderOperationId]?.placeholder || selectedOperationConfig.placeholder
    : EMPTY_RECIPE_INPUT_PLACEHOLDER
  const outputPlaceholder = recipe.length
    ? outputPlaceholderFor(outputPlaceholderOperationId)
    : EMPTY_RECIPE_OUTPUT_PLACEHOLDER
  const categories = useMemo(() => BASE_CATEGORIES.map((category) => (
    category.id === "favourites" ? { ...category, operations: favourites } : category
  )), [favourites])
  const query = search.trim().toLowerCase()
  const visiblePresetRecipes = QUICK_RECIPE_PRESETS.filter(({ label, operations, description }) => {
    if (!operations.length) return false
    if (!query) return true
    return `${label} ${description} ${operations.join(" ")}`.toLowerCase().includes(query)
  })
  const currentOutputSignature = useMemo(() => outputSignatureFor(input, recipe), [input, recipe])
  const outputStale = !autoBake && outputState !== "empty" && outputSignature !== currentOutputSignature
  const analysisText = output || input
  const iocSummary = useMemo(() => extractIocsLocal(analysisText || ""), [analysisText])
  const secretFindings = useMemo(() => scanSecrets(analysisText || ""), [analysisText])
  const markdownSummary = useMemo(() => cyberChefMarkdownSummary({
    sourceText: input,
    output,
    recipe,
    iocs: iocSummary,
    secrets: secretFindings,
  }), [input, output, recipe, iocSummary, secretFindings])
  const outputStateMessage = (() => {
    if (outputStale) return "Output is stale. Click Bake to update."
    if (!input.trim()) return "No input yet. Paste text or open a file to begin."
    if (!recipe.length) return ""
    if (error) return "Recipe failed. Review the failed step and error message."
    if (outputState === "ready") return "Recipe output is current."
    return "Click Bake to run the visible recipe."
  })()
  const outputStatus = (() => {
    if (outputStale) return { label: "Stale", className: "ba-status-warning" }
    if (error || outputState === "error") return { label: "Error", className: "ba-status-danger" }
    if (outputState === "ready") return { label: "Current", className: "ba-status-ready" }
    return { label: "Waiting", className: "ba-status-local" }
  })()
  const transformationSummary = useMemo(() => {
    if (!output || outputState === "empty" || outputState === "error") return []

    const operationIds = recipe.map((step) => getStepOperationId(step)).filter(Boolean)
    if (!operationIds.length) return ["Input mirrored unchanged"]

    const summary = []
    if (operationIds.includes("defang")) {
      const indicatorCount = [
        ...(input.match(/https?:\/\/[^\s"'<>]+/gi) || []),
        ...(input.match(/\b[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+\b/g) || []),
        ...(input.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g) || []),
      ].length

      if (indicatorCount) {
        summary.push(`${indicatorCount} indicator${indicatorCount === 1 ? "" : "s"} transformed`)
      }
      if (/\[\.\]|\[:\]\/\/|\[@\]/.test(output)) {
        summary.push("Defanged indicators for safe reporting")
      }
    }

    if (!summary.length) {
      summary.push(`${recipe.length} recipe step${recipe.length === 1 ? "" : "s"} applied`)
    }

    return summary
  }, [input, output, outputState, recipe])

  const recipePipeline = useMemo(() => (
    recipe
      .map((step) => OPERATION_BY_ID[getStepOperationId(step)]?.label || getStepOperationId(step))
      .filter(Boolean)
      .join(" → ")
  ), [recipe])

  const sendToPayload = useMemo(() => ({
    type: "cyberchef_transform",
    title: `CyberChef transform: ${recipePipeline || "manual review"}`,
    value: output || input,
    summary: `${recipePipeline || "Manual transform"}; ${String(output || input).length.toLocaleString()} chars. IOCs: ${iocSummary.summary || "none"}. Secrets: ${secretFindings.length}.`,
    raw: markdownSummary || output || input,
    tags: ["cyberchef", "transform", ...recipe.map((step) => getStepOperationId(step)).filter(Boolean).slice(0, 5)],
    confidence: outputState === "ready" ? "current-output" : "draft",
  }), [input, iocSummary.summary, markdownSummary, output, outputState, recipe, recipePipeline, secretFindings.length])

  function operationsForCategory(category) {
    const allowed = category.operations ? new Set(category.operations) : null

    return OPERATIONS.filter((operation) => {
      if (allowed && !allowed.has(operation.id)) return false
      if (!query) return true
      return `${operation.label} ${operation.description}`.toLowerCase().includes(query)
    })
  }

  async function bake({ manual = false } = {}) {
    const runSignature = outputSignatureFor(input, recipe)

    if (!input && !manual) {
      setOutput("")
      setSteps([])
      setError("")
      setOutputState("empty")
      setOutputSignature(runSignature)
      return
    }

    if (!input) {
      setOutput("")
      setSteps([])
      setError("")
      setOutputState("empty")
      setOutputSignature(runSignature)
      return
    }

    if (!recipe.length) {
      setOutput("")
      setSteps([])
      setError("")
      setNotice("")
      setOutputState("empty")
      setOutputSignature(runSignature)
      return
    }

    if (!input && recipe.some((step) => ["sha1", "sha256", "sha384", "sha512"].includes(getStepOperationId(step)))) {
      setOutput("")
      setSteps([])
      setError("Hash operations need input. Enter text or open a file, then bake.")
      setOutputState("error")
      setOutputSignature(runSignature)
      return
    }

    setLoading(true)
    setError("")
    setNotice("")
    setSteps([])

    try {
      let current = input
      const nextSteps = []

      for (let index = 0; index < recipe.length; index += 1) {
        const step = recipe[index]
        const operationId = getStepOperationId(step)
        const options = getStepOptions(step)
        const operation = OPERATION_BY_ID[operationId]

        try {
          const result = await applyOperation(operationId, current, options)
          const nextOutput = outputToText(result)

          nextSteps.push({
            id: `${operationId}-${nextSteps.length}`,
            operation: operation?.label || operationId,
            status: "ok",
            input_preview: current.slice(0, 1200),
            output: nextOutput,
            result,
          })
          current = nextOutput
        } catch (stepErr) {
          const message = stepErr.message || "Step failed."
          nextSteps.push({
            id: `${operationId}-${nextSteps.length}`,
            operation: operation?.label || operationId,
            status: "failed",
            error: message,
            input_preview: current.slice(0, 1200),
          })
          setSteps(nextSteps)
          setOutput(current)
          throw new Error(`Step ${index + 1} (${operation?.label || operationId}) failed: ${message}`, { cause: stepErr })
        }
      }

      setSteps(nextSteps)
      setOutput(current)
      setOutputState("ready")
      setOutputSignature(runSignature)
    } catch (err) {
      setError(err.message || "Recipe failed.")
      setOutput("")
      setOutputState("error")
      setOutputSignature(runSignature)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!autoBake) return

    const timer = window.setTimeout(() => {
      bake()
    }, 300)

    return () => window.clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [input, recipe, autoBake])

  function addOperation(operationId = selectedOperation) {
    if (!OPERATION_BY_ID[operationId]) return
    setRecipe((current) => [...current, createRecipeStep(operationId)])
    setSelectedOperation(operationId)
  }

  function insertOperation(operationId, index = recipe.length) {
    if (!OPERATION_BY_ID[operationId]) return
    setRecipe((current) => {
      const next = [...current]
      next.splice(index, 0, createRecipeStep(operationId))
      return next
    })
  }

  function removeOperation(index) {
    setRecipe((current) => current.filter((_, itemIndex) => itemIndex !== index))
  }

  function updateStepOptions(index, nextOptions) {
    setRecipe((current) => current.map((step, stepIndex) => {
      if (stepIndex !== index) return step
      const operationId = getStepOperationId(step)
      return {
        ...(typeof step === "string" ? createRecipeStep(operationId) : step),
        operationId,
        options: {
          ...getStepOptions(step),
          ...nextOptions,
        },
      }
    }))
  }

  function moveOperation(index, direction) {
    setRecipe((current) => {
      const nextIndex = index + direction
      if (nextIndex < 0 || nextIndex >= current.length) return current

      const next = [...current]
      const [item] = next.splice(index, 1)
      next.splice(nextIndex, 0, item)
      return next
    })
  }

  function selectOperation(operationId) {
    setSelectedOperation(operationId)
  }

  function copyOutput() {
    navigator.clipboard?.writeText(output)
    setNotice("Output copied.")
  }

  function copyAllStepsOutput() {
    const stepSummaries = steps.filter((s) => s.status === "ok" && s.output).map((s) => `[Step ${s.index + 1}] ${s.label}\n${"─".repeat(40)}\n${s.output}`).join("\n\n")
    navigator.clipboard?.writeText(stepSummaries || output)
    setNotice("All step outputs copied.")
  }

  function copyMarkdownSummary() {
    navigator.clipboard?.writeText(markdownSummary)
    setNotice("Markdown summary copied.")
  }

  function saveRecipe() {
    localStorage.setItem(SAVED_RECIPE_KEY, JSON.stringify({
      version: 1,
      saved_at: new Date().toISOString(),
      recipe: serializeRecipe(recipe),
    }))
    setNotice("Recipe saved locally. Input text was not saved.")
  }

  function loadPreset(presetId) {
    const preset = QUICK_RECIPE_PRESETS.find(({ id }) => id === presetId)
    if (!preset || !preset.operations) return

    setRecipe(preset.operations.map((operationId) => createRecipeStep(operationId)))
    setSelectedOperation(preset.operations[0])
    if (preset.sample) setInput(preset.sample)
    setNotice(`${preset.label} loaded${preset.sample ? " with sample input" : ""}.`)
  }

  function loadSavedRecipe() {
    const raw = localStorage.getItem(SAVED_RECIPE_KEY)
    if (!raw) return

    try {
      importRecipeText(raw)
    } catch (err) {
      setError(err.message || "Saved recipe could not be loaded.")
    }
  }

  function importRecipeText(text) {
    const parsed = JSON.parse(text)
    const importedRecipe = Array.isArray(parsed) ? parsed : parsed.recipe
    if (!Array.isArray(importedRecipe)) throw new Error("Recipe import must be an array or an object with a recipe array.")

    const normalized = normalizeRecipeItems(importedRecipe)

    if (!normalized.length) throw new Error("Recipe does not contain supported operations.")

    setRecipe(normalized)
    setError("")
    setNotice("Recipe loaded. Input text was not loaded.")
  }

  async function loadInputFileObject(file) {
    if (!file) return

    setInput(await file.text())
    setInputFileName(file.name)
    setNotice(`Opened ${file.name}.`)
  }

  async function loadInputFile(event) {
    const file = event.target.files?.[0]
    await loadInputFileObject(file)
    event.target.value = ""
  }

  function downloadOutput() {
    const blob = new Blob([output], { type: "text/plain" })
    const url = URL.createObjectURL(blob)
    const link = document.createElement("a")
    link.href = url
    link.download = `beyondarch-cyberchef-output-${Date.now()}.txt`
    link.click()
    URL.revokeObjectURL(url)
    setNotice("Output downloaded as text.")
  }

  function exportRecipe() {
    const payload = {
      version: 1,
      exported_at: new Date().toISOString(),
      label: "BeyondArch CyberChef Recipe",
      recipe: serializeRecipe(recipe),
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" })
    const url = URL.createObjectURL(blob)
    const link = document.createElement("a")
    link.href = url
    link.download = `beyondarch-recipe-${Date.now()}.json`
    link.click()
    URL.revokeObjectURL(url)
    setNotice("Recipe exported as JSON.")
  }

  function importRecipeFromFile(event) {
    const file = event.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        importRecipeText(e.target.result)
        setNotice(`Recipe imported from ${file.name}.`)
      } catch (err) {
        setError(err.message || "Recipe import failed.")
      }
    }
    reader.readAsText(file)
    event.target.value = ""
  }

  function clearInput() {
    setInput("")
    setInputFileName("")
    if (!autoBake) {
      setOutput("")
      setSteps([])
      setError("")
      setOutputState("empty")
      setOutputSignature("")
    }
    setNotice("Input cleared.")
  }

  function swapInputOutput() {
    setInput(output)
    setOutput(input)
    setNotice("Input and output swapped.")
  }

  function loadSample() {
    const firstRecipeOperation = getStepOperationId(recipe[0])
    const operationId = firstRecipeOperation || selectedOperation
    const sample = OPERATION_BY_ID[operationId]?.placeholder || ""
    setInput(sample)
    setInputFileName("")
    setNotice(`Sample input loaded for ${OPERATION_BY_ID[operationId]?.label || "selected operation"}.`)
  }

  function sendOutputTo(target) {
    const text = output || input
    if (!text) {
      setNotice("Nothing to send yet.")
      return
    }

    const route = CYBERCHEF_HANDOFF_TARGETS[target]
    if (!route) return

    try {
      localStorage.setItem(PENDING_ARTIFACT_KEY, JSON.stringify(buildCyberChefHandoff({
        value: text,
        target: route.target,
        recipe: recipe.map((step) => OPERATION_BY_ID[getStepOperationId(step)]?.label || getStepOperationId(step)),
        iocSummary: iocSummary.summary,
      })))
    } catch {
      navigator.clipboard?.writeText(text)
      setNotice(`${route.label}: output copied because local handoff storage was unavailable.`)
      return
    }

    if (typeof setPage === "function") {
      setPage(route.page)
    } else {
      navigator.clipboard?.writeText(text)
      setNotice(`${route.label}: output prepared and copied. Open the target module from the sidebar.`)
    }
  }

  function duplicateOperation(index) {
    setRecipe((current) => {
      const step = current[index]
      if (!step) return current
      const operationId = getStepOperationId(step)
      return [
        ...current.slice(0, index + 1),
        createRecipeStep(operationId, getStepOptions(step)),
        ...current.slice(index + 1),
      ]
    })
  }

  function toggleStepOptions(stepKey) {
    setExpandedStepIds((current) => {
      const next = new Set(current)
      if (next.has(stepKey)) next.delete(stepKey)
      else next.add(stepKey)
      return next
    })
  }

  function resetRecipe() {
    setRecipe([])
    setSteps([])
    setOutput("")
    setError("")
    setOutputState("empty")
    setOutputSignature("")
    setNotice("Recipe reset. Input text was kept.")
  }

  function handleOperationDragStart(event, operationId) {
    event.dataTransfer.effectAllowed = "copy"
    event.dataTransfer.setData("application/x-beyondarch-operation", operationId)
    draggedOperationRef.current = operationId
    draggedRecipeIndexRef.current = null
  }

  function handleRecipeDragStart(event, index) {
    event.dataTransfer.effectAllowed = "move"
    event.dataTransfer.setData("application/x-beyondarch-recipe-index", String(index))
    recipeDropHandledRef.current = false
    draggedOperationRef.current = null
    draggedRecipeIndexRef.current = index
  }

  function insertIndexFromPointer(event) {
    const cards = Array.from(recipePanelRef.current?.querySelectorAll("[data-recipe-card='true']") || [])

    if (!cards.length) return 0

    for (let index = 0; index < cards.length; index += 1) {
      const rect = cards[index].getBoundingClientRect()
      if (event.clientY < rect.top + rect.height / 2) return index
    }

    return recipe.length
  }

  function handleRecipeDrop(event, index = insertIndexFromPointer(event)) {
    event.preventDefault()
    event.stopPropagation()
    recipeDropHandledRef.current = true
    setDropIndex(null)

    const operationId = draggedOperationRef.current || event.dataTransfer.getData("application/x-beyondarch-operation")
    if (operationId) {
      insertOperation(operationId, index)
      setSelectedOperation(operationId)
      draggedOperationRef.current = null
      return
    }

    const fromIndexValue = event.dataTransfer.getData("application/x-beyondarch-recipe-index")
    const fromIndex = draggedRecipeIndexRef.current ?? Number(fromIndexValue)

    if (Number.isNaN(fromIndex) || fromIndex === index) return

    setRecipe((current) => {
      const next = [...current]
      const [item] = next.splice(fromIndex, 1)
      const adjustedIndex = fromIndex < index ? index - 1 : index
      next.splice(adjustedIndex, 0, item)
      return next
    })
    draggedRecipeIndexRef.current = null
  }

  function handleRecipeDragOver(event, index = insertIndexFromPointer(event)) {
    event.preventDefault()
    event.stopPropagation()
    setDropIndex(index)
  }

  function handleRecipeCardDragOver(event, index) {
    event.preventDefault()
    event.stopPropagation()
    const rect = event.currentTarget.getBoundingClientRect()
    const insertAfter = event.clientY > rect.top + rect.height / 2
    setDropIndex(index + (insertAfter ? 1 : 0))
  }

  function handleRecipeCardDrop(event, index) {
    const rect = event.currentTarget.getBoundingClientRect()
    const insertAfter = event.clientY > rect.top + rect.height / 2
    handleRecipeDrop(event, index + (insertAfter ? 1 : 0))
  }

  function handleRecipeDragEnd(event, index) {
    const rect = recipePanelRef.current?.getBoundingClientRect()
    const isInsideRecipe = rect
      && event.clientX >= rect.left
      && event.clientX <= rect.right
      && event.clientY >= rect.top
      && event.clientY <= rect.bottom

    if (!recipeDropHandledRef.current && !isInsideRecipe) {
      removeOperation(index)
    }

    setDropIndex(null)
    recipeDropHandledRef.current = false
    draggedOperationRef.current = null
    draggedRecipeIndexRef.current = null
  }

  function addFavourite(operationId) {
    if (!OPERATION_BY_ID[operationId]) return

    setFavourites((current) => {
      const next = current.includes(operationId) ? current : [...current, operationId]
      localStorage.setItem(SAVED_FAVOURITES_KEY, JSON.stringify(next))
      return next
    })
  }

  function handleFavouriteDragOver(event) {
    const operationId = draggedOperationRef.current || event.dataTransfer.getData("application/x-beyondarch-operation")
    if (!operationId) return

    event.preventDefault()
    event.stopPropagation()
    setFavouritesDropActive(true)
  }

  function handleFavouriteDrop(event) {
    event.preventDefault()
    event.stopPropagation()
    const operationId = draggedOperationRef.current || event.dataTransfer.getData("application/x-beyondarch-operation")
    if (operationId) addFavourite(operationId)
    setFavouritesDropActive(false)
    draggedOperationRef.current = null
  }

  function toggleCategory(categoryId) {
    setSelectedCategory(categoryId)
    setExpandedCategories((current) => {
      const next = new Set(current)
      if (next.has(categoryId)) {
        next.delete(categoryId)
      } else {
        next.add(categoryId)
      }
      return next
    })
  }

  return (
    <WorkbenchPage fixed className="ba-cyberchef ba-cyberchef-page ba-cyberchef-polished">
      <WorkbenchHeader
        eyebrow="Local SOC workbench"
        title="CyberChef"
        subtitle="Decode, transform, defang, hash, extract, and triage text artifacts locally."
        icon={ChefHat}
        chips={[
          { label: "Local transforms", tone: "ready" },
          { label: "Browser-safe", tone: "info" },
          { label: "No execution", tone: "local" },
          { label: "Backend fallback", tone: "warning" },
        ]}
      />
      <div className="cyberchef-main-grid grid min-h-0 flex-1 gap-3 lg:grid-cols-[240px_300px_minmax(0,1fr)]">
        <section className="ba-panel flex min-h-0 flex-col rounded-2xl">
          <div className="shrink-0 border-b border-white/10 p-3">
            <h2 className="text-base font-semibold text-zinc-100"><Wrench className="mr-2 inline h-4 w-4" />Operations</h2>
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search operations..."
              className="ba-workbench-field mt-2 w-full rounded-lg border px-3 py-2 text-sm text-zinc-100 outline-none ring-cyan-500 focus:ring-2"
            />
          </div>

          <div className="cyberchef-operations-scroll min-h-0 flex-1 overflow-auto p-2">
            <div className="mb-1">
              <button
                onClick={() => toggleCategory("recipes")}
                className={`w-full rounded-md px-2 py-1.5 text-left text-xs font-semibold ${
                  selectedCategory === "recipes"
                    ? "border border-cyan-300/60 bg-cyan-400 text-zinc-950"
                    : "bg-black/40 text-zinc-300 hover:bg-black/40"
                }`}
              >
                {expandedCategories.has("recipes") ? <ChevronDown className="mr-2 inline h-3 w-3" /> : <ChevronRight className="mr-2 inline h-3 w-3" />}
                Recipes
                <span className="float-right text-[10px] opacity-60">{visiblePresetRecipes.length}</span>
              </button>

              {expandedCategories.has("recipes") && (
                <div className="ml-3 border-l border-white/10 py-1 pl-2">
                  {visiblePresetRecipes.map(({ id, label, description, operations }) => (
                    <button
                      key={id}
                      onClick={() => loadPreset(id)}
                      className="mb-1 w-full rounded-md border border-white/10 bg-black/40 px-2 py-1.5 text-left transition hover:border-cyan-800 hover:bg-white/5"
                    >
                      <span className="block truncate text-xs font-semibold text-zinc-100">{label}</span>
                      <span className="mt-0.5 line-clamp-2 block text-[10px] leading-4 text-zinc-500">Purpose: {description}</span>
                      <span className="mt-1 flex items-center gap-2">
                        <span className="block truncate text-[10px] text-cyan-300/80">{operations.map((operationId) => OPERATION_BY_ID[operationId]?.label || operationId).join(" -> ")}</span>
                        {RECIPE_MITRE_MAP[id] && <span className="ba-chip ba-status-info shrink-0">MITRE: {RECIPE_MITRE_MAP[id]}</span>}
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {categories.map((category) => {
              const isExpanded = expandedCategories.has(category.id)
              const categoryOperations = operationsForCategory(category)

              return (
                <div key={category.id} className="mb-1">
                  <button
                    onClick={() => toggleCategory(category.id)}
                    onDragOver={category.id === "favourites" ? handleFavouriteDragOver : undefined}
                    onDragLeave={category.id === "favourites" ? () => setFavouritesDropActive(false) : undefined}
                    onDrop={category.id === "favourites" ? handleFavouriteDrop : undefined}
                    className={`w-full rounded-md px-2 py-1.5 text-left text-xs font-semibold ${
                      selectedCategory === category.id
                        ? "bg-cyan-500 text-zinc-950"
                        : favouritesDropActive && category.id === "favourites"
                          ? "bg-amber-500 text-zinc-950"
                          : "bg-black/40 text-zinc-300 hover:bg-black/40"
                    }`}
                  >
                    {isExpanded ? <ChevronDown className="mr-2 inline h-3 w-3" /> : <ChevronRight className="mr-2 inline h-3 w-3" />}
                    {category.label}
                    <span className="float-right text-[10px] opacity-60">{categoryOperations.length}</span>
                  </button>

                  {isExpanded && (
                    <div className="ml-3 border-l border-white/10 py-1 pl-2">
                      {categoryOperations.map((operation) => (
                        <button
                          key={`${category.id}-${operation.id}`}
                          type="button"
                          draggable
                          title={operation.description}
                          onClick={() => selectOperation(operation.id)}
                          onDoubleClick={() => addOperation(operation.id)}
                          onDragStart={(event) => handleOperationDragStart(event, operation.id)}
                          className={`mb-1 flex w-full items-center justify-between gap-2 rounded-md border px-2 py-1.5 text-left text-xs font-semibold transition ${
                            selectedOperation === operation.id
                              ? "border-cyan-600 bg-cyan-950/45 text-cyan-50 shadow-sm shadow-cyan-950/30"
                              : "border-white/10 bg-black/40 text-zinc-100 hover:border-white/10 hover:bg-black/40"
                          }`}
                        >
                          <span className="min-w-0 truncate">{operation.label}</span>
                          <span className="rounded-md border border-white/10 px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-zinc-500">{operation.category}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}

          </div>
        </section>

        <section
          className={`ba-panel flex min-h-0 flex-col rounded-2xl border transition ${
            dropIndex !== null ? "border-cyan-700" : "border-white/10"
          }`}
          onDragOver={(event) => handleRecipeDragOver(event)}
          onDrop={(event) => handleRecipeDrop(event)}
          onDragLeave={(event) => {
            if (!event.currentTarget.contains(event.relatedTarget)) setDropIndex(null)
          }}
        >
          <div className="shrink-0 border-b border-white/10 p-3">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <h2 className="text-lg font-semibold text-zinc-100"><ChefHat className="mr-2 inline h-4 w-4" />Recipe</h2>
                <p className="mt-1 truncate text-xs text-zinc-400">{recipePipeline || "Double-click or drag operations to build a pipeline"}</p>
              </div>
              <div className="flex flex-wrap justify-end gap-1">
                <button className={iconButtonClass(autoBake)} onClick={() => setAutoBake((value) => !value)} title="Toggle automatic recipe runs">
                  Auto {autoBake ? "On" : "Off"}
                </button>
                <button className={iconButtonClass()} onClick={saveRecipe} title="Save recipe" aria-label="Save recipe">
                  <Save className="h-4 w-4" />
                </button>
                <button className={iconButtonClass()} onClick={loadSavedRecipe} title="Open recipe" aria-label="Open recipe">
                  <FolderOpen className="h-4 w-4" />
                </button>
                <button className={iconButtonClass()} onClick={exportRecipe} title="Export recipe as JSON" aria-label="Export recipe">
                  <Upload className="h-4 w-4" />
                </button>
                <label className={iconButtonClass() + " relative cursor-pointer"} title="Import recipe from JSON" aria-label="Import recipe">
                  <Download className="h-4 w-4" />
                  <input type="file" accept=".json" className="absolute inset-0 cursor-pointer opacity-0" onChange={importRecipeFromFile} />
                </label>
                <button className={iconButtonClass()} onClick={resetRecipe} title="Clear recipe" aria-label="Clear recipe">
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5 border-t border-white/10 pt-3">
              {[
                ["url-decode-iocs", "URL decode + IOCs"],
                ["normalize-then-defang", "Normalize + defang"],
                ["base64-powershell", "Base64 + PS triage"],
                ["json-ioc-review", "JSON + IOCs"],
                ["base64-hex-decode", "B64 → Hex"],
              ].map(([presetId, label]) => (
                <button key={presetId} className="ba-button-ghost rounded-lg px-2.5 py-1.5 text-[11px] font-black" onClick={() => loadPreset(presetId)}>{label}</button>
              ))}
            </div>
          </div>

          <div
            ref={recipePanelRef}
            className={`min-h-0 flex-1 overflow-auto p-3 transition ${
              dropIndex !== null ? "bg-cyan-950/10" : ""
            }`}
          >
            {!recipe.length && (
              <div className="grid min-h-[180px] place-items-center rounded-xl border border-dashed border-white/10 bg-black/40 p-6 text-center">
                <div className="flex flex-col items-center gap-2">
                  <ChefHat className="h-8 w-8 text-zinc-500" />
                  <p className="text-sm font-semibold text-zinc-200">No recipe steps added</p>
                  <p className="text-xs text-zinc-500">Double-click an operation or drag it here to build a recipe.</p>
                </div>
              </div>
            )}

            {recipe.map((step, index) => {
              const operationId = getStepOperationId(step)
              const operation = OPERATION_BY_ID[operationId]
              const options = getStepOptions(step)
              const stepKey = typeof step === "string" ? `${operationId}-${index}` : step.id

              return (
                <div key={stepKey}>
                  <div
                    data-recipe-card="true"
                    draggable
                    onDragStart={(event) => handleRecipeDragStart(event, index)}
                    onDragOver={(event) => handleRecipeCardDragOver(event, index)}
                    onDrop={(event) => handleRecipeCardDrop(event, index)}
                    onDragEnd={(event) => handleRecipeDragEnd(event, index)}
                    className={`mb-3 cursor-grab rounded-xl border bg-black/50 p-3 shadow-sm transition hover:border-cyan-900/80 hover:bg-white/5 active:cursor-grabbing ${
                      dropIndex === index || dropIndex === index + 1 ? "border-cyan-500" : "border-white/10"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="text-sm font-semibold text-zinc-100">
                          <span className="mr-2 rounded-md border border-white/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-zinc-400">Step</span>
                          {index + 1}. {operation?.label || operationId}
                        </p>
                        <p className="mt-1 text-xs leading-5 text-zinc-500">{operation?.description}</p>
                      </div>
                      <button
                        onClick={() => removeOperation(index)}
                        className="rounded-lg px-2 py-1 text-xs font-bold text-zinc-500 hover:bg-red-950 hover:text-red-200"
                        title="Remove"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    </div>

                    <div className="mt-2 flex flex-wrap gap-2">
                      <button className={iconButtonClass()} onClick={() => moveOperation(index, -1)} title="Move step up" aria-label="Move step up"><ArrowUp className="h-3.5 w-3.5" /></button>
                      <button className={iconButtonClass()} onClick={() => moveOperation(index, 1)} title="Move step down" aria-label="Move step down"><ArrowDown className="h-3.5 w-3.5" /></button>
                      <button className={iconButtonClass()} onClick={() => duplicateOperation(index)} title="Duplicate step" aria-label="Duplicate step"><Copy className="h-3.5 w-3.5" /></button>
                      <button className={iconButtonClass(expandedStepIds.has(stepKey))} onClick={() => toggleStepOptions(stepKey)} title="Toggle step options">
                        Options {expandedStepIds.has(stepKey) ? "−" : "+"}
                      </button>
                    </div>

                    {expandedStepIds.has(stepKey) && (
                      <StepOptions
                        operationId={operationId}
                        options={options}
                        onChange={(nextOptions) => updateStepOptions(index, nextOptions)}
                      />
                    )}
                  </div>
                </div>
              )
            })}

            <div className="mt-2 grid grid-cols-3 gap-2 rounded-xl border border-white/10 bg-black/40 p-2 text-[11px]">
              <div>
                <p className="font-black uppercase tracking-[0.12em] text-zinc-500">Steps</p>
                <p className="mt-0.5 font-semibold text-zinc-200">{recipe.length}</p>
              </div>
              <div>
                <p className="font-black uppercase tracking-[0.12em] text-zinc-500">Auto-run</p>
                <p className="mt-0.5 font-semibold text-zinc-200">{autoBake ? "On" : "Off"}</p>
              </div>
              <div>
                <p className="font-black uppercase tracking-[0.12em] text-zinc-500">Last run</p>
                <p className="mt-0.5 font-semibold text-zinc-200">{outputStatus.label}</p>
              </div>
            </div>
          </div>
        </section>

        <section className="cyberchef-io-grid grid min-h-0 gap-3 lg:grid-rows-2">
          <div
            className={`ba-panel flex min-h-0 flex-col rounded-2xl ${inputDragActive ? "cyberchef-drop-active" : ""}`}
            onDragOver={(event) => {
              event.preventDefault()
              setInputDragActive(true)
            }}
            onDragLeave={(event) => {
              if (!event.currentTarget.contains(event.relatedTarget)) setInputDragActive(false)
            }}
            onDrop={async (event) => {
              event.preventDefault()
              setInputDragActive(false)
              await loadInputFileObject(event.dataTransfer.files?.[0])
            }}
          >
            <div className="shrink-0 flex items-center justify-between border-b border-white/10 p-3">
              <div>
                <h2 className="text-lg font-semibold text-zinc-100"><Terminal className="mr-2 inline h-4 w-4" />Input</h2>
                {inputFileName && <p className="mt-0.5 max-w-[20rem] truncate text-[11px] text-zinc-400">{inputFileName}</p>}
              </div>
              <div className="flex gap-2">
                <button className={iconButtonClass()} onClick={loadSample} title="Load sample input" aria-label="Load sample">
                  Sample
                </button>
                <button className={iconButtonClass()} onClick={() => setWordWrap((value) => !value)} title="Toggle word wrap">
                  Wrap {wordWrap ? "On" : "Off"}
                </button>
                <button className={iconButtonClass()} onClick={() => inputFileRef.current?.click()} title="Open file" aria-label="Open file">
                  <Upload className="h-4 w-4" />
                  <span className="hidden xl:inline">Open</span>
                </button>
                <button className={iconButtonClass()} onClick={clearInput} title="Clear input" aria-label="Clear input">
                  <Eraser className="h-4 w-4" />
                </button>
                <input ref={inputFileRef} type="file" onChange={loadInputFile} className="hidden" />
              </div>
            </div>
            <textarea
              value={input}
              onChange={(event) => setInput(event.target.value)}
              placeholder={inputPlaceholder}
              wrap={wordWrap ? "soft" : "off"}
              className="min-h-0 flex-1 resize-none rounded-b-2xl border-0 bg-black/40 p-4 font-mono text-sm leading-6 text-zinc-100 outline-none placeholder:text-zinc-600"
            />
          </div>

          <div className="ba-panel flex min-h-0 flex-col rounded-2xl">
            <div className="shrink-0 flex flex-wrap items-center justify-between gap-3 border-b border-white/10 p-3">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-lg font-semibold text-zinc-100"><Play className="mr-2 inline h-4 w-4" />Output</h2>
                  <span className={`ba-chip ${outputStatus.className}`}>{outputStatus.label}</span>
                  <span className="ba-chip ba-status-local">{output.length.toLocaleString()} chars</span>
                </div>
                {error && <p className="mt-1 text-xs text-red-300">{error}</p>}
              </div>
              <div className="flex flex-wrap justify-end gap-2">
                <button className="ba-button-primary rounded-xl px-3 py-2 text-xs font-black" onClick={() => bake({ manual: true })} disabled={loading} title="Re-run output" aria-label="Re-run output">
                  {loading ? "Running..." : <><Play className="mr-1.5 inline h-3.5 w-3.5" />Run</>}
                </button>
                <button className={iconButtonClass()} onClick={copyOutput} title="Copy output" aria-label="Copy output">
                  <Copy className="h-4 w-4" /> Copy
                </button>
                <details className="relative">
                  <summary className={iconButtonClass()} title="More output actions">More</summary>
                  <div className="cyberchef-send-menu absolute right-0 z-20 mt-2 w-56 rounded-xl border border-white/10 bg-black/40 p-2 shadow-xl">
                    <button className="w-full rounded-lg px-2 py-1.5 text-left text-xs font-semibold text-zinc-200 hover:bg-white/5 hover:text-cyan-100" onClick={swapInputOutput} disabled={!input && !output}><Shuffle className="mr-2 inline h-3.5 w-3.5" />Swap input/output</button>
                    <button className="w-full rounded-lg px-2 py-1.5 text-left text-xs font-semibold text-zinc-200 hover:bg-white/5 hover:text-cyan-100" onClick={downloadOutput}><Download className="mr-2 inline h-3.5 w-3.5" />Download output</button>
                    <button className="w-full rounded-lg px-2 py-1.5 text-left text-xs font-semibold text-zinc-200 hover:bg-white/5 hover:text-cyan-100" onClick={copyAllStepsOutput} disabled={steps.length < 2}>Copy all step outputs</button>
                    <button className="w-full rounded-lg px-2 py-1.5 text-left text-xs font-semibold text-zinc-200 hover:bg-white/5 hover:text-cyan-100" onClick={copyMarkdownSummary}>Copy analyst summary</button>
                    <button className="w-full rounded-lg px-2 py-1.5 text-left text-xs font-semibold text-zinc-200 hover:bg-white/5 hover:text-cyan-100" onClick={() => {
                      const entry = addTimelineArtifact({ title: `CyberChef output: ${recipePipeline || "manual transform"}`, summary: `Recipe ${recipePipeline || "empty"}; output ${output.length} chars.`, source: "CyberChef", raw: output || input, tags: ["transform"] })
                      setNotice(`Added to Case Timeline: ${entry.title}`)
                    }}>Add to timeline</button>
                    <button
                      className="w-full rounded-lg px-2 py-1.5 text-left text-xs font-semibold text-zinc-200 hover:bg-white/5 hover:text-cyan-100"
                      onClick={() => {
                        setOutput("")
                        setSteps([])
                        setError("")
                        setOutputState("empty")
                        setOutputSignature("")
                      }}
                    >
                      <Eraser className="mr-2 inline h-3.5 w-3.5" />Clear output
                    </button>
                  </div>
                </details>
                <details className="relative">
                  <summary className={iconButtonClass()} title="Send output to another module">Send to</summary>
                  <div className="cyberchef-send-menu absolute right-0 z-20 mt-2 w-60 rounded-xl border border-white/10 bg-black/40 p-2 shadow-xl">
                    {[
                      ["smartParser", "Smart Parser"],
                      ["phishing", "Phishing Triage"],
                      ["recon", "Recon & Exposure"],
                      ["logs", "Logs & Alerts"],
                      ["detection", "Detection & MITRE"],
                    ].map(([target, label]) => (
                      <button
                        key={target}
                        type="button"
                        onClick={() => sendOutputTo(target)}
                        className="w-full rounded-lg px-2 py-1.5 text-left text-xs font-semibold text-zinc-200 hover:bg-white/5 hover:text-cyan-100"
                      >
                        Send to {label}
                      </button>
                    ))}
                  </div>
                </details>
              </div>
            </div>
            {outputStateMessage && <p className="border-b border-white/10 px-4 py-1.5 text-xs text-zinc-400">{outputStateMessage}</p>}
            <textarea
              value={output}
              readOnly
              placeholder={outputPlaceholder}
              wrap={wordWrap ? "soft" : "off"}
              className="min-h-0 flex-1 resize-none border-0 bg-black/40 p-4 font-mono text-sm leading-6 text-zinc-100 outline-none placeholder:text-zinc-600"
            />
            {(transformationSummary.length > 0 || output) && (
              <div className="shrink-0 border-t border-white/10 px-4 py-1.5 text-xs text-zinc-300">
                {transformationSummary.join(" · ")}
              </div>
            )}
            <div className="shrink-0 border-t border-white/10 px-4 py-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <button
                  type="button"
                  onClick={() => setSecretScanOpen((value) => !value)}
                  className="text-xs font-black uppercase tracking-[0.14em] text-zinc-300 hover:text-cyan-100"
                >
                  Sensitive data check: {secretFindings.length} finding{secretFindings.length === 1 ? "" : "s"}
                </button>
                <button
                  type="button"
                  onClick={() => setSecretScanOpen((value) => !value)}
                  className="text-[11px] font-semibold text-zinc-400 hover:text-cyan-100"
                >
                  {secretScanOpen ? "Hide details" : "Details"}
                </button>
              </div>
              {secretScanOpen && (
                secretFindings.length ? (
                  <div className="mt-2 max-h-28 space-y-2 overflow-auto">
                    {secretFindings.map((item) => (
                      <article key={`${item.type}-${item.line}-${item.preview}`} className="rounded-lg border border-white/10 bg-black/40 p-2">
                        <div className="flex flex-wrap gap-2">
                          <span className="ba-chip ba-status-warning">Line {item.line}</span>
                          <span className="ba-chip ba-status-info">{item.type}</span>
                          <span className="ba-chip ba-status-local">{item.confidence} evidence</span>
                        </div>
                        <p className="mt-1 break-all font-mono text-xs text-zinc-200">{item.preview}</p>
                        <p className="mt-1 text-xs text-zinc-400">{item.remediation}</p>
                      </article>
                    ))}
                  </div>
                ) : (
                  <p className="mt-1 text-xs text-zinc-500">No sensitive-data-like patterns detected in the current output or input.</p>
                )
              )}
              {!!steps.length && (
                <div className="mt-2 border-t border-white/10 pt-2">
                  <button
                    type="button"
                    onClick={() => setStepDetailsOpen((value) => !value)}
                    className="text-xs font-black uppercase tracking-[0.14em] text-zinc-300 hover:text-cyan-100"
                  >
                    Step outputs and raw details ({steps.length}) {stepDetailsOpen ? "−" : "+"}
                  </button>
                  {stepDetailsOpen && (
                    <div className="mt-2 max-h-48 space-y-2 overflow-auto">
                      {steps.map((step) => (
                        <div key={step.id} className={`rounded-xl border p-3 ${
                          step.status === "failed" ? "border-rose-400/25 bg-rose-400/10" : "border-white/10 bg-black/40"
                        }`}>
                          <div className="mb-2 flex items-center justify-between gap-3">
                            <p className="text-sm font-bold text-zinc-100">{step.operation}</p>
                            <span className={`rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase ${
                              step.status === "failed" ? "border-rose-400/25 text-rose-200" : "border-emerald-400/25 text-emerald-200"
                            }`}>
                              {step.status}
                            </span>
                          </div>
                          {step.error ? (
                            <p className="text-xs leading-5 text-rose-200">{step.error}</p>
                          ) : (
                            <pre className="max-h-32 overflow-auto whitespace-pre-wrap rounded-lg bg-black/40 p-3 text-xs text-zinc-200">
                              {step.output}
                            </pre>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </section>
      </div>

      {(output || input) && (
        <AnalystOutputCard
          title="Transform output quality"
          verdict={outputState === "error" ? "transform failed" : outputStale ? "stale output" : output ? "output ready" : "input only"}
          confidence={steps.length ? `${steps.filter((step) => step.status === "success").length}/${steps.length} step(s) succeeded` : "manual/local transform"}
          summary={transformationSummary.join(" · ") || "Use the output as a transformation artifact and verify it before adding to a case."}
          evidence={[recipePipeline ? `Recipe: ${recipePipeline}` : "No recipe selected", iocSummary.summary ? `IOCs: ${iocSummary.summary}` : "No IOCs extracted", secretFindings.length ? `${secretFindings.length} sensitive-data finding(s)` : "No sensitive-data-like pattern detected"]}
          limitations={["Transforms do not prove intent or maliciousness.", "Decoded content should not be executed.", outputStale ? "Output is stale; re-run before exporting." : "Output reflects the current recipe and input."]}
          nextActions={["Copy or export only the relevant output section.", "Send extracted IOCs to Intake, Recon, URL Analyzer, or Logs as appropriate.", "Add sensitive-data findings to a case only after confirming exposure."]}
          metrics={[
            ["Input chars", input.length],
            ["Output chars", output.length],
            ["Recipe steps", recipe.length],
          ]}
        />
      )}

      {(output || input) && (
        <section className="ba-workbench-panel ba-cyberchef-case-actions">
          <div>
            <p className="ba-panel-kicker"><Save className="mr-1.5 inline h-3.5 w-3.5" />Case handoff</p>
            <h2>Save or pivot this transform</h2>
            <p>Send decoded output, extracted indicators, or analyst summaries into the shared case workflow without leaving the utility workspace.</p>
          </div>
          <SendToActions payload={sendToPayload} source="CyberChef" setPage={setPage} />
        </section>
      )}

      {(notice || error) && (
        <div className={`rounded-lg border px-3 py-2 text-xs ${
          error ? "border-rose-400/25 bg-rose-400/10 text-rose-200" : "border-cyan-400/20 bg-cyan-400/10 text-cyan-100"
        }`}>
          {error || notice}
        </div>
      )}

    </WorkbenchPage>
  )
}
