import type { LucideIcon } from "lucide-react";
import {
  Search, Globe2, KeyRound, Wifi, Zap, Code2, Package,
  FileText, Cloud, Server, Image as ImageIcon,
} from "lucide-react";

export const CACHE_KEY = "ba.hacking.catalog.v3";
export const CACHE_TTL = 24 * 60 * 60 * 1000;
export const PIN_KEY = "ba.hacking.pinned";
export const HISTORY_KEY = "ba.hacking.history.v3";
export const MAX_HISTORY = 100;

export const ICON_MAP: Record<string, LucideIcon> = {
  search: Search, globe: Globe2, lock: KeyRound, wifi: Wifi, zap: Zap,
  code: Code2, package: Package, "file-text": FileText, cloud: Cloud,
  server: Server, image: ImageIcon,
};

export const TONE_MAP: Record<string, "primary" | "warning" | "destructive" | "success" | "info" | "accent"> = {
  information_gathering: "info",
  web_attack: "primary",
  password_attacks: "warning",
  forensics: "accent",
  wireless: "info",
  exploit: "destructive",
  reverse_engineering: "primary",
  payload: "warning",
  wordlist: "accent",
  cloud_security: "info",
  active_directory: "destructive",
  steganography: "accent",
};

export const PRESETS: Record<string, { label: string; args: string }[]> = {
  nmap: [{ label: "Quick", args: "-sV -T4 -F" }, { label: "Full A+O", args: "-sS -sV -sC -A -O" }, { label: "Stealth", args: "-sS -T2" }, { label: "Top-100", args: "--top-ports 100 -sV" }],
  sqlmap: [{ label: "Check inj", args: "--batch --level=1" }, { label: "Dump DBs", args: "--batch --dbs" }, { label: "Full L3 R2", args: "--batch --level=3 --risk=2" }],
  nuclei: [{ label: "All sev", args: "-severity low,medium,high,critical" }, { label: "Tech tag", args: "-tags tech" }],
  nikto: [{ label: "Default", args: "-ssl -Format txt" }, { label: "Tuning 1-3", args: "-Tuning 1 2 3" }],
  gobuster: [{ label: "Dir common", args: "dir -w /usr/share/wordlists/dirb/common.txt" }, { label: "DNS subs", args: "dns -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt" }],
  ffuf: [{ label: "Dir fuzz", args: "-w /usr/share/wordlists/dirb/common.txt -u FUZZ" }],
  hydra: [{ label: "SSH root", args: "-l root -P /usr/share/wordlists/rockyou.txt ssh" }, { label: "HTTP admin", args: "-l admin -P /usr/share/wordlists/rockyou.txt http-post-form" }],
  dirb: [{ label: "Common", args: "/usr/share/wordlists/dirb/common.txt" }, { label: "Big", args: "/usr/share/wordlists/dirb/big.txt" }],
  wpscan: [{ label: "Quick", args: "--enumerate vp,vt,u" }, { label: "Full", args: "--enumerate ap,at,cb,dbe" }],
  whatweb: [{ label: "Aggressive L3", args: "--aggression 3" }],
  wafw00f: [{ label: "Default", args: "" }],
  dnsrecon: [{ label: "Std", args: "-t std" }, { label: "Brute", args: "-t brt -D /usr/share/wordlists/dns/subdomains-top1million-5000.txt" }],
  theharvester: [{ label: "Google 50", args: "-b google -l 50" }, { label: "All 100", args: "-b all -l 100" }],
  amass: [{ label: "Passive", args: "-passive" }, { label: "Active", args: "-active" }],
  sublist3r: [{ label: "Default", args: "" }],
};

export type ToolInputField = {
  key: string;
  label: string;
  type: "text" | "number" | "dropdown" | "toggle";
  placeholder?: string;
  defaultValue?: string | number | boolean;
  options?: { label: string; value: string }[];
  group?: string;
  hint?: string;
  flag?: string | null;
};

export type ToolSchema = { fields: ToolInputField[] };

export const TOOL_SCHEMAS: Record<string, ToolSchema> = {
  nmap: { fields: [
    { key: "target", label: "Target", group: "Target", type: "text", placeholder: "scanme.nmap.org", flag: null },
    { key: "ports", label: "Ports", group: "Scan Options", type: "text", placeholder: "22,80,443", defaultValue: "1000", flag: "-p", hint: "Comma-separated or range (e.g. 1-1000)" },
    { key: "scan_type", label: "Scan type", group: "Scan Options", type: "dropdown", options: [{label:"SYN stealth",value:"-sS"},{label:"TCP connect",value:"-sT"},{label:"UDP",value:"-sU"},{label:"Ping",value:"-sn"}], defaultValue: "-sS", flag: "" },
    { key: "service_detect", label: "Service detect", group: "Detection", type: "toggle", defaultValue: true, flag: "-sV" },
    { key: "os_detect", label: "OS detection", group: "Detection", type: "toggle", defaultValue: false, flag: "-O" },
    { key: "aggressive", label: "Aggressive", group: "Detection", type: "toggle", defaultValue: false, flag: "-A" },
    { key: "script", label: "Script scan", group: "Scripting", type: "dropdown", options: [{label:"None",value:""},{label:"Default",value:"-sC"},{label:"Vuln",value:"--script=vuln"},{label:"Safe",value:"--script=safe"}], defaultValue: "", flag: "" },
  ]},
  dig: { fields: [
    { key: "domain", label: "Domain", group: "Target", type: "text", placeholder: "example.com", flag: null },
    { key: "type", label: "Record type", group: "Query", type: "dropdown", options: [{label:"ANY",value:"ANY"},{label:"A",value:"A"},{label:"AAAA",value:"AAAA"},{label:"MX",value:"MX"},{label:"NS",value:"NS"},{label:"TXT",value:"TXT"},{label:"CNAME",value:"CNAME"},{label:"SOA",value:"SOA"}], defaultValue: "ANY", flag: "" },
    { key: "server", label: "DNS server", group: "Server", type: "text", placeholder: "8.8.8.8 (optional)", defaultValue: "", flag: "@", hint: "Defaults to system resolver" },
  ]},
  ping: { fields: [
    { key: "host", label: "Host", group: "Target", type: "text", placeholder: "8.8.8.8", flag: null },
    { key: "count", label: "Count", group: "Options", type: "number", placeholder: "4", defaultValue: 4, flag: "-c", hint: "Number of echo requests" },
    { key: "flood", label: "Flood", group: "Options", type: "toggle", defaultValue: false, flag: "-f" },
  ]},
  hydra: { fields: [
    { key: "target", label: "Target", group: "Target", type: "text", placeholder: "192.168.1.1", flag: null },
    { key: "service", label: "Service", group: "Target", type: "dropdown", options: [{label:"ssh",value:"ssh"},{label:"ftp",value:"ftp"},{label:"http-post-form",value:"http-post-form"},{label:"https-post-form",value:"https-post-form"},{label:"mysql",value:"mysql"},{label:"rdp",value:"rdp"},{label:"smb",value:"smb"}], defaultValue: "ssh", flag: "" },
    { key: "username", label: "Username", group: "Credentials", type: "text", placeholder: "root", defaultValue: "", flag: "-l", hint: "Single username" },
    { key: "userlist", label: "User wordlist", group: "Credentials", type: "text", placeholder: "/path/to/users.txt", defaultValue: "", flag: "-L", hint: "Path to username wordlist" },
    { key: "password", label: "Password", group: "Credentials", type: "text", placeholder: "admin", defaultValue: "", flag: "-p", hint: "Single password" },
    { key: "wordlist", label: "Password wordlist", group: "Credentials", type: "text", placeholder: "/usr/share/wordlists/rockyou.txt", defaultValue: "", flag: "-P", hint: "Path to password wordlist" },
    { key: "threads", label: "Threads", group: "Performance", type: "number", placeholder: "16", defaultValue: 16, flag: "-t", hint: "Parallel tasks" },
  ]},
  sqlmap: { fields: [
    { key: "url", label: "URL", group: "Target", type: "text", placeholder: "http://example.com/page?id=1", flag: null, hint: "The injectable URL" },
    { key: "level", label: "Level", group: "Exploit", type: "dropdown", options: [{label:"1",value:"1"},{label:"2",value:"2"},{label:"3",value:"3"},{label:"4",value:"4"},{label:"5",value:"5"}], defaultValue: "1", flag: "--level=", hint: "Tests depth (1–5)" },
    { key: "risk", label: "Risk", group: "Exploit", type: "dropdown", options: [{label:"1",value:"1"},{label:"2",value:"2"},{label:"3",value:"3"}], defaultValue: "1", flag: "--risk=" },
    { key: "batch", label: "Batch mode", group: "Options", type: "toggle", defaultValue: true, flag: "--batch" },
    { key: "dbs", label: "Enumerate DBs", group: "Options", type: "toggle", defaultValue: false, flag: "--dbs" },
    { key: "tables", label: "Enumerate tables", group: "Options", type: "toggle", defaultValue: false, flag: "--tables" },
    { key: "dump", label: "Dump data", group: "Options", type: "toggle", defaultValue: false, flag: "--dump" },
  ]},
  gobuster: { fields: [
    { key: "mode", label: "Mode", group: "Mode", type: "dropdown", options: [{label:"dir",value:"dir"},{label:"dns",value:"dns"},{label:"vhost",value:"vhost"},{label:"fuzz",value:"fuzz"}], defaultValue: "dir", flag: "" },
    { key: "url", label: "Target URL/Domain", group: "Target", type: "text", placeholder: "http://example.com", flag: null },
    { key: "wordlist", label: "Wordlist", group: "Target", type: "text", placeholder: "/usr/share/wordlists/dirb/common.txt", flag: "-w" },
    { key: "extensions", label: "Extensions", group: "Options", type: "text", placeholder: "php,txt,html", defaultValue: "", flag: "-x", hint: "Comma-separated" },
    { key: "threads", label: "Threads", group: "Performance", type: "number", placeholder: "10", defaultValue: 10, flag: "-t" },
  ]},
  ffuf: { fields: [
    { key: "url", label: "Target URL", group: "Target", type: "text", placeholder: "http://example.com/FUZZ", flag: null, hint: "Use FUZZ keyword as placeholder" },
    { key: "wordlist", label: "Wordlist", group: "Target", type: "text", placeholder: "/usr/share/wordlists/dirb/common.txt", flag: "-w" },
    { key: "extensions", label: "Extensions", group: "Options", type: "text", placeholder: "php,txt,html", defaultValue: "", flag: "-e" },
    { key: "threads", label: "Threads", group: "Performance", type: "number", placeholder: "40", defaultValue: 40, flag: "-t" },
    { key: "recursion", label: "Recursion", group: "Options", type: "toggle", defaultValue: false, flag: "-recursion" },
  ]},
  theharvester: { fields: [
    { key: "domain", label: "Domain", group: "Target", type: "text", placeholder: "example.com", flag: null },
    { key: "source", label: "Source", group: "Source", type: "dropdown", options: [{label:"Google",value:"google"},{label:"Bing",value:"bing"},{label:"LinkedIn",value:"linkedin"},{label:"All",value:"all"}], defaultValue: "google", flag: "-b" },
    { key: "limit", label: "Results", group: "Source", type: "number", placeholder: "50", defaultValue: 50, flag: "-l" },
  ]},
  whois: { fields: [
    { key: "query", label: "Domain/IP", group: "Target", type: "text", placeholder: "example.com", flag: null },
  ]},
  nslookup: { fields: [
    { key: "query", label: "Domain/IP", group: "Target", type: "text", placeholder: "example.com", flag: null },
    { key: "type", label: "Type", group: "Options", type: "dropdown", options: [{label:"A",value:"-type=A"},{label:"AAAA",value:"-type=AAAA"},{label:"MX",value:"-type=MX"},{label:"NS",value:"-type=NS"},{label:"TXT",value:"-type=TXT"}, {label:"ANY",value:"-type=ANY"}], defaultValue: "-type=A", flag: "" },
    { key: "server", label: "Server", group: "Options", type: "text", placeholder: "8.8.8.8 (optional)", defaultValue: "", flag: "" },
  ]},
  traceroute: { fields: [
    { key: "host", label: "Host", group: "Target", type: "text", placeholder: "8.8.8.8", flag: null },
    { key: "max_hops", label: "Max hops", group: "Options", type: "number", placeholder: "30", defaultValue: 30, flag: "-m" },
    { key: "port", label: "Port", group: "Options", type: "number", placeholder: "80 (optional)", defaultValue: "", flag: "-p" },
  ]},
  curl: { fields: [
    { key: "url", label: "URL", group: "Target", type: "text", placeholder: "https://example.com", flag: null },
    { key: "method", label: "Method", group: "Request", type: "dropdown", options: [{label:"GET",value:""},{label:"HEAD",value:"-I"},{label:"POST",value:"-X POST"},{label:"PUT",value:"-X PUT"},{label:"DELETE",value:"-X DELETE"}], defaultValue: "", flag: "" },
    { key: "headers", label: "Headers", group: "Request", type: "text", placeholder: "-H 'Authorization: ...'", defaultValue: "", flag: "", hint: "Pass raw header flags" },
    { key: "data", label: "Request body", group: "Request", type: "text", placeholder: "key=value", defaultValue: "", flag: "-d" },
    { key: "follow", label: "Follow redirects", group: "Options", type: "toggle", defaultValue: false, flag: "-L" },
    { key: "verbose", label: "Verbose", group: "Options", type: "toggle", defaultValue: false, flag: "-v" },
  ]},
  nikto: { fields: [
    { key: "host", label: "Host", group: "Target", type: "text", placeholder: "http://example.com", flag: null },
    { key: "port", label: "Port", group: "Target", type: "number", placeholder: "80", defaultValue: 80, flag: "-port" },
    { key: "ssl", label: "SSL", group: "Options", type: "toggle", defaultValue: false, flag: "-ssl" },
    { key: "tuning", label: "Tuning", group: "Options", type: "text", placeholder: "1 2 3", defaultValue: "", flag: "-Tuning", hint: "Space-separated tuning values" },
  ]},
  nuclei: { fields: [
    { key: "target", label: "Target", group: "Target", type: "text", placeholder: "http://example.com", flag: null },
    { key: "severity", label: "Severity", group: "Scan", type: "dropdown", options: [{label:"All",value:""},{label:"Critical",value:"-severity critical"},{label:"High",value:"-severity high"},{label:"Medium",value:"-severity medium"},{label:"Low",value:"-severity low"},{label:"All",value:"-severity low,medium,high,critical"}], defaultValue: "-severity low,medium,high,critical", flag: "" },
    { key: "tags", label: "Tags", group: "Scan", type: "text", placeholder: "cve,tech,panel", defaultValue: "", flag: "-tags" },
    { key: "rate_limit", label: "Rate limit", group: "Performance", type: "number", placeholder: "150", defaultValue: 150, flag: "-rl" },
  ]},
  whatweb: { fields: [
    { key: "url", label: "URL", group: "Target", type: "text", placeholder: "http://example.com", flag: null },
    { key: "aggression", label: "Aggression", group: "Options", type: "dropdown", options: [{label:"1 — Stealthy",value:"1"},{label:"2 — Default",value:"2"},{label:"3 — Aggressive",value:"3"},{label:"4 — Heavy",value:"4"}], defaultValue: "3", flag: "--aggression" },
    { key: "verbose", label: "Verbose", group: "Options", type: "toggle", defaultValue: false, flag: "--verbose" },
  ]},
  wpscan: { fields: [
    { key: "url", label: "WordPress URL", group: "Target", type: "text", placeholder: "http://example.com", flag: null },
    { key: "enumerate", label: "Enumerate", group: "Scan", type: "dropdown", options: [{label:"Vuln plugins+themes+users",value:"--enumerate vp,vt,u"},{label:"All plugins",value:"--enumerate ap"},{label:"All themes",value:"--enumerate at"},{label:"Users",value:"--enumerate u"},{label:"Full",value:"--enumerate ap,at,cb,dbe"}], defaultValue: "--enumerate vp,vt,u", flag: "" },
    { key: "api_token", label: "WPScan API token", group: "Options", type: "text", placeholder: "(optional)", defaultValue: "", flag: "--api-token" },
  ]},
  dnsrecon: { fields: [
    { key: "domain", label: "Domain", group: "Target", type: "text", placeholder: "example.com", flag: null },
    { key: "type", label: "Scan type", group: "Scan", type: "dropdown", options: [{label:"Standard records",value:"-t std"},{label:"Brute force subdomains",value:"-t brt"},{label:"Zone transfer",value:"-t axfr"},{label:"Reverse lookup",value:"-t rvl"},{label:"SRV records",value:"-t srv"}], defaultValue: "-t std", flag: "" },
    { key: "wordlist", label: "Wordlist (brute)", group: "Scan", type: "text", placeholder: "/path/to/subdomains.txt (optional)", defaultValue: "", flag: "-D" },
    { key: "threads", label: "Threads", group: "Performance", type: "number", placeholder: "10", defaultValue: 10, flag: "--threads" },
  ]},
  amass: { fields: [
    { key: "domain", label: "Domain", group: "Target", type: "text", placeholder: "example.com", flag: null },
    { key: "mode", label: "Mode", group: "Mode", type: "dropdown", options: [{label:"Passive",value:"-passive"},{label:"Active",value:"-active"},{label:"Intel",value:"intel"}], defaultValue: "-passive", flag: "" },
    { key: "org", label: "Org name (Intel)", group: "Mode", type: "text", placeholder: "(optional for intel mode)", defaultValue: "", flag: "-org", hint: "Only for intel mode" },
  ]},
  sublist3r: { fields: [
    { key: "domain", label: "Domain", group: "Target", type: "text", placeholder: "example.com", flag: null },
    { key: "ports", label: "Ports", group: "Options", type: "text", placeholder: "80,443 (optional)", defaultValue: "", flag: "-p" },
    { key: "verbose", label: "Verbose", group: "Options", type: "toggle", defaultValue: false, flag: "-v" },
    { key: "threads", label: "Threads", group: "Performance", type: "number", placeholder: "30", defaultValue: 30, flag: "-t" },
  ]},
  dirb: { fields: [
    { key: "url", label: "Target URL", group: "Target", type: "text", placeholder: "http://example.com", flag: null },
    { key: "wordlist", label: "Wordlist", group: "Target", type: "text", placeholder: "/usr/share/wordlists/dirb/common.txt", flag: null },
    { key: "extensions", label: "Extensions", group: "Options", type: "text", placeholder: "php,txt,html", defaultValue: "", flag: "-X" },
    { key: "threads", label: "Threads", group: "Performance", type: "number", placeholder: "10", defaultValue: 10, flag: "-t" },
  ]},
  wafw00f: { fields: [
    { key: "url", label: "Target URL", group: "Target", type: "text", placeholder: "http://example.com", flag: null },
  ]},
  hashcat: { fields: [
    { key: "hash_file", label: "Hash file", group: "Input", type: "text", placeholder: "/path/to/hashes.txt", flag: null },
    { key: "wordlist", label: "Wordlist", group: "Input", type: "text", placeholder: "/usr/share/wordlists/rockyou.txt", flag: null },
    { key: "mode", label: "Hash type", group: "Mode", type: "dropdown", options: [{label:"MD5",value:"0"},{label:"SHA1",value:"100"},{label:"SHA256",value:"1400"},{label:"bcrypt",value:"3200"},{label:"NTLM",value:"1000"}], defaultValue: "0", flag: "-m" },
    { key: "rules", label: "Rules file", group: "Mode", type: "text", placeholder: "(optional)", defaultValue: "", flag: "-r" },
  ]},
  john: { fields: [
    { key: "hash_file", label: "Hash file", group: "Input", type: "text", placeholder: "/path/to/hashes.txt", flag: null },
    { key: "wordlist", label: "Wordlist", group: "Input", type: "text", placeholder: "/usr/share/wordlists/rockyou.txt", defaultValue: "", flag: "--wordlist=" },
    { key: "format", label: "Format", group: "Mode", type: "text", placeholder: "raw-md5 (optional)", defaultValue: "", flag: "--format=" },
  ]},
  searchsploit: { fields: [
    { key: "query", label: "Search term", group: "Search", type: "text", placeholder: "Apache 2.4.49", flag: null, hint: "Keyword or CVE ID" },
    { key: "exact", label: "Exact match", group: "Options", type: "toggle", defaultValue: false, flag: "-e" },
    { key: "case_sensitive", label: "Case-sensitive", group: "Options", type: "toggle", defaultValue: false, flag: "-c" },
    { key: "title", label: "Title only", group: "Options", type: "toggle", defaultValue: false, flag: "-t" },
  ]},
  binwalk: { fields: [
    { key: "file", label: "File path", group: "Input", type: "text", placeholder: "/path/to/firmware.bin", flag: null },
    { key: "extract", label: "Extract", group: "Actions", type: "toggle", defaultValue: false, flag: "-e" },
    { key: "me", label: "Extract + matryoshka", group: "Actions", type: "toggle", defaultValue: false, flag: "-Me", hint: "Recursive extraction" },
  ]},
  foremost: { fields: [
    { key: "file", label: "File path", group: "Input", type: "text", placeholder: "/path/to/image.dd", flag: null },
    { key: "output", label: "Output dir", group: "Options", type: "text", placeholder: "/tmp/foremost_output", defaultValue: "", flag: "-o" },
    { key: "types", label: "File types", group: "Options", type: "text", placeholder: "jpeg,png,gif", defaultValue: "", flag: "-t" },
  ]},
  volatility3: { fields: [
    { key: "file", label: "Memory image", group: "Input", type: "text", placeholder: "/path/to/memory.dump", flag: null },
    { key: "profile", label: "Profile", group: "Input", type: "text", placeholder: "Win10x64_19041", defaultValue: "", flag: null, hint: "Auto-detected if omitted" },
    { key: "plugin", label: "Plugin", group: "Analysis", type: "dropdown", options: [{label:"pslist",value:"windows.pslist"},{label:"pstree",value:"windows.pstree"},{label:"netscan",value:"windows.netscan"},{label:"cmdline",value:"windows.cmdline.CmdLine"},{label:"filescan",value:"windows.filescan"},{label:"registry",value:"windows.registry"}], defaultValue: "windows.pslist", flag: null, hint: "Analysis plugin to run" },
  ]},
  trivy: { fields: [
    { key: "target", label: "Target", group: "Target", type: "text", placeholder: "alpine:latest or /path/to/project", flag: null },
    { key: "scan_type", label: "Scan type", group: "Target", type: "dropdown", options: [{label:"Container image",value:"image"},{label:"Filesystem",value:"filesystem"},{label:"Git repo",value:"repo"},{label:"K8s cluster",value:"k8s"}], defaultValue: "image", flag: "" },
    { key: "severity", label: "Min severity", group: "Output", type: "dropdown", options: [{label:"CRITICAL",value:"CRITICAL"},{label:"HIGH",value:"HIGH"},{label:"MEDIUM",value:"MEDIUM"},{label:"LOW",value:"LOW"},{label:"All",value:"CRITICAL,HIGH,MEDIUM,LOW"}], defaultValue: "CRITICAL,HIGH", flag: "--severity" },
    { key: "format", label: "Output format", group: "Output", type: "dropdown", options: [{label:"table",value:"table"},{label:"json",value:"json"},{label:"sarif",value:"sarif"}], defaultValue: "table", flag: "--format" },
  ]},
  impacket: { fields: [
    { key: "script", label: "Script", group: "Mode", type: "dropdown", options: [{label:"secretsdump",value:"secretsdump"},{label:"psexec",value:"psexec"},{label:"smbexec",value:"smbexec"},{label:"wmiexec",value:"wmiexec"},{label:"GetADUsers",value:"GetADUsers"},{label:"GetNPUsers",value:"GetNPUsers"}], defaultValue: "secretsdump", flag: null },
    { key: "target", label: "Target", group: "Target", type: "text", placeholder: "domain/user:pass@target", flag: null },
  ]},
  responder: { fields: [
    { key: "interface", label: "Interface", group: "Target", type: "text", placeholder: "eth0", flag: "-I" },
    { key: "mode", label: "Mode", group: "Mode", type: "dropdown", options: [{label:"Analyze only",value:"-A"},{label:"Full",value:""},{label:"DHCP",value:"--dhcp"},{label:"HTTP/FTP/SMB/LDAP",value:"-w"},{label:"Only NBT-NS",value:"--NBTNS"}], defaultValue: "", flag: "" },
    { key: "verbose", label: "Verbose", group: "Options", type: "toggle", defaultValue: false, flag: "-v" },
  ]},
  bloodhound: { fields: [
    { key: "method", label: "Method", group: "Mode", type: "dropdown", options: [{label:"Collector",value:"-c"},{label:"Ingest",value:"-u"}], defaultValue: "-c", flag: "" },
    { key: "target", label: "Target/Domain", group: "Target", type: "text", placeholder: "DOMAIN.local", flag: null },
    { key: "username", label: "Username", group: "Options", type: "text", placeholder: "user (optional)", defaultValue: "", flag: "-u" },
  ]},
  stegocracker: { fields: [
    { key: "file", label: "File path", group: "Input", type: "text", placeholder: "/path/to/stego_file", flag: null },
    { key: "wordlist", label: "Wordlist", group: "Input", type: "text", placeholder: "/usr/share/wordlists/rockyou.txt", flag: null },
  ]},
};

export function buildArgsFromSchema(toolId: string, fields: Record<string, any>): string {
  const schema = TOOL_SCHEMAS[toolId];
  if (!schema) return "";
  const parts: string[] = [];
  schema.fields.forEach(f => {
    const val = fields[f.key] ?? f.defaultValue ?? "";
    if (val === "" || val === false || val === 0) return;
    if (f.flag === null) return;
    if (f.flag === "") {
      parts.push(String(val));
    } else if (f.type === "number" || f.type === "text") {
      if (f.flag === "@") {
        parts.push(`@${val}`);
      } else {
        parts.push(`${f.flag} ${val}`);
      }
    } else if (f.type === "toggle") {
      if (val) parts.push(f.flag ?? "");
    }
  });
  return parts.join(" ");
}

export function defaultFieldValues(toolId: string): Record<string, any> {
  const schema = TOOL_SCHEMAS[toolId];
  if (!schema) return {};
  const vals: Record<string, any> = {};
  schema.fields.forEach(f => {
    vals[f.key] = f.defaultValue ?? (f.type === "toggle" ? false : "");
  });
  return vals;
}

export function getTargetFromSchema(toolId: string, fields: Record<string, any>): string {
  const schema = TOOL_SCHEMAS[toolId];
  if (!schema) return "";
  const positional = schema.fields.find(f => f.flag === null);
  return positional ? String(fields[positional.key] ?? "") : "";
}

export type BackendTool = { id: string; name: string; binary: string; installed: boolean };
export type BackendCategory = { id: string; name: string; icon: string; tools: BackendTool[] };

export type HistoryEntry = {
  id: string;
  toolId: string;
  toolName: string;
  binary: string;
  catName: string;
  target: string;
  args: string;
  command: string;
  status: string;
  body: string;
  ts: number;
};

export function genId() { return crypto.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`; }

export function loadHistory(): HistoryEntry[] {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch { return []; }
}
export function saveHistory(h: HistoryEntry[]) {
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(h.slice(0, MAX_HISTORY))); } catch {}
}

export function loadCachedCatalog(): BackendCategory[] | null {
  try {
    const raw = localStorage.getItem(CACHE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed._cachedAt && Date.now() - parsed._cachedAt > CACHE_TTL) {
      localStorage.removeItem(CACHE_KEY);
      return null;
    }
    const { _cachedAt, ...data } = parsed;
    return data.categories ?? parsed;
  } catch { return null; }
}
