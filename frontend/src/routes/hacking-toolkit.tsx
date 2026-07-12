import { useEffect, useMemo, useState, useCallback } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { PageShell } from "@/components/PageShell";
import { getHackingtoolCategories, runHackingtoolTool } from "@/api/backend";
import { Panel, SectionBar, Chip, Field, SendToRow } from "@/components/soc";
import { Empty, ResultBanner, EvidenceCard } from "@/components/output";
import { useOutputFilter, OutputFilterBar, OutputFilter } from "@/components/soc/OutputFilter";
import { PreviewBadge } from "@/components/PreviewBadge";
import { sendArtifact, takePendingArtifact } from "@/lib/handoff";
import { pushTimelineEvent } from "@/lib/timeline";
import { toast } from "sonner";
import { PanelSkeleton } from "@/components/Skeleton";
import { TerminalOutput } from "@/components/soc/TerminalOutput";
import { NmapOutput } from "@/components/output/NmapOutput";
import type { LucideIcon } from "lucide-react";
import {
  Swords, Search, Globe2, KeyRound, Wifi, Zap, Code2, Package,
  FileText, Cloud, Server, Image as ImageIcon, Terminal, Copy, Check,
  X, AlertTriangle, ChevronRight, Sparkles, Send, Pin, PinOff,
  Loader2, Bug, History, RotateCcw, Clock, Trash2,
} from "lucide-react";

export const Route = createFileRoute("/hacking-toolkit")({ component: HackingToolkitPage });

const CACHE_KEY = "ba.hacking.catalog.v3";
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24h
const PIN_KEY = "ba.hacking.pinned";
const HISTORY_KEY = "ba.hacking.history.v3";
const MAX_HISTORY = 100;

const ICON_MAP: Record<string, LucideIcon> = {
  search: Search, globe: Globe2, lock: KeyRound, wifi: Wifi, zap: Zap,
  code: Code2, package: Package, "file-text": FileText, cloud: Cloud,
  server: Server, image: ImageIcon,
};

const TONE_MAP: Record<string, "primary" | "warning" | "destructive" | "success" | "info" | "accent"> = {
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

const PRESETS: Record<string, { label: string; args: string }[]> = {
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

/* ── Per-tool input schemas ── */
type ToolInputField = {
  key: string;
  label: string;
  type: "text" | "number" | "dropdown" | "toggle";
  placeholder?: string;
  defaultValue?: string | number | boolean;
  options?: { label: string; value: string }[];
  /** If set, the value is joined with the flag (e.g. "-p 80,443"). If null, value is a positional arg. */
  flag?: string | null;
};
type ToolSchema = { fields: ToolInputField[] };

const TOOL_SCHEMAS: Record<string, ToolSchema> = {
  nmap: { fields: [
    { key: "target", label: "Target", type: "text", placeholder: "scanme.nmap.org", flag: null },
    { key: "ports", label: "Ports", type: "text", placeholder: "22,80,443", defaultValue: "1000", flag: "-p" },
    { key: "scan_type", label: "Scan type", type: "dropdown", options: [{label:"SYN stealth",value:"-sS"},{label:"TCP connect",value:"-sT"},{label:"UDP",value:"-sU"},{label:"Ping",value:"-sn"}], defaultValue: "-sS", flag: "" },
    { key: "service_detect", label: "Service detect", type: "toggle", defaultValue: true, flag: "-sV" },
    { key: "os_detect", label: "OS detection", type: "toggle", defaultValue: false, flag: "-O" },
    { key: "aggressive", label: "Aggressive", type: "toggle", defaultValue: false, flag: "-A" },
    { key: "script", label: "Script scan", type: "dropdown", options: [{label:"None",value:""},{label:"Default",value:"-sC"},{label:"Vuln",value:"--script=vuln"},{label:"Safe",value:"--script=safe"}], defaultValue: "", flag: "" },
  ]},
  dig: { fields: [
    { key: "domain", label: "Domain", type: "text", placeholder: "example.com", flag: null },
    { key: "type", label: "Record type", type: "dropdown", options: [{label:"ANY",value:"ANY"},{label:"A",value:"A"},{label:"AAAA",value:"AAAA"},{label:"MX",value:"MX"},{label:"NS",value:"NS"},{label:"TXT",value:"TXT"},{label:"CNAME",value:"CNAME"},{label:"SOA",value:"SOA"}], defaultValue: "ANY", flag: "" },
    { key: "server", label: "DNS server", type: "text", placeholder: "8.8.8.8 (optional)", defaultValue: "", flag: "@" },
  ]},
  ping: { fields: [
    { key: "host", label: "Host", type: "text", placeholder: "8.8.8.8", flag: null },
    { key: "count", label: "Count", type: "number", placeholder: "4", defaultValue: 4, flag: "-c" },
    { key: "flood", label: "Flood", type: "toggle", defaultValue: false, flag: "-f" },
  ]},
  hydra: { fields: [
    { key: "target", label: "Target", type: "text", placeholder: "192.168.1.1", flag: null },
    { key: "username", label: "Username", type: "text", placeholder: "root", defaultValue: "", flag: "-l" },
    { key: "userlist", label: "User wordlist", type: "text", placeholder: "/path/to/users.txt", defaultValue: "", flag: "-L" },
    { key: "password", label: "Password", type: "text", placeholder: "admin", defaultValue: "", flag: "-p" },
    { key: "wordlist", label: "Password wordlist", type: "text", placeholder: "/usr/share/wordlists/rockyou.txt", defaultValue: "", flag: "-P" },
    { key: "service", label: "Service", type: "dropdown", options: [{label:"ssh",value:"ssh"},{label:"ftp",value:"ftp"},{label:"http-post-form",value:"http-post-form"},{label:"https-post-form",value:"https-post-form"},{label:"mysql",value:"mysql"},{label:"rdp",value:"rdp"},{label:"smb",value:"smb"}], defaultValue: "ssh", flag: "" },
    { key: "threads", label: "Threads", type: "number", placeholder: "16", defaultValue: 16, flag: "-t" },
  ]},
  sqlmap: { fields: [
    { key: "url", label: "URL", type: "text", placeholder: "http://example.com/page?id=1", flag: null },
    { key: "level", label: "Level", type: "dropdown", options: [{label:"1",value:"1"},{label:"2",value:"2"},{label:"3",value:"3"},{label:"4",value:"4"},{label:"5",value:"5"}], defaultValue: "1", flag: "--level=" },
    { key: "risk", label: "Risk", type: "dropdown", options: [{label:"1",value:"1"},{label:"2",value:"2"},{label:"3",value:"3"}], defaultValue: "1", flag: "--risk=" },
    { key: "batch", label: "Batch mode", type: "toggle", defaultValue: true, flag: "--batch" },
    { key: "dbs", label: "Enumerate DBs", type: "toggle", defaultValue: false, flag: "--dbs" },
    { key: "tables", label: "Enumerate tables", type: "toggle", defaultValue: false, flag: "--tables" },
    { key: "dump", label: "Dump data", type: "toggle", defaultValue: false, flag: "--dump" },
  ]},
  gobuster: { fields: [
    { key: "mode", label: "Mode", type: "dropdown", options: [{label:"dir",value:"dir"},{label:"dns",value:"dns"},{label:"vhost",value:"vhost"},{label:"fuzz",value:"fuzz"}], defaultValue: "dir", flag: "" },
    { key: "url", label: "Target URL/Domain", type: "text", placeholder: "http://example.com", flag: null },
    { key: "wordlist", label: "Wordlist", type: "text", placeholder: "/usr/share/wordlists/dirb/common.txt", flag: "-w" },
    { key: "extensions", label: "Extensions", type: "text", placeholder: "php,txt,html", defaultValue: "", flag: "-x" },
    { key: "threads", label: "Threads", type: "number", placeholder: "10", defaultValue: 10, flag: "-t" },
  ]},
  ffuf: { fields: [
    { key: "url", label: "Target URL", type: "text", placeholder: "http://example.com/FUZZ", flag: null },
    { key: "wordlist", label: "Wordlist", type: "text", placeholder: "/usr/share/wordlists/dirb/common.txt", flag: "-w" },
    { key: "extensions", label: "Extensions", type: "text", placeholder: "php,txt,html", defaultValue: "", flag: "-e" },
    { key: "threads", label: "Threads", type: "number", placeholder: "40", defaultValue: 40, flag: "-t" },
    { key: "recursion", label: "Recursion", type: "toggle", defaultValue: false, flag: "-recursion" },
  ]},
  theharvester: { fields: [
    { key: "domain", label: "Domain", type: "text", placeholder: "example.com", flag: null },
    { key: "source", label: "Source", type: "dropdown", options: [{label:"Google",value:"google"},{label:"Bing",value:"bing"},{label:"LinkedIn",value:"linkedin"},{label:"All",value:"all"}], defaultValue: "google", flag: "-b" },
    { key: "limit", label: "Results", type: "number", placeholder: "50", defaultValue: 50, flag: "-l" },
  ]},
  whois: { fields: [
    { key: "query", label: "Domain/IP", type: "text", placeholder: "example.com", flag: null },
  ]},
  nslookup: { fields: [
    { key: "query", label: "Domain/IP", type: "text", placeholder: "example.com", flag: null },
    { key: "type", label: "Type", type: "dropdown", options: [{label:"A",value:"-type=A"},{label:"AAAA",value:"-type=AAAA"},{label:"MX",value:"-type=MX"},{label:"NS",value:"-type=NS"},{label:"TXT",value:"-type=TXT"}, {label:"ANY",value:"-type=ANY"}], defaultValue: "-type=A", flag: "" },
    { key: "server", label: "Server", type: "text", placeholder: "8.8.8.8 (optional)", defaultValue: "", flag: null },
  ]},
  traceroute: { fields: [
    { key: "host", label: "Host", type: "text", placeholder: "8.8.8.8", flag: null },
    { key: "max_hops", label: "Max hops", type: "number", placeholder: "30", defaultValue: 30, flag: "-m" },
    { key: "port", label: "Port", type: "number", placeholder: "80 (optional)", defaultValue: "", flag: "-p" },
  ]},
  curl: { fields: [
    { key: "url", label: "URL", type: "text", placeholder: "https://example.com", flag: null },
    { key: "method", label: "Method", type: "dropdown", options: [{label:"GET",value:""},{label:"HEAD",value:"-I"},{label:"POST",value:"-X POST"},{label:"PUT",value:"-X PUT"},{label:"DELETE",value:"-X DELETE"}], defaultValue: "", flag: "" },
    { key: "headers", label: "Headers", type: "text", placeholder: "-H 'Authorization: ...'", defaultValue: "", flag: "" },
    { key: "follow", label: "Follow redirects", type: "toggle", defaultValue: false, flag: "-L" },
    { key: "verbose", label: "Verbose", type: "toggle", defaultValue: false, flag: "-v" },
    { key: "data", label: "Request body", type: "text", placeholder: "key=value", defaultValue: "", flag: "-d" },
  ]},
  nikto: { fields: [
    { key: "host", label: "Host", type: "text", placeholder: "http://example.com", flag: null },
    { key: "port", label: "Port", type: "number", placeholder: "80", defaultValue: 80, flag: "-port" },
    { key: "ssl", label: "SSL", type: "toggle", defaultValue: false, flag: "-ssl" },
    { key: "tuning", label: "Tuning", type: "text", placeholder: "1 2 3", defaultValue: "", flag: "-Tuning" },
  ]},
  nuclei: { fields: [
    { key: "target", label: "Target", type: "text", placeholder: "http://example.com", flag: null },
    { key: "severity", label: "Severity", type: "dropdown", options: [{label:"All",value:""},{label:"Critical",value:"-severity critical"},{label:"High",value:"-severity high"},{label:"Medium",value:"-severity medium"},{label:"Low",value:"-severity low"},{label:"All",value:"-severity low,medium,high,critical"}], defaultValue: "-severity low,medium,high,critical", flag: "" },
    { key: "tags", label: "Tags", type: "text", placeholder: "cve,tech,panel", defaultValue: "", flag: "-tags" },
    { key: "rate_limit", label: "Rate limit", type: "number", placeholder: "150", defaultValue: 150, flag: "-rl" },
  ]},
  whatweb: { fields: [
    { key: "url", label: "URL", type: "text", placeholder: "http://example.com", flag: null },
    { key: "aggression", label: "Aggression", type: "dropdown", options: [{label:"1 — Stealthy",value:"1"},{label:"2 — Default",value:"2"},{label:"3 — Aggressive",value:"3"},{label:"4 — Heavy",value:"4"}], defaultValue: "3", flag: "--aggression" },
    { key: "verbose", label: "Verbose", type: "toggle", defaultValue: false, flag: "--verbose" },
  ]},
  wpscan: { fields: [
    { key: "url", label: "WordPress URL", type: "text", placeholder: "http://example.com", flag: null },
    { key: "enumerate", label: "Enumerate", type: "dropdown", options: [{label:"Vuln plugins+themes+users",value:"--enumerate vp,vt,u"},{label:"All plugins",value:"--enumerate ap"},{label:"All themes",value:"--enumerate at"},{label:"Users",value:"--enumerate u"},{label:"Full",value:"--enumerate ap,at,cb,dbe"}], defaultValue: "--enumerate vp,vt,u", flag: "" },
    { key: "api_token", label: "WPScan API token", type: "text", placeholder: "(optional)", defaultValue: "", flag: "--api-token" },
  ]},
  dnsrecon: { fields: [
    { key: "domain", label: "Domain", type: "text", placeholder: "example.com", flag: null },
    { key: "type", label: "Scan type", type: "dropdown", options: [{label:"Standard records",value:"-t std"},{label:"Brute force subdomains",value:"-t brt"},{label:"Zone transfer",value:"-t axfr"},{label:"Reverse lookup",value:"-t rvl"},{label:"SRV records",value:"-t srv"}], defaultValue: "-t std", flag: "" },
    { key: "wordlist", label: "Wordlist (brute)", type: "text", placeholder: "/path/to/subdomains.txt (optional)", defaultValue: "", flag: "-D" },
    { key: "threads", label: "Threads", type: "number", placeholder: "10", defaultValue: 10, flag: "--threads" },
  ]},
  amass: { fields: [
    { key: "domain", label: "Domain", type: "text", placeholder: "example.com", flag: null },
    { key: "mode", label: "Mode", type: "dropdown", options: [{label:"Passive",value:"-passive"},{label:"Active",value:"-active"},{label:"Intel",value:"intel"}], defaultValue: "-passive", flag: "" },
    { key: "org", label: "Org name (Intel)", type: "text", placeholder: "(optional for intel mode)", defaultValue: "", flag: "-org" },
  ]},
  sublist3r: { fields: [
    { key: "domain", label: "Domain", type: "text", placeholder: "example.com", flag: null },
    { key: "ports", label: "Ports", type: "text", placeholder: "80,443 (optional)", defaultValue: "", flag: "-p" },
    { key: "verbose", label: "Verbose", type: "toggle", defaultValue: false, flag: "-v" },
    { key: "threads", label: "Threads", type: "number", placeholder: "30", defaultValue: 30, flag: "-t" },
  ]},
  dirb: { fields: [
    { key: "url", label: "Target URL", type: "text", placeholder: "http://example.com", flag: null },
    { key: "wordlist", label: "Wordlist", type: "text", placeholder: "/usr/share/wordlists/dirb/common.txt", flag: null },
    { key: "extensions", label: "Extensions", type: "text", placeholder: "php,txt,html", defaultValue: "", flag: "-X" },
    { key: "threads", label: "Threads", type: "number", placeholder: "10", defaultValue: 10, flag: "-t" },
  ]},
  wafw00f: { fields: [
    { key: "url", label: "Target URL", type: "text", placeholder: "http://example.com", flag: null },
  ]},
  hashcat: { fields: [
    { key: "hash_file", label: "Hash file", type: "text", placeholder: "/path/to/hashes.txt", flag: null },
    { key: "wordlist", label: "Wordlist", type: "text", placeholder: "/usr/share/wordlists/rockyou.txt", flag: null },
    { key: "mode", label: "Hash type", type: "dropdown", options: [{label:"MD5",value:"0"},{label:"SHA1",value:"100"},{label:"SHA256",value:"1400"},{label:"bcrypt",value:"3200"},{label:"NTLM",value:"1000"}], defaultValue: "0", flag: "-m" },
    { key: "rules", label: "Rules file", type: "text", placeholder: "(optional)", defaultValue: "", flag: "-r" },
  ]},
  john: { fields: [
    { key: "hash_file", label: "Hash file", type: "text", placeholder: "/path/to/hashes.txt", flag: null },
    { key: "wordlist", label: "Wordlist", type: "text", placeholder: "/usr/share/wordlists/rockyou.txt", defaultValue: "", flag: "--wordlist=" },
    { key: "format", label: "Format", type: "text", placeholder: "raw-md5 (optional)", defaultValue: "", flag: "--format=" },
  ]},
  searchsploit: { fields: [
    { key: "query", label: "Search term", type: "text", placeholder: "Apache 2.4.49", flag: null },
    { key: "exact", label: "Exact match", type: "toggle", defaultValue: false, flag: "-e" },
    { key: "case_sensitive", label: "Case-sensitive", type: "toggle", defaultValue: false, flag: "-c" },
    { key: "title", label: "Title only", type: "toggle", defaultValue: false, flag: "-t" },
  ]},
  binwalk: { fields: [
    { key: "file", label: "File path", type: "text", placeholder: "/path/to/firmware.bin", flag: null },
    { key: "extract", label: "Extract", type: "toggle", defaultValue: false, flag: "-e" },
    { key: "me", label: "Extract + matryoshka", type: "toggle", defaultValue: false, flag: "-Me" },
  ]},
  foremost: { fields: [
    { key: "file", label: "File path", type: "text", placeholder: "/path/to/image.dd", flag: null },
    { key: "output", label: "Output dir", type: "text", placeholder: "/tmp/foremost_output", defaultValue: "", flag: "-o" },
    { key: "types", label: "File types", type: "text", placeholder: "jpeg,png,gif", defaultValue: "", flag: "-t" },
  ]},
  volatility3: { fields: [
    { key: "file", label: "Memory image", type: "text", placeholder: "/path/to/memory.dump", flag: null },
    { key: "profile", label: "Profile", type: "text", placeholder: "Win10x64_19041", defaultValue: "", flag: null },
    { key: "plugin", label: "Plugin", type: "dropdown", options: [{label:"pslist",value:"windows.pslist"},{label:"pstree",value:"windows.pstree"},{label:"netscan",value:"windows.netscan"},{label:"cmdline",value:"windows.cmdline.CmdLine"},{label:"filescan",value:"windows.filescan"},{label:"registry",value:"windows.registry"}], defaultValue: "windows.pslist", flag: null },
  ]},
  trivy: { fields: [
    { key: "target", label: "Target", type: "text", placeholder: "alpine:latest or /path/to/project", flag: null },
    { key: "scan_type", label: "Scan type", type: "dropdown", options: [{label:"Container image",value:"image"},{label:"Filesystem",value:"filesystem"},{label:"Git repo",value:"repo"},{label:"K8s cluster",value:"k8s"}], defaultValue: "image", flag: "" },
    { key: "severity", label: "Min severity", type: "dropdown", options: [{label:"CRITICAL",value:"CRITICAL"},{label:"HIGH",value:"HIGH"},{label:"MEDIUM",value:"MEDIUM"},{label:"LOW",value:"LOW"},{label:"All",value:"CRITICAL,HIGH,MEDIUM,LOW"}], defaultValue: "CRITICAL,HIGH", flag: "--severity" },
    { key: "format", label: "Output format", type: "dropdown", options: [{label:"table",value:"table"},{label:"json",value:"json"},{label:"sarif",value:"sarif"}], defaultValue: "table", flag: "--format" },
  ]},
  impacket: { fields: [
    { key: "script", label: "Script", type: "dropdown", options: [{label:"secretsdump",value:"secretsdump"},{label:"psexec",value:"psexec"},{label:"smbexec",value:"smbexec"},{label:"wmiexec",value:"wmiexec"},{label:"GetADUsers",value:"GetADUsers"},{label:"GetNPUsers",value:"GetNPUsers"}], defaultValue: "secretsdump", flag: null },
    { key: "target", label: "Target", type: "text", placeholder: "domain/user:pass@target", flag: null },
  ]},
  responder: { fields: [
    { key: "interface", label: "Interface", type: "text", placeholder: "eth0", flag: "-I" },
    { key: "mode", label: "Mode", type: "dropdown", options: [{label:"Analyze only",value:"-A"},{label:"Full",value:""},{label:"DHCP",value:"--dhcp"},{label:"HTTP/FTP/SMB/LDAP",value:"-w"},{label:"Only NBT-NS",value:"--NBTNS"}], defaultValue: "", flag: "" },
    { key: "verbose", label: "Verbose", type: "toggle", defaultValue: false, flag: "-v" },
  ]},
  bloodhound: { fields: [
    { key: "method", label: "Method", type: "dropdown", options: [{label:"Collector",value:"-c"},{label:"Ingest",value:"-u"}], defaultValue: "-c", flag: null },
    { key: "target", label: "Target/Domain", type: "text", placeholder: "DOMAIN.local", flag: null },
    { key: "username", label: "Username", type: "text", placeholder: "user (optional)", defaultValue: "", flag: "-u" },
  ]},
  stegocracker: { fields: [
    { key: "file", label: "File path", type: "text", placeholder: "/path/to/stego_file", flag: null },
    { key: "wordlist", label: "Wordlist", type: "text", placeholder: "/usr/share/wordlists/rockyou.txt", flag: null },
  ]},
};

function buildArgsFromSchema(toolId: string, fields: Record<string, any>): string {
  const schema = TOOL_SCHEMAS[toolId];
  if (!schema) return "";
  const parts: string[] = [];
  schema.fields.forEach(f => {
    const val = fields[f.key] ?? f.defaultValue ?? "";
    if (val === "" || val === false || val === 0) return;
    if (f.flag === null) {
      // positional — already used as target
      return;
    }
    if (f.flag === "") {
      // flag contains the entire value already (e.g. "--severity high" or "-p")
      parts.push(String(val));
    } else if (f.type === "number" || f.type === "text") {
      parts.push(`${f.flag} ${val}`);
    } else if (f.type === "toggle") {
      if (val) parts.push(f.flag ?? "");
    }
  });
  return parts.join(" ");
}

function defaultFieldValues(toolId: string): Record<string, any> {
  const schema = TOOL_SCHEMAS[toolId];
  if (!schema) return {};
  const vals: Record<string, any> = {};
  schema.fields.forEach(f => {
    vals[f.key] = f.defaultValue ?? (f.type === "toggle" ? false : "");
  });
  return vals;
}

function getTargetFromSchema(toolId: string, fields: Record<string, any>): string {
  const schema = TOOL_SCHEMAS[toolId];
  if (!schema) return "";
  const positional = schema.fields.find(f => f.flag === null);
  return positional ? String(fields[positional.key] ?? "") : "";
}

type BackendTool = { id: string; name: string; binary: string; installed: boolean };
type BackendCategory = { id: string; name: string; icon: string; tools: BackendTool[] };

type HistoryEntry = {
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

function genId() { return crypto.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`; }

function loadHistory(): HistoryEntry[] {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch { return []; }
}
function saveHistory(h: HistoryEntry[]) {
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(h.slice(0, MAX_HISTORY))); } catch {}
}

function HackingToolkitPage() {
  const { filterText, setFilterText, showFilter, setShowFilter, toggleFilter } = useOutputFilter();
  const [cats, setCats] = useState<BackendCategory[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [installed, setInstalled] = useState(false);
  const [offline, setOffline] = useState(false);
  const [activeCatId, setActiveCatId] = useState<string>("");
  const [activeToolId, setActiveToolId] = useState<string>("");
  const [search, setSearch] = useState("");
  const [targets, setTargets] = useState<Record<string, string>>(() => {
    try { return JSON.parse(localStorage.getItem("ba.hacking.targets.v2") || "{}"); } catch { return {}; }
  });
  const [argsMap, setArgsMap] = useState<Record<string, string>>(() => {
    try { return JSON.parse(localStorage.getItem("ba.hacking.args.v2") || "{}"); } catch { return {}; }
  });
  const [outputs, setOutputs] = useState<Record<string, { command: string; status: string; body: string } | null>>({});
  const [running, setRunning] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [pinned, setPinned] = useState<Set<string>>(new Set());
  const [history, setHistory] = useState<HistoryEntry[]>(() => loadHistory());
  const [showHistory, setShowHistory] = useState(false);
  const [historyFilter, setHistoryFilter] = useState("");
  const [fieldValues, setFieldValues] = useState<Record<string, Record<string, any>>>({});
  const [nmapConfirmed, setNmapConfirmed] = useState(false);
  const [nmapMode, setNmapMode] = useState("service");
  const [scanStartTime, setScanStartTime] = useState<number | null>(null);

  const NMAP_MODES = useMemo(() => [
    { k: "discovery", label: "Discovery",         args: "-sn -PE -PA80,443",                          risk: "low",    desc: "ICMP & ACK host discovery — no port probes." },
    { k: "fast",      label: "Top-100 TCP",       args: "-sS --top-ports 100 -Pn",                    risk: "medium", desc: "SYN scan of the 100 most common TCP ports." },
    { k: "service",   label: "Service & version", args: "-sV -sC --top-ports 1000 -Pn",               risk: "medium", desc: "Version detection + default NSE on common ports." },
    { k: "vuln",      label: "Safe NSE scripts",  args: "-sV --script default,safe --top-ports 200 -Pn", risk: "high", desc: "Safe NSE scripts. Noisy — explicit auth only." },
    { k: "full",      label: "Full TCP + OS",     args: "-sS -p- -O -sV -Pn",                         risk: "high",   desc: "Every TCP port + OS fingerprint. Slow and loud." },
  ] as const, []);

  const NMAP_TIMINGS = useMemo(() => [
    { k: "T2", label: "Polite",      hint: "stealth · low rate" },
    { k: "T3", label: "Normal",      hint: "default" },
    { k: "T4", label: "Aggressive",  hint: "lab / authorised" },
    { k: "T5", label: "Insane",      hint: "very loud" },
  ] as const, []);

  const [nmapTiming, setNmapTiming] = useState<(typeof NMAP_TIMINGS)[number]["k"]>("T3");

  function NmapProgress({ startTime }: { startTime: number }) {
    const [elapsed, setElapsed] = useState(0);
    const [phase, setPhase] = useState<"indeterminate" | "determinate">("indeterminate");
    const estimatedSeconds = 30;
    useEffect(() => {
      const interval = setInterval(() => {
        const e = (Date.now() - startTime) / 1000;
        setElapsed(e);
        if (e >= 5) setPhase("determinate");
      }, 100);
      return () => clearInterval(interval);
    }, [startTime]);
    const pct = phase === "determinate" ? Math.min(95, (elapsed / estimatedSeconds) * 100) : null;
    return (
      <div className="w-full space-y-1">
        <div className="h-1 w-full overflow-hidden rounded-full bg-muted/30">
          <div
            className={
              "h-full rounded-full transition-all duration-300 " +
              (phase === "indeterminate"
                ? "w-1/3 animate-[ba-shimmer_1.5s_ease-in-out_infinite] bg-gradient-to-r from-primary/40 via-primary to-primary/40"
                : "bg-primary")
            }
            style={pct !== null ? { width: `${pct}%` } : undefined}
          />
        </div>
        <div className="flex justify-between text-mono ba-text-2xs text-muted-foreground">
          <span>{phase === "indeterminate" ? "Starting nmap scan…" : `Scanning… ${Math.round(elapsed)}s / ${estimatedSeconds}s`}</span>
        </div>
      </div>
    );
  }

  function getFieldVals(toolId: string): Record<string, any> {
    return fieldValues[toolId] ?? defaultFieldValues(toolId);
  }
  function setFieldVal(toolId: string, key: string, val: any) {
    setFieldValues(prev => ({ ...prev, [toolId]: { ...(prev[toolId] ?? defaultFieldValues(toolId)), [key]: val } }));
  }

  /* Persist targets/args */
  useEffect(() => { try { localStorage.setItem("ba.hacking.targets.v2", JSON.stringify(targets)); } catch {} }, [targets]);
  useEffect(() => { try { localStorage.setItem("ba.hacking.args.v2", JSON.stringify(argsMap)); } catch {} }, [argsMap]);

  /* Load catalog */
  useEffect(() => {
    getHackingtoolCategories()
      .then((res: any) => {
        if (res.categories) {
          setCats(res.categories);
          setInstalled(res.installed ?? false);
          setOffline(false);
          try { localStorage.setItem(CACHE_KEY, JSON.stringify({ _cachedAt: Date.now(), categories: res.categories })); } catch {}
          if (res.categories.length > 0) {
            setActiveCatId("");
            setActiveToolId("");
          }
        }
        setLoading(false);
      })
      .catch((err: any) => {
        /* Offline fallback: load cached catalog */
        const cached = loadCachedCatalog();
        if (cached) {
          setCats(cached);
          setInstalled(false);
          setOffline(true);
          if (cached.length > 0) {
            setActiveCatId("");
            setActiveToolId("");
          }
        } else {
          setBackendError(err?.message || "Cannot reach backend");
        }
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    try { const raw = localStorage.getItem(PIN_KEY); if (raw) setPinned(new Set(JSON.parse(raw))); } catch {}
  }, []);
  useEffect(() => {
    try { localStorage.setItem(PIN_KEY, JSON.stringify([...pinned])); } catch {}
  }, [pinned]);

  useEffect(() => {
    const h = takePendingArtifact();
    if (h?.value) setTargets((p) => ({ ...p, [activeToolId]: h.value }));
  }, [activeToolId]);

  const allTools = useMemo(() => {
    if (!cats) return [];
    return cats.flatMap((c) => c.tools.map((t) => ({ ...t, catId: c.id, catName: c.name })));
  }, [cats]);

  const totalTools = allTools.length;
  const installedCount = allTools.filter((t) => t.installed).length;
  const pinnedCount = pinned.size;

  const lower = search.trim().toLowerCase();
  const filteredCats = useMemo(() => {
    if (!cats) return [];
    if (!lower) return cats;
    return cats.map((c) => ({
      ...c,
      tools: c.tools.filter((t) =>
        t.name.toLowerCase().includes(lower) ||
        t.binary.toLowerCase().includes(lower) ||
        t.id.toLowerCase().includes(lower) ||
        c.name.toLowerCase().includes(lower),
      ),
    })).filter((c) => c.tools.length > 0);
  }, [cats, lower]);

  const activeCat = cats?.find((c) => c.id === activeCatId);
  const activeTool = activeCat?.tools.find((t) => t.id === activeToolId);
  const schema = activeTool ? TOOL_SCHEMAS[activeTool.id] : null;

  const target = activeTool ? (schema ? getTargetFromSchema(activeTool.id, getFieldVals(activeTool.id)) : (targets[activeTool.id] ?? "")) : "";
  const args = activeTool ? (schema ? buildArgsFromSchema(activeTool.id, getFieldVals(activeTool.id)) : (argsMap[activeTool.id] ?? "")) : "";
  const cmd = activeTool ? [activeTool.binary, target, args].filter(Boolean).join(" ") : "";
  const output = activeTool ? outputs[activeTool.id] : null;

  function selectTool(catId: string, toolId: string) {
    setActiveCatId(catId);
    setActiveToolId(toolId);
  }

  function togglePin(toolId: string) {
    setPinned((prev) => {
      const next = new Set(prev);
      if (next.has(toolId)) next.delete(toolId); else next.add(toolId);
      return next;
    });
  }

  function applyPreset(args: string) {
    if (!activeTool) return;
    setArgsMap((p) => ({ ...p, [activeTool.id]: args }));
  }

  async function run() {
    if (!activeTool || !activeCat) return;
    if (activeTool.id === "nmap" && !nmapConfirmed) {
      toast.error("Confirm you have permission to scan this target first.");
      return;
    }
    setRunning(activeTool.id);
    setScanStartTime(Date.now());
    setOutputs((p) => ({ ...p, [activeTool.id]: null }));
    try {
      const finalArgs = activeTool.id === "nmap" && !args ? NMAP_MODES.find(m => m.k === nmapMode)?.args ?? args : args;
      const res: any = await runHackingtoolTool({
        categoryId: activeCat.id,
        toolId: activeTool.id,
        target,
        args,
      });
      const body = res.stdout || res.stderr || res.error || JSON.stringify(res, null, 2);
      const status = res.error ? "error" : (res.status === "completed" ? "completed" : "failed");
      const entry: HistoryEntry = {
        id: genId(),
        toolId: activeTool.id,
        toolName: activeTool.name,
        binary: activeTool.binary,
        catName: activeCat.name,
        target, args,
        command: res.command || cmd,
        status,
        body,
        ts: Date.now(),
      };
      setHistory(prev => { const next = [entry, ...prev].slice(0, MAX_HISTORY); saveHistory(next); return next; });
      setOutputs((p) => ({
        ...p,
        [activeTool.id]: {
          command: res.command || cmd,
          status,
          body,
        },
      }));
      if (activeTool.id === "nmap" && status === "completed") {
        const portCount = (body.match(/^\d+\/(tcp|udp)\s+open/m) || []).length;
        pushTimelineEvent({ source: "nmap", verb: "scanned", detail: `${target} — ${NMAP_MODES.find(m => m.k === nmapMode)?.label ?? "scan"} (${portCount} open ports)`, target });
      }
    } catch (err: any) {
      const body = err?.message || "API call failed";
      const entry: HistoryEntry = {
        id: genId(), toolId: activeTool.id, toolName: activeTool.name,
        binary: activeTool.binary, catName: activeCat.name,
        target, args, command: cmd, status: "error", body, ts: Date.now(),
      };
      setHistory(prev => { const next = [entry, ...prev].slice(0, MAX_HISTORY); saveHistory(next); return next; });
      setOutputs((p) => ({
        ...p,
        [activeTool.id]: { command: cmd, status: "error", body },
      }));
    } finally {
      setRunning(null);
    }
  }

  async function copyText(key: string, text: string) {
    try { await navigator.clipboard.writeText(text); setCopied(key); setTimeout(() => setCopied(null), 1200); } catch {}
  }

  const presets = activeTool ? (PRESETS[activeTool.id] ?? []) : [];

  const metaItems: { label: string; value: string; tone?: "default" | "primary" | "warning" | "destructive" | "success" }[] = [
    { label: "categories", value: String(cats?.length ?? 0), tone: "primary" },
    { label: "tools", value: String(totalTools), tone: "primary" },
    { label: "available", value: String(installedCount), tone: installedCount > 0 ? "success" : "default" },
    { label: "pinned", value: String(pinnedCount), tone: pinnedCount > 0 ? "success" : "default" },
  ];

  const historyLc = historyFilter.trim().toLowerCase();
  const filteredHistory = historyLc
    ? history.filter(h => h.toolName.toLowerCase().includes(historyLc) || h.target.toLowerCase().includes(historyLc) || h.command.toLowerCase().includes(historyLc))
    : history;

  const clearHistory = () => { setHistory([]); saveHistory([]); };
  const replayHistory = (h: HistoryEntry) => {
    const cat = cats?.find(c => c.tools.some(t => t.id === h.toolId));
    if (cat) { setActiveCatId(cat.id); setActiveToolId(h.toolId); }
    setTargets(p => ({ ...p, [h.toolId]: h.target }));
    setArgsMap(p => ({ ...p, [h.toolId]: h.args }));
    setShowHistory(false);
  };

  return (
    <PageShell
      eyebrow="Offensive"
      title="Hacking Toolkit"
      description="Browse 50+ offensive-security tools by category, build commands with presets, and run against locally installed binaries via the BeyondLabs backend."
      crumbs={[{ label: "Workbench", href: "/" }, { label: "Offensive" }, { label: "Hacking Toolkit" }]}
      meta={metaItems}
      actions={<PreviewBadge label={offline ? "offline catalog" : (installed ? "live backend" : "catalog")} />}
    >
      {loading && (
        <div className="space-y-3">
          <PanelSkeleton title lines={4} />
          <PanelSkeleton title lines={2} />
        </div>
      )}

      {!loading && backendError && !cats && (
        <Panel className="border-warning/30 bg-warning/5">
          <div className="flex items-start gap-3 px-4 py-2.5">
            <span className="grid h-7 w-7 shrink-0 place-items-center rounded border border-warning/40 bg-warning/15 text-warning">
              <AlertTriangle className="h-3.5 w-3.5" />
            </span>
            <div className="min-w-0 ba-text-base leading-relaxed text-foreground/85">
              <span className="font-semibold text-warning">Cannot reach backend.</span>{" "}
              No cached catalog available. Start the FastAPI server to use toolkit features.{" "}
              <code className="text-mono ba-text-sm text-foreground">cd backend && uvicorn app.main:app --reload</code>
            </div>
          </div>
        </Panel>
      )}

      {offline && (
        <Panel className="border-warning/30 bg-warning/5">
          <div className="flex items-start gap-3 px-4 py-2.5">
            <span className="grid h-7 w-7 shrink-0 place-items-center rounded border border-warning/40 bg-warning/15 text-warning">
              <AlertTriangle className="h-3.5 w-3.5" />
            </span>
            <div className="min-w-0 ba-text-base leading-relaxed text-foreground/85">
              <span className="font-semibold text-warning">Offline mode.</span>{" "}
              Backend unreachable — showing cached tool catalog. Tool execution requires the backend.{" "}
              <code className="text-mono ba-text-sm text-foreground">cd backend && uvicorn app.main:app --reload</code>
            </div>
          </div>
        </Panel>
      )}

      {!loading && !backendError && cats && (
        <>
          {!installed && !offline && (
            <Panel className="border-warning/30 bg-warning/5">
              <div className="flex items-start gap-3 px-4 py-2.5">
                <span className="grid h-7 w-7 shrink-0 place-items-center rounded border border-warning/40 bg-warning/15 text-warning">
                  <AlertTriangle className="h-3.5 w-3.5" />
                </span>
                <div className="min-w-0 ba-text-base leading-relaxed text-foreground/85">
                  <span className="font-semibold text-warning">hackingtool directory not found.</span>{" "}
                  The catalog is shown but binaries are not checked. Clone into{" "}
                  <code className="text-mono ba-text-sm text-foreground">~/Projects/hackingtool</code> to enable installed-tool detection.
                </div>
              </div>
            </Panel>
          )}

          <div className="grid gap-4 grid-cols-[minmax(0,18rem)_minmax(0,1fr)]">
            {/* ── Left rail ── */}
            <div className="space-y-3 sticky top-16 self-start">
              <Panel bodyClassName="p-0">
                <div className="border-b border-border p-2">
                  <div className="relative">
                    <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                    <input
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      placeholder="search tools, binaries…"
                      spellCheck={false}
                      className="w-full rounded-md border border-border bg-background/60 py-1.5 pl-7 pr-7 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
                    />
                    {search && (
                      <button onClick={() => setSearch("")} className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1 text-muted-foreground hover:text-foreground" aria-label="clear">
                        <X className="h-3 w-3" />
                      </button>
                    )}
                  </div>
                </div>

                {pinnedCount > 0 && (
                  <div className="border-b border-divider-strong p-2">
                    <div className="mb-1.5 flex items-center gap-1.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground">
                      <Pin className="h-3 w-3 text-primary" /> pinned
                    </div>
                    <ul className="space-y-0.5">
                      {[...pinned].map((tid) => {
                        const cat = cats?.find((c) => c.tools.some((t) => t.id === tid));
                        const t = cat?.tools.find((x) => x.id === tid);
                        if (!cat || !t) return null;
                        const active = t.id === activeToolId;
                        return (
                          <li key={tid}>
                            <button
                              onClick={() => selectTool(cat.id, t.id)}
                              className={"flex w-full items-center gap-2 rounded px-2 py-1 text-left text-mono ba-text-sm transition-colors " + (active ? "bg-primary/10 text-primary" : "text-foreground/80 hover:bg-accent/40 hover:text-foreground")}
                            >
                              <span className="truncate">{t.name}</span>
                              <span className="ml-auto truncate ba-text-3xs text-muted-foreground">{cat.name}</span>
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                )}

                <nav className="max-h-[calc(100vh-22rem)] overflow-auto p-2">
                  {filteredCats.length === 0 && (
                    <div className="px-2 py-6 text-center text-mono ba-text-sm text-muted-foreground">
                      no tools match <span className="text-foreground">{search}</span>
                    </div>
                  )}
                  {filteredCats.map((cat) => {
                    const Icon = ICON_MAP[cat.icon] || Search;
                    const open = cat.id === activeCatId || !!lower;
                    const toneCls =
                      TONE_MAP[cat.id] === "primary" ? "text-primary" :
                      TONE_MAP[cat.id] === "warning" ? "text-warning" :
                      TONE_MAP[cat.id] === "destructive" ? "text-destructive" :
                      TONE_MAP[cat.id] === "success" ? "text-success" :
                      TONE_MAP[cat.id] === "accent" ? "text-accent" : "text-info";
                    return (
                      <div key={cat.id} className="mb-1.5">
                        <button
                          onClick={() => setActiveCatId((id) => (id === cat.id ? "" : cat.id))}
                          className={"group flex w-full items-center gap-2 rounded-md border border-transparent px-2 py-1.5 text-left transition-colors hover:border-border hover:bg-accent/30 " + (open ? "border-border bg-card/60" : "")}
                        >
                          <span className={"grid h-6 w-6 place-items-center rounded border border-border bg-background/60 " + toneCls}>
                            <Icon className="h-3.5 w-3.5" />
                          </span>
                          <span className="flex-1 truncate text-mono ba-text-sm font-semibold uppercase tracking-widest text-foreground/90">
                            {cat.name}
                          </span>
                          <span className="text-mono ba-text-3xs text-muted-foreground">{cat.tools.length}</span>
                          <ChevronRight className={"h-3 w-3 text-muted-foreground transition-transform " + (open ? "rotate-90" : "")} />
                        </button>
                        {open && (
                          <ul className="mt-1 space-y-0.5 pl-2">
                            {cat.tools.map((t) => {
                              const active = t.id === activeToolId;
                              return (
                                <li key={t.id}>
                                  <button
                                    onClick={() => selectTool(cat.id, t.id)}
                                    className={"group/r relative flex w-full items-center gap-2 rounded px-2 py-1 text-left text-mono ba-text-sm transition-colors " + (active ? "bg-primary/10 text-primary" : "text-foreground/75 hover:bg-accent/40 hover:text-foreground")}
                                  >
                                    <span aria-hidden className={"h-1.5 w-1.5 shrink-0 rounded-full " + (active ? "bg-primary shadow-[0_0_8px_var(--primary)]" : "bg-muted-foreground/30")} />
                                    <span className="truncate">{t.name}</span>
                                    {t.installed && (
                                      <span className="ml-auto h-1.5 w-1.5 shrink-0 rounded-full bg-success" title="installed" />
                                    )}
                                    <span className="ml-1 truncate ba-text-3xs text-muted-foreground/80">{t.binary}</span>
                                    {pinned.has(t.id) && <Pin className="h-2.5 w-2.5 fill-primary text-primary" />}
                                  </button>
                                </li>
                              );
                            })}
                          </ul>
                        )}
                      </div>
                    );
                  })}
                </nav>
              </Panel>
            </div>

            {/* ── Right column ── */}
            <div className="min-w-0 space-y-4">
              {!activeTool ? (
                <Empty icon={Terminal} title="No tool selected" hint="Hacking Toolkit provides 50+ offensive security tools grouped by category — recon, web, forensics, exploit, password attacks, and more. Select a tool from the left rail, configure flags or presets, and run against locally installed binaries." />
              ) : (
                <>
                  {/* Tool header */}
                  <Panel>
                    <div className="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
                      <div className="flex min-w-0 items-start gap-3">
                        <span className="grid h-10 w-10 shrink-0 place-items-center rounded-md border border-primary/40 bg-primary/10 text-primary shadow-[0_0_0_3px_color-mix(in_oklab,var(--primary)_8%,transparent)]">
                          <Swords className="h-4 w-4" />
                        </span>
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <h2 className="truncate text-mono text-base font-semibold text-foreground">{activeTool.name}</h2>
                            <Chip tone="default">{activeCat?.name ?? ""}</Chip>
                            <Chip tone={activeTool.installed ? "success" : "warning"}>{activeTool.installed ? "installed" : "not detected"}</Chip>
                          </div>
                          <div className="mt-1.5 inline-flex items-center gap-1.5 rounded border border-divider-strong bg-background/40 px-1.5 py-0.5 text-mono text-[10px] text-muted-foreground">
                            <Terminal className="h-3 w-3 text-primary/70" />
                            <span className="text-foreground/80">{activeTool.binary}</span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => togglePin(activeTool.id)}
                          className="inline-flex items-center gap-1 rounded border border-border bg-card/40 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:border-primary/50 hover:text-primary"
                        >
                          {pinned.has(activeTool.id) ? <><PinOff className="h-3 w-3" /> unpin</> : <><Pin className="h-3 w-3" /> pin</>}
                        </button>
                      </div>
                    </div>
                  </Panel>

                  {/* Intake */}
                  <div>
                    <SectionBar id="IN" label="Intake" meta={schema ? "structured inputs" : "target · args · preset"} />
                    <Panel bodyClassName="p-0">
                      {schema ? (
                        <div className="grid gap-x-3 gap-y-2 grid-cols-[repeat(auto-fill,minmax(180px,1fr))] p-3">
                          {schema.fields.map(f => {
                            const val = getFieldVals(activeTool.id)[f.key] ?? f.defaultValue ?? (f.type === "toggle" ? false : "");
                            return (
                              <div key={f.key}>
                                <label className="mb-1 block text-mono text-[10px] uppercase tracking-widest text-muted-foreground">{f.label}</label>
                                {f.type === "toggle" ? (
                                  <button
                                    onClick={() => setFieldVal(activeTool.id, f.key, !val)}
                                    className={"inline-flex items-center gap-1.5 rounded border px-2 py-1 text-mono ba-text-sm transition-colors " + (val ? "border-primary/50 bg-primary/15 text-primary" : "border-border text-muted-foreground hover:text-foreground")}
                                  >
                                    <span className={"h-3 w-3 rounded border " + (val ? "border-primary bg-primary" : "border-border")}>
                                      {val && <Check className="h-2.5 w-2.5 text-background" />}
                                    </span>
                                    {f.label}
                                  </button>
                                ) : f.type === "dropdown" ? (
                                  <select
                                    value={String(val)}
                                    onChange={e => setFieldVal(activeTool.id, f.key, e.target.value)}
                                    className="w-full rounded-md border border-border bg-background/60 px-2 py-1.5 text-mono ba-text-base text-foreground outline-none focus:border-primary/50"
                                  >
                                    {f.options?.map(o => (
                                      <option key={o.value} value={o.value}>{o.label}</option>
                                    ))}
                                  </select>
                                ) : (
                                  <input
                                    type={f.type === "number" ? "number" : "text"}
                                    value={String(val)}
                                    onChange={e => setFieldVal(activeTool.id, f.key, f.type === "number" ? Number(e.target.value) : e.target.value)}
                                    placeholder={f.placeholder}
                                    spellCheck={false}
                                    className="w-full rounded-md border border-border bg-background/60 px-2 py-1.5 text-mono ba-text-base text-foreground outline-none placeholder:text-muted-foreground/50 focus:border-primary/50"
                                  />
                                )}
                              </div>
                            );
                          })}
                        </div>
                      ) : (
                        <div className="grid gap-0 grid-cols-[1fr_1fr]">
                          <div className="border-b border-divider-strong p-3 border-b-0 border-r">
                            <label className="mb-1 block text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Target</label>
                            <input
                              value={target}
                              onChange={(e) => setTargets((p) => ({ ...p, [activeTool.id]: e.target.value }))}
                              placeholder="example.com · 10.0.0.1 · https://app"
                              spellCheck={false}
                              className="w-full rounded-md border border-border bg-background/60 px-2 py-1.5 text-mono ba-text-base text-foreground outline-none placeholder:text-muted-foreground/50 focus:border-primary/50"
                            />
                          </div>
                          <div className="p-3">
                            <label className="mb-1 block text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Args</label>
                            <input
                              value={args}
                              onChange={(e) => setArgsMap((p) => ({ ...p, [activeTool.id]: e.target.value }))}
                              placeholder="-sV -p 22,80,443 (optional)"
                              spellCheck={false}
                              className="w-full rounded-md border border-border bg-background/60 px-2 py-1.5 text-mono ba-text-base text-foreground outline-none placeholder:text-muted-foreground/50 focus:border-primary/50"
                            />
                          </div>
                        </div>
                      )}

                      {presets.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1.5 border-t border-border bg-muted/15 px-3 py-2">
                          <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                            <Sparkles className="mr-1 inline h-3 w-3 text-primary" /> presets
                          </span>
                          {presets.map((p) => (
                            <button
                              key={p.label}
                              onClick={() => applyPreset(p.args)}
                              className="rounded border border-border bg-background/60 px-2 py-0.5 text-mono text-[10px] text-foreground/85 transition-colors hover:border-primary/50 hover:bg-primary/10 hover:text-primary"
                            >
                              {p.label}
                            </button>
                          ))}
                        </div>
                      )}

                      {activeTool.id === "nmap" && (
                        <div className="border-t border-border bg-muted/10 px-3 py-2 space-y-2">
                          <div>
                            <label className="mb-1 block text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Scan mode</label>
                            <div className="flex flex-wrap gap-1">
                              {NMAP_MODES.map((m) => (
                                <button
                                  key={m.k}
                                  onClick={() => { setNmapMode(m.k); setArgsMap((p) => ({ ...p, nmap: m.args })); }}
                                  className={"rounded border px-2 py-1 text-mono text-[10px] transition-colors " + (nmapMode === m.k ? "border-primary/50 bg-primary/15 text-primary" : "border-divider-strong bg-background/40 text-muted-foreground hover:text-foreground")}
                                  title={m.desc}
                                >
                                  {m.label}
                                </button>
                              ))}
                            </div>
                          </div>
                          <div className="flex items-center gap-3">
                            <label className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Timing</label>
                            <div className="flex gap-1">
                              {NMAP_TIMINGS.map((t) => (
                                <button
                                  key={t.k}
                                  onClick={() => setNmapTiming(t.k)}
                                  className={"rounded border px-2 py-0.5 text-mono text-[10px] transition-colors " + (nmapTiming === t.k ? "border-primary/50 bg-primary/15 text-primary" : "border-divider-strong bg-background/40 text-muted-foreground hover:text-foreground")}
                                  title={t.hint}
                                >
                                  -{t.k}
                                </button>
                              ))}
                            </div>
                          </div>
                          <label className="flex items-center gap-2 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={nmapConfirmed}
                              onChange={(e) => setNmapConfirmed(e.target.checked)}
                              className="h-3.5 w-3.5 rounded border-border accent-primary"
                            />
                            <span className="text-mono text-[10px] text-muted-foreground">I own or have permission to scan this target</span>
                          </label>
                          {running === activeTool.id && scanStartTime && (
                            <NmapProgress startTime={scanStartTime} />
                          )}
                        </div>
                      )}
                      <div className="flex flex-wrap items-center gap-2 border-t border-border bg-background/40 px-3 py-2">
                        <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">cmd</span>
                        <code className="min-w-0 flex-1 truncate rounded border border-divider-strong bg-background/70 px-2 py-1 text-mono ba-text-sm text-foreground/90">
                          <span className="text-primary/70">$</span> {cmd || activeTool.binary}
                        </code>
                        <button
                          onClick={() => copyText("cmd", cmd || activeTool.binary)}
                          className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:border-primary/50 hover:text-primary"
                          title="Copy command"
                        >
                          {copied === "cmd" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />} copy
                        </button>
                        <button
                          onClick={run}
                          disabled={running === activeTool.id || offline}
                          className="inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-3 py-1 text-mono ba-text-sm font-semibold uppercase tracking-widest text-primary transition-colors hover:bg-primary/20 disabled:opacity-50"
                        >
                          {running === activeTool.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Bug className="h-3 w-3" />}
                          {running === activeTool.id ? "running…" : "run"}
                        </button>
                        {offline && <span className="text-mono ba-text-3xs text-muted-foreground">(offline — cannot run)</span>}
                      </div>
                    </Panel>
                  </div>

                  {/* Output + History */}
                  <div>
                    <div className="flex items-center gap-2">
                      <SectionBar id="OT" label="Output" meta={output ? output.status : "no run yet"} />
                      <button
                        onClick={toggleFilter}
                        className={"inline-flex shrink-0 items-center gap-1 rounded border px-2 py-1 text-mono text-[10px] uppercase tracking-widest transition-colors " + (showFilter ? "border-primary/50 bg-primary/10 text-primary" : "border-divider-strong text-muted-foreground hover:border-primary/40 hover:text-primary")}
                      >
                        <Search className="h-3 w-3" />
                        filter
                      </button>
                      <button
                        onClick={() => setShowHistory(s => !s)}
                        className={"inline-flex shrink-0 items-center gap-1 rounded border px-2 py-1 text-mono text-[10px] uppercase tracking-widest transition-colors " + (showHistory ? "border-primary/50 bg-primary/10 text-primary" : "border-divider-strong text-muted-foreground hover:border-primary/40 hover:text-primary")}
                      >
                        <History className="h-3 w-3" />
                        history
                        {history.length > 0 && <Chip tone={showHistory ? "primary" : "default"}>{history.length}</Chip>}
                      </button>
                    </div>

                    {showFilter && (
                      <OutputFilterBar
                        filterText={filterText}
                        onChange={setFilterText}
                        onClear={() => setFilterText("")}
                        onClose={() => { setShowFilter(false); setFilterText(""); }}
                      />
                    )}

                    {showHistory && (
                      <Panel title="Command history" icon={History} meta={`${history.length} entries`} className="mb-3" actions={
                        history.length > 0 && (
                          <button onClick={clearHistory} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase text-muted-foreground hover:text-destructive">
                            <Trash2 className="h-3 w-3" /> clear all
                          </button>
                        )
                      }>
                        <div className="relative mb-2">
                          <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
                          <input
                            value={historyFilter}
                            onChange={e => setHistoryFilter(e.target.value)}
                            placeholder="filter history…"
                            className="h-7 w-full rounded border border-border bg-background/60 pl-6 pr-2 text-mono text-[10px] text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
                          />
                        </div>
                        {filteredHistory.length === 0 ? (
                          <div className="py-4 text-center text-mono ba-text-sm text-muted-foreground">{history.length === 0 ? "No runs yet. Run a tool to see history here." : "No entries match the filter."}</div>
                        ) : (
                          <div className="max-h-80 space-y-1 overflow-auto">
                            {filteredHistory.map(h => (
                              <div key={h.id} className="group flex items-start justify-between gap-2 rounded border border-divider-soft bg-background/30 px-2.5 py-1.5 hover:border-primary/30">
                                <div className="min-w-0 flex-1">
                                  <div className="flex items-center gap-2">
                                    <span className="text-mono ba-text-sm font-semibold text-foreground/85">{h.toolName}</span>
                                    <Chip tone={h.status === "completed" ? "success" : h.status === "error" ? "destructive" : "warning"}>{h.status}</Chip>
                                  </div>
                                  <div className="mt-0.5 truncate text-mono text-[10px] text-muted-foreground">
                                    <span className="text-primary/70">$</span> {h.command}
                                  </div>
                                  <div className="flex items-center gap-2 text-mono ba-text-3xs text-muted-foreground">
                                    <Clock className="inline h-2.5 w-2.5" />
                                    <span>{new Date(h.ts).toLocaleString()}</span>
                                    <span>· {h.catName}</span>
                                    <span>· {h.body.length} b</span>
                                  </div>
                                </div>
                                <div className="flex shrink-0 items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                                  <button onClick={() => replayHistory(h)} className="rounded border border-border px-1.5 py-0.5 text-mono ba-text-3xs uppercase text-muted-foreground hover:text-primary" title="Replay">replay</button>
                                  <button onClick={() => copyText(h.id, h.body)} className="rounded border border-border px-1.5 py-0.5 text-mono ba-text-3xs uppercase text-muted-foreground hover:text-primary" title="Copy output">{copied === h.id ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}</button>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </Panel>
                    )}

                    <OutputFilter query={filterText.toLowerCase()}>
                    {!output ? (
                      <Empty
                        icon={Terminal}
                        title="No execution recorded"
                        hint="Hacking Toolkit wraps local CLI tools (nmap, whois, dig, curl, jq, and more) via the backend. Pick a tool from the left rail and set a target to run."
                      />
                    ) : (
                      <>
                        <ResultBanner
                          badge={output.status}
                          caseId={activeTool.binary}
                          title={`${activeTool.name} — ${output.status === "completed" ? "execution result" : output.status === "error" ? "execution failed" : "output"}`}
                          subtitle={output.status === "completed" ? "Binary ran on the local host via BeyondLabs backend." : output.status === "error" ? "The tool returned an error or is not installed." : "The tool produced output with non-zero exit code."}
                          metrics={[
                            { label: "lines", value: String(output.body.split("\n").length), tone: "primary" },
                            { label: "bytes", value: output.body.length.toLocaleString(), tone: "default" },
                            { label: "status", value: output.status, tone: output.status === "completed" ? "success" : "warning" },
                            { label: "tool", value: activeTool.binary, tone: "default" },
                          ]}
                        />

                        <TerminalOutput
                          command={output.command}
                          body={output.body}
                          status={output.status}
                          onClear={() => setOutputs((p) => ({ ...p, [activeTool.id]: null }))}
                          filename={`hacking-${activeTool.id}.txt`}
                        />

                        {activeTool.id === "nmap" && (
                          <div className="mt-3 space-y-3">
                            <NmapOutput
                              body={output.body}
                              command={output.command}
                              target={target}
                              status={output.status}
                            />
                          </div>
                        )}

                        {target && (
                          <div className="mt-3">
                            <SendToRow
                              targets={[
                                { label: "OSINT Tools", to: "/osint", onClick: () => sendArtifact({ kind: "raw", value: target, source: "/hacking-toolkit" }) },
                                { label: "URL Analyzer", to: "/url", onClick: () => sendArtifact({ kind: "raw", value: target, source: "/hacking-toolkit" }) },
                                { label: "Recon", to: "/recon", onClick: () => sendArtifact({ kind: "raw", value: target, source: "/hacking-toolkit" }) },
                              ]}
                            />
                          </div>
                        )}

                        <div className="mt-3">
                          <Panel title="Tool facts" icon={Terminal} collapsible storageKey="ba.panel.hacking.facts" defaultCollapsed>
                            <div className="grid gap-x-6 grid-cols-2">
                              <Field label="binary" value={<code className="text-mono">{activeTool.binary}</code>} />
                              <Field label="category" value={activeCat?.name ?? ""} />
                              <Field label="id" value={<code className="text-mono">{activeTool.id}</code>} tone="muted" />
                              <Field label="presets" value={String(presets.length)} tone={presets.length ? "primary" : "muted"} />
                              <Field label="installed" value={activeTool.installed ? "yes" : "no"} tone={activeTool.installed ? "success" : "warning"} />
                              <Field label="pinned" value={pinned.has(activeTool.id) ? "yes" : "no"} tone={pinned.has(activeTool.id) ? "success" : "muted"} />
                            </div>
                          </Panel>
                        </div>
                      </>
                    )}
                    </OutputFilter>
                  </div>
                </>
              )}
            </div>
          </div>
        </>
      )}
    </PageShell>
  );
}

function loadCachedCatalog(): BackendCategory[] | null {
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
