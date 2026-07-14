import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, SendToRow } from "@/components/soc";
import {
  getBackendUrl, setBackendUrl, pingBackend, runToolRemote,
  type BackendStatus,
} from "@/lib/backend";
import {
  Terminal as TerminalIcon, Plug, PlugZap, RefreshCw, Trash2, Download, Plus, X,
} from "lucide-react";
import { pushTimelineEvent } from "@/lib/timeline";
import { useLocker } from "@/lib/locker";
import { sendToCase } from "@/lib/handoff";
import { toast } from "sonner";

export const Route = createFileRoute("/terminal")({ component: TerminalPage });

type ToolRef = { categoryId: string; toolId: string; binary: string; name: string };

const BIN_MAP: Record<string, ToolRef> = {
  nmap:         { categoryId: "information_gathering", toolId: "nmap",         binary: "nmap",         name: "Nmap" },
  theharvester: { categoryId: "information_gathering", toolId: "theharvester", binary: "theharvester", name: "theHarvester" },
  amass:        { categoryId: "information_gathering", toolId: "amass",        binary: "amass",        name: "Amass" },
  sublist3r:    { categoryId: "information_gathering", toolId: "sublist3r",    binary: "sublist3r",    name: "Sublist3r" },
  maigret:      { categoryId: "information_gathering", toolId: "maigret",      binary: "maigret",      name: "Maigret" },
  reconspider:  { categoryId: "information_gathering", toolId: "reconspider",  binary: "ReconSpider",  name: "ReconSpider" },
  shodanfy:     { categoryId: "information_gathering", toolId: "shodanfy",     binary: "shodanfy",     name: "Shodanfy" },
  dnsrecon:     { categoryId: "information_gathering", toolId: "dnsrecon",     binary: "dnsrecon",     name: "DNSRecon" },
  "recon-ng":   { categoryId: "information_gathering", toolId: "recon_ng",     binary: "recon-ng",     name: "Recon-ng" },

  nuclei:   { categoryId: "web_attack", toolId: "nuclei",   binary: "nuclei",   name: "Nuclei" },
  nikto:    { categoryId: "web_attack", toolId: "nikto",    binary: "nikto",    name: "Nikto" },
  dirb:     { categoryId: "web_attack", toolId: "dirb",     binary: "dirb",     name: "Dirb" },
  gobuster: { categoryId: "web_attack", toolId: "gobuster", binary: "gobuster", name: "Gobuster" },
  ffuf:     { categoryId: "web_attack", toolId: "ffuf",     binary: "ffuf",     name: "Ffuf" },
  wafw00f:  { categoryId: "web_attack", toolId: "wafw00f",  binary: "wafw00f",  name: "Wafw00f" },
  zap:      { categoryId: "web_attack", toolId: "zap",      binary: "zap",      name: "OWASP ZAP" },
  katana:   { categoryId: "web_attack", toolId: "katana",   binary: "katana",   name: "Katana" },
  sqlmap:   { categoryId: "web_attack", toolId: "sqlmap",   binary: "sqlmap",   name: "SQLMap" },
  whatweb:  { categoryId: "web_attack", toolId: "whatweb",  binary: "whatweb",  name: "WhatWeb" },
  wpscan:   { categoryId: "web_attack", toolId: "wpscan",   binary: "wpscan",   name: "WPScan" },
  wfuzz:    { categoryId: "web_attack", toolId: "wfuzz",    binary: "wfuzz",    name: "WFuzz" },

  hydra:   { categoryId: "password_attacks", toolId: "hydra",   binary: "hydra",   name: "Hydra" },
  crunch:  { categoryId: "password_attacks", toolId: "crunch",  binary: "crunch",  name: "Crunch" },
  cewl:    { categoryId: "password_attacks", toolId: "cewl",    binary: "cewl",    name: "CeWL" },
  john:    { categoryId: "password_attacks", toolId: "john",    binary: "john",    name: "John the Ripper" },
  hashcat: { categoryId: "password_attacks", toolId: "hashcat", binary: "hashcat", name: "Hashcat" },

  vol:            { categoryId: "forensics", toolId: "volatility3",    binary: "vol",            name: "Volatility 3" },
  volatility:     { categoryId: "forensics", toolId: "volatility3",    binary: "vol",            name: "Volatility 3" },
  binwalk:        { categoryId: "forensics", toolId: "binwalk",        binary: "binwalk",        name: "Binwalk" },
  bulk_extractor: { categoryId: "forensics", toolId: "bulk_extractor", binary: "bulk_extractor", name: "Bulk Extractor" },
  foremost:       { categoryId: "forensics", toolId: "foremost",       binary: "foremost",       name: "Foremost" },
  testdisk:       { categoryId: "forensics", toolId: "testdisk",       binary: "testdisk",       name: "TestDisk" },

  wifite:      { categoryId: "wireless", toolId: "wifite",      binary: "wifite",      name: "Wifite" },
  airgeddon:   { categoryId: "wireless", toolId: "airgeddon",   binary: "airgeddon",   name: "Airgeddon" },
  bettercap:   { categoryId: "wireless", toolId: "bettercap",   binary: "bettercap",   name: "Bettercap" },
  "aircrack-ng": { categoryId: "wireless", toolId: "aircrack_ng", binary: "aircrack-ng", name: "Aircrack-ng" },

  routersploit: { categoryId: "exploit", toolId: "routersploit", binary: "routersploit", name: "RouterSploit" },
  commix:       { categoryId: "exploit", toolId: "commix",       binary: "commix",       name: "Commix" },
  searchsploit: { categoryId: "exploit", toolId: "searchsploit", binary: "searchsploit", name: "SearchSploit" },
  msfconsole:   { categoryId: "exploit", toolId: "metasploit",   binary: "msfconsole",   name: "Metasploit" },
  metasploit:   { categoryId: "exploit", toolId: "metasploit",   binary: "msfconsole",   name: "Metasploit" },

  ghidra:  { categoryId: "reverse_engineering", toolId: "ghidra",  binary: "ghidra",  name: "Ghidra" },
  r2:      { categoryId: "reverse_engineering", toolId: "radare2", binary: "r2",      name: "Radare2" },
  radare2: { categoryId: "reverse_engineering", toolId: "radare2", binary: "r2",      name: "Radare2" },
  jadx:    { categoryId: "reverse_engineering", toolId: "jadx",    binary: "jadx",    name: "JadX" },
  apktool: { categoryId: "reverse_engineering", toolId: "apktool", binary: "apktool", name: "Apktool" },

  msfpc: { categoryId: "payload", toolId: "msfpc", binary: "msfpc", name: "MSFvenom Payload Creator" },
  cupp:  { categoryId: "wordlist", toolId: "cupp", binary: "cupp",  name: "Cupp" },

  prowler: { categoryId: "cloud_security", toolId: "prowler", binary: "prowler", name: "Prowler" },
  trivy:   { categoryId: "cloud_security", toolId: "trivy",   binary: "trivy",   name: "Trivy" },

  bloodhound: { categoryId: "active_directory", toolId: "bloodhound", binary: "bloodhound", name: "BloodHound" },
  impacket:   { categoryId: "active_directory", toolId: "impacket",   binary: "impacket",   name: "Impacket" },
  responder:  { categoryId: "active_directory", toolId: "responder",  binary: "responder",  name: "Responder" },

  stegocracker: { categoryId: "steganography", toolId: "stegocracker", binary: "stegocracker", name: "StegoCracker" },

  dig:       { categoryId: "network_utilities", toolId: "dig",       binary: "dig",       name: "dig" },
  host:      { categoryId: "network_utilities", toolId: "host",      binary: "host",      name: "host" },
  ping:      { categoryId: "network_utilities", toolId: "ping",      binary: "ping",      name: "ping" },
  traceroute:{ categoryId: "network_utilities", toolId: "traceroute",binary: "traceroute",name: "traceroute" },
  whois:     { categoryId: "network_utilities", toolId: "whois",     binary: "whois",     name: "whois" },
  curl:      { categoryId: "network_utilities", toolId: "curl",      binary: "curl",      name: "curl" },
  nslookup:  { categoryId: "network_utilities", toolId: "nslookup",  binary: "nslookup",  name: "nslookup" },
  mtr:       { categoryId: "network_utilities", toolId: "mtr",       binary: "mtr",       name: "MTR" },
  nc:        { categoryId: "network_utilities", toolId: "nc",        binary: "nc",        name: "Netcat" },
  telnet:    { categoryId: "network_utilities", toolId: "telnet",    binary: "telnet",    name: "Telnet" },
  ssh:       { categoryId: "network_utilities", toolId: "ssh",       binary: "ssh",       name: "SSH" },
  netstat:   { categoryId: "network_utilities", toolId: "netstat",   binary: "netstat",   name: "Netstat" },
  ss:        { categoryId: "network_utilities", toolId: "ss",        binary: "ss",        name: "SS" },
  ip:        { categoryId: "network_utilities", toolId: "ip",        binary: "ip",        name: "ip" },
  ifconfig:  { categoryId: "network_utilities", toolId: "ifconfig",  binary: "ifconfig",  name: "ifconfig" },
  arp:       { categoryId: "network_utilities", toolId: "arp",       binary: "arp",       name: "arp" },
  iwconfig:  { categoryId: "network_utilities", toolId: "iwconfig",  binary: "iwconfig",  name: "iwconfig" },
  route:     { categoryId: "network_utilities", toolId: "route",     binary: "route",     name: "route" },
};

const ALIASES: Record<string, string> = { "?": "help", h: "help", ls: "tools", cls: "clear" };

const FLAG_SUGGESTIONS: Record<string, string[]> = {
  nmap: ["-sS", "-sT", "-sU", "-sV", "-sC", "-A", "-O", "-T4", "-T5", "-p-", "-p ", "--top-ports ", "-v", "-vv", "-oN ", "-oX ", "-Pn", "-n", "--reason", "--open"],
  dig: ["+short", "+noall", "+answer", "+trace", "-x ", "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "ANY", "@"],
  ping: ["-c ", "-i ", "-t ", "-s ", "-f", "-q", "-W ", "-4", "-6"],
  curl: ["-s", "-S", "-v", "-L", "-k", "-I", "-X ", "-H ", "-d ", "-o ", "-O", "-f", "--connect-timeout ", "https://", "http://"],
  whois: ["-h ", "-p ", "-H"],
  nslookup: ["-type=", "-port=", "-debug", "-timeout="],
  traceroute: ["-n", "-m ", "-q ", "-w ", "-p ", "-4", "-6"],
  sqlmap: ["--batch", "--dbs", "--tables", "--dump", "--level=", "--risk=", "--dbms=", "--os-shell", "-r ", "-u "],
  gobuster: ["dir", "dns", "vhost", "fuzz", "-w ", "-u ", "-t ", "-x ", "-s ", "-k", "-r"],
  hydra: ["-l ", "-L ", "-p ", "-P ", "-t ", "-s ", "-V", "-f", "-e nsr", "ssh://", "ftp://", "http-post-form://"],
  nuclei: ["-severity ", "-tags ", "-t ", "-rl ", "-c ", "-o ", "-json", "-silent", "-v"],
  nikto: ["-ssl", "-nossl", "-port ", "-Format ", "-Tuning ", "-id ", "-evasion ", "-Plugins "],
  ffuf: ["-w ", "-u ", "-t ", "-e ", "-c", "-s", "-v", "-recursion", "-H ", "-X ", "-d "],
  wpscan: ["--enumerate ", "--api-token ", "--plugins-detection ", "--url ", "-o "],
  hashcat: ["-m ", "-a ", "-o ", "--force", "--show", "--username", "-r ", "-O", "-w "],
  john: ["--wordlist=", "--format=", "--rules", "--show", "--incremental"],
  theharvester: ["-b ", "-l ", "-d ", "-f "],
  amass: ["-passive", "-active", "-intel", "-d ", "-o ", "-dir ", "-ip", "-brute", "-min-for-recursive ", "-config "],
  sublist3r: ["-d ", "-p ", "-t ", "-v", "-o "],
  dnsrecon: ["-t ", "-d ", "-D ", "-n ", "-r ", "--lifetime ", "--threads ", "--db ", "-a", "-s"],
  dirb: ["-w ", "-o ", "-X ", "-r", "-z ", "-t ", "-p ", "-H "],
  searchsploit: ["-e", "-c", "-t", "-w", "--www", "-j", "--id"],
  binwalk: ["-e", "-Me", "-D", "-d ", "-M", "-r", "-T"],
  trivy: ["image ", "fs ", "repo ", "k8s ", "--severity ", "--format ", "--output ", "--scanners ", "--ignore-unfixed"],
  impacket: ["secretsdump", "psexec", "smbexec", "wmiexec", "GetADUsers", "GetNPUsers"],
  responder: ["-I ", "-A", "-w", "-v", "-F", "--lm", "--NBTNS", "--DHCP"],
}

const TARGET_RX = /^(?:https?:\/\/)?[a-z0-9][\w.-]*\.[a-z]{2,}(?:\/\S*)?$|^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?$|^\[?[a-f0-9:]+\]?$/i;

type Line = { kind: "prompt" | "stdout" | "stderr" | "info" | "warn" | "ok" | "err"; text: string };

type TerminalSession = {
  id: string;
  name: string;
  lines: Line[];
  input: string;
  history: string[];
  histIdx: number;
  busy: boolean;
  abortController: AbortController | null;
};

const LS_HIST = "ba.terminal.history.v1";
const LS_LINES = "ba.terminal.buffer.v1";
const PROMPT = "analyst@beyondlabs:~$";
const MAX_LINES = 2000;

function loadJSON<T>(k: string, fb: T): T { try { const r = localStorage.getItem(k); return r ? JSON.parse(r) : fb; } catch { return fb; } }
function saveJSON<T>(k: string, v: T) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} }

function tokenize(input: string): string[] {
  const out: string[] = [];
  let cur = "", q: '"' | "'" | null = null, esc = false;
  for (const ch of input) {
    if (esc) { cur += ch; esc = false; continue; }
    if (ch === "\\") { esc = true; continue; }
    if (q) {
      if (ch === q) q = null; else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") { q = ch; continue; }
    if (/\s/.test(ch)) { if (cur) { out.push(cur); cur = ""; } continue; }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

function splitTargetAndArgs(rest: string[]): { target?: string; args: string } {
  const optWithValue = new Set(["-o", "-i", "-w", "-x", "-t", "-b", "-l", "-p", "-u", "-d", "-f"]);
  let targetIdx = -1;
  for (let i = 0; i < rest.length; i++) {
    const tok = rest[i];
    if (tok.startsWith("-")) continue;
    if (i > 0 && optWithValue.has(rest[i - 1])) continue;
    if (TARGET_RX.test(tok)) { targetIdx = i; break; }
  }
  if (targetIdx < 0) {
    for (let i = rest.length - 1; i >= 0; i--) {
      const tok = rest[i];
      if (tok.startsWith("-")) continue;
      if (i > 0 && optWithValue.has(rest[i - 1])) continue;
      targetIdx = i; break;
    }
  }
  if (targetIdx < 0) return { args: rest.join(" ") };
  const target = rest[targetIdx];
  const args = [...rest.slice(0, targetIdx), ...rest.slice(targetIdx + 1)].join(" ");
  return { target, args };
}

function TerminalPage() {
  const [sessions, setSessions] = useState<TerminalSession[]>(() => {
    const saved = loadJSON<{ id: string; name: string }[]>("ba.terminal.sessions.meta", []);
    if (saved.length > 0) {
      return saved.map(m => ({
        id: m.id,
        name: m.name,
        lines: loadJSON<Line[]>(`ba.terminal.session.${m.id}.lines`, []),
        history: loadJSON<string[]>(`ba.terminal.session.${m.id}.history`, []),
        input: "",
        histIdx: -1,
        busy: false,
        abortController: null,
      }));
    }
    const legacyLines = loadJSON<Line[]>(LS_LINES, []);
    const legacyHistory = loadJSON<string[]>(LS_HIST, []);
    return [{
      id: crypto.randomUUID(),
      name: "Session 1",
      lines: legacyLines.length > 0 ? legacyLines : [
        { kind: "info", text: "BeyondLabs Terminal — connected to the FastAPI toolkit backend." },
        { kind: "info", text: "Type `help` for built-ins, `tools` for available binaries, or run any tool directly (e.g. `nmap -sV scanme.nmap.org`)." },
      ],
      history: legacyHistory,
      input: "",
      histIdx: -1,
      busy: false,
      abortController: null,
    }];
  });

  const [activeIdx, setActiveIdx] = useState(() => {
    const p = new URLSearchParams(window.location.search);
    const t = parseInt(p.get("tab") ?? "0", 10);
    return isNaN(t) || t < 0 ? 0 : t;
  });

  const activeSession = sessions[activeIdx] ?? sessions[0]!;

  useEffect(() => {
    const url = new URL(window.location.href);
    const cur = url.searchParams.get("tab");
    if (cur !== String(activeIdx)) {
      url.searchParams.set("tab", String(activeIdx));
      window.history.replaceState(null, "", url.toString());
    }
  }, [activeIdx]);

  useEffect(() => {
    if (sessions.length > 0 && activeIdx >= sessions.length) {
      setActiveIdx(Math.max(0, sessions.length - 1));
    }
  }, [sessions.length, activeIdx]);

  useEffect(() => {
    setHistorySearch(false);
  }, [activeIdx]);

  const [historySearch, setHistorySearch] = useState(false);
  const [historyQuery, setHistoryQuery] = useState("");
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [cmdError, setCmdError] = useState<string | null>(null);
  const locker = useLocker();
  const [backendUrl, setLocalUrl] = useState(() => getBackendUrl());
  const [status, setStatus] = useState<BackendStatus>("unknown");

  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const pendingExpand = useRef<Record<string, string[]>>({});
  const MAX_OUTPUT_LINES = 150;

  useEffect(() => {
    saveJSON("ba.terminal.sessions.meta", sessions.map(s => ({ id: s.id, name: s.name })));
    for (const s of sessions) {
      saveJSON(`ba.terminal.session.${s.id}.lines`, s.lines.slice(-MAX_LINES));
      saveJSON(`ba.terminal.session.${s.id}.history`, s.history.slice(-500));
    }
  });

  useEffect(() => {
    try { localStorage.removeItem(LS_HIST); } catch {}
    try { localStorage.removeItem(LS_LINES); } catch {}
  }, []);

  function pushAt(idx: number, ...xs: Line[]) {
    setSessions(prev => prev.map((s, i) => i === idx ? { ...s, lines: [...s.lines, ...xs].slice(-MAX_LINES) } : s));
  }

  function updateAt(idx: number, updater: (s: TerminalSession) => TerminalSession) {
    setSessions(prev => prev.map((s, i) => i === idx ? updater(s) : s));
  }

  const push = (...xs: Line[]) => pushAt(activeIdx, ...xs);
  const updateSession = (updater: (s: TerminalSession) => TerminalSession) => updateAt(activeIdx, updater);

  function expandOutput(rawLines: string[], key: string, kind: "stdout" | "stderr") {
    if (rawLines.length <= MAX_OUTPUT_LINES) {
      push(...rawLines.map(l => ({ kind, text: l })));
      return;
    }
    push(...rawLines.slice(0, MAX_OUTPUT_LINES).map(l => ({ kind, text: l })));
    const remaining = rawLines.slice(MAX_OUTPUT_LINES);
    const showKey = `${kind}-${key}`;
    push({
      kind: "info",
      text: `[expand-key:${showKey}] … ${remaining.length} more lines — click to show all`,
    });
    pendingExpand.current[showKey] = remaining;
  }

  const check = useCallback(async () => {
    setStatus("checking");
    const r = await pingBackend();
    setStatus(r.ok ? "online" : "offline");
  }, []);

  useEffect(() => { void check(); }, [check]);
  useEffect(() => { void check(); }, [backendUrl, check]);
  useEffect(() => { scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight }); }, [activeSession.lines, activeSession.busy]);

  function cancelRun() {
    updateSession(s => {
      s.abortController?.abort();
      return { ...s, busy: false };
    });
    push({ kind: "warn", text: "^C — cancelled" });
  }

  function clear() {
    updateSession(s => ({ ...s, lines: [{ kind: "info", text: "Cleared." }] }));
  }

  async function runCommand(raw: string) {
    const cmd = raw.trim();
    if (!cmd) return;
    const idx = activeIdx;

    pushAt(idx, { kind: "prompt", text: `${PROMPT} ${cmd}` });
    updateAt(idx, s => ({
      ...s,
      history: s.history[s.history.length - 1] === cmd ? s.history : [...s.history, cmd],
      histIdx: -1,
    }));

    const tokens = tokenize(cmd);
    let name = tokens[0].toLowerCase();
    name = ALIASES[name] ?? name;
    const rest = tokens.slice(1);

    if (name === "help") {
      pushAt(idx,
        { kind: "info", text: "Built-ins:" },
        { kind: "stdout", text: "  help                     Show this help" },
        { kind: "stdout", text: "  tools [category]         List available binaries (optionally filter)" },
        { kind: "stdout", text: "  history                  Show command history" },
        { kind: "stdout", text: "  clear                    Clear the screen" },
        { kind: "stdout", text: "  backend                  Show backend URL and status" },
        { kind: "stdout", text: "  backend set <url>        Point the terminal at a backend" },
        { kind: "stdout", text: "  backend ping             Recheck the backend" },
        { kind: "stdout", text: "  echo <text>              Print text" },
        { kind: "stdout", text: "  date                     Print current ISO timestamp" },
        { kind: "info", text: "Any other command is dispatched to the backend, e.g." },
        { kind: "stdout", text: "  nmap -sV -T4 scanme.nmap.org" },
        { kind: "stdout", text: "  dig +short example.com" },
        { kind: "stdout", text: "  whois example.com" },
        { kind: "stdout", text: "  curl -s https://httpbin.org/ip" },
        { kind: "stdout", text: "  ping -c 4 1.1.1.1" },
      );
      return;
    }
    if (name === "clear") { updateAt(idx, s => ({ ...s, lines: [{ kind: "info", text: "Cleared." }] })); return; }
    if (name === "history") {
      const hist = sessions[idx].history;
      if (!hist.length) pushAt(idx, { kind: "info", text: "(empty)" });
      else hist.slice(-50).forEach((h, i) => pushAt(idx, { kind: "stdout", text: `  ${String(i + 1).padStart(3)}  ${h}` }));
      return;
    }
    if (name === "echo") { pushAt(idx, { kind: "stdout", text: rest.join(" ") }); return; }
    if (name === "date") { pushAt(idx, { kind: "stdout", text: new Date().toISOString() }); return; }
    if (name === "pwd") { pushAt(idx, { kind: "stdout", text: "/analyst" }); return; }
    if (name === "whoami") { pushAt(idx, { kind: "stdout", text: "analyst" }); return; }
    if (name === "cd") { pushAt(idx, { kind: "info", text: "No-op — terminal runs remote binaries via the backend." }); return; }

    if (name === "tools") {
      const filter = rest[0]?.toLowerCase();
      const bins = Object.entries(BIN_MAP)
        .filter(([, t]) => !filter || t.categoryId.includes(filter) || t.binary.includes(filter))
        .sort((a, b) => a[0].localeCompare(b[0]));
      if (!bins.length) { pushAt(idx, { kind: "warn", text: `No tools match "${filter}".` }); return; }
      const groups = new Map<string, string[]>();
      bins.forEach(([bin, t]) => {
        const arr = groups.get(t.categoryId) ?? [];
        arr.push(bin);
        groups.set(t.categoryId, arr);
      });
      pushAt(idx, { kind: "info", text: `${bins.length} binaries available across ${groups.size} categories.` });
      [...groups.entries()].forEach(([cat, arr]) => {
        pushAt(idx, { kind: "stdout", text: `  [${cat}]` });
        pushAt(idx, { kind: "stdout", text: "    " + arr.join("  ") });
      });
      return;
    }

    if (name === "backend") {
      const sub = rest[0]?.toLowerCase();
      if (!sub) {
        pushAt(idx, { kind: "stdout", text: `URL:    ${getBackendUrl()}` });
        pushAt(idx, { kind: "stdout", text: `Status: ${status}` });
        return;
      }
      if (sub === "ping") { await check(); pushAt(idx, { kind: status === "online" ? "ok" : "warn", text: `Backend is ${status}.` }); return; }
      if (sub === "set" && rest[1]) {
        setBackendUrl(rest[1]); setLocalUrl(rest[1]);
        pushAt(idx, { kind: "ok", text: `Backend URL set to ${rest[1]}. Rechecking…` });
        return;
      }
      pushAt(idx, { kind: "err", text: "Usage: backend | backend ping | backend set <url>" });
      return;
    }

    const tool = BIN_MAP[name];

    if (status !== "online") {
      pushAt(idx,
        { kind: "err", text: `backend is ${status}` },
        { kind: "info", text: `Start the FastAPI backend at ${getBackendUrl()} or run \`backend set <url>\`.` },
      );
      return;
    }

    const { target, args } = splitTargetAndArgs(rest);
    const ctl = new AbortController();
    updateAt(idx, s => {
      s.abortController?.abort();
      return { ...s, abortController: ctl, busy: true };
    });
    const blockId = crypto.randomUUID();
    try {
      const res = await runToolRemote({
        category_id: tool?.categoryId ?? "network_utilities",
        tool_id: tool?.toolId ?? name,
        target,
        args,
      }, ctl.signal);
      if (res.command) pushAt(idx, { kind: "info", text: `# ${res.command}` });
      if (res.stdout) expandOutput(res.stdout.replace(/\n$/, "").split("\n"), `stdout-${blockId}`, "stdout");
      if (res.stderr) expandOutput(res.stderr.replace(/\n$/, "").split("\n"), `stderr-${blockId}`, "stderr");
      if (res.error) pushAt(idx, { kind: "err", text: res.error });
      if (res.suggestion) pushAt(idx, { kind: "info", text: `hint: ${res.suggestion}` });
      const tone: Line["kind"] =
        res.status === "completed" ? "ok"
        : res.status === "failed" || res.status === "error" ? "err"
        : res.status === "timeout" ? "warn" : "info";
      pushAt(idx, { kind: tone, text: `[${res.status ?? "done"}] exit=${res.return_code ?? "?"}` });
      pushTimelineEvent({ source: "terminal", verb: res.status === "completed" ? "completed" : res.status === "error" || res.status === "failed" ? "failed" : "timeout", detail: `${name} ${target ?? args ?? ""} — ${res.status} (exit ${res.return_code ?? "?"})`.trim(), target: target, result: res.status ?? "done" });
    } catch (e) {
      pushAt(idx, { kind: "err", text: `request failed: ${(e as Error).message}` });
      setCmdError(`Command failed: ${(e as Error).message}`);
      setStatus("offline");
    } finally {
      updateAt(idx, s => ({ ...s, busy: false }));
    }
  }

  function onKey(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "r" && e.ctrlKey) {
      e.preventDefault();
      if (historySearch) { setHistorySearch(false); return; }
      setHistorySearch(true);
      setHistoryQuery("");
      setSelectedIdx(0);
      return;
    }

    if (historySearch) {
      if (e.key === "Escape") {
        e.preventDefault();
        setHistorySearch(false);
        return;
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIdx(prev => Math.max(0, prev - 1));
        return;
      }
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIdx(prev => Math.min(filteredHistory.length - 1, prev + 1));
        return;
      }
      if (e.key === "Enter") {
        e.preventDefault();
        if (filteredHistory.length > 0 && selectedIdx >= 0 && selectedIdx < filteredHistory.length) {
          updateSession(s => ({ ...s, input: filteredHistory[selectedIdx] }));
        }
        setHistorySearch(false);
        return;
      }
      return;
    }

    if (e.key === "Enter") {
      e.preventDefault();
      if (activeSession.busy) return;
      const val = activeSession.input;
      updateSession(s => ({ ...s, input: "" }));
      void runCommand(val);
      return;
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (!activeSession.history.length) return;
      const next = activeSession.histIdx < 0 ? activeSession.history.length - 1 : Math.max(0, activeSession.histIdx - 1);
      updateSession(s => ({ ...s, histIdx: next, input: s.history[next] ?? "" }));
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (activeSession.histIdx < 0) return;
      const next = activeSession.histIdx + 1;
      if (next >= activeSession.history.length) { updateSession(s => ({ ...s, histIdx: -1, input: "" })); }
      else { updateSession(s => ({ ...s, histIdx: next, input: activeSession.history[next] })); }
      return;
    }
    if (e.key === "Tab") {
      e.preventDefault();
      const parts = activeSession.input.split(/\s+/);
      if (parts.length === 1 && parts[0]) {
        const cands = Object.keys(BIN_MAP).filter(k => k.startsWith(parts[0].toLowerCase()));
        if (cands.length === 1) updateSession(s => ({ ...s, input: cands[0] + " " }));
        else if (cands.length > 1) push({ kind: "info", text: cands.join("  ") });
      } else if (parts.length >= 2) {
        const cmd = parts[0].toLowerCase();
        const flags = FLAG_SUGGESTIONS[cmd];
        if (flags) {
          const partial = parts[parts.length - 1];
          const cands = flags.filter(f => f.startsWith(partial));
          if (cands.length === 1) {
            const rest = parts.slice(0, -1).join(" ");
            updateSession(s => ({ ...s, input: rest + " " + cands[0] }));
          } else if (cands.length > 1) {
            push({ kind: "info", text: cands.join("  ") });
          }
        }
      }
      return;
    }
    if (e.key === "l" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); clear(); return; }
    if (e.key === "c" && e.ctrlKey && !window.getSelection()?.toString()) {
      e.preventDefault();
      push({ kind: "warn", text: "^C" });
      updateSession(s => ({ ...s, input: "" }));
      return;
    }
  }

  function download() {
    const text = activeSession.lines.map(l => l.text).join("\n");
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `beyondlabs-terminal-${new Date().toISOString().replace(/[:.]/g, "-")}.log`;
    a.click(); URL.revokeObjectURL(a.href);
  }

  function addSession() {
    const newIdx = sessions.length;
    const id = crypto.randomUUID();
    setSessions(prev => [...prev, {
      id,
      name: `Session ${newIdx + 1}`,
      lines: [
        { kind: "info", text: "BeyondLabs Terminal — connected to the FastAPI toolkit backend." },
        { kind: "info", text: "Type `help` for built-ins, `tools` for available binaries, or run any tool directly (e.g. `nmap -sV scanme.nmap.org`)." },
      ],
      history: [],
      input: "",
      histIdx: -1,
      busy: false,
      abortController: null,
    }]);
    setActiveIdx(newIdx);
  }

  function closeSession(i: number) {
    if (sessions.length <= 1) return;
    setSessions(prev => prev.filter((_, idx) => idx !== i));
    if (i <= activeIdx) {
      setActiveIdx(prev => Math.max(0, prev - 1));
    }
  }

  const statusTone = useMemo(() =>
    status === "online" ? "border-success/40 bg-success/15 text-success"
    : status === "offline" ? "border-destructive/40 bg-destructive/15 text-destructive"
    : status === "checking" ? "border-warning/40 bg-warning/15 text-warning"
    : "border-border text-muted-foreground",
  [status]);

  const filteredHistory = useMemo(() => {
    if (!activeSession) return [];
    const deduped = [...new Set(activeSession.history)].reverse();
    if (!historyQuery.trim()) return deduped.slice(0, 50);
    const q = historyQuery.toLowerCase();
    return deduped.filter(h => h.toLowerCase().includes(q)).slice(0, 50);
  }, [activeSession, historyQuery]);

  return (
    <PageShell
      eyebrow="OPS / TERMINAL"
      title="Analyst Terminal"
      description="A recreation of a shell wired to the BeyondLabs backend. Run any recognised binary (nmap, dig, whois, sqlmap, hydra…) or built-ins like `help`, `tools`, `history`, `backend`."
      crumbs={[{ label: "Ops" }, { label: "Terminal" }]}
      meta={[
        { label: "binaries", value: String(Object.keys(BIN_MAP).length), tone: "primary" },
        { label: "history", value: String(activeSession.history.length) },
        { label: "backend", value: status, tone: status === "online" ? "success" : status === "offline" ? "destructive" : "warning" },
      ]}
      actions={
        <>
          <button onClick={() => void check()} className="inline-flex items-center gap-1 rounded border border-border bg-card/40 px-2.5 py-1 text-mono text-[10px] uppercase text-muted-foreground hover:border-primary/50 hover:text-primary">
            <RefreshCw className="h-3 w-3" /> ping
          </button>
          <button onClick={download} className="inline-flex items-center gap-1 rounded border border-border bg-card/40 px-2.5 py-1 text-mono text-[10px] uppercase text-muted-foreground hover:border-primary/50 hover:text-primary">
            <Download className="h-3 w-3" /> save
          </button>
          <button onClick={clear} className="inline-flex items-center gap-1 rounded border border-border bg-card/40 px-2.5 py-1 text-mono text-[10px] uppercase text-muted-foreground hover:border-destructive/50 hover:text-destructive">
            <Trash2 className="h-3 w-3" /> clear
          </button>
        </>
      }
    >
      {cmdError && (
        <div className="flex items-center gap-2 rounded border border-destructive/40 bg-destructive/5 p-3 text-mono ba-text-sm text-destructive mb-2">
          <span className="flex-1">{cmdError}</span>
          <button onClick={() => setCmdError(null)} className="text-destructive/60 hover:text-destructive" aria-label="dismiss"><X className="h-3 w-3" /></button>
        </div>
      )}
      <Panel title="Session" icon={TerminalIcon} meta={backendUrl} bodyClassName="p-0">
        <div className="flex items-center gap-2 border-b border-divider-strong bg-gradient-to-b from-muted/30 to-muted/10 px-3 py-2">
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-destructive/70" />
            <span className="h-2.5 w-2.5 rounded-full bg-warning/80" />
            <span className="h-2.5 w-2.5 rounded-full bg-success/80" />
          </div>
          <span className="text-mono text-[10.5px] text-muted-foreground truncate">/dev/beyondlabs — analyst@shell</span>
          <span className={`ml-auto inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-mono text-[9.5px] uppercase tracking-widest ${statusTone}`}>
            {status === "online" ? <PlugZap className="h-3 w-3" /> : <Plug className="h-3 w-3" />}
            {status}
          </span>
        </div>

        <div className="flex items-center border-b border-border bg-background/40 px-2">
          {sessions.map((s, i) => (
            <button
              key={s.id}
              onClick={() => setActiveIdx(i)}
              className={
                "flex items-center gap-1.5 px-3 py-1.5 text-mono ba-text-2xs uppercase tracking-widest border-r border-border/50 transition-colors " +
                (i === activeIdx
                  ? "bg-background/80 text-foreground border-b-2 border-b-primary"
                  : "text-muted-foreground hover:text-foreground hover:bg-background/40")
              }
            >
              {s.name}
              {sessions.length > 1 && (
                <button
                  onClick={(e) => { e.stopPropagation(); closeSession(i); }}
                  className="ml-1 grid h-3.5 w-3.5 place-items-center rounded text-muted-foreground/60 hover:bg-destructive/20 hover:text-destructive"
                ><X className="h-2.5 w-2.5" /></button>
              )}
            </button>
          ))}
          <button
            onClick={addSession}
            className="flex items-center gap-1 px-2 py-1.5 text-mono ba-text-2xs text-muted-foreground hover:text-foreground transition-colors"
            title="New session"
          >
            <Plus className="h-3 w-3" />
          </button>
        </div>

        <div className="relative">
          <div
            ref={scrollRef}
            onClick={() => inputRef.current?.focus()}
            className="relative h-[60vh] min-h-[420px] overflow-auto bg-background/70 px-3 py-2 text-mono text-[12px] leading-[1.55] ba-rail"
          >
            <div aria-hidden className="pointer-events-none absolute inset-0 scanlines" />
            {activeSession.lines.map((l, i) => (
              <div key={i} className={cls(l.kind)} onClick={() => {
                if (l.kind === "info" && l.text.includes("expand-key:")) {
                  const m = l.text.match(/expand-key:(stdout|stderr)-([\w-]+)/);
                  if (m) {
                    const key = `${m[1]}-${m[2]}`;
                    const remaining = pendingExpand.current[key];
                    if (remaining) {
                      push(...remaining.map(t => ({ kind: m[1] as "stdout" | "stderr", text: t })));
                      push({ kind: "info", text: `[shown all ${remaining.length} lines]` });
                      delete pendingExpand.current[key];
                    }
                  }
                }
              }}>
                {l.kind === "prompt" ? l.text : l.kind === "stdout" || l.kind === "stderr"
                  ? <span dangerouslySetInnerHTML={{ __html: renderAnsi(l.text) || "&nbsp;" }} />
                  : l.kind === "info" && l.text.includes("expand-key:")
                    ? <span className="cursor-pointer text-info/70 hover:text-info underline decoration-dotted">{l.text.replace(/\[expand-key:\w+-\w+\]\s*/, "")}</span>
                    : l.text || "\u00a0"}
              </div>
            ))}
          <div className="flex items-baseline gap-2">
            <span className="text-primary/80 shrink-0">{PROMPT}</span>
            <input
              ref={inputRef}
              autoFocus
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              value={historySearch ? historyQuery : activeSession.input}
              onChange={e => {
                if (historySearch) {
                  setHistoryQuery(e.target.value);
                  setSelectedIdx(0);
                } else {
                  updateSession(s => ({ ...s, input: e.target.value }));
                }
              }}
              onKeyDown={onKey}
              disabled={activeSession.busy}
              className="flex-1 bg-transparent text-foreground outline-none placeholder:text-muted-foreground/50 disabled:opacity-50"
              placeholder={historySearch ? "type to filter history…" : activeSession.busy ? "running…" : "type a command — try `help`"}
            />
            {activeSession.busy && <>
              <span className="text-warning animate-pulse text-[11px]">● executing</span>
              <button onClick={cancelRun} className="rounded border border-destructive/40 px-2 py-0.5 text-[10px] uppercase tracking-wider text-destructive hover:bg-destructive/10">cancel</button>
            </>}
          </div>
          </div>

          {historySearch && (
            <div className="absolute bottom-0 left-0 right-0 z-50 mx-2 mb-1 max-h-48 overflow-hidden rounded-lg border border-border bg-card elevation-floating">
              <div className="flex items-center gap-2 border-b border-border/50 px-2.5 py-1 text-mono text-[9.5px] text-muted-foreground">
                <span className="text-primary/70">reverse-i-search</span>
                <span className="text-info">{historyQuery || "(empty)"}</span>
              </div>
              <div className="max-h-40 overflow-auto ba-rail">
                {filteredHistory.length === 0 ? (
                  <div className="px-3 py-2 text-mono text-[11px] text-muted-foreground">no matches</div>
                ) : (
                  filteredHistory.map((item, i) => (
                    <div
                      key={i + item}
                      onMouseDown={() => { updateSession(s => ({ ...s, input: item })); setHistorySearch(false); }}
                      className={`cursor-pointer px-3 py-1 text-mono text-[11px] ${
                        i === selectedIdx ? "bg-primary/20 text-primary" : "text-foreground/80 hover:bg-accent/50"
                      }`}
                    >
                      {item}
                    </div>
                  ))
                )}
              </div>
              <div className="flex items-center gap-3 border-t border-border/50 px-2.5 py-1 text-mono text-[9px] text-muted-foreground">
                <span>↑↓ navigate</span>
                <span>↵ select</span>
                <span>Esc cancel</span>
              </div>
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-border bg-background/50 px-3 py-1.5 text-mono text-[10px] text-muted-foreground">
          <span>{activeSession.lines.length.toLocaleString()} lines</span>
          <span>·</span>
          <span>↑/↓ history</span>
          <span>·</span>
          <span>Ctrl+R search</span>
          <span>·</span>
          <span>Tab complete</span>
          <span>·</span>
          <span>Ctrl+L clear</span>
          <button
            onClick={() => {
              const text = activeSession.lines.map(l => l.text).join("\n");
              const ips = [...new Set(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [])];
              const domains = [...new Set(text.match(/[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+/g) ?? [])];
              const hashes = [...new Set(text.match(/\b[a-fA-F0-9]{32,64}\b/g) ?? [])];
              ips.forEach(v => locker.add({ value: v, type: "ipv4", source: "/terminal" }));
              domains.forEach(v => locker.add({ value: v, type: "domain", source: "/terminal" }));
              hashes.forEach(v => locker.add({ value: v, type: v.length === 64 ? "sha256" : v.length === 40 ? "sha1" : "md5", source: "/terminal" }));
              toast(`Added ${ips.length + domains.length + hashes.length} IOCs to locker`);
            }}
            className="ml-auto inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-0.5 text-mono text-[9px] uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground"
          >
            send IOCs to locker
          </button>
        </div>
      </Panel>

      <SendToRow targets={[
        { label: "Case Notebook", to: "/case", icon: TerminalIcon, onClick: () => sendToCase({ body: `Terminal session output:\n${activeSession.lines.slice(-30).map(l => l.text).join("\n")}`, source: "/terminal", kind: "evidence" }) },
        { label: "Hacking Toolkit", to: "/hacking-toolkit", icon: TerminalIcon },
        { label: "Logs & Alerts", to: "/logs", icon: TerminalIcon },
      ]} />
    </PageShell>
  );
}


const ANSI_COLORS: Record<string, string> = {
  "0":  "",              "1": "font-weight:700",
  "30": "color:#555",   "31": "color:var(--destructive)", "32": "color:var(--success)",
  "33": "color:var(--warning)", "34": "color:var(--primary)", "35": "color:var(--chart-2,#c084fc)",
  "36": "color:var(--chart-3,#22d3ee)", "37": "color:var(--foreground)",
  "90": "color:#888",   "91": "color:var(--destructive)", "92": "color:var(--success)",
  "93": "color:var(--warning)", "94": "color:var(--primary)", "95": "color:var(--chart-2,#c084fc)",
  "96": "color:var(--chart-3,#22d3ee)", "97": "color:var(--foreground)",
};
function renderAnsi(text: string): string {
  const parts: string[] = [];
  let last = 0, m: RegExpExecArray | null;
  const re = /\x1b\[(\d+(?:;\d+)*)m/g;
  re.lastIndex = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) parts.push(escapeHtml(text.slice(last, m.index)));
    const codes = m[1].split(";").map(Number);
    const style: string[] = [];
    for (let i = 0; i < codes.length; i++) {
      const c = codes[i];
      if (c === 0) { style.length = 0; continue; }
      if (c === 1) { style.push("font-weight:700"); continue; }
      if (c === 4) { style.push("text-decoration:underline"); continue; }
      if (c === 38 && codes[i + 1] === 5 && codes[i + 2] !== undefined) {
        style.push(`color:${ansi256(codes[i + 2])}`); i += 2; continue;
      }
      if (c === 48 && codes[i + 1] === 5 && codes[i + 2] !== undefined) {
        style.push(`background-color:${ansi256(codes[i + 2])}`); i += 2; continue;
      }
      if (c === 38 && codes[i + 1] === 2 && codes[i + 2] !== undefined && codes[i + 3] !== undefined && codes[i + 4] !== undefined) {
        style.push(`color:rgb(${codes[i+2]},${codes[i+3]},${codes[i+4]})`); i += 4; continue;
      }
      if (c === 48 && codes[i + 1] === 2 && codes[i + 2] !== undefined && codes[i + 3] !== undefined && codes[i + 4] !== undefined) {
        style.push(`background-color:rgb(${codes[i+2]},${codes[i+3]},${codes[i+4]})`); i += 4; continue;
      }
      const s = ANSI_COLORS[String(c)];
      if (s) style.push(s);
    }
    parts.push(style.length ? `<span style="${style.join(";")}">` : "</span>");
    last = re.lastIndex;
  }
  if (last < text.length) parts.push(escapeHtml(text.slice(last)));
  return parts.join("");
}

function ansi256(code: number): string {
  if (code < 16) {
    const ansiBasic: [number,number,number][] = [
      [0,0,0],[205,0,0],[0,205,0],[205,205,0],
      [0,0,205],[205,0,205],[0,205,205],[229,229,229],
      [128,128,128],[255,0,0],[0,255,0],[255,255,0],
      [0,0,255],[255,0,255],[0,255,255],[255,255,255],
    ];
    const [r,g,b] = ansiBasic[code] ?? [0,0,0];
    return `rgb(${r},${g},${b})`;
  }
  if (code < 232) {
    const i = code - 16;
    const r = (i / 36) * 51 | 0; const g = ((i % 36) / 6) * 51 | 0; const b = (i % 6) * 51 | 0;
    return `rgb(${r},${g},${b})`;
  }
  const gray = (code - 232) * 10 + 8;
  return `rgb(${gray},${gray},${gray})`;
}
function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function cls(kind: Line["kind"]): string {
  switch (kind) {
    case "prompt": return "text-primary/85 whitespace-pre-wrap";
    case "stderr": return "text-destructive/85 whitespace-pre-wrap";
    case "info":   return "text-info/90 whitespace-pre-wrap";
    case "warn":   return "text-warning whitespace-pre-wrap";
    case "ok":     return "text-success whitespace-pre-wrap";
    case "err":    return "text-destructive font-semibold whitespace-pre-wrap";
    default:       return "text-foreground/90 whitespace-pre-wrap";
  }
}
