import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel } from "@/components/soc/Workspace";
import {
  getBackendUrl, setBackendUrl, pingBackend, runToolRemote,
  type BackendStatus,
} from "@/lib/backend";
import {
  Terminal as TerminalIcon, Plug, PlugZap, RefreshCw, Trash2, Download,
} from "lucide-react";

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
  nmap: ["-sS", "-sT", "-sU", "-sV", "-sC", "-A", "-O", "-T4", "-T5", "-p-", "-p ", "--top-ports ", "-v", "-vv", "-oN ", "-oX ", "-Pn", "-n", "--reason", "--open"],
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
  const [lines, setLines] = useState<Line[]>([]);
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [histIdx, setHistIdx] = useState<number>(-1);
  const [historySearch, setHistorySearch] = useState(false);
  const [historyQuery, setHistoryQuery] = useState("");
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [busy, setBusy] = useState(false);
  const [backendUrl, setLocalUrl] = useState(() => getBackendUrl());
  const [status, setStatus] = useState<BackendStatus>("unknown");

  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const MAX_OUTPUT_LINES = 150;

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
  const pendingExpand = useRef<Record<string, string[]>>({});

  const check = useCallback(async () => {
    setStatus("checking");
    setStatus((await pingBackend()) ? "online" : "offline");
  }, []);

  useEffect(() => {
    setHistory(loadJSON<string[]>(LS_HIST, []));
    const buf = loadJSON<Line[]>(LS_LINES, []);
    if (buf.length) setLines(buf);
    else setLines([
      { kind: "info", text: "BeyondLabs Terminal — connected to the FastAPI toolkit backend." },
      { kind: "info", text: "Type `help` for built-ins, `tools` for available binaries, or run any tool directly (e.g. `nmap -sV scanme.nmap.org`)." },
    ]);
    void check();
  }, [check]);

  useEffect(() => { saveJSON(LS_HIST, history.slice(-500)); }, [history]);
  useEffect(() => { saveJSON(LS_LINES, lines.slice(-MAX_LINES)); }, [lines]);
  useEffect(() => { scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight }); }, [lines, busy]);
  useEffect(() => { void check(); }, [backendUrl, check]);

  const push = useCallback((...xs: Line[]) => setLines(prev => [...prev, ...xs].slice(-MAX_LINES)), []);

  const clear = useCallback(() => setLines([{ kind: "info", text: "Cleared." }]), []);

  const runCommand = useCallback(async (raw: string) => {
    const cmd = raw.trim();
    if (!cmd) return;
    push({ kind: "prompt", text: `${PROMPT} ${cmd}` });
    setHistory(h => (h[h.length - 1] === cmd ? h : [...h, cmd]));
    setHistIdx(-1);

    const tokens = tokenize(cmd);
    let name = tokens[0].toLowerCase();
    name = ALIASES[name] ?? name;
    const rest = tokens.slice(1);

    if (name === "help") {
      push(
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
    if (name === "clear") { clear(); return; }
    if (name === "history") {
      if (!history.length) push({ kind: "info", text: "(empty)" });
      else history.slice(-50).forEach((h, i) => push({ kind: "stdout", text: `  ${String(i + 1).padStart(3)}  ${h}` }));
      return;
    }
    if (name === "echo") { push({ kind: "stdout", text: rest.join(" ") }); return; }
    if (name === "date") { push({ kind: "stdout", text: new Date().toISOString() }); return; }
    if (name === "pwd") { push({ kind: "stdout", text: "/analyst" }); return; }
    if (name === "whoami") { push({ kind: "stdout", text: "analyst" }); return; }
    if (name === "cd") { push({ kind: "info", text: "No-op — terminal runs remote binaries via the backend." }); return; }

    if (name === "tools") {
      const filter = rest[0]?.toLowerCase();
      const bins = Object.entries(BIN_MAP)
        .filter(([, t]) => !filter || t.categoryId.includes(filter) || t.binary.includes(filter))
        .sort((a, b) => a[0].localeCompare(b[0]));
      if (!bins.length) { push({ kind: "warn", text: `No tools match "${filter}".` }); return; }
      const groups = new Map<string, string[]>();
      bins.forEach(([bin, t]) => {
        const arr = groups.get(t.categoryId) ?? [];
        arr.push(bin);
        groups.set(t.categoryId, arr);
      });
      push({ kind: "info", text: `${bins.length} binaries available across ${groups.size} categories.` });
      [...groups.entries()].forEach(([cat, arr]) => {
        push({ kind: "stdout", text: `  [${cat}]` });
        push({ kind: "stdout", text: "    " + arr.join("  ") });
      });
      return;
    }

    if (name === "backend") {
      const sub = rest[0]?.toLowerCase();
      if (!sub) {
        push({ kind: "stdout", text: `URL:    ${getBackendUrl()}` });
        push({ kind: "stdout", text: `Status: ${status}` });
        return;
      }
      if (sub === "ping") { await check(); push({ kind: status === "online" ? "ok" : "warn", text: `Backend is ${status}.` }); return; }
      if (sub === "set" && rest[1]) {
        setBackendUrl(rest[1]); setLocalUrl(rest[1]);
        push({ kind: "ok", text: `Backend URL set to ${rest[1]}. Rechecking…` });
        return;
      }
      push({ kind: "err", text: "Usage: backend | backend ping | backend set <url>" });
      return;
    }

    const tool = BIN_MAP[name];

    if (status !== "online") {
      push(
        { kind: "err", text: `backend is ${status}` },
        { kind: "info", text: `Start the FastAPI backend at ${getBackendUrl()} or run \`backend set <url>\`.` },
      );
      return;
    }

    const { target, args } = splitTargetAndArgs(rest);
      setBusy(true);
      const blockId = crypto.randomUUID();
      try {
        const res = await runToolRemote({
          category_id: tool?.categoryId ?? "network_utilities",
          tool_id: tool?.toolId ?? name,
          target,
          args,
        });
        if (res.command) push({ kind: "info", text: `# ${res.command}` });
        if (res.stdout) expandOutput(res.stdout.replace(/\n$/, "").split("\n"), `stdout-${blockId}`, "stdout");
        if (res.stderr) expandOutput(res.stderr.replace(/\n$/, "").split("\n"), `stderr-${blockId}`, "stderr");
        if (res.error) push({ kind: "err", text: res.error });
      if (res.suggestion) push({ kind: "info", text: `hint: ${res.suggestion}` });
      const tone: Line["kind"] =
        res.status === "completed" ? "ok"
        : res.status === "failed" || res.status === "error" ? "err"
        : res.status === "timeout" ? "warn" : "info";
      push({ kind: tone, text: `[${res.status ?? "done"}] exit=${res.return_code ?? "?"}` });
    } catch (e) {
      push({ kind: "err", text: `request failed: ${(e as Error).message}` });
      setStatus("offline");
    } finally {
      setBusy(false);
    }
  }, [check, clear, history, push, status]);

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
          setInput(filteredHistory[selectedIdx]);
        }
        setHistorySearch(false);
        return;
      }
      return;
    }

    if (e.key === "Enter") {
      e.preventDefault();
      if (busy) return;
      const val = input;
      setInput("");
      void runCommand(val);
      return;
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (!history.length) return;
      const next = histIdx < 0 ? history.length - 1 : Math.max(0, histIdx - 1);
      setHistIdx(next); setInput(history[next] ?? "");
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (histIdx < 0) return;
      const next = histIdx + 1;
      if (next >= history.length) { setHistIdx(-1); setInput(""); }
      else { setHistIdx(next); setInput(history[next]); }
      return;
    }
    if (e.key === "Tab") {
      e.preventDefault();
      const parts = input.split(/\s+/);
      if (parts.length === 1 && parts[0]) {
        const cands = Object.keys(BIN_MAP).filter(k => k.startsWith(parts[0].toLowerCase()));
        if (cands.length === 1) setInput(cands[0] + " ");
        else if (cands.length > 1) push({ kind: "info", text: cands.join("  ") });
      } else if (parts.length >= 2) {
        const cmd = parts[0].toLowerCase();
        const flags = FLAG_SUGGESTIONS[cmd];
        if (flags) {
          const partial = parts[parts.length - 1];
          const cands = flags.filter(f => f.startsWith(partial));
          if (cands.length === 1) {
            const rest = parts.slice(0, -1).join(" ");
            setInput(rest + " " + cands[0]);
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
      setInput("");
      return;
    }
  }

  function download() {
    const text = lines.map(l => l.text).join("\n");
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `beyondlabs-terminal-${new Date().toISOString().replace(/[:.]/g, "-")}.log`;
    a.click(); URL.revokeObjectURL(a.href);
  }

  const statusTone = useMemo(() =>
    status === "online" ? "border-success/40 bg-success/15 text-success"
    : status === "offline" ? "border-destructive/40 bg-destructive/15 text-destructive"
    : status === "checking" ? "border-warning/40 bg-warning/15 text-warning"
    : "border-border text-muted-foreground",
  [status]);

  const filteredHistory = useMemo(() => {
    const deduped = [...new Set(history)].reverse();
    if (!historyQuery.trim()) return deduped.slice(0, 50);
    const q = historyQuery.toLowerCase();
    return deduped.filter(h => h.toLowerCase().includes(q)).slice(0, 50);
  }, [history, historyQuery]);

  return (
    <PageShell
      eyebrow="OPS / TERMINAL"
      title="Analyst Terminal"
      description="A recreation of a shell wired to the BeyondLabs backend. Run any recognised binary (nmap, dig, whois, sqlmap, hydra…) or built-ins like `help`, `tools`, `history`, `backend`."
      crumbs={[{ label: "Ops" }, { label: "Terminal" }]}
      meta={[
        { label: "binaries", value: String(Object.keys(BIN_MAP).length), tone: "primary" },
        { label: "history", value: String(history.length) },
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
      <Panel title="Session" icon={TerminalIcon} meta={backendUrl} bodyClassName="p-0">
        <div className="flex items-center gap-2 border-b border-border/60 bg-gradient-to-b from-muted/30 to-muted/10 px-3 py-2">
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

        <div className="relative">
          <div
            ref={scrollRef}
            onClick={() => inputRef.current?.focus()}
            className="relative h-[60vh] min-h-[420px] overflow-auto bg-background/70 px-3 py-2 text-mono text-[12px] leading-[1.55] ba-rail"
          >
            <div aria-hidden className="pointer-events-none absolute inset-0 scanlines" />
            {lines.map((l, i) => (
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
              value={historySearch ? historyQuery : input}
              onChange={e => {
                if (historySearch) {
                  setHistoryQuery(e.target.value);
                  setSelectedIdx(0);
                } else {
                  setInput(e.target.value);
                }
              }}
              onKeyDown={onKey}
              disabled={busy}
              className="flex-1 bg-transparent text-foreground outline-none placeholder:text-muted-foreground/50 disabled:opacity-50"
              placeholder={historySearch ? "type to filter history…" : busy ? "running…" : "type a command — try `help`"}
            />
            {busy && <span className="text-warning animate-pulse text-[11px]">● executing</span>}
          </div>
          </div>

          {historySearch && (
            <div className="absolute bottom-0 left-0 right-0 z-50 mx-2 mb-1 max-h-48 overflow-hidden rounded-lg border border-border bg-card shadow-xl">
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
                      onMouseDown={() => { setInput(item); setHistorySearch(false); }}
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
          <span>{lines.length.toLocaleString()} lines</span>
          <span>·</span>
          <span>↑/↓ history</span>
          <span>·</span>
          <span>Ctrl+R search</span>
          <span>·</span>
          <span>Tab complete</span>
          <span>·</span>
          <span>Ctrl+L clear</span>
        </div>
      </Panel>
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
