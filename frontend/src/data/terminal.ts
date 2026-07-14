export type ToolRef = { categoryId: string; toolId: string; binary: string; name: string };

export const BIN_MAP: Record<string, ToolRef> = {
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

export const ALIASES: Record<string, string> = { "?": "help", h: "help", ls: "tools", cls: "clear" };

export const FLAG_SUGGESTIONS: Record<string, string[]> = {
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
};

export const TARGET_RX = /^(?:https?:\/\/)?[a-z0-9][\w.-]*\.[a-z]{2,}(?:\/\S*)?$|^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?$|^\[?[a-f0-9:]+\]?$/i;

export type Line = { kind: "prompt" | "stdout" | "stderr" | "info" | "warn" | "ok" | "err"; text: string };

export type TerminalSession = {
  id: string;
  name: string;
  lines: Line[];
  input: string;
  history: string[];
  histIdx: number;
  busy: boolean;
  abortController: AbortController | null;
};

export const LS_HIST = "ba.terminal.history.v1";
export const LS_LINES = "ba.terminal.buffer.v1";
export const PROMPT = "analyst@beyondlabs:~$";
export const MAX_LINES = 2000;

export function loadJSON<T>(k: string, fb: T): T { try { const r = localStorage.getItem(k); return r ? JSON.parse(r) : fb; } catch { return fb; } }
export function saveJSON<T>(k: string, v: T) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} }

export function tokenize(input: string): string[] {
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

export function splitTargetAndArgs(rest: string[]): { target?: string; args: string } {
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
