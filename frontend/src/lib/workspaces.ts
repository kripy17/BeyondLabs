import {
  MailWarning, Link2, Paperclip, Radar, Wand2,
  Activity, Wrench, Target, ShieldCheck, BookOpen, FileText,
  LayoutDashboard, Settings, Swords, Code2, Search, Hash,
  Fingerprint, Bug, Users, Shield, Globe, Bookmark, Clock,
  Terminal, Network, User, ListChecks,
} from "lucide-react";

export type WorkspaceItem = {
  title: string;
  url: string;
  icon: import("lucide-react").LucideIcon;
  desc: string;
  group: string;
};

export type WorkspaceGroup = {
  label: string;
  items: WorkspaceItem[];
};

export const GROUPS: WorkspaceGroup[] = [
  {
    label: "Overview",
    items: [
      { title: "Command Deck", url: "/", icon: LayoutDashboard, desc: "Workbench home", group: "Overview" },
      { title: "Activity Feed", url: "/activity", icon: Clock, desc: "Timeline of all tool runs & events", group: "Overview" },
      { title: "Event Log", url: "/timeline", icon: Clock, desc: "Raw event log viewer", group: "Overview" },
    ],
  },
  {
    label: "Detection",
    items: [
      { title: "Detection Workspace", url: "/detection", icon: ShieldCheck, desc: "Author & simulate Sigma/YARA", group: "Detection" },
      { title: "Detection & MITRE",   url: "/mitre",     icon: Target,      desc: "ATT&CK coverage & gaps",       group: "Detection" },
      { title: "SOC Guide",           url: "/guide",     icon: BookOpen,    desc: "Runbooks, playbooks",          group: "Detection" },
    ],
  },
  {
    label: "Recon",
    items: [
      { title: "Recon & Exposure", url: "/recon", icon: Radar, desc: "Subdomains, certs, cloud surface", group: "Recon" },
      { title: "Nmap Scanner",     url: "/nmap", icon: Network, desc: "Port scans & service discovery", group: "Recon" },
    ],
  },
  {
    label: "Investigate",
    items: [
      { title: "Smart Parser",      url: "/parser",     icon: Wand2,      desc: "Universal intake — parse & pivot IOCs", group: "Investigate" },
      { title: "OSINT Investigation", url: "/osint",     icon: User,       desc: "Email, username, domain & phone lookups", group: "Investigate" },
      { title: "Phishing Triage",   url: "/phishing",   icon: MailWarning, desc: "Auth, headers, body verdict",           group: "Investigate" },
      { title: "URL Analyzer",      url: "/url",        icon: Link2,      desc: "Redirects, lists, reputation",          group: "Investigate" },
      { title: "Attachment Triage", url: "/attachment", icon: Paperclip,  desc: "Hashes, strings, markers",              group: "Investigate" },
    ],
  },
  {
    label: "Case",
    items: [
      { title: "Case & Report", url: "/case", icon: FileText, desc: "Compose handoff brief", group: "Case" },
    ],
  },
  {
    label: "SIEM",
    items: [
      { title: "SIEM Workspace", url: "/siem", icon: Activity, desc: "Search, correlate, pivot", group: "SIEM" },
      { title: "Triage Queue", url: "/triage", icon: ListChecks, desc: "Review & disposition events", group: "SIEM" },
    ],
  },
  {
    label: "Offensive",
    items: [
      { title: "Hacking Toolkit", url: "/hacking-toolkit", icon: Swords, desc: "Browse offensive tools & build commands", group: "Offensive" },
      { title: "Tool Terminal", url: "/terminal", icon: Terminal, desc: "Run shell commands & tool scripts", group: "Offensive" },
    ],
  },
  {
    label: "Tools",
    items: [
      { title: "CyberChef",      url: "/chef", icon: Wrench, desc: "Encode, decode, transform", group: "Tools" },
      { title: "CVE Database",    url: "/cve", icon: Bug, desc: "CVE lookup with EPSS, KEV, exploit availability", group: "Tools" },
      { title: "Threat Actors",   url: "/threat-actors", icon: Users, desc: "APT group & campaign lookup", group: "Tools" },
      { title: "Diff View",       url: "/diff", icon: Code2, desc: "Side-by-side artifact comparison", group: "Tools" },
      { title: "Regex Playground", url: "/regex-playground", icon: Search, desc: "Build & test SOC regex patterns", group: "Tools" },
      { title: "Hash Lookup",     url: "/hash-lookup", icon: Hash, desc: "Batch hash reputation lookup", group: "Tools" },
      { title: "JA3/JA4 & UA",    url: "/ja3-lookup", icon: Fingerprint, desc: "TLS fingerprint & user-agent DB", group: "Tools" },
      { title: "YARA/Sigma Tester", url: "/sigma-tester", icon: Shield, desc: "Test rules against samples", group: "Tools" },
      { title: "PCAP Analyzer",   url: "/pcap", icon: Globe, desc: "Quick pcap triage & CLI tools", group: "Tools" },
      { title: "Saved Snippets",  url: "/snippets", icon: Bookmark, desc: "SIEM queries, Sigma, regex & checklists", group: "Tools" },
    ],
  },
  {
    label: "System",
    items: [
      { title: "Settings", url: "/settings", icon: Settings, desc: "Theme, layout, prefs", group: "System" },
    ],
  },
];

export const ALL_ITEMS: WorkspaceItem[] = GROUPS.flatMap((g) => g.items);

export function findItem(url: string): WorkspaceItem | undefined {
  return ALL_ITEMS.find((i) => i.url === url);
}
