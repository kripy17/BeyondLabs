import {
  MailWarning, Link2, Paperclip, Radar, Wand2,
  Activity, Wrench, Target, ShieldCheck, BookOpen, FileText,
  LayoutDashboard, Settings, Swords, Code2, Search,
  Bug, Shield, Globe, Bookmark, Clock,
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
    label: "Dashboard",
    items: [
      { title: "Command Deck", url: "/", icon: LayoutDashboard, desc: "Workbench home", group: "Dashboard" },
    ],
  },
  {
    label: "SIEM",
    items: [
      { title: "Workspace", url: "/siem", icon: Activity, desc: "Search, correlate, pivot", group: "SIEM" },
      { title: "Log Explorer", url: "/logs", icon: Activity, desc: "Browse collected logs", group: "SIEM" },
    ],
  },
  {
    label: "Investigation",
    items: [
      { title: "Triage", url: "/triage", icon: ListChecks, desc: "Review & disposition events", group: "Investigation" },
      { title: "Cases", url: "/case", icon: FileText, desc: "Compose handoff brief", group: "Investigation" },
      { title: "Activity", url: "/activity", icon: Clock, desc: "Timeline of all tool runs & events", group: "Investigation" },
      { title: "Timeline", url: "/timeline", icon: Clock, desc: "Raw event log viewer", group: "Investigation" },
      { title: "Phishing", url: "/phishing", icon: MailWarning, desc: "Auth, headers, body verdict", group: "Investigation" },
      { title: "URL Analysis", url: "/url", icon: Link2, desc: "Redirects, lists, reputation", group: "Investigation" },
      { title: "File Analysis", url: "/attachment", icon: Paperclip, desc: "Hashes, strings, markers", group: "Investigation" },
      { title: "Parser", url: "/parser", icon: Wand2, desc: "Universal intake — parse & pivot IOCs", group: "Investigation" },
      { title: "PCAP Analysis", url: "/pcap", icon: Globe, desc: "Quick pcap triage & CLI tools", group: "Investigation" },
    ],
  },
  {
    label: "Detection",
    items: [
      { title: "Workspace", url: "/detection", icon: ShieldCheck, desc: "Author & simulate Sigma/YARA", group: "Detection" },
      { title: "Sigma Tester", url: "/sigma-tester", icon: Shield, desc: "Test rules against samples", group: "Detection" },
      { title: "MITRE", url: "/mitre", icon: Target, desc: "ATT&CK coverage & gaps", group: "Detection" },
    ],
  },
  {
    label: "Intelligence",
    items: [
      { title: "IOC Search", url: "/intel", icon: Bug, desc: "CVE, threat actors, hash reputation, JA3/UA — unified", group: "Intelligence" },
      { title: "Threat Actors", url: "/threat-actors", icon: User, desc: "Actor profiles & campaigns", group: "Intelligence" },
      { title: "CVE", url: "/cve", icon: Shield, desc: "Vulnerability lookup", group: "Intelligence" },
      { title: "JA3", url: "/ja3-lookup", icon: Shield, desc: "JA3 fingerprint lookup", group: "Intelligence" },
    ],
  },
  {
    label: "Tools",
    items: [
      { title: "OSINT", url: "/osint", icon: User, desc: "Email, username, domain & phone lookups", group: "Tools" },
      { title: "Recon", url: "/recon", icon: Radar, desc: "Subdomains, certs, cloud surface", group: "Tools" },
      { title: "Nmap", url: "/nmap", icon: Network, desc: "Port scans & service discovery", group: "Tools" },
      { title: "Hacking Toolkit", url: "/hacking-toolkit", icon: Swords, desc: "Browse offensive tools & build commands", group: "Tools" },
      { title: "Terminal", url: "/terminal", icon: Terminal, desc: "Run shell commands & tool scripts", group: "Tools" },
      { title: "CyberChef", url: "/chef", icon: Wrench, desc: "Encode, decode, transform", group: "Tools" },
      { title: "Diff", url: "/diff", icon: Code2, desc: "Side-by-side artifact comparison", group: "Tools" },
      { title: "Regex", url: "/regex-playground", icon: Search, desc: "Build & test SOC regex patterns", group: "Tools" },
      { title: "Snippets", url: "/snippets", icon: Bookmark, desc: "SIEM queries, Sigma, regex & checklists", group: "Tools" },
    ],
  },
  {
    label: "Resources",
    items: [
      { title: "Guide", url: "/guide", icon: BookOpen, desc: "Runbooks, playbooks", group: "Resources" },
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
