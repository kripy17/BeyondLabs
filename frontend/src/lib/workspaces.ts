import {
  MailWarning, Link2, Paperclip, Radar, ScanLine, Wand2,
  Activity, Wrench, Target, ShieldCheck, BookOpen, FileText,
  LayoutDashboard, Settings, Swords, Terminal,
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
    ],
  },
  {
    label: "Triage",
    items: [
      { title: "Smart Parser",      url: "/parser",     icon: Wand2,     desc: "Normalize IOCs from artifacts",  group: "Triage" },
      { title: "Phishing Triage",   url: "/phishing",   icon: MailWarning, desc: "Auth, headers, body verdict",    group: "Triage" },
      { title: "URL Analyzer",      url: "/url",        icon: Link2,     desc: "Redirects, lists, reputation",   group: "Triage" },
      { title: "Attachment Triage", url: "/attachment", icon: Paperclip, desc: "Hashes, strings, markers",       group: "Triage" },
    ],
  },
  {
    label: "Recon",
    items: [
      { title: "Recon & Exposure", url: "/recon", icon: Radar,    desc: "Subdomains, certs, cloud surface", group: "Recon" },
      { title: "Nmap Runner",      url: "/nmap",  icon: ScanLine, desc: "Bounded port scans",               group: "Recon" },
    ],
  },
  {
    label: "SIEM",
    items: [
      { title: "SIEM Workspace", url: "/siem", icon: Activity, desc: "Search, correlate, pivot", group: "SIEM" },
    ],
  },
  {
    label: "Offensive",
    items: [
      { title: "Hacking Toolkit", url: "/hacking-toolkit", icon: Swords,    desc: "Browse offensive tools & build commands", group: "Offensive" },
      { title: "Terminal",        url: "/terminal",        icon: Terminal, desc: "Shell wired to backend tools",               group: "Offensive" },
    ],
  },
  {
    label: "Tools",
    items: [
      { title: "CyberChef",      url: "/chef", icon: Wrench, desc: "Encode, decode, transform", group: "Tools" },
    ],
  },
  {
    label: "Detection",
    items: [
      { title: "Detection & MITRE",   url: "/mitre",     icon: Target,      desc: "ATT&CK coverage & gaps",       group: "Detection" },
      { title: "Detection Workspace", url: "/detection", icon: ShieldCheck, desc: "Author & simulate Sigma/YARA", group: "Detection" },
      { title: "SOC Guide",           url: "/guide",     icon: BookOpen,    desc: "Runbooks, playbooks",          group: "Detection" },
      { title: "Case & Report",       url: "/case",      icon: FileText,    desc: "Compose handoff brief",        group: "Detection" },
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
