export type CveEntry = {
  id: string; description: string; cvss: number; epss: number;
  kev: boolean; exploit: { metasploit: boolean; nuclei: boolean; exploitDb: boolean };
  vendor: string; published: string; affected: string;
};

export const CVE_DB: CveEntry[] = [
  { id: "CVE-2024-6387", description: "OpenSSH regreSSHion — remote unauthenticated code execution in sshd", cvss: 9.8, epss: 0.97, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "OpenSSH", published: "2024-07-01", affected: "OpenSSH 8.5p1-9.8p1" },
  { id: "CVE-2024-3094", description: "XZ Utils backdoor — supply chain compromise with RCE payload", cvss: 10.0, epss: 0.99, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "XZ Utils", published: "2024-03-29", affected: "XZ Utils 5.6.0, 5.6.1" },
  { id: "CVE-2024-21626", description: "runc container escape via leaked file descriptor", cvss: 8.6, epss: 0.85, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "runc", published: "2024-01-31", affected: "runc <1.1.12" },
  { id: "CVE-2023-44487", description: "HTTP/2 Rapid Reset Attack — DDoS via stream cancellation", cvss: 7.5, epss: 0.91, kev: true, exploit: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "HTTP/2", published: "2023-10-10", affected: "Multiple implementations" },
  { id: "CVE-2023-34362", description: "MOVEit Transfer SQL injection leading to RCE", cvss: 9.1, epss: 0.98, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Progress", published: "2023-06-09", affected: "MOVEit Transfer 2020.0-2023.0" },
  { id: "CVE-2023-35078", description: "Ivanti EPMM authentication bypass", cvss: 9.8, epss: 0.95, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Ivanti", published: "2023-07-23", affected: "EPMM 11.10-11.12" },
  { id: "CVE-2024-27198", description: "JetBrains TeamCity authentication bypass", cvss: 9.8, epss: 0.96, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "JetBrains", published: "2024-03-04", affected: "TeamCity <2023.11.4" },
  { id: "CVE-2024-1709", description: "ConnectWise ScreenConnect authentication bypass", cvss: 9.8, epss: 0.94, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "ConnectWise", published: "2024-02-19", affected: "ScreenConnect 23.9.7-23.9.11" },
  { id: "CVE-2024-24919", description: "Check Point Security Gateway information disclosure", cvss: 8.6, epss: 0.82, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Check Point", published: "2024-05-28", affected: "Security Gateway R81.20" },
  { id: "CVE-2023-46805", description: "Ivanti ICS authentication bypass chain", cvss: 9.0, epss: 0.93, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Ivanti", published: "2024-01-10", affected: "ICS 9.x, 22.x" },
  { id: "CVE-2024-4577", description: "PHP CGI argument injection on Windows", cvss: 9.8, epss: 0.88, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "PHP", published: "2024-06-06", affected: "PHP 5.x-8.3 on Windows" },
  { id: "CVE-2024-38077", description: "Windows DCOM RCE with LDAP query", cvss: 9.0, epss: 0.65, kev: false, exploit: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "Microsoft", published: "2024-07-09", affected: "Windows Server 2012-2022" },
  { id: "CVE-2024-21338", description: "Windows Kernel AppLocker bypass", cvss: 7.8, epss: 0.45, kev: false, exploit: { metasploit: false, nuclei: false, exploitDb: false }, vendor: "Microsoft", published: "2024-01-15", affected: "Windows 10-11, Server 2016-2022" },
  { id: "CVE-2024-4761", description: "Chrome V8 type confusion", cvss: 8.8, epss: 0.72, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Google", published: "2024-05-15", affected: "Chrome <125.0.6422.60" },
  { id: "CVE-2023-46604", description: "Apache ActiveMQ RCE via serialization", cvss: 10.0, epss: 0.97, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "Apache", published: "2023-10-27", affected: "ActiveMQ <5.15.16, <5.16.7, <5.17.6, <5.18.3" },
  { id: "CVE-2023-38408", description: "OpenSSH PKCS#11 provider remote code execution", cvss: 8.1, epss: 0.55, kev: false, exploit: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "OpenSSH", published: "2023-07-19", affected: "OpenSSH 9.3p1-9.3p2" },
  { id: "CVE-2024-27956", description: "WordPress Automatic Plugin SQL injection", cvss: 9.8, epss: 0.89, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "WordPress", published: "2024-03-14", affected: "WP Automatic <3.95.0" },
  { id: "CVE-2024-26234", description: "ProxyNotShell-style Proxy Server RCE", cvss: 9.0, epss: 0.75, kev: false, exploit: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "Microsoft", published: "2024-03-05", affected: "Windows Proxy Server 2019-2022" },
  { id: "CVE-2024-21413", description: "Microsoft Outlook remote code execution via moniker link", cvss: 8.8, epss: 0.78, kev: true, exploit: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "Microsoft", published: "2024-02-13", affected: "Outlook 2016-2021, Office 365" },
  { id: "CVE-2024-20656", description: "Windows Kerberos RCE via PAC", cvss: 9.0, epss: 0.58, kev: false, exploit: { metasploit: false, nuclei: false, exploitDb: false }, vendor: "Microsoft", published: "2024-01-09", affected: "Windows Server 2008-2022" },
  { id: "CVE-2023-22527", description: "Atlassian Confluence template injection RCE", cvss: 10.0, epss: 0.96, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "Atlassian", published: "2024-01-16", affected: "Confluence 8.5.0-8.5.3" },
  { id: "CVE-2024-0204", description: "GoAnywhere MFT authentication bypass", cvss: 9.8, epss: 0.92, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "F5", published: "2024-01-22", affected: "GoAnywhere MFT 7.x" },
  { id: "CVE-2024-23897", description: "Jenkins CLI arbitrary file read", cvss: 7.5, epss: 0.87, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "Jenkins", published: "2024-01-24", affected: "Jenkins <2.442, LTS <2.426.3" },
  { id: "CVE-2024-1504", description: "D-Link DIR-823G command injection", cvss: 9.8, epss: 0.63, kev: false, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "D-Link", published: "2024-04-01", affected: "DIR-823G firmware <1.02" },
  { id: "CVE-2023-50164", description: "Apache Struts file upload RCE", cvss: 9.8, epss: 0.90, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "Apache", published: "2023-12-07", affected: "Struts 2.0.0-2.5.32, 6.0.0-6.3.0" },
  { id: "CVE-2024-29824", description: "Telerik UI Report Server authentication bypass", cvss: 9.8, epss: 0.71, kev: false, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Progress", published: "2024-04-15", affected: "Report Server 3.0.0-3.8.0" },
  { id: "CVE-2024-28255", description: "Microsoft Defender SmartScreen bypass", cvss: 5.4, epss: 0.52, kev: true, exploit: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "Microsoft", published: "2024-03-12", affected: "Windows Defender 2024-02" },
  { id: "CVE-2024-27316", description: "Apache HTTP Server HTTP/2 denial of service", cvss: 7.5, epss: 0.28, kev: false, exploit: { metasploit: false, nuclei: false, exploitDb: false }, vendor: "Apache", published: "2024-04-04", affected: "httpd 2.4.55-2.4.58" },
];

export const PAGE_SIZE = 10;

export function cvssColor(c: number): string {
  if (c >= 9) return "text-red-400";
  if (c >= 7) return "text-orange-400";
  if (c >= 4) return "text-yellow-400";
  return "text-green-400";
}

export function cvssBg(c: number): string {
  if (c >= 9) return "bg-red-500/20 border-red-500/40";
  if (c >= 7) return "bg-orange-500/20 border-orange-500/40";
  if (c >= 4) return "bg-yellow-500/20 border-yellow-500/40";
  return "bg-green-500/20 border-green-500/40";
}

export type Actor = {
  name: string; aliases: string[]; origin: string; motivation: string;
  firstSeen: string; techniques: string[]; campaigns: string[];
  tools: string[]; targets: string[];
};

export const ACTORS: Actor[] = [
  { name: "APT29", aliases: ["Cozy Bear", "Midnight Blizzard", "The Dukes"], origin: "Russia", motivation: "Espionage", firstSeen: "2014", techniques: ["T1566", "T1059", "T1071", "T1003", "T1555", "T1090", "T1573"], campaigns: ["SolarWinds", "Hacking Team", "COVID-19 Vaccine Research"], tools: ["WellMess", "WellMail", "GoldMax", "SoreFang", "SnugMail"], targets: ["Government", "Think Tanks", "Energy", "Healthcare"] },
  { name: "APT28", aliases: ["Fancy Bear", "Sednit", "Sofacy", "Pawn Storm"], origin: "Russia", motivation: "Espionage", firstSeen: "2007", techniques: ["T1566", "T1059", "T1071", "T1003", "T1204", "T1105", "T1027"], campaigns: ["2016 US Election", "Olympic Destroyer", "French Election"], tools: ["X-Agent", "X-Tunnel", "Zebrocy", "GoMet", "ComRAT"], targets: ["Government", "Military", "Media", "Olympic Committees"] },
  { name: "Lazarus Group", aliases: ["HIDDEN COBRA", "Guardians of Peace", "APT38"], origin: "North Korea", motivation: "Financial / Espionage", firstSeen: "2009", techniques: ["T1566", "T1059", "T1071", "T1204", "T1105", "T1027", "T1573", "T1485"], campaigns: ["Sony Hack", "Bangladesh Bank Heist", "WannaCry", "Coincheck"], tools: ["Destover", "HOPLIGHT", "ELECTRICFISH", "Bankshot", "Manuscrypt"], targets: ["Financial", "Media", "Cryptocurrency", "Government"] },
  { name: "FIN7", aliases: ["Carbanak", "Navigator Group"], origin: "Russia", motivation: "Financial", firstSeen: "2013", techniques: ["T1566", "T1059", "T1204", "T1105", "T1027", "T1071", "T1003"], campaigns: ["Restaurant POS Attacks", "Carbanak", "Cobalt Strike Campaigns"], tools: ["Carbanak", "Cobalt Strike", "Powertrash", "Tirion", "Lizar"], targets: ["Hospitality", "Retail", "Financial", "Restaurants"] },
  { name: "APT41", aliases: ["Double Dragon", "Winnti", "GALLIUM"], origin: "China", motivation: "Espionage / Financial", firstSeen: "2012", techniques: ["T1566", "T1059", "T1071", "T1105", "T1027", "T1505", "T1573", "T1190"], campaigns: ["Supply Chain Attacks", "Video Game Industry", "COVID-19"], tools: ["Winnti", "ShadowPad", "PortReuse", "Milan", "PlugX"], targets: ["Technology", "Gaming", "Healthcare", "Government"] },
  { name: "MuddyWater", aliases: ["SeedWorm", "TEMP.Zagros", "Static Kitten"], origin: "Iran", motivation: "Espionage", firstSeen: "2017", techniques: ["T1566", "T1059", "T1071", "T1105", "T1027", "T1110", "T1573"], campaigns: ["Middle East Espionage", "Turkish Government", "Pakistani Targets"], tools: ["POWERSTATS", "Powertonel", "MuddyC3", "Canopy", "Mori"], targets: ["Government", "Telecom", "Defense", "Energy"] },
  { name: "APT33", aliases: ["Elfin", "Magnallium", "Refined Kitten"], origin: "Iran", motivation: "Espionage / Sabotage", firstSeen: "2013", techniques: ["T1566", "T1059", "T1071", "T1027", "T1485", "T1105"], campaigns: ["Saudi Arabia PetChem", "Aviation"], tools: ["Shamoon", "Dropshot", "TurnedUp", "Stoning", "FontOnLake"], targets: ["Energy", "Aerospace", "Chemical", "Government"] },
  { name: "Turla", aliases: ["Venomous Bear", "Uroboros", "Waterbug", "Krypton"], origin: "Russia", motivation: "Espionage", firstSeen: "2008", techniques: ["T1566", "T1059", "T1071", "T1095", "T1003", "T1105", "T1027", "T1573"], campaigns: ["Epic Turla", "Turla LightNeuron", "SolarWinds (secondary)"], tools: ["ComRAT", "Carbon", "Kazuar", "LightNeuron", "Topinambour"], targets: ["Government", "Embassies", "Education", "Technology"] },
  { name: "Silent Librarian", aliases: ["TA407", "COBALT DICKENS"], origin: "Iran", motivation: "Espionage", firstSeen: "2014", techniques: ["T1566", "T1059", "T1071", "T1204", "T1105"], campaigns: ["Academic Theft", "University Login Phishing"], tools: ["Phishing Kits", "DNSTunnel"], targets: ["Academic", "Research", "Government"] },
  { name: "APT10", aliases: ["Stone Panda", "Red Apollo", "MenuPass", "CVNX"], origin: "China", motivation: "Espionage", firstSeen: "2014", techniques: ["T1566", "T1059", "T1071", "T1105", "T1027", "T1529", "T1204"], campaigns: ["Cloud Hopper", "Japanese Defense", "Global Consulting"], tools: ["PlugX", "RedLeaves", "IronMan", "Cobalt Strike", "Mimikatz"], targets: ["Technology", "Government", "Defense", "Consulting"] },
  { name: "UNC1878", aliases: ["Scattered Spider", "Muddled Libra"], origin: "Western", motivation: "Financial", firstSeen: "2022", techniques: ["T1566", "T1059", "T1071", "T1110", "T1555", "T1003", "T1550", "T1573"], campaigns: ["Casino Hacks", "SIMS Swapping", "MGM Breach"], tools: ["Octo", "Raccoon", "Cobalt Strike", "Sliver", "Mimikatz"], targets: ["Casinos", "Tech", "Financial", "Telecom"] },
  { name: "TA444", aliases: ["Strawberry Tempest", "RoseCrypt"], origin: "Eastern Europe", motivation: "Financial", firstSeen: "2021", techniques: ["T1566", "T1059", "T1204", "T1105", "T1027", "T1071"], campaigns: ["Phishing-as-a-Service"], tools: ["StormKit", "W3LL", "EvilProxy"], targets: ["Financial", "E-commerce", "Social Media"] },
  { name: "APT19", aliases: ["Codoso", "Sunshop", "Gadolinium"], origin: "China", motivation: "Espionage", firstSeen: "2010", techniques: ["T1566", "T1059", "T1071", "T1105", "T1027", "T1190"], campaigns: ["Supply Chain Compromise"], tools: ["Derusbi", "Syndical", "PoisonIvy", "Gh0stRAT"], targets: ["Technology", "Government", "Media"] },
  { name: "Kimsuky", aliases: ["Black Banshee", "Thallium", "VELVET CHOLLIMA"], origin: "North Korea", motivation: "Espionage", firstSeen: "2012", techniques: ["T1566", "T1059", "T1071", "T1105", "T1204", "T1027"], campaigns: ["Korean Peninsula", "Nuclear Policy", "COVID-19"], tools: ["BabyShark", "Kimsuky", "AppleSeed", "PeBB", "CmdRAT"], targets: ["Government", "Think Tanks", "Academic", "Defense"] },
  { name: "TA551", aliases: ["Shathak"], origin: "Russia", motivation: "Financial", firstSeen: "2017", techniques: ["T1566", "T1059", "T1204", "T1105", "T1027", "T1071"], campaigns: ["Email Thread Hijacking"], tools: ["Valak", "Ursnif", "IcedID", "BazarLoader"], targets: ["Financial", "Healthcare", "Legal"] },
  { name: "TEMP.Veles", aliases: ["XENOTIME", "Veles"], origin: "Russia", motivation: "Sabotage", firstSeen: "2012", techniques: ["T1566", "T1059", "T1071", "T1190", "T1105", "T1485"], campaigns: ["ICS/SCADA Attacks", "Ukraine Power Grid"], tools: ["Industroyer", "CrashOverride", "Havex", "BlackEnergy"], targets: ["Energy", "Industrial", "Government"] },
  { name: "TA285", aliases: ["UNC2452", "Nobelium"], origin: "Russia", motivation: "Espionage", firstSeen: "2020", techniques: ["T1566", "T1071", "T1090", "T1059", "T1105", "T1027"], campaigns: ["SolarWinds Post-Compromise"], tools: ["MalwareBytes", "Cobalt Strike", "Beacon"], targets: ["Government", "Consulting", "Technology"] },
  { name: "LightBasin", aliases: ["UNC1945"], origin: "Unknown", motivation: "Espionage / Financial", firstSeen: "2016", techniques: ["T1566", "T1059", "T1071", "T1190", "T1105", "T1505"], campaigns: ["Telecom Attacks", "SS7 Exploitation"], tools: ["SignStopper", "PingPull", "RustDoor", "KillCron"], targets: ["Telecom", "Financial", "Health"] },
  { name: "APT39", aliases: ["Raspberry Teddy", "Chafer", "Remix Kitten"], origin: "Iran", motivation: "Espionage", firstSeen: "2014", techniques: ["T1566", "T1059", "T1071", "T1105", "T1027", "T1003"], campaigns: ["Tourism Sector", "IT Services"], tools: ["C3", "ASPXSpy", "NanoCore"], targets: ["Tourism", "IT", "Education"] },
  { name: "Wizard Spider", aliases: ["UNC1878", "Gold Blackburn"], origin: "Eastern Europe", motivation: "Financial", firstSeen: "2016", techniques: ["T1566", "T1059", "T1071", "T1204", "T1105", "T1027", "T1486"], campaigns: ["Ryuk Ransomware", "Conti Leaks"], tools: ["Ryuk", "Conti", "BazarLoader", "Cobalt Strike", "TrickBot"], targets: ["Healthcare", "Government", "Education", "Financial"] },
  { name: "APC", aliases: ["FIN12", "BlackMatter"], origin: "Eastern Europe", motivation: "Financial", firstSeen: "2020", techniques: ["T1566", "T1059", "T1071", "T1204", "T1486", "T1105"], campaigns: ["Ransomware Big Game Hunting"], tools: ["BlackMatter", "LockBit", "Cobalt Strike"], targets: ["Healthcare", "Manufacturing", "Food"] },
  { name: "Moses Staff", aliases: ["Exploitors"], origin: "Iran", motivation: "Destruction", firstSeen: "2021", techniques: ["T1566", "T1059", "T1105", "T1485", "T1486"], campaigns: ["Israel Organizations", "Wiper Attacks"], tools: ["StrifeWater", "Data Wiper"], targets: ["Government", "Transport", "Healthcare"] },
  { name: "Mustang Panda", aliases: ["Bronze President", "HoneyMyte", "DragonOK"], origin: "China", motivation: "Espionage", firstSeen: "2013", techniques: ["T1566", "T1059", "T1071", "T1105", "T1027", "T1204"], campaigns: ["Vietnam Espionage", "Taiwan Government"], tools: ["PlugX", "Cobalt Strike", "Trojan.ACK", "HODOR"], targets: ["Government", "NGO", "Media", "Research"] },
  { name: "TA569", aliases: ["SocGholish Distribution"], origin: "Russia", motivation: "Financial", firstSeen: "2018", techniques: ["T1566", "T1071", "T1105", "T1204", "T1027"], campaigns: ["FakeUpdates", "Drive-by Downloads"], tools: ["SocGholish", "Raccoon Stealer"], targets: ["Media", "Enterprise"] },
];

export const techniqueLabel: Record<string, string> = {
  T1566: "T1566 Phishing", T1059: "T1059 Command and Scripting Interpreter",
  T1071: "T1071 App Layer Protocol", T1003: "T1003 OS Credential Dumping",
  T1555: "T1555 Credentials from Password Stores", T1090: "T1090 Proxy",
  T1573: "T1573 Encrypted Channel", T1204: "T1204 User Execution",
  T1105: "T1105 Ingress Tool Transfer", T1027: "T1027 Obfuscated Files or Info",
  T1190: "T1190 Exploit Public-Facing Application", T1505: "T1505 Server Software Component",
  T1529: "T1529 System Shutdown/Reboot", T1110: "T1110 Brute Force",
  T1485: "T1485 Data Destruction", T1486: "T1486 Data Encrypted for Impact",
  T1550: "T1550 Use Alternate Auth Material", T1095: "T1095 Non-App Layer Protocol",
};

export function genMarkdown(a: Actor): string {
  return `# Threat Actor: ${a.name}\n\n**Aliases:** ${a.aliases.join(", ")}\n**Origin:** ${a.origin}\n**Motivation:** ${a.motivation}\n**First Seen:** ${a.firstSeen}\n\n## Techniques\n${a.techniques.map((t) => `- ${t}`).join("\n")}\n\n## Tools\n${a.tools.map((t) => `- ${t}`).join("\n")}\n\n## Targets\n${a.targets.map((t) => `- ${t}`).join("\n")}\n\n## Campaigns\n${a.campaigns.map((c) => `- ${c}`).join("\n")}\n`;
}

export type HashType = "MD5" | "SHA1" | "SHA256" | "SHA512" | "unknown";
export type Verdict = "malicious" | "suspicious" | "clean" | "unknown";
export type HashResult = { hash: string; type: HashType; verdict: Verdict; firstSeen: string; avDetections: number; avTotal: number; malware: string };

export const MALWARE_NAMES = ["Emotet", "TrickBot", "Cobalt Strike", "AgentTesla", "Qakbot", "FormBook", "Dridex", "RemcosRAT", "AsyncRAT", "NanoCore", "Ursnif", "IcedID", "Bumblebee", "SocGholish", "RedLine Stealer"];

export const TONE: Record<Verdict, "destructive" | "warning" | "success" | "default"> = { malicious: "destructive", suspicious: "warning", clean: "success", unknown: "default" };

export function detectType(h: string): HashType {
  if (/^[a-f0-9]{32}$/i.test(h)) return "MD5";
  if (/^[a-f0-9]{40}$/i.test(h)) return "SHA1";
  if (/^[a-f0-9]{64}$/i.test(h)) return "SHA256";
  if (/^[a-f0-9]{128}$/i.test(h)) return "SHA512";
  return "unknown";
}

export function validateHash(h: string): { valid: boolean; reason?: string } {
  if (h.length < 32) return { valid: false, reason: "Too short for any hash type" };
  if (h.length > 128) return { valid: false, reason: "Too long for any hash type" };
  if (!/^[a-f0-9]+$/i.test(h)) return { valid: false, reason: "Contains non-hex characters" };
  return { valid: true };
}

export function mockResult(hash: string): HashResult {
  const type = detectType(hash);
  const h = parseInt(hash.slice(0, 8), 16) || Math.abs(hash.split("").reduce((a, c) => a + c.charCodeAt(0), 0));
  const vIdx = h % 4;
  return {
    hash, type,
    verdict: vIdx === 0 ? "malicious" : vIdx === 1 ? "suspicious" : vIdx === 2 ? "clean" : "unknown",
    firstSeen: new Date(Date.now() - (h % 365) * 86400000).toISOString().split("T")[0],
    avDetections: vIdx === 0 ? 8 + (h % 15) : vIdx === 1 ? 2 + (h % 5) : 0,
    avTotal: 62,
    malware: vIdx === 0 ? MALWARE_NAMES[h % MALWARE_NAMES.length] : "-",
  };
}

export type Ja3Entry = { hash: string; type: "JA3" | "JA4"; malware: string; firstSeen: string; lastSeen: string };
export type UaEntry = { ua: string; type: string; os: string; freq: string };

export const JA3_DB: Ja3Entry[] = [
  { hash: "6734f37431670b3ab4292b8f60f29984", type: "JA3", malware: "Emotet", firstSeen: "2022-03", lastSeen: "2024-06" },
  { hash: "51c64c77e60f3980eea90869b68c58a8", type: "JA3", malware: "TrickBot", firstSeen: "2021-11", lastSeen: "2024-02" },
  { hash: "7e12c4a7c2e1e5c6c8d4f7a0b3c5d8e1", type: "JA3", malware: "Cobalt Strike", firstSeen: "2020-08", lastSeen: "2024-09" },
  { hash: "a0e2f4b6c8d0e2f4a6b8c0d2e4f6a8b0", type: "JA3", malware: "Qakbot", firstSeen: "2023-01", lastSeen: "2024-08" },
  { hash: "b1c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1", type: "JA3", malware: "Dridex", firstSeen: "2022-06", lastSeen: "2024-04" },
  { hash: "c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2", type: "JA3", malware: "AgentTesla", firstSeen: "2021-09", lastSeen: "2024-07" },
  { hash: "d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3", type: "JA3", malware: "RemcosRAT", firstSeen: "2022-01", lastSeen: "2024-05" },
  { hash: "e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4", type: "JA3", malware: "AsyncRAT", firstSeen: "2023-04", lastSeen: "2024-09" },
  { hash: "f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5", type: "JA3", malware: "FormBook", firstSeen: "2022-10", lastSeen: "2024-03" },
  { hash: "a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6", type: "JA3", malware: "IcedID", firstSeen: "2021-12", lastSeen: "2024-08" },
  { hash: "b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7", type: "JA3", malware: "Ursnif", firstSeen: "2022-04", lastSeen: "2024-06" },
  { hash: "c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8", type: "JA3", malware: "Bumblebee", firstSeen: "2023-07", lastSeen: "2024-09" },
  { hash: "d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9", type: "JA3", malware: "RedLine Stealer", firstSeen: "2023-02", lastSeen: "2024-07" },
  { hash: "e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0", type: "JA3", malware: "NanoCore", firstSeen: "2022-08", lastSeen: "2024-05" },
  { hash: "f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1", type: "JA3", malware: "SocGholish", firstSeen: "2021-07", lastSeen: "2024-09" },
  { hash: "a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2", type: "JA3", malware: "Mirai", firstSeen: "2019-05", lastSeen: "2024-09" },
  { hash: "b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3", type: "JA3", malware: "Gh0stRAT", firstSeen: "2020-11", lastSeen: "2024-04" },
  { hash: "c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4", type: "JA3", malware: "PlugX", firstSeen: "2021-03", lastSeen: "2024-08" },
  { hash: "d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5", type: "JA3", malware: "DarkComet", firstSeen: "2020-06", lastSeen: "2023-12" },
  { hash: "e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6", type: "JA3", malware: "njRAT", firstSeen: "2020-09", lastSeen: "2024-01" },
  { hash: "ja4_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0", type: "JA4", malware: "Cobalt Strike", firstSeen: "2023-01", lastSeen: "2024-09" },
  { hash: "ja4_b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1", type: "JA4", malware: "Sliver", firstSeen: "2023-06", lastSeen: "2024-09" },
  { hash: "ja4_c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", type: "JA4", malware: "Brute Ratel C4", firstSeen: "2023-08", lastSeen: "2024-07" },
  { hash: "ja4_d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3", type: "JA4", malware: "Nighthawk C2", firstSeen: "2024-01", lastSeen: "2024-09" },
];

export const UA_DB: UaEntry[] = [
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36", type: "Browser", os: "Windows 10", freq: "Very High" },
  { ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15", type: "Browser", os: "macOS", freq: "High" },
  { ua: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36", type: "Browser", os: "Linux", freq: "High" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", type: "Browser", os: "Windows 10", freq: "High" },
  { ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148", type: "Browser", os: "iOS", freq: "High" },
  { ua: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.6099.144 Mobile Safari/537.36", type: "Browser", os: "Android", freq: "Medium" },
  { ua: "python-requests/2.31.0", type: "Library", os: "Any", freq: "Very High" },
  { ua: "Go-http-client/2.0", type: "Library", os: "Any", freq: "High" },
  { ua: "curl/8.4.0", type: "CLI", os: "Any", freq: "High" },
  { ua: "Wget/1.21.4", type: "CLI", os: "Any", freq: "Medium" },
  { ua: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", type: "Bot", os: "Any", freq: "Very High" },
  { ua: "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)", type: "Bot", os: "Any", freq: "Very High" },
  { ua: "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", type: "Bot", os: "Any", freq: "High" },
  { ua: "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)", type: "Bot", os: "Any", freq: "Medium" },
  { ua: "Nuclei - Open-source project (https://github.com/projectdiscovery/nuclei)", type: "Scanner", os: "Any", freq: "Medium" },
  { ua: "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.101 Safari/537.36", type: "Scanner", os: "Windows 7", freq: "Medium" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299", type: "Browser", os: "Windows 10", freq: "Low" },
  { ua: "masscan/1.3.2 (https://github.com/robertdavidgraham/masscan)", type: "Scanner", os: "Any", freq: "Medium" },
  { ua: "PostmanRuntime/7.36.0", type: "Library", os: "Any", freq: "High" },
  { ua: "axios/1.6.2", type: "Library", os: "Any", freq: "Medium" },
  { ua: "Microsoft Office Word 2016 (16.0.4266.1001) Windows NT 10.0", type: "Application", os: "Windows 10", freq: "Medium" },
];
