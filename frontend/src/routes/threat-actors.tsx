import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, Chip, SendToRow } from "@/components/soc";
import { Empty } from "@/components/output";
import { Search, Copy, Check, Users, Download, Eye, ArrowLeft } from "lucide-react";
import { toast } from "sonner";
import { pushTimelineEvent } from "@/lib/timeline";
import { useLocker, guessType } from "@/lib/locker";
import { copyText } from "@/lib/copy";

export const Route = createFileRoute("/threat-actors")({ component: ThreatActorsPage });

type Actor = {
  name: string;
  aliases: string[];
  origin: string;
  motivation: string;
  firstSeen: string;
  techniques: string[];
  campaigns: string[];
  tools: string[];
  targets: string[];
};

const ACTORS: Actor[] = [
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
  { name: "TA555", aliases: ["SilentNovus"], origin: "Russia", motivation: "Financial", firstSeen: "2020", techniques: ["T1566", "T1059", "T1204", "T1071", "T1105"], campaigns: ["BEC Against SaaS"], tools: ["ProxyShell", "Email Access"], targets: ["SaaS", "Financial"] },
  { name: "TA569", aliases: ["SocGholish Distribution"], origin: "Russia", motivation: "Financial", firstSeen: "2018", techniques: ["T1566", "T1071", "T1105", "T1204", "T1027"], campaigns: ["FakeUpdates", "Drive-by Downloads"], tools: ["SocGholish", "Raccoon Stealer"], targets: ["Media", "Enterprise"] },
  { name: "Grayling", aliases: ["APT43", "Kimsuky Subgroup"], origin: "North Korea", motivation: "Espionage", firstSeen: "2019", techniques: ["T1566", "T1059", "T1071", "T1105", "T1027", "T1555"], campaigns: ["Cryptocurrency Research", "Think Tank Intrusions"], tools: ["CaiTab", "AB-Tracker", "Milan"], targets: ["Research", "Academic", "Cryptocurrency"] },
  { name: "Earth Longzhi", aliases: ["APT17", "Deputy Dog"], origin: "China", motivation: "Espionage", firstSeen: "2013", techniques: ["T1566", "T1059", "T1071", "T1105", "T1027", "T1190"], campaigns: ["Chinese Government Targets"], tools: ["PoisonIvy", "Gh0stRAT", "HttpServer"], targets: ["Government", "Agriculture", "Academic"] },
];

function genMarkdown(a: Actor): string {
  return `# Threat Actor: ${a.name}

**Aliases:** ${a.aliases.join(", ")}
**Origin:** ${a.origin}
**Motivation:** ${a.motivation}
**First Seen:** ${a.firstSeen}

## Techniques
${a.techniques.map((t) => `- ${t}`).join("\n")}

## Tools
${a.tools.map((t) => `- ${t}`).join("\n")}

## Targets
${a.targets.map((t) => `- ${t}`).join("\n")}

## Campaigns
${a.campaigns.map((c) => `- ${c}`).join("\n")}
`;
}

function ThreatActorsPage() {
  const locker = useLocker();
  const [query, setQuery] = useState("");
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null);
  const [selectedActor, setSelectedActor] = useState<string | null>(null);
  const [copied, setCopied] = useState("");

  useEffect(() => {
    if (selectedActor) {
      pushTimelineEvent({ source: "threat-actors", verb: "viewed", detail: `Viewed threat actor: ${selectedActor}`, target: selectedActor });
    }
  }, [selectedActor]);

  const allTechniques = useMemo(() => {
    const t = new Set<string>();
    ACTORS.forEach((a) => a.techniques.forEach((tech) => t.add(tech)));
    return Array.from(t).sort();
  }, []);

  const techniqueLabel: Record<string, string> = {
    T1566: "T1566 Phishing", T1059: "T1059 Command and Scripting Interpreter", T1071: "T1071 App Layer Protocol",
    T1003: "T1003 OS Credential Dumping", T1555: "T1555 Credentials from Password Stores",
    T1090: "T1090 Proxy", T1573: "T1573 Encrypted Channel", T1204: "T1204 User Execution",
    T1105: "T1105 Ingress Tool Transfer", T1027: "T1027 Obfuscated Files or Info",
    T1190: "T1190 Exploit Public-Facing Application", T1505: "T1505 Server Software Component",
    T1529: "T1529 System Shutdown/Reboot", T1110: "T1110 Brute Force", T1485: "T1485 Data Destruction",
    T1486: "T1486 Data Encrypted for Impact", T1550: "T1550 Use Alternate Auth Material",
    T1095: "T1095 Non-App Layer Protocol",
  };

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape" && selectedActor) { setSelectedActor(null); e.preventDefault(); }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [selectedActor]);

  const addToLocker = useCallback((value: string) => {
    locker.add({ value, type: guessType(value), source: "threat-actors" });
  }, [locker]);

  const exportAsMarkdown = useCallback((actor: Actor) => {
    const md = genMarkdown(actor);
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `threat-actor-${actor.name.toLowerCase().replace(/\s+/g, "-")}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  const filtered = useMemo(() => {
    let result = ACTORS;
    if (query.trim()) {
      const q = query.toLowerCase();
      result = result.filter((a) =>
        a.name.toLowerCase().includes(q) ||
        a.aliases.some((al) => al.toLowerCase().includes(q)) ||
        a.techniques.some((t) => t.toLowerCase().includes(q)) ||
        a.tools.some((tl) => tl.toLowerCase().includes(q))
      );
    }
    if (selectedTechnique) result = result.filter((a) => a.techniques.includes(selectedTechnique));
    return result;
  }, [query, selectedTechnique]);

  const selected = useMemo(() => ACTORS.find((a) => a.name === selectedActor) || null, [selectedActor]);

  const reverseTech = useMemo(() => {
    if (!selectedTechnique) return [];
    return ACTORS.filter((a) => a.techniques.includes(selectedTechnique)).map((a) => a.name);
  }, [selectedTechnique]);

  return (
    <PageShell
      eyebrow="TOOLS / THREAT ACTORS"
      title="Threat Actor & Campaign Lookup"
      description="Search APT groups, techniques, and campaigns. Reverse-lookup which actors use a given MITRE technique."
      crumbs={[{ label: "Tools" }, { label: "Threat Actors" }]}
      meta={[
        { label: "actors", value: String(filtered.length), tone: "primary" },
        ...(selectedTechnique ? [{ label: "technique", value: selectedTechnique, tone: "warning" as const }] : []),
      ]}
    >
      <div className="grid grid-cols-[280px_1fr] gap-4">
        <div className="space-y-3">
          <Panel title="Technique Filter" priority="secondary" bodyClassName="p-0">
            <div className="divide-y divide-border/50 max-h-80 overflow-y-auto">
              <button onClick={() => setSelectedTechnique(null)} className={"w-full px-3 py-1.5 text-left text-mono text-[11px] " + (!selectedTechnique ? "bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground")}>All techniques</button>
              {allTechniques.map((t) => (
                <button key={t} onClick={() => setSelectedTechnique(t === selectedTechnique ? null : t)} className={"w-full px-3 py-1.5 text-left font-mono text-[11px] " + (selectedTechnique === t ? "bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground")}>
                  {techniqueLabel[t] || t}
                  <span className="ml-1 text-[9px] opacity-60">({ACTORS.filter((a) => a.techniques.includes(t)).length})</span>
                </button>
              ))}
            </div>
          </Panel>
          {selectedTechnique && reverseTech.length > 0 && (
            <Panel title={`Used by (${reverseTech.length})`} priority="secondary">
              <div className="flex flex-wrap gap-1">
                {reverseTech.map((n) => <Chip key={n} tone="warning">{n}</Chip>)}
              </div>
            </Panel>
          )}
        </div>

        <div className="space-y-4">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search actor, alias, technique, or tool…" className="w-full rounded border border-border bg-background/60 py-1.5 pl-8 pr-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50" />
          </div>

          {selected ? (
            <div className="space-y-4">
              <button onClick={() => setSelectedActor(null)} className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground"><ArrowLeft className="h-3 w-3" /> Back to list</button>
              <Panel
                title={selected.name}
                actions={
                  <div className="flex items-center gap-1">
                    <button onClick={() => exportAsMarkdown(selected)} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground" title="Export as Markdown"><Download className="h-3 w-3" /> MD</button>
                    <button onClick={() => { const json = JSON.stringify(selected, null, 2); copyText(json); setCopied(selected.name); setTimeout(() => setCopied(""), 1200); }}
                      className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
                      {copied === selected.name ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> JSON</>}
                    </button>
                  </div>
                }
              >
                <div className="space-y-3">
                  <div className="flex flex-wrap gap-1.5">{selected.aliases.map((a) => <Chip key={a} tone="primary">{a}</Chip>)}</div>
                  <div className="grid grid-cols-3 gap-3 font-mono text-sm">
                    <div><span className="text-[10px] uppercase tracking-widest text-muted-foreground">Origin</span><div className="text-foreground/90">{selected.origin}</div></div>
                    <div><span className="text-[10px] uppercase tracking-widest text-muted-foreground">Motivation</span><div className="text-foreground/90">{selected.motivation}</div></div>
                    <div><span className="text-[10px] uppercase tracking-widest text-muted-foreground">First Seen</span><div className="text-foreground/90">{selected.firstSeen}</div></div>
                  </div>
                  <div><span className="text-[10px] uppercase tracking-widest text-muted-foreground">Techniques</span>
                    <div className="mt-1 flex flex-wrap gap-1">{selected.techniques.map((t) => <Chip key={t} tone="warning">{techniqueLabel[t] || t}</Chip>)}</div>
                  </div>
                  <div><span className="text-[10px] uppercase tracking-widest text-muted-foreground">Tools</span> <span className="text-[9px] text-muted-foreground/50">(click to add to locker)</span>
                    <div className="mt-1 flex flex-wrap gap-1">{selected.tools.map((t) => <button key={t} onClick={() => addToLocker(t)} title="Add to IOC Locker" className="rounded bg-destructive/10 px-2.5 py-0.5 text-mono text-[11px] text-destructive transition-colors hover:bg-destructive/20">{t}</button>)}</div>
                  </div>
                  <div><span className="text-[10px] uppercase tracking-widest text-muted-foreground">Targets</span>
                    <div className="mt-1 flex flex-wrap gap-1">{selected.targets.map((t) => <Chip key={t} tone="default">{t}</Chip>)}</div>
                  </div>
                  <div><span className="text-[10px] uppercase tracking-widest text-muted-foreground">Campaigns</span>
                    <div className="mt-1 flex flex-wrap gap-1">{selected.campaigns.map((c) => <button key={c} onClick={() => { locker.add({ value: c, type: "text", source: "/threat-actors" }); toast(`Added ${c} to locker`); }} title="Add to locker" className="rounded border border-border/50 bg-card/40 px-2 py-0.5 font-mono ba-text-2xs text-muted-foreground hover:text-foreground">{c}</button>)}</div>
                  </div>
                </div>
              </Panel>
              <SendToRow targets={[
                { label: "case", to: `/case?note=${encodeURIComponent(`${selected.name} (${selected.aliases[0]}) — ${selected.motivation}, origin: ${selected.origin}, first seen: ${selected.firstSeen}. Tools: ${selected.tools.join(", ")}. Techniques: ${selected.techniques.join(", ")}.`)}`, icon: Eye },
                { label: "detection", to: `/detection?note=${encodeURIComponent(`Threat actor ${selected.name} (${selected.aliases[0]}) — techniques: ${selected.techniques.join(", ")}, tools: ${selected.tools.join(", ")}`)}`, icon: Search },
              ]} />
            </div>
          ) : (
            <div className="space-y-2">
              {filtered.map((actor) => (
                <button key={actor.name} onClick={() => setSelectedActor(actor.name)}
                  className="w-full rounded-lg border border-border/60 bg-card/40 p-3 text-left transition-colors hover:border-primary/30">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="font-mono text-sm font-bold text-foreground/90">{actor.name}</div>
                      <div className="mt-0.5 text-[11px] text-muted-foreground">{actor.aliases.slice(0, 3).join(", ")}{actor.aliases.length > 3 ? "…" : ""}</div>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <button onClick={(e) => { e.stopPropagation(); locker.add({ value: actor.name, type: "text", source: "/threat-actors" }); toast(`Added ${actor.name} to locker`); }}
                        className="rounded border border-border/50 bg-card/40 px-1.5 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground"
                        title="Add to locker">+</button>
                      <Chip tone="default">{actor.origin}</Chip>
                      <Chip tone={actor.motivation.includes("Financial") ? "warning" : "primary"}>{actor.motivation.split("/")[0]}</Chip>
                    </div>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {actor.techniques.slice(0, 4).map((t) => <Chip key={t} tone="warning">{t}</Chip>)}
                    {actor.techniques.length > 4 && <Chip tone="default">+{actor.techniques.length - 4}</Chip>}
                  </div>
                </button>
              ))}
              {filtered.length === 0 && <Empty icon={Users} title="No actors found" hint="Try a different search term or clear the technique filter." />}
            </div>
          )}
        </div>
      </div>
    </PageShell>
  );
}
