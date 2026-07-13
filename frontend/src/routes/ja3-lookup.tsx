import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, Chip, SendToRow } from "@/components/soc";
import { Search, Fingerprint, Monitor, Copy, Check, Database } from "lucide-react";
import { toast } from "sonner";
import { pushTimelineEvent } from "@/lib/timeline";
import { useLocker } from "@/lib/locker";

export const Route = createFileRoute("/ja3-lookup")({ component: Ja3LookupPage });

type Ja3Entry = { hash: string; type: "JA3" | "JA4"; malware: string; firstSeen: string; lastSeen: string };
type UaEntry = { ua: string; type: string; os: string; freq: string };

const JA3_DB: Ja3Entry[] = [
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

const UA_DB: UaEntry[] = [
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
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299", type: "Browser", os: "Windows 10", freq: "Low" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0", type: "Browser", os: "Windows 10", freq: "Low" },
  { ua: "masscan/1.3.2 (https://github.com/robertdavidgraham/masscan)", type: "Scanner", os: "Any", freq: "Medium" },
  { ua: "ZmEu", type: "Scanner", os: "Any", freq: "Low" },
  { ua: "Mozilla/5.0 (Windows NT 6.1; rv:60.0) Gecko/20100101 Firefox/60.0", type: "Scanner", os: "Windows 7", freq: "Low" },
  { ua: "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)", type: "Scanner", os: "Windows XP", freq: "Low" },
  { ua: "PostmanRuntime/7.36.0", type: "Library", os: "Any", freq: "High" },
  { ua: "OkHttp/4.12.0", type: "Library", os: "Android", freq: "Medium" },
  { ua: "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UQ1A.240205.004)", type: "Library", os: "Android", freq: "Medium" },
  { ua: "axios/1.6.2", type: "Library", os: "Any", freq: "Medium" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", type: "Browser", os: "Windows 10", freq: "Medium" },
  { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134", type: "Browser", os: "Windows 10", freq: "Low" },
  { ua: "Microsoft Office Word 2016 (16.0.4266.1001) Windows NT 10.0", type: "Application", os: "Windows 10", freq: "Medium" },
  { ua: "Microsoft Office Excel 2019 (16.0.10366.20003) Windows NT 10.0", type: "Application", os: "Windows 10", freq: "Medium" },
];

function Ja3LookupPage() {
  const locker = useLocker();
  const [ja3Query, setJa3Query] = useState("");
  const [uaQuery, setUaQuery] = useState("");
  const [tab, setTab] = useState<"ja3" | "ua">("ja3");
  const [copiedHash, setCopiedHash] = useState("");

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") { setJa3Query(""); setUaQuery(""); }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  const ja3Filtered = useMemo(() => {
    const q = ja3Query.toLowerCase();
    if (!q) return JA3_DB;
    return JA3_DB.filter((e) => e.hash.toLowerCase().includes(q) || e.malware.toLowerCase().includes(q));
  }, [ja3Query]);

  useEffect(() => {
    if (ja3Query) pushTimelineEvent({ source: "ja3-lookup", verb: "searched", detail: `ja3: ${ja3Query}`, result: `${ja3Filtered.length} results` });
  }, [ja3Filtered]);

  const ja3Stats = useMemo(() => ({
    total: JA3_DB.length,
    ja3: JA3_DB.filter((e) => e.type === "JA3").length,
    ja4: JA3_DB.filter((e) => e.type === "JA4").length,
    filtered: ja3Filtered.length,
    malware: new Set(JA3_DB.map((e) => e.malware)).size,
  }), [ja3Filtered]);

  const uaFiltered = useMemo(() => {
    const q = uaQuery.toLowerCase();
    if (!q) return UA_DB;
    return UA_DB.filter((e) => e.ua.toLowerCase().includes(q) || e.type.toLowerCase().includes(q) || e.os.toLowerCase().includes(q));
  }, [uaQuery]);

  useEffect(() => {
    if (uaQuery) pushTimelineEvent({ source: "ja3-lookup", verb: "searched", detail: `ua: ${uaQuery}`, result: `${uaFiltered.length} results` });
  }, [uaFiltered]);

  const uaStats = useMemo(() => ({
    total: UA_DB.length,
    filtered: uaFiltered.length,
    types: new Set(UA_DB.map((e) => e.type)).size,
  }), [uaFiltered]);

  function copyAll(entries: { hash: string }[]) {
    const text = entries.map((e) => e.hash).join("\n");
    navigator.clipboard.writeText(text);
    setCopiedHash("__all__");
    setTimeout(() => setCopiedHash(""), 1200);
  }

  return (
    <PageShell
      eyebrow="TOOLS / FINGERPRINT LOOKUP"
      title="JA3/JA4 & UA Lookup"
      description="Lookup JA3/JA4 TLS fingerprints and User-Agent strings — identify tools, malware, and scanners."
      crumbs={[{ label: "Tools" }, { label: "JA3/UA" }]}
      meta={[
        { label: "JA3/JA4", value: String(ja3Stats.total), tone: "primary" },
        { label: "malware", value: String(ja3Stats.malware), tone: "destructive" },
        { label: "UA", value: String(uaStats.total), tone: "primary" },
      ]}
    >
      <div className="flex items-center gap-2 mb-4">
        <button onClick={() => setTab("ja3")} className={"rounded border px-3 py-1.5 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (tab === "ja3" ? "border-primary bg-primary/15 text-primary" : "border-border bg-card/40 text-muted-foreground hover:text-foreground")}>
          <Fingerprint className="mr-1 inline h-3 w-3" /> JA3/JA4 Database
        </button>
        <button onClick={() => setTab("ua")} className={"rounded border px-3 py-1.5 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (tab === "ua" ? "border-primary bg-primary/15 text-primary" : "border-border bg-card/40 text-muted-foreground hover:text-foreground")}>
          <Monitor className="mr-1 inline h-3 w-3" /> User-Agent Database
        </button>
      </div>

      {tab === "ja3" ? (
        <Panel
          title="JA3/JA4 Fingerprints"
          bodyClassName="p-0"
          actions={
            <button onClick={() => copyAll(ja3Filtered)}
              className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
              {copiedHash === "__all__" ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> copy all</>}
            </button>
          }
        >
          <div className="border-b border-border p-2">
            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <input value={ja3Query} onChange={(e) => setJa3Query(e.target.value)} placeholder="Search hash or malware family…" className="w-full rounded border border-border bg-background/60 py-1.5 pl-8 pr-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50" />
              </div>
              <span className="text-mono text-[10px] text-muted-foreground whitespace-nowrap">{ja3Stats.filtered}/{ja3Stats.total} · {ja3Stats.ja3} JA3 · {ja3Stats.ja4} JA4</span>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead><tr className="border-b border-border text-left text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground"><th className="px-3 py-2">Hash</th><th className="px-3 py-2">Type</th><th className="px-3 py-2">Malware</th><th className="px-3 py-2">First Seen</th><th className="px-3 py-2">Last Seen</th><th className="px-3 py-2 w-10"></th><th className="px-3 py-2 w-10"></th></tr></thead>
              <tbody className="divide-y divide-border/50">
                {ja3Filtered.map((e, i) => (
                  <tr key={i} className="group hover:bg-card/30">
                    <td className="px-3 py-2"><code className="font-mono text-[11px] text-foreground/90">{e.hash.slice(0, 32)}…</code></td>
                    <td className="px-3 py-2"><Chip tone={e.type === "JA4" ? "warning" : "primary"}>{e.type}</Chip></td>
                    <td className="px-3 py-2"><span className="font-mono text-sm text-foreground/90">{e.malware}</span></td>
                    <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{e.firstSeen}</td>
                    <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{e.lastSeen}</td>
                    <td className="px-3 py-2">
                      <button onClick={() => { locker.add({ value: e.hash, type: "ja3", source: "/ja3-lookup" }); toast("Added hash to locker"); }}
                        className="opacity-0 group-hover:opacity-100 grid h-6 w-6 place-items-center rounded text-muted-foreground hover:text-primary transition-all" title="Add to locker">
                        <Database className="h-3 w-3" />
                      </button>
                    </td>
                    <td className="px-3 py-2">
                      <button onClick={() => { navigator.clipboard.writeText(e.hash); setCopiedHash(e.hash); setTimeout(() => setCopiedHash(""), 1200); }}
                        className="opacity-0 group-hover:opacity-100 grid h-6 w-6 place-items-center rounded text-muted-foreground hover:text-primary transition-all">
                        {copiedHash === e.hash ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : (
        <Panel
          title="User-Agent Database"
          bodyClassName="p-0"
          actions={
            <span className="text-mono text-[10px] text-muted-foreground">{uaStats.filtered}/{uaStats.total} · {uaStats.types} types</span>
          }
        >
          <div className="border-b border-border p-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
              <input value={uaQuery} onChange={(e) => setUaQuery(e.target.value)} placeholder="Search UA string, type, or OS…" className="w-full rounded border border-border bg-background/60 py-1.5 pl-8 pr-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50" />
            </div>
          </div>
          <div className="overflow-x-auto max-h-[70vh] overflow-y-auto">
            <table className="w-full">
              <thead><tr className="border-b border-border text-left text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground sticky top-0 bg-background"><th className="px-3 py-2">User-Agent</th><th className="px-3 py-2 w-20">Type</th><th className="px-3 py-2 w-20">OS</th><th className="px-3 py-2 w-24">Frequency</th><th className="px-3 py-2 w-10"></th></tr></thead>
              <tbody className="divide-y divide-border/50">
                {uaFiltered.map((e, i) => (
                  <tr key={i} className="group hover:bg-card/30">
                    <td className="max-w-xs px-3 py-2"><code className="block truncate font-mono text-[11px] text-foreground/90" title={e.ua}>{e.ua}</code></td>
                    <td className="px-3 py-2"><Chip tone={e.type === "Scanner" ? "destructive" : e.type === "Bot" ? "warning" : e.type === "Library" ? "primary" : "default"}>{e.type}</Chip></td>
                    <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{e.os}</td>
                    <td className="px-3 py-2"><Chip tone={e.freq === "Very High" ? "success" : e.freq === "High" ? "primary" : "default"}>{e.freq}</Chip></td>
                    <td className="px-3 py-2">
                      <button onClick={() => { locker.add({ value: e.ua, type: "ua", source: "/ja3-lookup" }); toast("Added UA to locker"); }}
                        className="opacity-0 group-hover:opacity-100 grid h-6 w-6 place-items-center rounded text-muted-foreground hover:text-primary transition-all" title="Add to locker">
                        <Database className="h-3 w-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      <div className="mt-4">
        <SendToRow targets={[
          { label: "Detection Editor", to: "/detection", icon: Search },
          { label: "Case Notebook", to: "/case", icon: Database },
        ]} />
      </div>
    </PageShell>
  );
}
