import { useState } from "react";
import { Lightbulb, X } from "lucide-react";

function explainNmap(raw: string): string {
  const lines: string[] = [];
  const ports = raw.match(/(\d+)\/(tcp|udp)\s+open\s+(\S+)/g);
  if (ports?.length) {
    lines.push(`Found ${ports.length} open port(s).`);
    ports.slice(0, 10).forEach((p) => {
      const m = p.match(/(\d+)\/(tcp|udp)\s+open\s+(\S+)/);
      if (m) lines.push(`- Port ${m[1]}/${m[2]} → ${m[3]} service`);
    });
    if (ports.length > 10) lines.push(`  … and ${ports.length - 10} more`);
  }
  if (/filtered/i.test(raw)) lines.push("Some ports appear filtered (likely a firewall).");
  if (/closed/i.test(raw)) lines.push("Some ports are closed — no service listening.");
  if (/OS details/i.test(raw)) {
    const os = raw.match(/OS details:\s*(.+)/);
    if (os) lines.push(`Detected OS: ${os[1]}`);
  }
  if (!lines.length) lines.push("No structured port data found in this output.");
  lines.push("", "Tip: Open ports are potential attack surfaces. Cross-reference findings with CVEs for each service version.");
  return lines.join("\n");
}

function explainPcap(raw: string): string {
  const lines: string[] = [];
  const ips = raw.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g);
  const uniqueIPs = ips ? [...new Set(ips)] : [];
  if (uniqueIPs.length) lines.push(`Contains ${uniqueIPs.length} unique IP address(es).`);
  const protocols = ["HTTP", "DNS", "HTTPS", "SMB", "RDP", "SSH", "FTP", "SMTP", "TLS"];
  const found = protocols.filter((p) => new RegExp(p, "i").test(raw));
  if (found.length) lines.push(`Detected protocols: ${found.join(", ")}.`);
  if (/suspicious|malicious|alert|malware|c2|beacon/i.test(raw)) lines.push("Suspicious indicators present — investigate further.");
  if (/dns|resolve|query/i.test(raw)) lines.push("DNS activity detected — check for suspicious domains or data exfiltration.");
  if (/tls|ssl|certificate|handshake/i.test(raw)) lines.push("Encrypted traffic (TLS) detected — inspect certificates for suspicious issuers.");
  if (!lines.length) lines.push("No structured packet data found. Use tshark for deeper protocol analysis.");
  lines.push("", "Tip: Focus on external IPs and unusual protocol combinations for initial triage.");
  return lines.join("\n");
}

function explainEmail(raw: string): string {
  const lines: string[] = [];
  const spf = raw.match(/spf=(\w+)/i) || raw.match(/SPF:\s*(\w+)/i);
  if (spf) lines.push(`SPF result: ${spf[1].toUpperCase()} — ${spf[1].toLowerCase() === "pass" ? "sender authorized" : spf[1].toLowerCase() === "fail" ? "sender NOT authorized (spoof risk)" : "neutral/soft — review headers"}.`);
  const dkim = raw.match(/dkim=(\w+)/i) || raw.match(/DKIM:\s*(\w+)/i);
  if (dkim) lines.push(`DKIM result: ${dkim[1].toUpperCase()} — ${dkim[1].toLowerCase() === "pass" ? "email integrity verified" : "signature invalid or missing — possible tampering"}.`);
  const dmarc = raw.match(/dmarc=(\w+)/i) || raw.match(/DMARC:\s*(\w+)/i);
  if (dmarc) lines.push(`DMARC result: ${dmarc[1].toUpperCase()} — ${dmarc[1].toLowerCase() === "pass" ? "domain alignment confirmed" : "policy failure — domain may be spoofed"}.`);
  if (/(reply-to|return-path)/i.test(raw)) lines.push("Reply-To / Return-Path present — check for mismatch with From address (common phish indicator).");
  if (/received.*from/i.test(raw)) {
    const hops = raw.match(/received:\s*from\s+\S+/gi);
    if (hops) lines.push(`${hops.length} hop(s) in delivery path — trace the originating IP.`);
  }
  if (/(form|password|credential|login|verify|update.*account)/i.test(raw)) lines.push("Body contains credential-harvesting lures (form/password/login keywords).");
  if (/(invoice|payment|overdue|urgent)/i.test(raw)) lines.push("Urgency/invoice lures detected — common in BEC and invoice fraud.");
  if (!lines.length) lines.push("Review headers for authentication failures (SPF/DKIM/DMARC) and body for social-engineering lures.");
  lines.push("", "Tip: Cross-check sender domain age and MX records for lookalike domains.");
  return lines.join("\n");
}

export function ExplainThisButton({ kind, input }: { kind: "nmap" | "pcap" | "email"; input: string }) {
  const [open, setOpen] = useState(false);
  if (!input.trim()) return null;

  const explain = kind === "nmap" ? explainNmap : kind === "pcap" ? explainPcap : explainEmail;
  const text = explain(input);

  return (
    <div className="relative inline-block">
      <button onClick={() => setOpen((o) => !o)}
        className="inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-mono ba-text-2xs uppercase tracking-widest text-amber-400 hover:bg-amber-500/20"
        title="Explain this output"
      >
        <Lightbulb className="h-3 w-3" /> explain
      </button>
      {open && (
        <div className="absolute right-0 top-full z-50 mt-1 w-80 rounded border border-amber-500/30 bg-popover p-3 shadow-lg">
          <div className="mb-1.5 flex items-center justify-between">
            <span className="text-mono text-[10px] uppercase tracking-widest text-amber-400">what this means</span>
            <button onClick={() => setOpen(false)} className="text-muted-foreground hover:text-foreground"><X className="h-3 w-3" /></button>
          </div>
          <pre className="whitespace-pre-wrap text-mono ba-text-sm text-foreground/85 leading-relaxed">{text}</pre>
        </div>
      )}
    </div>
  );
}
