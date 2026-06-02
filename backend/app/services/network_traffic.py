import hashlib
import ipaddress
from collections import Counter, defaultdict


def _load_scapy():
    try:
        from scapy.all import DNS, DNSQR, IP, IPv6, TCP, UDP, rdpcap, Raw  # type: ignore

        return {
            "DNS": DNS,
            "DNSQR": DNSQR,
            "IP": IP,
            "IPv6": IPv6,
            "TCP": TCP,
            "UDP": UDP,
            "Raw": Raw,
            "rdpcap": rdpcap,
        }
    except Exception:
        return None


def _safe_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except Exception:
        return value


def _http_request(payload: bytes) -> dict | None:
    if not payload:
        return None

    try:
        text = payload[:2048].decode("utf-8", errors="ignore")
    except Exception:
        return None

    first = text.splitlines()[0] if text.splitlines() else ""
    if not first.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")):
        return None

    headers = {}
    for line in text.splitlines()[1:]:
        if not line.strip():
            break
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    parts = first.split(" ")
    return {
        "method": parts[0] if parts else "unknown",
        "path": parts[1] if len(parts) > 1 else "",
        "host": headers.get("host", ""),
        "user_agent": headers.get("user-agent", ""),
    }


def _tls_sni(payload: bytes) -> str:
    marker = b"\x00\x00"
    if len(payload) < 10 or payload[0] != 0x16:
        return ""

    # Lightweight best-effort SNI extraction. It is intentionally conservative.
    for offset in range(0, min(len(payload) - 8, 512)):
        if payload[offset:offset + 2] != marker:
            continue
        length = int.from_bytes(payload[offset + 2:offset + 4], "big")
        candidate = payload[offset + 4:offset + 4 + length]
        if 3 <= length <= 253 and b"." in candidate:
            try:
                name = candidate.decode("ascii")
            except Exception:
                continue
            if all(char.isalnum() or char in ".-" for char in name):
                return name.lower().strip(".")
    return ""


def analyze_pcap(filename: str, data: bytes) -> dict:
    scapy = _load_scapy()
    sha256 = hashlib.sha256(data).hexdigest()

    if not scapy:
        return {
            "status": "dependency_missing",
            "filename": filename,
            "sha256": sha256,
            "summary": {
                "packets": 0,
                "dns_queries": 0,
                "http_requests": 0,
                "tls_sni": 0,
                "findings": 1,
            },
            "findings": [
                {
                    "severity": "info",
                    "title": "PCAP parser dependency missing",
                    "detail": "Install scapy in the backend virtual environment to enable PCAP parsing.",
                    "recommendation": "Run pip install -r requirements.txt after scapy is added."
                }
            ],
            "iocs": {"ips": [], "domains": [], "urls": []},
            "limitations": ["No packets were parsed because scapy is not installed."]
        }

    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        tmp.write(data)
        tmp.flush()
        packets = scapy["rdpcap"](tmp.name)

    ip_counter = Counter()
    flows = Counter()
    dns_queries = []
    http_requests = []
    tls_names = []
    findings = []

    for packet in packets:
        src = dst = ""
        if packet.haslayer(scapy["IP"]):
            src = _safe_ip(packet[scapy["IP"]].src)
            dst = _safe_ip(packet[scapy["IP"]].dst)
        elif packet.haslayer(scapy["IPv6"]):
            src = _safe_ip(packet[scapy["IPv6"]].src)
            dst = _safe_ip(packet[scapy["IPv6"]].dst)

        if src:
            ip_counter[src] += 1
        if dst:
            ip_counter[dst] += 1

        dport = ""
        proto = ""
        if packet.haslayer(scapy["TCP"]):
            proto = "tcp"
            dport = str(packet[scapy["TCP"]].dport)
        elif packet.haslayer(scapy["UDP"]):
            proto = "udp"
            dport = str(packet[scapy["UDP"]].dport)

        if src and dst and proto:
            flows[(src, dst, proto, dport)] += 1

        if packet.haslayer(scapy["DNS"]) and packet.haslayer(scapy["DNSQR"]):
            query = packet[scapy["DNSQR"]].qname
            if isinstance(query, bytes):
                query = query.decode("utf-8", errors="ignore")
            query = str(query).strip(".").lower()
            if query:
                dns_queries.append(query)

        if packet.haslayer(scapy["Raw"]):
            payload = bytes(packet[scapy["Raw"]].load)
            request = _http_request(payload)
            if request:
                http_requests.append({
                    "src": src,
                    "dst": dst,
                    **request
                })

            sni = _tls_sni(payload)
            if sni:
                tls_names.append(sni)

    flow_totals = defaultdict(int)
    for (src, dst, proto, dport), count in flows.items():
        flow_totals[(src, dst)] += count
        if count >= 20 and dport in {"80", "443", "53"}:
            findings.append({
                "severity": "medium",
                "title": "Repeated destination flow",
                "detail": f"{src} contacted {dst}:{dport}/{proto} {count} times.",
                "recommendation": "Review timing, destination reputation, and process context for beaconing behavior."
            })

    repeated_pairs = [
        {"src": src, "dst": dst, "packets": count}
        for (src, dst), count in flow_totals.items()
        if count >= 50
    ]

    if repeated_pairs:
        findings.append({
            "severity": "medium",
            "title": "Potential beaconing candidate",
            "detail": f"{len(repeated_pairs)} source/destination pairs have repeated packet patterns.",
            "recommendation": "Check interval regularity and correlate with DNS, HTTP, and endpoint telemetry."
        })

    domains = sorted(set(dns_queries + tls_names + [item["host"] for item in http_requests if item.get("host")]))
    urls = sorted(set(
        f"http://{item['host']}{item['path']}"
        for item in http_requests
        if item.get("host") and item.get("path")
    ))

    return {
        "status": "parsed",
        "filename": filename,
        "sha256": sha256,
        "summary": {
            "packets": len(packets),
            "unique_ips": len(ip_counter),
            "dns_queries": len(dns_queries),
            "http_requests": len(http_requests),
            "tls_sni": len(tls_names),
            "findings": len(findings),
        },
        "top_ips": [{"ip": ip, "packets": count} for ip, count in ip_counter.most_common(20)],
        "dns_queries": sorted(set(dns_queries))[:100],
        "http_requests": http_requests[:100],
        "tls_server_names": sorted(set(tls_names))[:100],
        "beaconing_candidates": repeated_pairs[:50],
        "findings": findings,
        "iocs": {
            "ips": [item[0] for item in ip_counter.most_common(50)],
            "domains": domains[:100],
            "urls": urls[:100],
        },
        "limitations": [
            "Beaconing detection is heuristic and based on repeated packet patterns only.",
            "Encrypted payload content is not decrypted.",
            "PCAPs are parsed locally by the backend and are not uploaded to third-party services."
        ]
    }
