import re


PORT_LINE = re.compile(r"(?P<port>\d+)/(tcp|udp)\s+(?P<state>open|closed|filtered)\s+(?P<service>\S+)?")
URL_LINE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
PATH_LINE = re.compile(r"(/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{2,})")


def parse_generic_output(tool_id: str, stdout: str, stderr: str) -> dict:
    text = "\n".join(part for part in [stdout, stderr] if part)
    open_ports = []
    urls = sorted(set(URL_LINE.findall(text)))[:50]
    paths = sorted(set(PATH_LINE.findall(text)))[:80]

    for line in text.splitlines():
        match = PORT_LINE.search(line)
        if match:
            open_ports.append(match.groupdict())

    findings = []
    if open_ports:
        findings.append(f"Detected {len(open_ports)} open or reported port line(s).")
    if urls:
        findings.append(f"Extracted {len(urls)} URL(s) from output.")
    if paths:
        findings.append(f"Extracted {len(paths)} path-like artifact(s) from output.")
    if not findings and text.strip():
        findings.append("Tool produced output; review raw output for details.")

    return {
        "tool_id": tool_id,
        "open_ports": open_ports[:40],
        "urls": urls,
        "paths": paths,
        "findings": findings,
        "line_count": len(text.splitlines()),
    }

