# Workflow Design

How data flows through the platform. These flows prevent pages from being built as isolated screens.

---

## Core Pipeline

```
Artifact Intake
     │
     ▼
Analysis
     │
     ▼
Findings
     │
     ▼
IOCs / Evidence
     │
     ▼
Case Investigation
     │
     ▼
Timeline
     │
     ▼
Detection
     │
     ▼
Report
```

---

## Phishing Investigation Flow

```
User receives suspicious email (.eml)
     │
     ▼
Paste or upload in Phishing Analysis
     │
     ├── Parser extracts:
     │     • headers (from, to, subject, date)
     │     • authentication results (SPF, DKIM, DMARC)
     │     • body text
     │     • embedded URLs
     │     • attachments
     │
     ▼
Analyzer creates:
     │
     ├── Findings
     │     • SPF failure
     │     • suspicious sender domain
     │     • malicious attachment detected
     │
     ├── IOCs
     │     • sender domain
     │     • reply-to domain
     │     • embedded URLs
     │     • attachment hashes
     │
     └── Artifact
           • email metadata record
     │
     ▼
Actions (analyst chooses):
     │
     ├── Add IOCs to Locker
     ├── Create Case with evidence
     ├── Create Timeline Event
     └── Generate Report
     │
     ▼
Case contains:
     ├── Evidence: email source + analysis results
     ├── Findings: bullet points
     ├── IOCs: domains, URLs, hashes
     └── Timeline: email received → analysis complete
```

---

## URL Investigation Flow

```
Analyst encounters suspicious URL
     │
     ▼
Paste in URL Analysis
     │
     ▼
System retrieves:
     ├── Redirect chain
     ├── Domain WHOIS / registration
     ├── Reputation check
     └── Embedded indicators
     │
     ▼
Actions:
     ├── Add URL as IOC
     ├── Add domain as IOC
     ├── Add to Case
     └── Threat Intel enrichment
     │
     ▼
If malicious:
     Case is updated with URL evidence
```

---

## File Analysis Flow

```
Analyst encounters suspicious file
     │
     ▼
Upload in File Analysis
     │
     ▼
System extracts:
     ├── Hashes (MD5, SHA1, SHA256)
     ├── File metadata
     ├── File type
     └── Strings
     │
     ▼
Actions:
     ├── Lookup hashes in Intelligence
     ├── Add file as Evidence to Case
     ├── Create Finding
     └── Extract IOCs
     │
     ▼
If malicious:
     Case is updated with file evidence + intel context
```

---

## PCAP Investigation Flow

```
Analyst captures suspicious network traffic
     │
     ▼
Upload PCAP file or paste tcpdump output
     │
     ▼
System analyzes:
     ├── Packet summary
     ├── Conversations (IP pairs, ports)
     ├── DNS queries
     ├── HTTP requests
     ├── TLS SNI
     └── Suspicious indicators
     │
     ▼
Actions:
     ├── Extract IPs, domains, URLs as IOCs
     ├── Add PCAP as Evidence to Case
     ├── Create Timeline Events
     └── Copy findings
     │
     ▼
Case contains:
     ├── Evidence: PCAP summary + extracted data
     ├── IOCs: IPs, domains, URLs
     └── Timeline: traffic capture → analysis complete
```

---

## SIEM Alert to Investigation Flow

```
SIEM detects suspicious event
     │
     ▼
Analyst reviews alert in SIEM Workspace
     │
     ▼
Actions:
     ├── Investigate (drill into logs)
     ├── Create Case
     └── Extract IOCs
     │
     ▼
If escalated:
     Case is created from SIEM alert
     │
     ▼
Investigation proceeds:
     ├── Evidence: logs, alert data
     ├── Findings: alert details
     └── IOCs: extracted from logs
```

---

## Finding to Detection Flow

```
Investigation identifies malicious pattern
     │
     ▼
Finding is created
     │
     ▼
Analyst maps finding to MITRE technique
     │
     ▼
Detection Workspace:
     ├── Generate Sigma rule from description
     ├── Test rule against samples
     └── Save as detection
     │
     ▼
Case is updated:
     ├── MITRE technique mapped
     └── Detection rule attached
```

---

## Case to Report Flow

```
Investigation complete
     │
     ▼
Case contains:
     ├── Evidence (files, logs, PCAP)
     ├── Findings (analysis results)
     ├── IOCs (indicators)
     ├── Timeline (chronological events)
     └── MITRE mapping
     │
     ▼
Generate Report:
     ├── Incident summary
     ├── Evidence list
     ├── IOCs found
     ├── Timeline of events
     ├── MITRE techniques
     └── Detection rules created
     │
     ▼
Report exported as markdown
```

---

## Tool to Investigation Flow (Optional)

```
Analyst uses standalone Tool (OSINT, Nmap, etc.)
     │
     ▼
Tool produces result
     │
     ▼
Actions:
     ├── Copy result
     └── Send result to Case (optional)
     │
     ▼
If sent to Case:
     Result is attached as evidence note
     No automatic IOCs or findings created
```

Tools never auto-attach to cases or create timeline events. They are analyst utilities with optional manual case integration.
