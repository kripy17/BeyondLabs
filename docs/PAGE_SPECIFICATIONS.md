# Page Specifications

What each page does, what data it produces, what actions are available, and how it connects to other modules.

---

## Dashboard (`/`)

**Purpose:** Analyst command center — overview of active work.

**Shows:**
- Active cases
- Recent investigations
- Critical findings
- Suspicious artifacts
- Recent activity
- Alerts
- Quick actions

**Data produced:** None (aggregation view).

**Connections:** Drills into Investigation, Cases, Activity.

---

## Investigation Pages

### Triage (`/triage`)

**Purpose:** Artifact intake — the starting point for suspicious data.

**Inputs:** Emails, files, URLs, logs, PCAP, hashes, paste text.

**Shows:**
- Severity distribution (PieChart)
- Queue of items filtered by status/severity
- Quick intake form

**Data produced:** Items in `localStorage` triage queue.

**Actions:**
- Add artifact
- Assign severity
- Analyze
- Create Case
- Extract IOCs

**Connections:** Feeds into Cases, Analysis modules.

---

### Cases (`/case`)

**Purpose:** Central investigation workspace.

**Shows:**
- Notebook-style entries (evidence, findings, notes)
- Handoff report generation
- Timeline of case activity

**Data produced:** Case objects in `localStorage`.

**Actions:**
- Add evidence entries
- Extract IOCs to locker
- Copy handoff report
- Send to timeline

**Future:**
- Evidence view
- Findings view
- IOCs view
- MITRE mapping
- Detection suggestions
- Report generation

**Connections:** Receives from all Analysis modules and Triage.

---

### Activity (`/activity`)

**Purpose:** Timeline of all tool runs, analysis events, and case activity.

**Shows:** Chronological feed with source, verb, detail, result.

**Data produced:** None (reads from `localStorage` timeline).

**Actions:** None (read-only log).

**Connections:** Fed by every analysis module via `pushTimelineEvent`.

---

### Timeline (`/timeline`)

**Purpose:** Raw event log viewer.

**Shows:** Events with timestamps, sources, details.

**Data produced:** None (reads from `localStorage`).

**Actions:** Filter by source.

---

### Phishing Analysis (`/phishing`)

**Purpose:** Analyze suspicious emails.

**Input:** `.eml` file paste or upload.

**Shows:**
- Email metadata (from, to, subject, date)
- Authentication results (SPF, DKIM, DMARC)
- Header analysis
- Body text
- Extracted URLs and attachments
- Verdict with severity

**Data produced:**
- Findings: SPF failure, suspicious sender, malicious indicators
- IOCs: URLs, domains, hashes, IPs
- Artifact: email representation
- Timeline event

**Actions:**
- Add to Case
- Extract IOCs to locker
- Create Timeline Event
- Send to URL Analysis
- Copy results

**Connections:** Feeds IOCs → locker, Timeline, Cases.

---

### URL Analysis (`/url`)

**Purpose:** Investigate suspicious URLs.

**Input:** URL string.

**Shows:**
- Redirect chain
- Domain info
- Reputation
- Embedded indicators
- Screenshot/preview

**Data produced:**
- IOCs: URL, domain
- Findings: suspicious patterns, redirects

**Actions:**
- Add IOC to locker
- Add to Case
- Threat Intel lookup
- Extract indicators

**Connections:** Feeds into Intel, Cases.

---

### File Analysis (`/attachment`)

**Purpose:** Analyze suspicious files.

**Input:** File upload or paste.

**Shows:**
- Hashes (MD5, SHA1, SHA256)
- File metadata
- File type
- Extracted strings
- Suspicious indicators
- YARA matches

**Data produced:**
- Evidence: file hash, metadata
- Findings: suspicious patterns
- IOCs: hashes

**Actions:**
- Add Evidence to Case
- Lookup Hash in Intelligence
- Create Finding
- Extract IOCs

**Connections:** Feeds into Intel (hash lookup), Cases.

---

### Parser (`/parser`)

**Purpose:** Universal artifact intake — parse raw data and extract structured fields.

**Input:** Raw text (logs, email source, configs, anything structured).

**Shows:**
- Parsed fields in structured view
- Extracted IOCs
- Copyable output formats

**Data produced:**
- Structured data from raw input
- IOCs

**Actions:**
- Copy as JSON/CSV/table
- Add to locker
- Send to Case

**Future:** Auto-detect format and route to appropriate analyzer.

**Connections:** Feeds into Analysis modules, Cases.

---

### PCAP Analysis (`/pcap`)

**Purpose:** Network traffic investigation.

**Input:** `.pcap` file upload or text paste (tcpdump/tshark output).

**Shows:**
- Summary (packets, IPs, protocols)
- Conversations
- DNS queries
- HTTP requests
- TLS SNI
- Extracted IOCs
- Timing/bandwidth metrics

**Data produced:**
- Evidence: PCAP data
- Findings: suspicious traffic patterns
- IOCs: IPs, domains, URLs
- Timeline events

**Actions:**
- Extract IOCs to locker
- Add Evidence to Case
- Create Timeline Events
- Copy results

**Connections:** Feeds into Cases, Timeline, Locker.

---

## SIEM Pages

### SIEM Workspace (`/siem`)

**Purpose:** Log search, correlation, and alert triage.

**Input:** Log text paste or file upload.

**Shows:**
- Event timeline (BarChart by severity over time)
- Event list with filters
- Event detail modal with narrative
- Metrics
- Extracted IOCs
- MITRE mapping

**Data produced:**
- Findings
- IOCs
- Timeline events

**Actions:**
- Copy narrative
- Copy JSON
- Filter by time/severity

**Connections:** SIEM Alerts → Cases (future).

---

### Log Explorer (`/logs`)

**Purpose:** Browse and search collected logs.

**Shows:**
- Log entries with timestamps
- Filters
- Search
- MITRE tactic coverage
- Extracted IOCs

---

## Detection Pages

### Detection Workspace (`/detection`)

**Purpose:** Author, test, and manage Sigma/YARA detection rules.

**Shows:**
- Rule editor with templates
- MITRE mapping from findings
- Rule generation from description
- Testing interface
- Saved rules list

**Data produced:** Detection rules (Sigma YAML, YARA).

**Actions:**
- Generate rule
- Map to MITRE
- Test rule
- Save rule
- Copy rule

**Connections:** Receives findings from Investigation, produces rules.

---

### Sigma Tester (`/sigma-tester`)

**Purpose:** Test Sigma rules against log samples.

**Shows:**
- Rule input
- Sample data
- Match results with highlighting
- Rule explanation

---

### MITRE (`/mitre`)

**Purpose:** ATT&CK coverage mapping and gap analysis.

**Shows:**
- Technique browser by tactic
- Coverage indicators
- Search/filter

**Data produced:** MITRE technique mappings.

**Connections:** Maps findings → techniques → detection rules.

---

## Intelligence Pages

### IOC Search (`/intel`)

**Purpose:** Unified threat intelligence lookup.

**Input:** IP, domain, hash, URL, CVE ID, JA3, threat actor name.

**Shows:**
- CVE details
- Threat actor profiles
- Hash reputation
- JA3 information
- User-agent analysis

**Actions:**
- Search
- Copy
- Add to Case

**Connections:** Enriches IOCs from Investigation modules.

---

## Tools Pages

### OSINT (`/osint`)

**Purpose:** Open-source intelligence gathering.

**Input:** Email, username, domain, phone.

**Shows:** Results from multiple OSINT sources, configurable tool selection, pinned targets.

**Actions:** Search, pin targets, copy results, send to Case.

---

### Recon (`/recon`)

**Purpose:** Passive reconnaissance — subdomains, certificates, cloud surface.

**Input:** Domain.

**Shows:** Subdomains, certs, tech stack, cloud assets.

---

### Nmap (`/nmap`)

**Purpose:** Port scanning and service discovery.

**Input:** Target, flags.

**Shows:** Open ports, services, OS detection, scan progress.

---

### Hacking Toolkit (`/hacking-toolkit`)

**Purpose:** Browse and build offensive tool commands.

**Shows:** Categorized tool list with binary paths, argument builders, command preview.

**Actions:** Build command, copy, run in Terminal.

---

### Terminal (`/terminal`)

**Purpose:** Run shell commands and tool scripts.

**Shows:** Terminal output, command history, status indicators.

---

### CyberChef (`/chef`)

**Purpose:** Encode, decode, transform data.

**Input:** Text/data.

**Shows:** Configurable transformation pipeline with output preview.

---

### Regex (`/regex-playground`)

**Purpose:** Build and test SOC regex patterns.

**Shows:** Pattern input, test string, match highlighting, explanation.

---

### Diff (`/diff`)

**Purpose:** Compare artifacts side by side.

**Input:** Two text inputs.

**Shows:** Line-by-line diff with additions/removals, IOC extraction.

---

### Snippets (`/snippets`)

**Purpose:** Save and organize reusable SIEM queries, Sigma rules, regex, and checklists.

**Shows:** Category browser, snippet viewer/editor.

---

## Resources

### Guide (`/guide`)

**Purpose:** SOC playbook reference.

**Shows:** Structured playbooks by incident type with step-by-step instructions and tool links.

---

## System

### Settings (`/settings`)

**Purpose:** Application configuration.

**Shows:** Theme, layout, sidebar preferences, backend URL, brand customization.
