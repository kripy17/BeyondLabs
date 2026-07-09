OFFENSIVE_KNOWLEDGE_DETAILS: dict[str, dict] = {
    "hashcat-helper": {
        "learning_objectives": [
            "Plan an offline password audit without touching live authentication services.",
            "Map hash type, source, authorization, and remediation into a report-ready finding.",
            "Understand what host telemetry a defender should expect from approved cracking workstations.",
        ],
        "safe_lab_scope": [
            "Use only owned lab hashes or hashes exported under written authorization.",
            "Keep hash files local and do not paste real user passwords or recovered secrets into reports.",
            "Prefer documenting hash type and weakness class over storing cracked values.",
        ],
        "not_implemented": [
            "No cracking jobs are launched.",
            "No GPU workload is started.",
            "No wordlists, masks, rules, or recovered passwords are bundled or generated here.",
        ],
        "workflow": [
            "Record authorization, hash source, and suspected hash type.",
            "Use the Hash Analyzer and John offline audit pages for local deterministic context.",
            "Document password policy weaknesses, reused patterns, and remediation guidance.",
            "Save the finding with limitations instead of claiming full credential exposure without evidence.",
        ],
        "defender_view": [
            "Approved audit host, process execution, GPU load, file access to hash material, and ticket/change record.",
            "Unexpected hashcat execution on endpoints should be treated as credential-access triage.",
        ],
        "detections_to_build": [
            "Process execution for hashcat outside approved admin hosts.",
            "Access to dumped hash files followed by compression or outbound transfer.",
            "Password audit activity without a matching change/ticket window.",
        ],
        "mitre": [
            {"technique_id": "T1110.002", "technique": "Password Cracking", "tactic": "Credential Access", "confidence": "medium", "evidence": "Offline password-audit workflow or cracking-tool execution."},
        ],
        "report_sections": ["Scope", "Hash Source", "Audit Method", "Findings", "Limitations", "Remediation"],
        "practice_prompts": [
            "Write a report note for weak lab hashes without disclosing recovered passwords.",
            "Draft a SIEM query idea for hashcat running on a non-audit workstation.",
        ],
    },
    "hydra-lab": {
        "learning_objectives": [
            "Understand online brute-force behavior from a SOC and authorization perspective.",
            "Design detection thresholds for failures, lockouts, and success-after-failure patterns.",
            "Separate offline password audits from live authentication testing.",
        ],
        "safe_lab_scope": [
            "Use intentionally vulnerable local labs or platforms that explicitly permit brute-force exercises.",
            "Throttle, document scope, and avoid real users, third-party systems, and production auth services.",
        ],
        "not_implemented": [
            "Hydra is not executed by BeyondLabs.",
            "No live credential guessing, password spraying, or login attack commands are generated.",
        ],
        "workflow": [
            "Define service, test account, lockout policy, rate limit, and written authorization.",
            "Collect authentication logs from the lab target.",
            "Map failed-login bursts, lockouts, and any successful login to detection logic.",
            "Write mitigation notes for MFA, lockout, rate limiting, and alert tuning.",
        ],
        "defender_view": [
            "Repeated authentication failures, lockout events, source IP concentration, user-agent/client fingerprints, and possible success after many failures.",
        ],
        "detections_to_build": [
            "Many failures for one account from one source.",
            "Many accounts targeted by one source in a short window.",
            "Successful login after a high-failure burst.",
            "MFA failures or lockouts clustered by source network.",
        ],
        "mitre": [
            {"technique_id": "T1110", "technique": "Brute Force", "tactic": "Credential Access", "confidence": "medium", "evidence": "Authentication failures and lockout patterns."},
            {"technique_id": "T1110.003", "technique": "Password Spraying", "tactic": "Credential Access", "confidence": "low", "evidence": "One or few passwords attempted across many accounts."},
        ],
        "report_sections": ["Authorization", "Target Service", "Observed Auth Events", "Detection Logic", "False Positives", "Recommendations"],
        "practice_prompts": [
            "Given 120 SSH failures and one success, decide what evidence supports brute force.",
            "Write false-positive notes for vulnerability scanners, admin testing, and expired service credentials.",
        ],
    },
    "metasploit-concepts": {
        "learning_objectives": [
            "Understand exploit-module lifecycle, validation, and defender telemetry without running exploitation.",
            "Map public-facing application exploitation to logs, EDR, and network evidence.",
            "Prepare ethical lab notes that separate vulnerability validation from impact claims.",
        ],
        "safe_lab_scope": [
            "Use intentionally vulnerable local VMs or sanctioned training platforms only.",
            "Record module name, CVE, target version, and lab authorization if testing elsewhere.",
        ],
        "not_implemented": [
            "BeyondLabs does not run Metasploit modules, exploit payloads, handlers, sessions, or post-exploitation actions.",
            "No payload generation or listener setup is provided.",
        ],
        "workflow": [
            "Start with passive version and exposure evidence.",
            "Validate vulnerability applicability from vendor advisories and lab documentation.",
            "If a sanctioned lab is used externally, import observed artifacts into BeyondLabs as evidence.",
            "Build detection notes from exploit path, user-agent, process tree, and network callback evidence.",
        ],
        "defender_view": [
            "Web/application exploit attempts, crash/error logs, abnormal child processes, IDS signatures, outbound callback attempts, and EDR exploit-block events.",
        ],
        "detections_to_build": [
            "Known exploit URI or parameter patterns in web logs.",
            "Service process spawning shell or scripting engines.",
            "Inbound exploit attempt followed by unusual outbound connection.",
        ],
        "mitre": [
            {"technique_id": "T1190", "technique": "Exploit Public-Facing Application", "tactic": "Initial Access", "confidence": "medium", "evidence": "Exploit attempt against exposed application service."},
        ],
        "report_sections": ["Vulnerability Context", "Lab Evidence", "Observed Artifacts", "Detection Opportunities", "Limitations"],
        "practice_prompts": [
            "Turn a lab exploit attempt into a detection rule summary without including exploit instructions.",
            "List evidence required before saying exploitation succeeded.",
        ],
    },
    "tshark-helper": {
        "learning_objectives": [
            "Plan packet-analysis pivots for DNS, HTTP, TLS, conversations, and beaconing.",
            "Connect PCAP observations to IOCs, MITRE mapping, and report evidence.",
        ],
        "safe_lab_scope": [
            "Analyze captures you generated, own, or are authorized to review.",
            "Treat packet captures as sensitive because they can contain credentials, cookies, and private content.",
        ],
        "not_implemented": [
            "The generic runner does not execute tshark on arbitrary local paths.",
            "Use the existing PCAP analyzer upload workflow for BeyondLabs-managed parsing.",
        ],
        "workflow": [
            "Identify capture source, timeframe, and collection consent.",
            "Extract conversations, DNS names, HTTP hosts, TLS SNI, and periodic traffic candidates.",
            "Defang and save IOCs with checked_at and limitations.",
            "Write detection notes for rare destinations, beacon timing, and protocol anomalies.",
        ],
        "defender_view": [
            "DNS rarity, HTTP paths, TLS SNI, JA3/JA4 where available, flow duration, byte ratios, and periodic callbacks.",
        ],
        "detections_to_build": [
            "Periodic outbound connections with low jitter.",
            "DNS requests to rare domains followed by outbound TLS.",
            "HTTP traffic with suspicious paths or uncommon user-agents.",
        ],
        "mitre": [
            {"technique_id": "T1071", "technique": "Application Layer Protocol", "tactic": "Command and Control", "confidence": "low", "evidence": "Network protocol metadata and beacon-like timing."},
        ],
        "report_sections": ["Capture Scope", "Network Summary", "IOC Table", "Beaconing Assessment", "Limitations"],
        "practice_prompts": [
            "Write a beaconing hypothesis using timing evidence and false-positive considerations.",
            "Decide which extracted network indicators should be added to the case.",
        ],
    },
    "set-phishing-concepts": {
        "learning_objectives": [
            "Understand social engineering campaign components from a defender and awareness-training lens.",
            "Map pretext, lure, delivery, credential-harvest risk, and user-reporting workflow.",
        ],
        "safe_lab_scope": [
            "Use only approved awareness training, internal simulations, or isolated demo environments.",
            "Do not collect real credentials or impersonate real organizations without authorization.",
        ],
        "not_implemented": [
            "No phishing kits, credential collection, email sending, or SET automation are provided.",
            "No templates for impersonating real brands or bypassing controls are generated.",
        ],
        "workflow": [
            "Define training goal, audience, consent/approval, and measurement boundaries.",
            "Document lure indicators and expected email/security-control artifacts.",
            "Build SOC triage notes for reported messages and identity events.",
            "Generate awareness and detection recommendations.",
        ],
        "defender_view": [
            "Email gateway verdicts, URL clicks, user reports, identity sign-in logs, mailbox rules, and MFA prompts.",
        ],
        "detections_to_build": [
            "Lookalike sender/domain plus credential language.",
            "New inbox rule after suspicious sign-in.",
            "Clustered user reports for similar subject, sender, or URL.",
        ],
        "mitre": [
            {"technique_id": "T1566", "technique": "Phishing", "tactic": "Initial Access", "confidence": "medium", "evidence": "Phishing lure, delivery evidence, or user report."},
        ],
        "report_sections": ["Simulation Scope", "Email Indicators", "User Reporting", "Detection Notes", "Awareness Recommendations"],
        "practice_prompts": [
            "Write a safe awareness-training summary without including reusable phishing-kit steps.",
            "Map reported-message evidence to T1566 with limitations.",
        ],
    },
    "evilginx2-concepts": {
        "learning_objectives": [
            "Understand adversary-in-the-middle phishing risk and why MFA alone may not be sufficient.",
            "Identify identity, proxy, and browser artifacts defenders can use during triage.",
        ],
        "safe_lab_scope": [
            "Use defensive study, tabletop exercises, or sanctioned identity-lab simulations only.",
            "Do not configure real credential interception or session token capture.",
        ],
        "not_implemented": [
            "No proxy setup, phishlet configuration, credential interception, or bypass workflow is provided.",
        ],
        "workflow": [
            "Study identity logs for suspicious sign-ins, token reuse, new devices, and impossible travel.",
            "Document domain, certificate, hosting, and URL indicators from lab evidence.",
            "Write containment guidance for token revocation and session invalidation.",
        ],
        "defender_view": [
            "Suspicious sign-ins, unfamiliar device/browser, impossible travel, new MFA prompts, token/session anomalies, and phishing domain infrastructure.",
        ],
        "detections_to_build": [
            "Successful sign-in shortly after phishing click from unusual location.",
            "Session token use from unexpected ASN or device.",
            "New OAuth grant, mailbox rule, or MFA method after suspicious sign-in.",
        ],
        "mitre": [
            {"technique_id": "T1566", "technique": "Phishing", "tactic": "Initial Access", "confidence": "medium", "evidence": "Phishing delivery and identity telemetry."},
            {"technique_id": "T1539", "technique": "Steal Web Session Cookie", "tactic": "Credential Access", "confidence": "low", "evidence": "Session/token anomaly evidence."},
        ],
        "report_sections": ["Identity Timeline", "Phishing Infrastructure", "Session Risk", "Containment", "Limitations"],
        "practice_prompts": [
            "Build a timeline from click, sign-in, MFA, and mailbox-rule events.",
            "Write token-revocation recommendations with evidence requirements.",
        ],
    },
    "reverse-shells": {
        "learning_objectives": [
            "Understand reverse-shell behavior as network and process telemetry.",
            "Differentiate a lab callback from confirmed interactive compromise.",
        ],
        "safe_lab_scope": [
            "Study only in isolated local labs or training rooms that explicitly allow it.",
            "Do not run payloads or callbacks through BeyondLabs.",
        ],
        "not_implemented": [
            "No reverse-shell payloads, one-liners, listeners, or callback commands are generated.",
        ],
        "workflow": [
            "Focus on process lineage, outbound connection, destination, and user context.",
            "Correlate command interpreter spawning, network connection, and parent process.",
            "Write a detection hypothesis and save raw evidence.",
        ],
        "defender_view": [
            "Unexpected shell process, parent process mismatch, outbound connection, EDR command-line alert, and firewall/proxy logs.",
        ],
        "detections_to_build": [
            "Web server or Office process spawning a shell.",
            "Shell process initiating outbound network connection.",
            "Encoded or obfuscated command-line followed by external connection.",
        ],
        "mitre": [
            {"technique_id": "T1059", "technique": "Command and Scripting Interpreter", "tactic": "Execution", "confidence": "medium", "evidence": "Shell process and command-line telemetry."},
            {"technique_id": "T1105", "technique": "Ingress Tool Transfer", "tactic": "Command and Control", "confidence": "low", "evidence": "Transfer/callback evidence if observed."},
        ],
        "report_sections": ["Process Evidence", "Network Evidence", "Timeline", "Containment", "Limitations"],
        "practice_prompts": [
            "Write a detection idea for shell spawned by a web service account.",
            "List evidence needed before claiming interactive attacker access.",
        ],
    },
    "payload-creation": {
        "learning_objectives": [
            "Understand payload categories, delivery risk, and defensive review without creating payloads.",
            "Map payload behavior to static indicators and execution telemetry.",
        ],
        "safe_lab_scope": [
            "Use known-benign toy examples or published lab artifacts only.",
            "Do not generate, compile, encode, or package payloads in BeyondLabs.",
        ],
        "not_implemented": [
            "No payload code, encoders, loaders, droppers, macros, or bypass guidance are generated.",
        ],
        "workflow": [
            "Describe intended behavior at a high level.",
            "Identify expected static strings, file metadata, process behavior, and network behavior.",
            "Create defensive test cases and report limitations.",
        ],
        "defender_view": [
            "File hashes, suspicious imports, script-block logs, child process behavior, network callback, and persistence attempts.",
        ],
        "detections_to_build": [
            "Script spawning network utilities or interpreters.",
            "Unsigned binary from user-writable path with outbound connection.",
            "Archive or document leading to script execution.",
        ],
        "mitre": [
            {"technique_id": "T1204", "technique": "User Execution", "tactic": "Execution", "confidence": "low", "evidence": "User-opened file or lure execution chain."},
            {"technique_id": "T1027", "technique": "Obfuscated Files or Information", "tactic": "Defense Evasion", "confidence": "low", "evidence": "Obfuscation or packing indicators."},
        ],
        "report_sections": ["Behavior Summary", "Static Indicators", "Execution Chain", "Defensive Controls", "Limitations"],
        "practice_prompts": [
            "Turn a high-level payload behavior into a defensive test checklist.",
            "Write report wording that avoids giving payload-building instructions.",
        ],
    },
    "post-exploitation": {
        "learning_objectives": [
            "Understand common post-exploitation objectives from a defender timeline perspective.",
            "Map discovery, credential access, lateral movement, persistence, and exfiltration hypotheses to evidence.",
        ],
        "safe_lab_scope": [
            "Use tabletop, CTF, or owned local lab evidence.",
            "Do not run post-exploitation frameworks or commands through BeyondLabs.",
        ],
        "not_implemented": [
            "No post-exploitation commands, privilege abuse steps, or lateral movement playbooks are generated.",
        ],
        "workflow": [
            "Build a timeline of observed activity.",
            "Separate confirmed facts from hypotheses.",
            "Map each hypothesis to evidence and missing data.",
            "Create containment and hardening recommendations.",
        ],
        "defender_view": [
            "Process creation, account changes, service creation, scheduled tasks, network shares, credential access signals, and data staging.",
        ],
        "detections_to_build": [
            "Discovery command clusters after initial access.",
            "New service or scheduled task from unusual account.",
            "Credential material access followed by lateral authentication.",
        ],
        "mitre": [
            {"technique_id": "T1087", "technique": "Account Discovery", "tactic": "Discovery", "confidence": "low", "evidence": "Account enumeration commands or API use."},
            {"technique_id": "T1021", "technique": "Remote Services", "tactic": "Lateral Movement", "confidence": "low", "evidence": "Remote service authentication and execution evidence."},
        ],
        "report_sections": ["Timeline", "Confirmed Activity", "Hypotheses", "MITRE Mapping", "Containment"],
        "practice_prompts": [
            "Classify evidence as confirmed fact or hypothesis.",
            "Write a post-exploitation timeline with unknowns clearly labeled.",
        ],
    },
    "ddos-concepts": {
        "learning_objectives": [
            "Understand DDoS categories, business impact, and defensive telemetry.",
            "Plan SOC triage and escalation without simulating traffic floods.",
        ],
        "safe_lab_scope": [
            "Use synthetic logs, tabletop exercises, or provider dashboards only.",
            "Do not generate traffic floods or stress tests from BeyondLabs.",
        ],
        "not_implemented": [
            "No traffic generation, amplification, stress testing, or bypass instructions are provided.",
        ],
        "workflow": [
            "Classify volumetric, protocol, or application-layer symptoms from logs.",
            "Collect provider, CDN, WAF, firewall, and application metrics.",
            "Document impact, mitigation, and customer-facing timeline.",
        ],
        "defender_view": [
            "Traffic volume, request rate, source distribution, cache hit ratio, error rate, WAF/CDN actions, and service saturation.",
        ],
        "detections_to_build": [
            "Request-rate anomalies by endpoint and ASN.",
            "Error-rate spike with source diversity.",
            "Protocol/resource exhaustion indicators.",
        ],
        "mitre": [
            {"technique_id": "T1498", "technique": "Network Denial of Service", "tactic": "Impact", "confidence": "medium", "evidence": "Network traffic volume and service impact."},
            {"technique_id": "T1499", "technique": "Endpoint Denial of Service", "tactic": "Impact", "confidence": "low", "evidence": "Endpoint/application resource exhaustion."},
        ],
        "report_sections": ["Impact Summary", "Traffic Pattern", "Mitigation Timeline", "Provider Actions", "Lessons Learned"],
        "practice_prompts": [
            "Write an executive summary for an application-layer DDoS tabletop.",
            "List false positives for traffic spikes from product launches or crawlers.",
        ],
    },
    "rat-keylogger-concepts": {
        "learning_objectives": [
            "Understand RAT and keylogger behavior from endpoint and identity telemetry.",
            "Map collection, persistence, and C2 indicators to investigation steps.",
        ],
        "safe_lab_scope": [
            "Use benign training logs, static malware triage, or sandbox reports you are authorized to review.",
            "Do not run RATs, keyloggers, or surveillance code.",
        ],
        "not_implemented": [
            "No malware execution, keylogging, surveillance, persistence setup, or C2 configuration is provided.",
        ],
        "workflow": [
            "Triage static indicators and process/network behavior.",
            "Look for persistence, credential/input collection signals, and outbound C2.",
            "Document containment, credential reset, and host isolation recommendations.",
        ],
        "defender_view": [
            "Suspicious process persistence, keyboard hook APIs, screenshot/file collection, outbound C2, and credential access alerts.",
        ],
        "detections_to_build": [
            "Unsigned process from user-writable path registering persistence.",
            "Suspicious API/import strings in static triage.",
            "Repeated outbound callbacks from unusual process.",
        ],
        "mitre": [
            {"technique_id": "T1056.001", "technique": "Keylogging", "tactic": "Collection", "confidence": "low", "evidence": "Keylogging behavior or static indicators."},
            {"technique_id": "T1219", "technique": "Remote Access Software", "tactic": "Command and Control", "confidence": "low", "evidence": "Remote access behavior or unauthorized tool use."},
        ],
        "report_sections": ["Host Evidence", "Persistence", "Collection Risk", "Network Indicators", "Containment"],
        "practice_prompts": [
            "Write a host-isolation recommendation for suspected RAT activity.",
            "Map static strings to hypotheses without overstating certainty.",
        ],
    },
    "wireless-attack-concepts": {
        "learning_objectives": [
            "Understand wireless attack categories and defensive monitoring opportunities.",
            "Plan authorized lab learning around rogue APs, weak configuration, and authentication logs.",
        ],
        "safe_lab_scope": [
            "Use only owned RF lab equipment, shielded/isolated practice, or sanctioned training.",
            "Do not capture third-party traffic or interfere with nearby networks.",
        ],
        "not_implemented": [
            "No wireless attacks, deauthentication, handshake capture, cracking, or interface control are provided.",
        ],
        "workflow": [
            "Inventory approved SSIDs, encryption modes, and management controls.",
            "Review controller logs for rogue APs, auth failures, and signal anomalies.",
            "Document hardening: WPA3/Enterprise, strong PSK rotation, MFP, segmentation, and monitoring.",
        ],
        "defender_view": [
            "Wireless controller alerts, rogue AP detection, association/auth failures, unusual BSSID/SSID, and NAC logs.",
        ],
        "detections_to_build": [
            "Rogue SSID/BSSID similar to corporate naming.",
            "Spike in deauth/disassociation events.",
            "Repeated authentication failures from one client.",
        ],
        "mitre": [
            {"technique_id": "T1565", "technique": "Data Manipulation", "tactic": "Impact", "confidence": "low", "evidence": "Wireless attack mapping depends on scenario evidence."},
        ],
        "report_sections": ["Wireless Scope", "Controller Evidence", "Risk", "Hardening Recommendations", "Limitations"],
        "practice_prompts": [
            "Write a safe wireless lab scope that avoids third-party networks.",
            "Draft detection notes for rogue AP alerts.",
        ],
    },
    "persistence-concepts": {
        "learning_objectives": [
            "Understand persistence mechanisms as artifacts defenders can inventory and detect.",
            "Build cleanup and validation notes for lab reports.",
        ],
        "safe_lab_scope": [
            "Use controlled lab logs or benign administrative examples.",
            "Do not create persistence on real systems through BeyondLabs.",
        ],
        "not_implemented": [
            "No registry, service, scheduled task, startup, web shell, or account persistence steps are generated.",
        ],
        "workflow": [
            "Identify persistence artifact, owner, creation time, parent process, and signer.",
            "Correlate with initial access and post-exploitation timeline.",
            "Define removal and monitoring steps.",
        ],
        "defender_view": [
            "Service creation, scheduled tasks, autoruns, startup folders, launch agents, cron, web shells, and new accounts.",
        ],
        "detections_to_build": [
            "New autorun from user-writable path.",
            "Service creation by non-admin workflow or unusual parent process.",
            "Scheduled task executing script interpreter.",
        ],
        "mitre": [
            {"technique_id": "T1053", "technique": "Scheduled Task/Job", "tactic": "Persistence", "confidence": "low", "evidence": "Scheduled job creation/execution."},
            {"technique_id": "T1547", "technique": "Boot or Logon Autostart Execution", "tactic": "Persistence", "confidence": "low", "evidence": "Autostart artifact evidence."},
        ],
        "report_sections": ["Persistence Artifact", "Evidence", "Owner/Timeline", "Removal", "Monitoring"],
        "practice_prompts": [
            "Classify a new scheduled task as benign admin work or suspicious based on context.",
            "Write cleanup validation steps after persistence removal.",
        ],
    },
    "privilege-escalation-concepts": {
        "learning_objectives": [
            "Understand privilege escalation signals without providing exploitation steps.",
            "Map misconfiguration findings to hardening and detection.",
        ],
        "safe_lab_scope": [
            "Use intentionally vulnerable local labs or defensive configuration reviews.",
            "Do not run exploit code or abuse real misconfigurations through BeyondLabs.",
        ],
        "not_implemented": [
            "No exploit commands, kernel exploit guidance, credential abuse steps, or bypass instructions are generated.",
        ],
        "workflow": [
            "Document observed privilege boundary, misconfiguration, and affected asset.",
            "Collect logs for privilege assignment, token changes, service changes, and admin actions.",
            "Write remediation and monitoring guidance.",
        ],
        "defender_view": [
            "New admin membership, privilege assignment events, service binary changes, sudo usage, setuid changes, and exploit-block telemetry.",
        ],
        "detections_to_build": [
            "New privileged group membership outside change window.",
            "Service binary path or permissions changed.",
            "Unexpected sudo/admin command from low-privileged account.",
        ],
        "mitre": [
            {"technique_id": "T1068", "technique": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "confidence": "low", "evidence": "Exploit or privilege boundary evidence."},
            {"technique_id": "T1078", "technique": "Valid Accounts", "tactic": "Privilege Escalation", "confidence": "low", "evidence": "Privileged account use evidence."},
        ],
        "report_sections": ["Privilege Boundary", "Evidence", "Risk", "Remediation", "Monitoring"],
        "practice_prompts": [
            "Write cautious report language for suspected privilege escalation.",
            "List evidence needed to confirm escalation versus normal admin work.",
        ],
    },
    "credential-dumping-concepts": {
        "learning_objectives": [
            "Understand credential dumping risk, artifacts, and containment actions.",
            "Map credential access hypotheses to endpoint and identity evidence.",
        ],
        "safe_lab_scope": [
            "Use synthetic logs, static indicators, or sanctioned lab telemetry.",
            "Do not dump, extract, store, or display real credentials.",
        ],
        "not_implemented": [
            "No dumping commands, LSASS access steps, memory extraction, token theft, or secret retrieval workflows are provided.",
        ],
        "workflow": [
            "Look for process access, suspicious tools, handle opens, memory dump files, and follow-on authentication.",
            "Treat all potentially exposed credentials as sensitive and avoid storing secrets in reports.",
            "Document containment: host isolation, credential reset, token revocation, and monitoring.",
        ],
        "defender_view": [
            "LSASS access alerts, credential store access, suspicious dump files, EDR blocks, and identity activity after exposure.",
        ],
        "detections_to_build": [
            "Untrusted process accessing LSASS or credential stores.",
            "Creation of memory dump files in unusual paths.",
            "Credential access signal followed by lateral authentication.",
        ],
        "mitre": [
            {"technique_id": "T1003", "technique": "OS Credential Dumping", "tactic": "Credential Access", "confidence": "medium", "evidence": "Credential store or LSASS access telemetry."},
        ],
        "report_sections": ["Credential Exposure Risk", "Endpoint Evidence", "Identity Evidence", "Containment", "Limitations"],
        "practice_prompts": [
            "Write a finding without exposing secret values.",
            "Build a containment checklist after suspected credential dumping.",
        ],
    },
    "c2-beaconing-concepts": {
        "learning_objectives": [
            "Understand C2/beaconing behavior as network timing, protocol, and process evidence.",
            "Build confidence-aware beaconing detections and report language.",
        ],
        "safe_lab_scope": [
            "Use PCAPs, proxy logs, synthetic logs, or sanctioned lab telemetry.",
            "Do not deploy agents, implants, listeners, or C2 infrastructure through BeyondLabs.",
        ],
        "not_implemented": [
            "No C2 framework setup, listener operation, payload generation, or evasion guidance is provided.",
        ],
        "workflow": [
            "Extract destinations, intervals, jitter, byte counts, protocol, and process context.",
            "Compare with known software update, telemetry, and monitoring patterns.",
            "Save hypotheses with confidence and false-positive notes.",
        ],
        "defender_view": [
            "Periodic outbound traffic, rare domains, suspicious TLS SNI, unusual user-agent, process-network correlation, and low-volume callbacks.",
        ],
        "detections_to_build": [
            "Low-jitter periodic outbound traffic to rare destination.",
            "New process repeatedly contacting external endpoint.",
            "DNS query followed by recurring TLS sessions with similar byte counts.",
        ],
        "mitre": [
            {"technique_id": "T1071", "technique": "Application Layer Protocol", "tactic": "Command and Control", "confidence": "medium", "evidence": "Application-layer beaconing pattern."},
            {"technique_id": "T1102", "technique": "Web Service", "tactic": "Command and Control", "confidence": "low", "evidence": "Use of web service for command-and-control if supported by evidence."},
        ],
        "report_sections": ["Network Timeline", "Beaconing Evidence", "False Positives", "MITRE Mapping", "Recommendations"],
        "practice_prompts": [
            "Write a beaconing finding with confidence and limitations.",
            "List benign services that could look periodic before escalating.",
        ],
    },
}
