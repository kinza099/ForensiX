# ForensiX

### Professional Digital Forensic Investigation, Evidence Analysis & Case Management Platform

**ForensiX** is an enterprise-grade digital forensic investigation platform designed for authorized cybersecurity investigations, university education, digital-forensics labs, research, and controlled forensic analysis.

---

## 🔍 Core Investigation Workflow

```text
Create Investigation Case
        ↓
Add / Import Evidence (Files, Logs, Browser Exports, Images, Docs)
        ↓
Evidence Verification & Hash Calculation (MD5, SHA-1, SHA-256)
        ↓
Evidence Classification & Categorization
        ↓
Artifact & Metadata Extraction (EXIF, PE Headers, Office/PDF Meta)
        ↓
Log & Browser Artifact Analysis (Explainable Rules & Heuristics)
        ↓
Suspicious Artifact Detection & Shannon Entropy Scoring
        ↓
Indicator Identification & IOC Registry (IPs, Domains, URLs, Hashes)
        ↓
Normalized Forensic Timeline Generation
        ↓
Interactive Relationship / Evidence Graph Visualization
        ↓
Investigator Review & Triage
        ↓
Tags + Notes + Findings Management
        ↓
Immutable Forensic Chain of Custody Ledger
        ↓
Dynamic Investigation Executive Summary
        ↓
Official Forensic PDF Report Generation & Export
```

---

## 🚀 Key Features & Architectural Modules

### 1. Case Management (Full CRUD)
* **Create**: Initialize new forensic investigation cases with auto-generated identifiers (`FL-2026-XXX`), priority, category, investigator assignment, and scope.
* **Read**: Inspect case registry, active status, evidence counts, findings, and telemetry summaries.
* **Update**: Dedicated `Edit Case Information` modal to modify title, category, priority, status (`Open`, `Under Investigation`, `On Hold`, `Completed`, `Archived`), assigned investigator, and case objectives.
* **Delete**: Safe case deletion modal with automatic cascade removal of associated evidence records, hashes, timeline events, and vault files.
* **Strict Case Isolation**: Selecting a case in the Cockpit Switcher instantly scopes every single module (Dashboard, Vault, Browser, Logs, Timeline, Graph, Findings, IOCs, Reports, Custody) exclusively to that case.

### 2. Tactical Cyber Command Console (Unique Design)
* **Command HUD Bar**: Real-time UTC Forensic Clock, digital status tickers (`SYS_INTEGRITY: LOCKED`), Case Cockpit Selector, and Global Command Search.
* **Segmented Command Navigation Dock**: Fast, horizontal iconic tabs with live count pills, distinct from standard generic left-sidebars.
* **Active Case Hero Cockpit**: Prominently highlights the active target case with quick inline `[✏️ Edit Case]`, `[🗑️ Delete Case]`, `[+ Add Evidence]`, and `[📄 Generate Forensic PDF]` operations.
* **Telemetry Matrix**: 6 live tactical metric widgets with glowing indicators and entropy gauges.
* **Senior Examiner Section**: Dedicated investigator dossier displaying examiner credentials, security clearance level, digital signature keys, and live case journal notes.

### 2. Evidence Management & Vault
* Supports **Documents**, **Images**, **Executables**, **Scripts**, **Logs**, **Browser Artifacts**, **Archives**, **System Files**, and **Configuration Files**.
* Immutable evidence storage: original raw files preserved in `evidence_vault/raw/<case_id>/`.
* Live review state tracking: *Not Reviewed*, *Under Review*, *Reviewed*, *Requires Attention*.

### 3. Cryptographic Hashes & Integrity
* Chunked computation of **MD5**, **SHA-1**, and **SHA-256** integrity hashes.
* Re-verification of evidence against physical storage at any time.
* Dedicated **Cryptographic Hash Comparison Tool** to verify matches between evidence items or external threat feeds.

### 4. File Metadata & Entropy Analysis
* File timestamps (Created, Modified, Accessed), permissions, file formats.
* **Document Metadata**: Author, creation dates, application, page counts for DOCX and PDF.
* **Image Metadata**: EXIF metadata tags, camera make/model, dimensions, format, color mode.
* **Executable / PE Analysis**: Architecture (`x86`, `x64`), PE section headers, compilation timestamps, imported Win32 APIs, suspicious API flags (`VirtualAlloc`, `CreateRemoteThread`, `WriteProcessMemory`).
* **Shannon Entropy Calculation**: 0.0 to 8.0 score; flags entropy $> 7.2$ as potentially packed, obfuscated, or encrypted payloads.
* Clearly distinguishes between extracted metadata and `Not Available` / `Not Extracted`.

### 5. Browser Artifact Analysis
* Parses exported browser history, downloads, search queries, bookmarks, and cookies.
* Extracts timestamps, browsers (Chrome, Edge, Firefox), target URLs, FQDN domains, and titles.
* Filter by date, browser, domain, and artifact type.

### 6. Log Analysis & Explainable Heuristics
* Analyzes Windows Event Logs (`.evtx`), Linux `auth.log`, Nginx/Apache access logs, firewall telemetry, and CSV/JSON logs.
* Extracts timestamps, event types, usernames, source IPs, destination IPs, and status codes.
* Explainable detection rules:
  * *Repeated Failed Login*
  * *Unusual Event Frequency*
  * *Unexpected Account Activity*
  * *Privilege Escalation / Admin Access*
  * *Web Attack Signatures* (SQL injection, directory traversal)
* Strict forensic terminology: **Potentially Suspicious**, **Requires Review**, **Notable Event**.

### 7. Suspicious Artifact Analysis
* Explainable rule-based heuristics evaluating file extensions, double extensions (`invoice.pdf.exe`), staging paths (`%APPDATA%`, `Temp`), PE APIs, and Shannon entropy.
* Provides clear, transparent detection reasons for every flagged item.

### 8. Indicator Extraction & IOC Registry
* Automatic regex and heuristic extraction of IPv4 addresses, domains, URLs, email addresses, usernames, and hashes.
* Indicator dashboard with occurrence counts, first seen/last seen dates, tags, and bookmarking.

### 9. Unified Forensic Timeline
* Aggregates timestamps across file creations, modifications, browser visits, downloads, authentication events, firewall blocks, and investigator actions into a normalized UTC timeline.
* Filterable by category, date range, and keyword search.

### 10. Interactive Canvas Relationship Graph
* Zero-dependency HTML5 Canvas Force-Directed Network Graph with physics simulation.
* Connects Cases, Evidence, Hashes, Domains, URLs, IP Addresses, and Findings.
* Click any node to open the Inspector Panel showing node properties and connected entities.
* Interactive zoom, pan, and node dragging.

### 11. Visual Telemetry Dashboard
* Dynamic HTML5 Canvas charts:
  * *Evidence Category Distribution* (Donut chart)
  * *Investigation Activity Over Time* (Hourly bar chart)
  * *Indicator Breakdown*
  * *Evidence Review & Triage Status*

### 12. Findings Management
* Document formal forensic conclusions with severity levels (**Informational**, **Low**, **Medium**, **High**, **Critical**).
* Links directly to evaluated evidence items, indicators, and timeline events with an explainable evidentiary basis.

### 13. Chain of Custody Ledger
* Immutable audit log tracking evidence actions: *Evidence Added*, *Evidence Verified*, *Evidence Transferred*, *Evidence Analyzed*, *Evidence Reviewed*, *Evidence Included in Report*.
* Records investigator identity, timestamp, description, and cryptographic hash.

### 14. Professional PDF Forensic Report
* Built with Python `reportlab` to produce authentic, publication-quality forensic investigation reports.
* Includes:
  1. Official Cover Page with Case Metadata and Legal Compliance Notice
  2. Executive Investigation Summary & Statistics
  3. Evidence Inventory & Cryptographic Integrity Table
  4. Suspicious Artifact Findings with Explainable Reasons
  5. Indicators of Interest (IOCs) Table
  6. Formal Investigation Findings
  7. Unified Forensic Timeline Excerpt
  8. Chain of Custody Audit Log
  9. Formal Investigator Attestation & Signature Block
* Instant 1-click generation and browser download.

---

## 💻 Tech Stack & Design

* **Backend**: Python 3.14 + Flask + SQLite (WAL mode)
* **Forensic Libraries**: `reportlab` (PDF generation), `pefile` (PE headers), `pillow` (EXIF image metadata), `pypdf`, `python-docx`
* **Frontend**: Pure HTML5, Modern CSS (Cybersecurity Dark & High-Contrast Light themes), Vanilla JavaScript (Canvas Charts, Force-Directed Graph Engine, Timeline Controller)
* **Zero External Dependencies**: Works completely offline without requiring Node.js, npm, or CDN access.

---

## ⚡ Quick Start

### 1. Launch the Application
Run the runner script using Python:
```bash
python run.py
```
Or double-click `start.bat` on Windows.

### 2. Access the Web Console
Open your browser to:
```
http://127.0.0.1:5000
```

### 3. Default Investigator Credentials
* **Username**: `investigator`
* **Password**: `forensix2026`
* **Role**: `Lead Digital Forensic Analyst`

---

## 🧪 Pre-loaded Demonstration Scenario

ForensiX comes pre-configured with a realistic incident response case:

* **Case ID**: `FL-2026-001`
* **Title**: `[DEMO] Corporate Workstation Investigation (FinCorp Inc.)`
* **Evidence Items**: 15 authentic files (E01 triage image, suspicious updater binary, confidential financial forecast spreadsheet, Windows event logs, Chrome history and download exports, encoded PowerShell transcripts, Nginx web access logs, firewall egress logs, screen capture PNG, persistence DLL, and staged zip archive).
* **Indicators**: 9 threat indicators (threat actor IP `194.26.29.112`, masqueraded CDN `update-service-cloud-cdn.com`, C2 hashes, compromised accounts).
* **Timeline**: 32+ correlated chronological events.
* **Findings**: 4 validated findings with explainable evidentiary basis.
* **Chain of Custody**: Complete verifiable audit trail.

You can also seed or re-seed the demo scenario anytime using the **"Seed Demo Scenario"** button in the header.

---

## 🛡️ Forensic Safety Principles
ForensiX is strictly designed for authorized cybersecurity investigations, university education, digital forensics research, and controlled forensic analysis of lawfully obtained evidence. It does not contain capabilities to compromise third-party systems or execute unauthorized credential theft. All analysis focuses on post-acquisition evidence triage and verification.
