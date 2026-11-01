import re
import json
import csv
from datetime import datetime

IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
TIMESTAMP_REGEX = re.compile(r'\b(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b')

def parse_log_file(file_path: str, evidence_id: int = None, case_id: int = None) -> list[dict]:
    """
    Parses various forensic log formats (auth.log, Windows event logs, Nginx/Apache logs, CSV/JSON)
    and evaluates explainable security heuristics.
    """
    events = []
    if not file_path:
        return events

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()

        # Check JSON
        if content.startswith("{") or content.startswith("["):
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    data = data.get("events") or data.get("logs") or [data]
                if isinstance(data, list):
                    for item in data:
                        event = _normalize_log_record(item, case_id, evidence_id)
                        _evaluate_log_rules(event)
                        events.append(event)
                    return events
            except Exception:
                pass

        lines = content.splitlines()
        
        # Check CSV
        if len(lines) > 1 and ("," in lines[0] or "\t" in lines[0]):
            delimiter = "\t" if "\t" in lines[0] else ","
            try:
                reader = csv.DictReader(lines, delimiter=delimiter)
                for row in reader:
                    event = {
                        "case_id": case_id,
                        "evidence_id": evidence_id,
                        "timestamp": row.get("timestamp") or row.get("Time") or row.get("Date") or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                        "event_type": row.get("event_type") or row.get("EventID") or row.get("Action") or "Log Record",
                        "username": row.get("username") or row.get("User") or row.get("Account") or "-",
                        "source_ip": row.get("source_ip") or row.get("SourceIP") or row.get("ClientIP") or "-",
                        "dest_ip": row.get("dest_ip") or row.get("DestIP") or row.get("ServerIP") or "-",
                        "status": row.get("status") or row.get("Status") or "Success",
                        "message": row.get("message") or row.get("Description") or row.get("Details") or "",
                        "severity": row.get("severity") or "Informational",
                        "suspicious_flag": "Normal",
                        "flag_reason": ""
                    }
                    _evaluate_log_rules(event)
                    events.append(event)
                if events:
                    return events
            except Exception:
                pass

        # Text line-by-line parsing (Syslog, Auth.log, Web logs)
        failed_login_count = {}
        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue

            # Extract timestamp
            ts_match = TIMESTAMP_REGEX.search(line_str)
            timestamp = ts_match.group(0) if ts_match else datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            # Extract IPs
            ips = IP_REGEX.findall(line_str)
            src_ip = ips[0] if len(ips) > 0 else "-"
            dst_ip = ips[1] if len(ips) > 1 else "-"

            # Extract user
            user = "-"
            user_match = re.search(r'(?:user(?:name)?|for|by|account)\s+([a-zA-Z0-9_\-\.]+)', line_str, re.IGNORECASE)
            if user_match and user_match.group(1).lower() not in ["invalid", "from", "port"]:
                user = user_match.group(1)

            # Determine Event Type & Status
            event_type = "System Event"
            status = "Information"
            if "failed password" in line_str.lower() or "logon failure" in line_str.lower() or "4625" in line_str:
                event_type = "Failed Authentication"
                status = "Failure"
            elif "accepted password" in line_str.lower() or "logon success" in line_str.lower() or "4624" in line_str:
                event_type = "Successful Authentication"
                status = "Success"
            elif "session opened" in line_str.lower() or "session closed" in line_str.lower():
                event_type = "Session State Change"
            elif "sudo:" in line_str.lower() or "privilege" in line_str.lower() or "4672" in line_str:
                event_type = "Privilege Escalation / Admin"
            elif "get " in line_str.lower() or "post " in line_str.lower():
                event_type = "Web HTTP Request"

            event = {
                "case_id": case_id,
                "evidence_id": evidence_id,
                "timestamp": timestamp,
                "event_type": event_type,
                "username": user,
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "status": status,
                "message": line_str[:300],
                "severity": "Informational",
                "suspicious_flag": "Normal",
                "flag_reason": ""
            }

            _evaluate_log_rules(event, failed_login_count)
            events.append(event)

    except Exception as e:
        print(f"Error parsing log file: {e}")

    return events

def _normalize_log_record(item: dict, case_id: int, evidence_id: int) -> dict:
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "timestamp": item.get("timestamp") or item.get("time") or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": item.get("event_type") or item.get("type") or "System Log",
        "username": item.get("username") or item.get("user") or "-",
        "source_ip": item.get("source_ip") or item.get("ip") or "-",
        "dest_ip": item.get("dest_ip") or "-",
        "status": item.get("status") or "Success",
        "message": item.get("message") or item.get("msg") or "",
        "severity": item.get("severity") or "Informational",
        "suspicious_flag": "Normal",
        "flag_reason": ""
    }

def _evaluate_log_rules(event: dict, failed_counter: dict = None):
    msg = (event.get("message") or "").lower()
    event_type = (event.get("event_type") or "").lower()
    src_ip = event.get("source_ip") or ""

    # Rule 1: Repeated Failed Logins
    if "failed" in msg or "failure" in msg or "failed" in event_type:
        event["severity"] = "Medium"
        event["suspicious_flag"] = "Potentially Suspicious"
        event["flag_reason"] = "Repeated Failed Login or authentication rejection detected"
        if failed_counter is not None and src_ip != "-":
            failed_counter[src_ip] = failed_counter.get(src_ip, 0) + 1
            if failed_counter[src_ip] >= 3:
                event["severity"] = "High"
                event["suspicious_flag"] = "Potentially Suspicious"
                event["flag_reason"] = f"Unusual Event Frequency: {failed_counter[src_ip]} repeated authentication failures from {src_ip}"

    # Rule 2: Web Attacks (SQLi, Directory Traversal, Shell probes)
    elif any(pattern in msg for pattern in ["union select", "or 1=1", "../..", "/etc/passwd", "cmd.exe", "powershell", "eval(", "/wp-admin/install.php", "c99.php"]):
        event["severity"] = "High"
        event["suspicious_flag"] = "Potentially Suspicious"
        event["flag_reason"] = "Notable Event: Attack pattern or command execution sequence identified in payload"

    # Rule 3: Privilege Escalation
    elif "sudo" in msg or "privilege" in msg or "4672" in msg or "admin" in msg:
        event["severity"] = "Medium"
        event["suspicious_flag"] = "Requires Review"
        event["flag_reason"] = "Unexpected Account Activity: Special elevated privileges or administrator token assignment"

    # Rule 4: Unusual network / error states
    elif any(term in msg for term in ["refused", "segfault", "core dump", "denied", "unauthorized", "kernel panic"]):
        event["severity"] = "Low"
        event["suspicious_flag"] = "Notable Event"
        event["flag_reason"] = "Important System Event: Anomaly or security restriction enforced"
