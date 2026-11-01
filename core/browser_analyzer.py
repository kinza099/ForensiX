import json
import csv
import re
import urllib.parse
from datetime import datetime

def extract_domain(url: str) -> str:
    if not url:
        return ""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    except Exception:
        return ""

def parse_browser_file(file_path: str, evidence_id: int = None, case_id: int = None) -> list[dict]:
    """
    Parses browser forensic artifacts from JSON, CSV, or text files.
    Returns normalized artifact records.
    """
    artifacts = []
    if not file_path:
        return artifacts

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
            
        # Try JSON
        if content.startswith("{") or content.startswith("["):
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    data = data.get("history") or data.get("artifacts") or data.get("downloads") or [data]
                if isinstance(data, list):
                    for item in data:
                        url = item.get("url") or item.get("target_url") or item.get("address") or ""
                        domain = item.get("domain") or extract_domain(url)
                        artifacts.append({
                            "case_id": case_id,
                            "evidence_id": evidence_id,
                            "timestamp": item.get("timestamp") or item.get("visit_time") or item.get("time") or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                            "browser": item.get("browser", "Chrome"),
                            "artifact_type": item.get("artifact_type") or item.get("type", "History"),
                            "url": url,
                            "domain": domain,
                            "title": item.get("title") or item.get("name") or "Page Visit",
                            "details": item.get("details") or item.get("search_query") or item.get("status") or ""
                        })
                    return artifacts
            except Exception:
                pass

        # Try CSV
        lines = content.splitlines()
        if len(lines) > 1 and ("," in lines[0] or "\t" in lines[0]):
            delimiter = "\t" if "\t" in lines[0] else ","
            reader = csv.DictReader(lines, delimiter=delimiter)
            for row in reader:
                url = row.get("url") or row.get("URL") or row.get("Target") or ""
                domain = row.get("domain") or row.get("Domain") or extract_domain(url)
                artifacts.append({
                    "case_id": case_id,
                    "evidence_id": evidence_id,
                    "timestamp": row.get("timestamp") or row.get("Time") or row.get("Date") or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                    "browser": row.get("browser") or row.get("Browser") or "Edge",
                    "artifact_type": row.get("type") or row.get("Artifact Type") or "History",
                    "url": url,
                    "domain": domain,
                    "title": row.get("title") or row.get("Title") or "Web Record",
                    "details": row.get("details") or row.get("Details") or ""
                })
            if artifacts:
                return artifacts

        # Text fallback search for URLs and timestamps
        url_regex = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
        date_regex = re.compile(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}')
        for line in lines[:200]:
            found_urls = url_regex.findall(line)
            found_dates = date_regex.findall(line)
            if found_urls:
                ts = found_dates[0] if found_dates else datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                for u in found_urls:
                    artifacts.append({
                        "case_id": case_id,
                        "evidence_id": evidence_id,
                        "timestamp": ts,
                        "browser": "Forensic Raw Stream",
                        "artifact_type": "URL Stream",
                        "url": u,
                        "domain": extract_domain(u),
                        "title": "Raw URL Extract",
                        "details": line.strip()[:150]
                    })
    except Exception as e:
        print(f"Error parsing browser file: {e}")

    return artifacts
