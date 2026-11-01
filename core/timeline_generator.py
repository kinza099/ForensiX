from datetime import datetime

def normalize_timestamp(ts_str: str) -> str:
    """Normalizes various timestamp strings into ISO YYYY-MM-DD HH:MM:SS."""
    if not ts_str or ts_str in ["Not Available", "None", "-"]:
        return ""
    
    clean_ts = ts_str.replace("UTC", "").strip()
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d",
        "%b %d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S",
        "%m/%d/%Y %H:%M:%S"
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(clean_ts, fmt)
            if fmt == "%b %d %H:%M:%S":
                dt = dt.replace(year=datetime.utcnow().year)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return clean_ts[:19]

def build_timeline_event(
    case_id: int,
    timestamp: str,
    event_type: str,
    title: str,
    description: str,
    category: str,
    evidence_id: int = None,
    source_ref: str = None,
    icon: str = "clock"
) -> dict:
    """Creates a standardized timeline event entry."""
    norm_ts = normalize_timestamp(timestamp)
    if not norm_ts:
        norm_ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "timestamp": norm_ts,
        "event_type": event_type,
        "title": title,
        "description": description,
        "category": category,
        "source_ref": source_ref or f"Evidence #{evidence_id}" if evidence_id else "System Event",
        "icon": icon
    }
