import os
import re

SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".bat", ".ps1", ".vbs", ".hta", ".wsf", ".cpl"}
SUSPICIOUS_LOCATIONS = ["temp", "appdata", "local\\temp", "roaming", "startup", "recycle.bin", "/tmp", "/dev/shm", "/var/tmp"]
SUSPICIOUS_NAMES = ["update.exe", "svchost.exe", "lsass.exe", "taskhost.exe", "explorer.exe", "winlogon.exe", "csrss.exe", "powershell.exe"]

def evaluate_suspicious_artifact(evidence_data: dict, metadata: dict = None) -> dict:
    """
    Evaluates evidence attributes using explainable forensic rules.
    Returns:
      is_suspicious: bool
      risk_level: 'Critical', 'High', 'Medium', 'Low', or 'Clean'
      status_label: 'Potentially Suspicious', 'Requires Investigation', 'Review Recommended', or 'Normal'
      reasons: list of explainable reasons
      entropy: float
    """
    filename = (evidence_data.get("name") or evidence_data.get("original_filename") or "").lower()
    location = (evidence_data.get("original_location") or "").lower()
    category = evidence_data.get("category", "")
    entropy = metadata.get("entropy", 0.0) if metadata else 0.0
    
    reasons = []
    points = 0

    _, ext = os.path.splitext(filename)

    # 1. Double extension check (e.g. invoice.pdf.exe)
    if re.search(r'\.(pdf|doc|docx|xlsx|jpg|png|txt)\.(exe|scr|bat|vbs|ps1|hta)$', filename):
        reasons.append("Deceptive double-extension naming pattern (e.g. masquerading as a document/image)")
        points += 4

    # 2. Executable in user temporary / AppData location
    if ext in SUSPICIOUS_EXTENSIONS:
        if any(loc in location for loc in SUSPICIOUS_LOCATIONS):
            reasons.append(f"Executable artifact located in anomalous user directory ({location})")
            points += 3
        else:
            reasons.append(f"Executable / Script binary format ({ext})")
            points += 1

    # 3. Masquerading as critical system process in non-system directory
    base_name = os.path.basename(filename)
    if base_name in SUSPICIOUS_NAMES and not ("system32" in location or "syswow64" in location):
        reasons.append(f"System binary name '{base_name}' observed running outside official System32 hierarchy")
        points += 4

    # 4. High Shannon Entropy (> 7.2 indicates packing, obfuscation, or encryption)
    if entropy > 7.2:
        reasons.append(f"Elevated Shannon entropy ({entropy:.2f} / 8.0), indicating packing, code obfuscation, or encrypted payload")
        points += 3
    elif entropy > 6.5 and ext in SUSPICIOUS_EXTENSIONS:
        reasons.append(f"Above average entropy ({entropy:.2f}), suggesting compressed or embedded binary chunks")
        points += 1

    # 5. Suspicious API imports from PE header
    if metadata and "executable_metadata" in metadata:
        pe_meta = metadata["executable_metadata"]
        apis = pe_meta.get("Suspicious APIs Detected", "")
        if apis and apis != "None Flagged":
            reasons.append(f"Potentially sensitive Win32 API imports detected: {apis}")
            points += 3

    # 6. Script in unexpected category
    if ext in [".vbs", ".hta", ".ps1"] and any(loc in location for loc in ["downloads", "desktop", "temp"]):
        reasons.append(f"Active script file ({ext}) identified in user staging folder")
        points += 2

    # Determine risk level & forensic terminology
    if points >= 5:
        risk_level = "High"
        status_label = "Potentially Suspicious"
    elif points >= 3:
        risk_level = "Medium"
        status_label = "Requires Investigation"
    elif points >= 1:
        risk_level = "Low"
        status_label = "Review Recommended"
    else:
        risk_level = "Informational"
        status_label = "Normal"

    return {
        "is_suspicious": points >= 2,
        "risk_level": risk_level,
        "status_label": status_label,
        "reasons": reasons,
        "entropy": entropy
    }
