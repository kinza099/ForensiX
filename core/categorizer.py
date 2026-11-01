import os
import mimetypes

CATEGORY_MAPPING = {
    "Documents": [".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt", ".ods", ".txt", ".rtf", ".csv", ".md"],
    "Images": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".svg", ".ico", ".raw", ".cr2", ".nef"],
    "Videos": [".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".m4v"],
    "Archives": [".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz", ".iso", ".e01", ".vmdk", ".vhd"],
    "Executables": [".exe", ".dll", ".sys", ".bin", ".elf", ".so", ".dylib", ".com", ".scr", ".msi"],
    "Scripts": [".ps1", ".bat", ".cmd", ".vbs", ".sh", ".py", ".js", ".php", ".rb", ".pl", ".hta"],
    "Logs": [".log", ".evtx", ".audit", ".trace", ".err", ".out"],
    "Browser Artifacts": [".sqlite", ".db", ".history", ".cookies", ".bookmarks", ".json"],
    "System Files": [".registry", ".reg", ".dat", ".hive", ".lnk", ".pf", ".dmp", ".evtx"],
    "Configuration Files": [".ini", ".cfg", ".conf", ".yaml", ".yml", ".xml", ".properties", ".env"]
}

def categorize_file(filename: str, file_path: str = None) -> tuple[str, str]:
    """
    Returns (category, mime_type) for a given filename and optional file path.
    """
    _, ext = os.path.splitext(filename.lower())
    
    # MIME guess
    mime_type, _ = mimetypes.guess_type(filename)
    if not mime_type:
        mime_type = "application/octet-stream"

    # Specific names indicating categories
    lower_name = filename.lower()
    if "history" in lower_name or "browser" in lower_name or "download" in lower_name or "cookie" in lower_name:
        if ext in [".json", ".sqlite", ".db", ".csv", ".txt"]:
            return "Browser Artifacts", mime_type
            
    if "access.log" in lower_name or "error.log" in lower_name or "syslog" in lower_name or "eventlog" in lower_name:
        return "Logs", "text/plain"

    # Match by extension
    for category, extensions in CATEGORY_MAPPING.items():
        if ext in extensions:
            return category, mime_type

    # Header check if file exists
    if file_path and os.path.exists(file_path):
        try:
            with open(file_path, "rb") as f:
                header = f.read(16)
                if header.startswith(b"MZ"):
                    return "Executables", "application/x-dosexec"
                elif header.startswith(b"\x7fELF"):
                    return "Executables", "application/x-elf"
                elif header.startswith(b"%PDF"):
                    return "Documents", "application/pdf"
                elif header.startswith(b"PK\x03\x04"):
                    if ext in [".docx", ".xlsx", ".pptx"]:
                        return "Documents", mime_type
                    return "Archives", "application/zip"
                elif header.startswith(b"\x89PNG\r\n\x1a\n"):
                    return "Images", "image/png"
                elif header.startswith(b"\xff\xd8\xff"):
                    return "Images", "image/jpeg"
                elif header.startswith(b"SQLite format 3"):
                    return "Browser Artifacts", "application/x-sqlite3"
        except Exception:
            pass

    return "Unknown", mime_type
