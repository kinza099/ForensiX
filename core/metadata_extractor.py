import os
import math
import stat
import time
from datetime import datetime
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import pefile

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of byte data (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_file_metadata(file_path: str, filename: str) -> dict:
    """
    Extracts rich forensic metadata from any file.
    Distinguishes clearly between extracted metadata and 'Not Available' / 'Not Extracted'.
    """
    result = {
        "general": {},
        "timestamps": {},
        "image_metadata": {},
        "document_metadata": {},
        "executable_metadata": {},
        "entropy": 0.0,
        "is_entropy_high": False
    }

    exists = os.path.exists(file_path) if file_path else False

    name = filename or (os.path.basename(file_path) if file_path else "Unknown")
    _, ext = os.path.splitext(name)

    result["general"]["File Name"] = name
    result["general"]["File Extension"] = ext if ext else "None"

    if exists:
        try:
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            result["general"]["File Size"] = f"{file_size:,} bytes ({round(file_size / 1024, 2)} KB)"
            result["general"]["File Size (Bytes)"] = file_size

            # Timestamps
            result["timestamps"]["Created Time"] = datetime.fromtimestamp(file_stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S UTC")
            result["timestamps"]["Modified Time"] = datetime.fromtimestamp(file_stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S UTC")
            result["timestamps"]["Accessed Time"] = datetime.fromtimestamp(file_stat.st_atime).strftime("%Y-%m-%d %H:%M:%S UTC")

            # Permissions
            mode = file_stat.st_mode
            result["general"]["Permissions"] = stat.filemode(mode)

            # Read content for entropy and specialized parsers
            with open(file_path, "rb") as f:
                content = f.read(5 * 1024 * 1024) # read first 5MB for analysis
                result["entropy"] = calculate_shannon_entropy(content)
                result["is_entropy_high"] = result["entropy"] > 7.2

            # Specialized extractions
            lower_ext = ext.lower()

            # Image analysis (EXIF, Dimensions, GPS)
            if lower_ext in [".jpg", ".jpeg", ".png", ".tiff", ".bmp", ".webp"]:
                _extract_image_metadata(file_path, result)

            # Executable / PE Analysis (pefile)
            elif lower_ext in [".exe", ".dll", ".sys", ".scr"]:
                _extract_pe_metadata(file_path, result)

            # Document analysis
            elif lower_ext in [".docx", ".pdf", ".txt", ".csv", ".json", ".xlsx"]:
                _extract_document_metadata(file_path, lower_ext, result)

        except Exception as e:
            result["general"]["Analysis Notice"] = f"Partial extraction error: {str(e)}"
    else:
        result["general"]["File Size"] = "Not Available"
        result["timestamps"]["Created Time"] = "Not Available"
        result["timestamps"]["Modified Time"] = "Not Available"
        result["timestamps"]["Accessed Time"] = "Not Available"
        result["general"]["Permissions"] = "Not Available"

    return result

def _extract_image_metadata(file_path: str, result: dict):
    try:
        with Image.open(file_path) as img:
            result["image_metadata"]["Dimensions"] = f"{img.width} x {img.height} pixels"
            result["image_metadata"]["Format"] = img.format or "Not Available"
            result["image_metadata"]["Color Mode"] = img.mode or "Not Available"
            
            exif_data = img.getexif()
            if exif_data:
                camera_make = "Not Available"
                camera_model = "Not Available"
                date_time = "Not Available"
                software = "Not Available"
                
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    if tag_name == "Make":
                        camera_make = str(value).strip()
                    elif tag_name == "Model":
                        camera_model = str(value).strip()
                    elif tag_name == "DateTime":
                        date_time = str(value).strip()
                    elif tag_name == "Software":
                        software = str(value).strip()
                        
                result["image_metadata"]["Camera Make"] = camera_make
                result["image_metadata"]["Camera Model"] = camera_model
                result["image_metadata"]["EXIF Timestamp"] = date_time
                result["image_metadata"]["Software Used"] = software
                result["image_metadata"]["GPS Coordinates"] = "Not Present"
            else:
                result["image_metadata"]["Camera Make"] = "Not Available"
                result["image_metadata"]["Camera Model"] = "Not Available"
                result["image_metadata"]["EXIF Timestamp"] = "Not Available"
                result["image_metadata"]["GPS Coordinates"] = "Not Present"
    except Exception:
        result["image_metadata"]["Image Extraction"] = "Not Extracted (Unsupported format or corrupt)"

def _extract_pe_metadata(file_path: str, result: dict):
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories()

        # Architecture
        arch = "x86 (32-bit)"
        if pe.FILE_HEADER.Machine == 0x8664:
            arch = "x64 (64-bit)"
        elif pe.FILE_HEADER.Machine == 0x014c:
            arch = "i386 (32-bit)"
        elif pe.FILE_HEADER.Machine == 0xaa64:
            arch = "ARM64"

        result["executable_metadata"]["Target Architecture"] = arch
        
        # Compile Timestamp
        compile_time = pe.FILE_HEADER.TimeDateStamp
        try:
            dt = datetime.utcfromtimestamp(compile_time)
            result["executable_metadata"]["Compilation Timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            result["executable_metadata"]["Compilation Timestamp"] = f"Raw Epoch: {compile_time}"

        # Sections & section entropy
        sections_info = []
        for sec in pe.sections:
            sec_name = sec.Name.decode('utf-8', errors='ignore').strip('\x00')
            sec_entropy = round(sec.get_entropy(), 3)
            sec_size = sec.SizeOfRawData
            sections_info.append(f"{sec_name} (Size: {sec_size:,} B, Entropy: {sec_entropy})")
        result["executable_metadata"]["PE Sections"] = ", ".join(sections_info) if sections_info else "None"

        # Imported Suspicious Functions
        suspicious_apis = {
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "CreateRemoteThread",
            "WriteProcessMemory", "ReadProcessMemory", "OpenProcess", "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent", "WinExec", "ShellExecuteA", "URLDownloadToFileA",
            "HttpSendRequestA", "InternetReadFile", "SetWindowsHookExA", "GetAsyncKeyState"
        }
        found_suspicious_apis = []
        total_imports = 0

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    total_imports += 1
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        if func_name in suspicious_apis:
                            found_suspicious_apis.append(func_name)

        result["executable_metadata"]["Total Imported APIs"] = total_imports
        result["executable_metadata"]["Suspicious APIs Detected"] = ", ".join(set(found_suspicious_apis)) if found_suspicious_apis else "None Flagged"
        result["executable_metadata"]["Subsystem"] = pefile.subsystem_types.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown")
        pe.close()
    except Exception as e:
        result["executable_metadata"]["PE Analysis"] = f"Not Extracted: {str(e)}"

def _extract_document_metadata(file_path: str, ext: str, result: dict):
    result["document_metadata"]["Document Type"] = ext.upper().replace(".", "")
    result["document_metadata"]["Author"] = "Not Available"
    result["document_metadata"]["Application"] = "Not Available"
    result["document_metadata"]["Creation Date"] = "Not Available"
    result["document_metadata"]["Modification Date"] = "Not Available"

    if ext == ".docx":
        try:
            import docx
            doc = docx.Document(file_path)
            core_props = doc.core_properties
            if core_props.author:
                result["document_metadata"]["Author"] = core_props.author
            if core_props.created:
                result["document_metadata"]["Creation Date"] = str(core_props.created)
            if core_props.modified:
                result["document_metadata"]["Modification Date"] = str(core_props.modified)
            if core_props.title:
                result["document_metadata"]["Title"] = core_props.title
            result["document_metadata"]["Application"] = "Microsoft Word / Office OpenXML"
            result["document_metadata"]["Paragraph Count"] = len(doc.paragraphs)
        except Exception:
            pass
    elif ext == ".pdf":
        try:
            import pypdf
            reader = pypdf.PdfReader(file_path)
            meta = reader.metadata
            if meta:
                result["document_metadata"]["Author"] = meta.author or "Not Available"
                result["document_metadata"]["Application"] = meta.creator or meta.producer or "Not Available"
                result["document_metadata"]["Creation Date"] = str(meta.creation_date) if meta.creation_date else "Not Available"
                result["document_metadata"]["Modification Date"] = str(meta.modification_date) if meta.modification_date else "Not Available"
            result["document_metadata"]["Page Count"] = len(reader.pages)
        except Exception:
            pass
