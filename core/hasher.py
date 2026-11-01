import hashlib
import os

def calculate_hashes(file_input, chunk_size=65536):
    """
    Calculates MD5, SHA-1, and SHA-256 hashes for a given file path or byte stream.
    Returns a dictionary of hashes and verification status.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    if isinstance(file_input, (str, os.PathLike)):
        if not os.path.exists(file_input):
            return {
                "md5": "Error: File not found",
                "sha1": "Error: File not found",
                "sha256": "Error: File not found",
                "integrity_status": "FAILED",
                "error": f"File not found: {file_input}"
            }
        with open(file_input, "rb") as f:
            while chunk := f.read(chunk_size):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
    elif isinstance(file_input, (bytes, bytearray)):
        md5.update(file_input)
        sha1.update(file_input)
        sha256.update(file_input)
    else:
        # File-like object
        file_input.seek(0)
        while chunk := file_input.read(chunk_size):
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
        file_input.seek(0)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "integrity_status": "VERIFIED"
    }

def compare_hashes(hash_a: str, hash_b: str) -> dict:
    """
    Compares two hashes ignoring case and whitespace.
    """
    clean_a = (hash_a or "").strip().lower()
    clean_b = (hash_b or "").strip().lower()
    
    is_match = (clean_a == clean_b) and len(clean_a) > 0
    
    # Identify algorithm by length
    algo = "Unknown"
    if len(clean_a) == 32:
        algo = "MD5"
    elif len(clean_a) == 40:
        algo = "SHA-1"
    elif len(clean_a) == 64:
        algo = "SHA-256"
        
    return {
        "is_match": is_match,
        "algorithm": algo,
        "hash_a": clean_a,
        "hash_b": clean_b,
        "result_message": "MATCH: Cryptographic hashes are identical. Evidence integrity confirmed." if is_match else "MISMATCH: Cryptographic hashes do not match. Integrity cannot be verified."
    }
