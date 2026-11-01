import sqlite3
from datetime import datetime

def log_custody_event(
    conn: sqlite3.Connection,
    case_id: int,
    evidence_id: int,
    action: str,
    performed_by: str,
    description: str,
    integrity_hash: str = None
):
    """
    Appends an immutable chain-of-custody entry for an evidence item.
    """
    cursor = conn.cursor()
    
    # If no integrity hash is explicitly passed, fetch the latest SHA-256
    if not integrity_hash:
        row = cursor.execute("SELECT sha256 FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        if row and row["sha256"]:
            integrity_hash = f"SHA-256: {row['sha256']}"
        else:
            integrity_hash = "Hash Pending Calculation"

    cursor.execute('''
        INSERT INTO chain_of_custody (case_id, evidence_id, action, performed_by, timestamp, description, integrity_hash)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
    ''', (case_id, evidence_id, action, performed_by, description, integrity_hash))

    # Also log to system audit trail
    cursor.execute('''
        INSERT INTO audit_logs (case_id, username, action, object_type, object_id, details, timestamp)
        VALUES (?, ?, ?, 'evidence', ?, ?, CURRENT_TIMESTAMP)
    ''', (case_id, performed_by, f"Custody: {action}", evidence_id, description))

    conn.commit()
