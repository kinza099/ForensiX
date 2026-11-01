import sqlite3
import os
import hashlib
from datetime import datetime
from config import DATABASE_PATH, DEFAULT_INVESTIGATOR

def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def hash_password(password: str) -> str:
    salt = "forensix_salt_2026_"
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_number TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        investigator TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Open',
        priority TEXT NOT NULL DEFAULT 'Medium',
        category TEXT NOT NULL DEFAULT 'General Investigation',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_archived INTEGER DEFAULT 0,
        notes TEXT
    );

    CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        evidence_number TEXT NOT NULL,
        name TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        file_type TEXT,
        category TEXT NOT NULL DEFAULT 'Unknown',
        source TEXT,
        description TEXT,
        acquisition_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        original_location TEXT,
        file_size INTEGER DEFAULT 0,
        file_format TEXT,
        md5 TEXT,
        sha1 TEXT,
        sha256 TEXT,
        integrity_status TEXT DEFAULT 'VERIFIED',
        investigator TEXT NOT NULL,
        status TEXT DEFAULT 'Active',
        review_status TEXT DEFAULT 'Not Reviewed',
        file_path TEXT,
        is_demo INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS evidence_metadata (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id INTEGER NOT NULL,
        meta_key TEXT NOT NULL,
        meta_value TEXT NOT NULL,
        category TEXT DEFAULT 'General',
        FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS browser_artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        evidence_id INTEGER,
        timestamp TIMESTAMP,
        browser TEXT DEFAULT 'Chrome',
        artifact_type TEXT NOT NULL, -- History, Download, Bookmark, Cookie, Search
        url TEXT,
        domain TEXT,
        title TEXT,
        details TEXT,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS log_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        evidence_id INTEGER,
        timestamp TIMESTAMP,
        event_type TEXT NOT NULL,
        username TEXT,
        source_ip TEXT,
        dest_ip TEXT,
        status TEXT,
        message TEXT,
        severity TEXT DEFAULT 'Informational',
        suspicious_flag TEXT DEFAULT 'Normal', -- Potentially Suspicious, Requires Review, Notable Event
        flag_reason TEXT,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS suspicious_artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        evidence_id INTEGER NOT NULL,
        risk_level TEXT NOT NULL, -- Critical, High, Medium, Low
        reasons_json TEXT NOT NULL,
        entropy REAL DEFAULT 0.0,
        detection_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        evidence_id INTEGER,
        indicator_value TEXT NOT NULL,
        indicator_type TEXT NOT NULL, -- IP, Domain, URL, Hash, Email, Username, Filename
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        occurrence_count INTEGER DEFAULT 1,
        tags TEXT,
        notes TEXT,
        is_bookmarked INTEGER DEFAULT 0,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS timeline_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        evidence_id INTEGER,
        timestamp TIMESTAMP NOT NULL,
        event_type TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        category TEXT NOT NULL, -- File System, Authentication, Browser, Network, System, Investigation, Finding
        source_ref TEXT,
        icon TEXT,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        finding_number TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL, -- Informational, Low, Medium, High, Critical
        status TEXT DEFAULT 'Open', -- Open, Validated, Under Review, Closed
        investigator TEXT NOT NULL,
        explainable_basis TEXT,
        evidence_ids TEXT, -- JSON array of evidence ids
        indicator_ids TEXT, -- JSON array of indicator ids
        timeline_ids TEXT, -- JSON array of timeline ids
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        notes TEXT,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS tags (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        target_type TEXT NOT NULL, -- case, evidence, indicator, finding, timeline
        target_id INTEGER NOT NULL,
        tag_name TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        target_type TEXT NOT NULL, -- case, evidence, finding, indicator, timeline
        target_id INTEGER NOT NULL,
        author TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS chain_of_custody (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        evidence_id INTEGER NOT NULL,
        action TEXT NOT NULL, -- Evidence Added, Evidence Verified, Evidence Transferred, Evidence Analyzed, Evidence Reviewed, Evidence Included in Report
        performed_by TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        description TEXT,
        integrity_hash TEXT,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        object_type TEXT NOT NULL,
        object_id INTEGER,
        details TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS bookmarks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        target_type TEXT NOT NULL, -- evidence, indicator, finding, timeline
        target_id INTEGER NOT NULL,
        title TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS case_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        snapshot_json TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        report_number TEXT UNIQUE NOT NULL,
        file_path TEXT NOT NULL,
        generated_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );
    ''')

    # Seed default investigator account if not present
    cursor.execute("SELECT id FROM users WHERE username = ?", (DEFAULT_INVESTIGATOR["username"],))
    if not cursor.fetchone():
        cursor.execute('''
            INSERT INTO users (username, password_hash, full_name, role)
            VALUES (?, ?, ?, ?)
        ''', (
            DEFAULT_INVESTIGATOR["username"],
            hash_password(DEFAULT_INVESTIGATOR["password"]),
            DEFAULT_INVESTIGATOR["full_name"],
            DEFAULT_INVESTIGATOR["role"]
        ))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
