#!/usr/bin/env python3
"""
ForensiX — Digital Forensic Investigation & Evidence Analysis Platform
Launch script.
"""
import sys
import webbrowser
from app import app, init_db
from database import get_db
from sample_data import seed_sample_case

def main():
    print("=" * 70)
    print(" FORENSIX — Digital Forensic Investigation & Evidence Analysis Platform")
    print("=" * 70)
    
    # Initialize DB schema
    init_db()

    # Seed sample case if database is empty
    conn = get_db()
    case_count = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    if case_count == 0:
        print("[*] Initializing baseline forensic demonstration scenario FL-2026-001...")
        seed_sample_case(conn)
    conn.close()

    print("[+] Database verified and initialized.")
    print("[+] Evidence Vault directory: evidence_vault/")
    print("[+] Report output directory: evidence_vault/reports/")
    print("[+] Starting Web Console on http://127.0.0.1:5000 ...")
    print("[+] Default Investigator Credentials: investigator / forensix2026")
    print("=" * 70)

    # Launch browser automatically
    try:
        webbrowser.open_new_tab("http://127.0.0.1:5000")
    except Exception:
        pass

    app.run(host="127.0.0.1", port=5000, debug=False)

if __name__ == "__main__":
    main()
