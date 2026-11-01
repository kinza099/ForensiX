import os
import json
import sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template, send_file, session, g
from werkzeug.utils import secure_filename

import config
from database import get_db, init_db, hash_password
from sample_data import seed_sample_case
from core.hasher import calculate_hashes, compare_hashes
from core.categorizer import categorize_file
from core.metadata_extractor import extract_file_metadata
from core.suspicious_detector import evaluate_suspicious_artifact
from core.indicator_extractor import extract_indicators_from_text
from core.timeline_generator import build_timeline_event
from core.graph_builder import generate_case_graph
from core.chain_of_custody import log_custody_event
from core.report_generator import generate_pdf_report, generate_docx_report
from core.browser_analyzer import parse_browser_file
from core.log_analyzer import parse_log_file

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized. Please authenticate.", "authenticated": False}), 401
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    if 'user_id' in session:
        conn = get_db()
        user = conn.execute("SELECT id, username, full_name, role FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        conn.close()
        return dict(user) if user else None
    return None

def log_audit(case_id, action, object_type, object_id=None, details=""):
    username = session.get('username', 'System')
    try:
        conn = get_db()
        conn.execute('''
            INSERT INTO audit_logs (case_id, username, action, object_type, object_id, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (case_id, username, action, object_type, object_id, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging audit: {e}")

# ==========================================
# AUTHENTICATION ROUTES
# ==========================================

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if user and user['password_hash'] == hash_password(password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['full_name'] = user['full_name']
        session['role'] = user['role']
        log_audit(None, "User Login", "auth", user['id'], f"Successful login by {user['username']}")
        return jsonify({
            "success": True,
            "user": {
                "id": user['id'],
                "username": user['username'],
                "full_name": user['full_name'],
                "role": user['role']
            }
        })
    return jsonify({"error": "Invalid forensic investigator credentials"}), 401

@app.route('/api/logout', methods=['POST'])
def api_logout():
    user_id = session.get('user_id')
    username = session.get('username', 'Unknown')
    log_audit(None, "User Logout", "auth", user_id, f"Session terminated by {username}")
    session.clear()
    return jsonify({"success": True})

@app.route('/api/me', methods=['GET'])
def api_me():
    user = get_current_user()
    if user:
        return jsonify({"authenticated": True, "user": user})
    return jsonify({"authenticated": False, "user": None})

# ==========================================
# CASE MANAGEMENT ROUTES
# ==========================================

@app.route('/api/cases', methods=['GET'])
@login_required
def get_cases():
    status = request.args.get('status')
    priority = request.args.get('priority')
    search = request.args.get('search')
    include_archived = request.args.get('include_archived', 'false').lower() == 'true'

    query = "SELECT * FROM cases WHERE 1=1"
    params = []

    if not include_archived:
        query += " AND is_archived = 0"
    if status and status != 'All':
        query += " AND status = ?"
        params.append(status)
    if priority and priority != 'All':
        query += " AND priority = ?"
        params.append(priority)
    if search:
        query += " AND (case_number LIKE ? OR name LIKE ? OR description LIKE ? OR investigator LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term, term])

    query += " ORDER BY updated_at DESC"

    conn = get_db()
    rows = conn.execute(query, params).fetchall()

    cases = []
    for r in rows:
        c = dict(r)
        # Fetch counts
        cid = c['id']
        c['evidence_count'] = conn.execute("SELECT COUNT(*) FROM evidence WHERE case_id = ?", (cid,)).fetchone()[0]
        c['finding_count'] = conn.execute("SELECT COUNT(*) FROM findings WHERE case_id = ?", (cid,)).fetchone()[0]
        c['indicator_count'] = conn.execute("SELECT COUNT(*) FROM indicators WHERE case_id = ?", (cid,)).fetchone()[0]
        c['suspicious_count'] = conn.execute("SELECT COUNT(*) FROM suspicious_artifacts WHERE case_id = ?", (cid,)).fetchone()[0]
        c['timeline_count'] = conn.execute("SELECT COUNT(*) FROM timeline_events WHERE case_id = ?", (cid,)).fetchone()[0]
        cases.append(c)

    conn.close()
    return jsonify({"cases": cases})

@app.route('/api/cases', methods=['POST'])
@login_required
def create_case():
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({"error": "Case name is required"}), 400

    conn = get_db()
    # Generate unique case number
    count = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0] + 1
    case_num = data.get('case_number') or f"FL-2026-{count:03d}"

    investigator = data.get('investigator') or session.get('full_name', 'Investigator')
    description = data.get('description', '')
    priority = data.get('priority', 'Medium')
    category = data.get('category', 'General Digital Forensics')
    notes = data.get('notes', '')

    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO cases (case_number, name, description, investigator, status, priority, category, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'Open', ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    ''', (case_num, name, description, investigator, priority, category, notes))
    case_id = cursor.lastrowid

    # Create storage folder
    case_vault = os.path.join(config.RAW_VAULT_DIR, f"case_{case_id}")
    os.makedirs(case_vault, exist_ok=True)

    # Initial timeline event
    cursor.execute('''
        INSERT INTO timeline_events (case_id, timestamp, event_type, title, description, category, source_ref, icon)
        VALUES (?, CURRENT_TIMESTAMP, 'Case Created', ?, ?, 'Investigation', 'Case Initiation', 'folder-plus')
    ''', (case_id, f"Case {case_num} Initialized", f"Investigation launched by {investigator}"))

    conn.commit()
    conn.close()

    log_audit(case_id, "Case Created", "case", case_id, f"Created case {case_num}: {name}")
    return jsonify({"success": True, "case_id": case_id, "case_number": case_num})

@app.route('/api/cases/<int:case_id>', methods=['GET'])
@login_required
def get_case(case_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Case not found"}), 404

    c = dict(row)
    c['evidence_count'] = conn.execute("SELECT COUNT(*) FROM evidence WHERE case_id = ?", (case_id,)).fetchone()[0]
    c['analyzed_count'] = conn.execute("SELECT COUNT(*) FROM evidence WHERE case_id = ? AND review_status != 'Not Reviewed'", (case_id,)).fetchone()[0]
    c['suspicious_count'] = conn.execute("SELECT COUNT(*) FROM suspicious_artifacts WHERE case_id = ?", (case_id,)).fetchone()[0]
    c['indicator_count'] = conn.execute("SELECT COUNT(*) FROM indicators WHERE case_id = ?", (case_id,)).fetchone()[0]
    c['timeline_count'] = conn.execute("SELECT COUNT(*) FROM timeline_events WHERE case_id = ?", (case_id,)).fetchone()[0]
    c['finding_count'] = conn.execute("SELECT COUNT(*) FROM findings WHERE case_id = ?", (case_id,)).fetchone()[0]
    c['custody_count'] = conn.execute("SELECT COUNT(*) FROM chain_of_custody WHERE case_id = ?", (case_id,)).fetchone()[0]
    c['notes_count'] = conn.execute("SELECT COUNT(*) FROM notes WHERE case_id = ?", (case_id,)).fetchone()[0]

    # Calculate progress indicator
    ev_pct = 100 if c['evidence_count'] > 0 else 0
    an_pct = int((c['analyzed_count'] / c['evidence_count']) * 100) if c['evidence_count'] > 0 else 0
    tl_pct = 100 if c['timeline_count'] >= 10 else int((c['timeline_count'] / 10) * 100)
    rev_pct = 100 if c['finding_count'] >= 3 else int((c['finding_count'] / 3) * 100)
    rep_count = conn.execute("SELECT COUNT(*) FROM reports WHERE case_id = ?", (case_id,)).fetchone()[0]
    rep_pct = 100 if rep_count > 0 else 20

    c['progress'] = {
        "evidence_collection": ev_pct,
        "artifact_analysis": an_pct,
        "timeline_analysis": tl_pct,
        "investigation_review": rev_pct,
        "reporting": rep_pct
    }

    # Dynamic summary
    most_common_cat_row = conn.execute('''
        SELECT category, COUNT(*) as cnt FROM evidence WHERE case_id = ? GROUP BY category ORDER BY cnt DESC LIMIT 1
    ''', (case_id,)).fetchone()
    most_common_cat = most_common_cat_row['category'] if most_common_cat_row else "None"

    time_range = conn.execute('''
        SELECT MIN(timestamp) as min_ts, MAX(timestamp) as max_ts FROM timeline_events WHERE case_id = ?
    ''', (case_id,)).fetchone()

    c['dynamic_summary'] = {
        "most_common_category": most_common_cat,
        "activity_start": time_range['min_ts'] or "N/A",
        "activity_end": time_range['max_ts'] or "N/A"
    }

    conn.close()
    return jsonify({"case": c})

@app.route('/api/cases/<int:case_id>', methods=['PUT'])
@login_required
def update_case(case_id):
    data = request.get_json() or {}
    conn = get_db()
    cursor = conn.cursor()

    fields = []
    params = []
    for field in ['name', 'description', 'investigator', 'status', 'priority', 'category', 'notes', 'is_archived']:
        if field in data:
            fields.append(f"{field} = ?")
            params.append(data[field])

    if not fields:
        conn.close()
        return jsonify({"error": "No update fields provided"}), 400

    fields.append("updated_at = CURRENT_TIMESTAMP")
    params.append(case_id)

    cursor.execute(f"UPDATE cases SET {', '.join(fields)} WHERE id = ?", params)
    conn.commit()
    conn.close()

    log_audit(case_id, "Case Updated", "case", case_id, f"Updated case fields: {', '.join(data.keys())}")
    return jsonify({"success": True})

@app.route('/api/cases/<int:case_id>', methods=['DELETE'])
@login_required
def delete_case(case_id):
    conn = get_db()
    cursor = conn.cursor()
    case = cursor.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not case:
        conn.close()
        return jsonify({"error": "Case not found"}), 404

    case_num = case['case_number']
    case_name = case['name']

    # Delete case record; cascade removes related items
    cursor.execute("DELETE FROM cases WHERE id = ?", (case_id,))
    cursor.execute("DELETE FROM audit_logs WHERE case_id = ?", (case_id,))
    cursor.execute("DELETE FROM reports WHERE case_id = ?", (case_id,))
    conn.commit()

    # Clean up physical directory in vault
    case_vault = os.path.join(config.RAW_VAULT_DIR, f"case_{case_id}")
    if os.path.exists(case_vault):
        import shutil
        shutil.rmtree(case_vault, ignore_errors=True)

    # Next remaining case if any
    next_case = cursor.execute("SELECT id FROM cases ORDER BY updated_at DESC LIMIT 1").fetchone()
    next_id = next_case['id'] if next_case else None

    conn.close()
    return jsonify({
        "success": True,
        "deleted_case_id": case_id,
        "next_case_id": next_id,
        "message": f"Case {case_num} ({case_name}) was successfully removed."
    })

@app.route('/api/cases/seed-demo', methods=['POST'])
@login_required
def seed_demo_endpoint():
    conn = get_db()
    case_id = seed_sample_case(conn)
    conn.close()
    log_audit(case_id, "Demo Seeded", "case", case_id, "Seeded complete forensic demo case FL-2026-001")
    return jsonify({"success": True, "case_id": case_id, "message": "Demo case FL-2026-001 successfully initialized."})

# ==========================================
# EVIDENCE MANAGEMENT ROUTES
# ==========================================

@app.route('/api/cases/<int:case_id>/evidence', methods=['GET'])
@login_required
def get_evidence_list(case_id):
    category = request.args.get('category')
    review_status = request.args.get('review_status')
    search = request.args.get('search')

    query = "SELECT * FROM evidence WHERE case_id = ?"
    params = [case_id]

    if category and category != 'All':
        query += " AND category = ?"
        params.append(category)
    if review_status and review_status != 'All':
        query += " AND review_status = ?"
        params.append(review_status)
    if search:
        query += " AND (name LIKE ? OR description LIKE ? OR original_location LIKE ? OR sha256 LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term, term])

    query += " ORDER BY id ASC"

    conn = get_db()
    rows = conn.execute(query, params).fetchall()

    evidence_list = []
    for r in rows:
        item = dict(r)
        # Check if flagged suspicious
        susp = conn.execute("SELECT risk_level, reasons_json FROM suspicious_artifacts WHERE evidence_id = ?", (item['id'],)).fetchone()
        if susp:
            item['is_suspicious'] = True
            item['risk_level'] = susp['risk_level']
            item['suspicious_reasons'] = json.loads(susp['reasons_json'])
        else:
            item['is_suspicious'] = False
            item['risk_level'] = 'Normal'
            item['suspicious_reasons'] = []
        evidence_list.append(item)

    conn.close()
    return jsonify({"evidence": evidence_list})

@app.route('/api/cases/<int:case_id>/evidence/upload', methods=['POST'])
@login_required
def upload_evidence(case_id):
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error": "Empty filename"}), 400

    orig_name = uploaded_file.filename
    clean_name = secure_filename(orig_name) or "evidence_file.bin"

    conn = get_db()
    # Check case exists
    case = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not case:
        conn.close()
        return jsonify({"error": "Case not found"}), 404

    # Determine next evidence ID
    count = conn.execute("SELECT COUNT(*) FROM evidence WHERE case_id = ?", (case_id,)).fetchone()[0] + 1
    ev_num = f"EVD-{count:03d}"

    # Save to vault
    case_vault = os.path.join(config.RAW_VAULT_DIR, f"case_{case_id}")
    os.makedirs(case_vault, exist_ok=True)
    saved_path = os.path.join(case_vault, f"{ev_num}_{clean_name}")
    uploaded_file.save(saved_path)

    # Compute Hashes
    hashes = calculate_hashes(saved_path)
    file_size = os.path.getsize(saved_path)
    _, ext = os.path.splitext(clean_name)

    # Metadata & Category
    meta = extract_file_metadata(saved_path, clean_name)
    category_guess, mime_type = categorize_file(clean_name, saved_path)

    # Form parameters
    name = request.form.get('name') or orig_name
    source = request.form.get('source') or "Direct Forensic Import"
    original_location = request.form.get('original_location') or f"Acquired from upload stream ({orig_name})"
    description = request.form.get('description') or "Forensic evidence acquired for investigation."
    category = request.form.get('category') or category_guess
    investigator = session.get('full_name', case['investigator'])

    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO evidence (
            case_id, evidence_number, name, original_filename, file_type, category,
            source, description, acquisition_date, original_location, file_size,
            file_format, md5, sha1, sha256, integrity_status, investigator,
            status, review_status, file_path, is_demo, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?, 'Active', 'Not Reviewed', ?, 0, CURRENT_TIMESTAMP)
    ''', (
        case_id, ev_num, name, orig_name, mime_type, category, source, description,
        original_location, file_size, ext, hashes['md5'], hashes['sha1'], hashes['sha256'],
        investigator, saved_path
    ))
    evidence_id = cursor.lastrowid

    # Store metadata
    for k, v in meta['general'].items():
        cursor.execute("INSERT INTO evidence_metadata (evidence_id, meta_key, meta_value, category) VALUES (?, ?, ?, 'General')", (evidence_id, k, str(v)))
    for k, v in meta['timestamps'].items():
        cursor.execute("INSERT INTO evidence_metadata (evidence_id, meta_key, meta_value, category) VALUES (?, ?, ?, 'Timestamps')", (evidence_id, k, str(v)))
    for k, v in meta['image_metadata'].items():
        cursor.execute("INSERT INTO evidence_metadata (evidence_id, meta_key, meta_value, category) VALUES (?, ?, ?, 'Image/EXIF')", (evidence_id, k, str(v)))
    for k, v in meta['document_metadata'].items():
        cursor.execute("INSERT INTO evidence_metadata (evidence_id, meta_key, meta_value, category) VALUES (?, ?, ?, 'Document')", (evidence_id, k, str(v)))
    for k, v in meta['executable_metadata'].items():
        cursor.execute("INSERT INTO evidence_metadata (evidence_id, meta_key, meta_value, category) VALUES (?, ?, ?, 'Executable/PE')", (evidence_id, k, str(v)))

    # Evaluate suspiciousness
    susp = evaluate_suspicious_artifact({
        "name": name,
        "original_filename": orig_name,
        "original_location": original_location,
        "category": category
    }, meta)

    if susp['is_suspicious']:
        cursor.execute('''
            INSERT INTO suspicious_artifacts (case_id, evidence_id, risk_level, reasons_json, entropy, detection_timestamp)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (case_id, evidence_id, susp['risk_level'], json.dumps(susp['reasons']), susp['entropy']))

    # Chain of custody
    log_custody_event(conn, case_id, evidence_id, "Evidence Added", investigator, f"Acquired and hashed file {clean_name}", f"SHA-256: {hashes['sha256']}")
    log_custody_event(conn, case_id, evidence_id, "Evidence Verified", investigator, "Integrity baseline calculated and locked", f"SHA-256: {hashes['sha256']}")

    # Timeline event
    cursor.execute('''
        INSERT INTO timeline_events (case_id, evidence_id, timestamp, event_type, title, description, category, source_ref, icon)
        VALUES (?, ?, CURRENT_TIMESTAMP, 'Evidence Added', ?, ?, 'Investigation', ?, 'folder-plus')
    ''', (case_id, evidence_id, f"Evidence {ev_num} Added: {name}", f"Hash verified (SHA-256: {hashes['sha256'][:16]}...)", ev_num))

    # Automatic Parsing if Log or Browser
    if category == "Browser Artifacts":
        browser_records = parse_browser_file(saved_path, evidence_id, case_id)
        for b in browser_records:
            cursor.execute('''
                INSERT INTO browser_artifacts (case_id, evidence_id, timestamp, browser, artifact_type, url, domain, title, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (case_id, evidence_id, b['timestamp'], b['browser'], b['artifact_type'], b['url'], b['domain'], b['title'], b['details']))
            cursor.execute('''
                INSERT INTO timeline_events (case_id, evidence_id, timestamp, event_type, title, description, category, source_ref, icon)
                VALUES (?, ?, ?, 'Browser Activity', ?, ?, 'Browser', ?, 'compass')
            ''', (case_id, evidence_id, b['timestamp'], b['title'], b['url'], ev_num))

    elif category == "Logs":
        log_records = parse_log_file(saved_path, evidence_id, case_id)
        for l in log_records:
            cursor.execute('''
                INSERT INTO log_events (case_id, evidence_id, timestamp, event_type, username, source_ip, dest_ip, status, message, severity, suspicious_flag, flag_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (case_id, evidence_id, l['timestamp'], l['event_type'], l['username'], l['source_ip'], l['dest_ip'], l['status'], l['message'], l['severity'], l['suspicious_flag'], l['flag_reason']))
            cursor.execute('''
                INSERT INTO timeline_events (case_id, evidence_id, timestamp, event_type, title, description, category, source_ref, icon)
                VALUES (?, ?, ?, ?, ?, ?, 'System', ?, 'file-text')
            ''', (case_id, evidence_id, l['timestamp'], l['event_type'], l['message'][:100], ev_num))

    # Automatic Indicator Extraction for text/logs/browser
    try:
        with open(saved_path, 'r', encoding='utf-8', errors='ignore') as f:
            text_sample = f.read(500000) # Read up to 500KB
            iocs = extract_indicators_from_text(text_sample, evidence_id, case_id)
            for ioc in iocs:
                cursor.execute('''
                    INSERT INTO indicators (case_id, evidence_id, indicator_value, indicator_type, first_seen, last_seen, occurrence_count, tags, notes, is_bookmarked)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                ''', (case_id, evidence_id, ioc['indicator_value'], ioc['indicator_type'], ioc['first_seen'], ioc['last_seen'], ioc['occurrence_count'], ioc['tags'], ioc['notes']))
    except Exception:
        pass

    conn.commit()
    conn.close()

    log_audit(case_id, "Evidence Added", "evidence", evidence_id, f"Uploaded {name} ({ev_num})")
    return jsonify({
        "success": True,
        "evidence_id": evidence_id,
        "evidence_number": ev_num,
        "hashes": hashes
    })

@app.route('/api/evidence/<int:ev_id>', methods=['GET'])
@login_required
def get_evidence_details(ev_id):
    conn = get_db()
    ev_row = conn.execute("SELECT * FROM evidence WHERE id = ?", (ev_id,)).fetchone()
    if not ev_row:
        conn.close()
        return jsonify({"error": "Evidence not found"}), 404

    ev = dict(ev_row)

    # Metadata
    meta_rows = conn.execute("SELECT meta_key, meta_value, category FROM evidence_metadata WHERE evidence_id = ?", (ev_id,)).fetchall()
    ev['metadata'] = [dict(m) for m in meta_rows]

    # Suspicious heuristic record
    susp_row = conn.execute("SELECT * FROM suspicious_artifacts WHERE evidence_id = ?", (ev_id,)).fetchone()
    if susp_row:
        ev['suspicious_analysis'] = {
            "risk_level": susp_row['risk_level'],
            "entropy": susp_row['entropy'],
            "reasons": json.loads(susp_row['reasons_json']) if susp_row['reasons_json'] else []
        }
    else:
        ev['suspicious_analysis'] = None

    # Custody log
    custody_rows = conn.execute("SELECT * FROM chain_of_custody WHERE evidence_id = ? ORDER BY id ASC", (ev_id,)).fetchall()
    ev['custody_log'] = [dict(c) for c in custody_rows]

    # Associated indicators
    ind_rows = conn.execute("SELECT * FROM indicators WHERE evidence_id = ?", (ev_id,)).fetchall()
    ev['indicators'] = [dict(i) for i in ind_rows]

    # Associated timeline events
    tl_rows = conn.execute("SELECT * FROM timeline_events WHERE evidence_id = ? ORDER BY timestamp ASC", (ev_id,)).fetchall()
    ev['timeline_events'] = [dict(t) for t in tl_rows]

    # Preview text or hex
    ev['preview'] = {"type": "none", "content": ""}
    if ev['file_path'] and os.path.exists(ev['file_path']):
        try:
            with open(ev['file_path'], 'rb') as f:
                raw_bytes = f.read(4096) # first 4KB
            # Check if text
            try:
                text_content = raw_bytes.decode('utf-8')
                ev['preview'] = {"type": "text", "content": text_content[:2000]}
            except UnicodeDecodeError:
                # Format hex preview
                hex_dump = []
                for i in range(0, min(len(raw_bytes), 512), 16):
                    chunk = raw_bytes[i:i+16]
                    hex_str = " ".join(f"{b:02X}" for b in chunk)
                    ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                    hex_dump.append(f"{i:08X}  {hex_str:<48}  |{ascii_str}|")
                ev['preview'] = {"type": "hex", "content": "\n".join(hex_dump)}
        except Exception as e:
            ev['preview'] = {"type": "error", "content": f"Unable to generate preview: {str(e)}"}

    conn.close()
    return jsonify({"evidence": ev})

@app.route('/api/evidence/<int:ev_id>/verify', methods=['POST'])
@login_required
def verify_evidence_hash(ev_id):
    conn = get_db()
    ev = conn.execute("SELECT * FROM evidence WHERE id = ?", (ev_id,)).fetchone()
    if not ev:
        conn.close()
        return jsonify({"error": "Evidence not found"}), 404

    if not ev['file_path'] or not os.path.exists(ev['file_path']):
        conn.close()
        return jsonify({"error": "Original forensic file not present in vault", "integrity": "FAILED"}), 400

    calc = calculate_hashes(ev['file_path'])
    match = (calc['sha256'] == ev['sha256'])

    status = "VERIFIED" if match else "INTEGRITY_MISMATCH"
    conn.execute("UPDATE evidence SET integrity_status = ? WHERE id = ?", (status, ev_id))

    user = session.get('full_name', 'Investigator')
    log_custody_event(
        conn, ev['case_id'], ev_id, "Evidence Verified", user,
        f"Cryptographic integrity re-verification: {status}. SHA-256 match: {match}",
        f"SHA-256: {calc['sha256']}"
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "is_match": match,
        "integrity_status": status,
        "current_sha256": calc['sha256'],
        "stored_sha256": ev['sha256']
    })

@app.route('/api/evidence/compare-hashes', methods=['POST'])
@login_required
def compare_hashes_endpoint():
    data = request.get_json() or {}
    hash_a = data.get('hash_a', '')
    hash_b = data.get('hash_b', '')
    res = compare_hashes(hash_a, hash_b)
    return jsonify(res)

@app.route('/api/evidence/<int:ev_id>/review-status', methods=['PUT'])
@login_required
def update_review_status(ev_id):
    data = request.get_json() or {}
    new_status = data.get('review_status', 'Reviewed')

    conn = get_db()
    ev = conn.execute("SELECT * FROM evidence WHERE id = ?", (ev_id,)).fetchone()
    if not ev:
        conn.close()
        return jsonify({"error": "Evidence not found"}), 404

    conn.execute("UPDATE evidence SET review_status = ? WHERE id = ?", (new_status, ev_id))
    user = session.get('full_name', 'Investigator')
    log_custody_event(conn, ev['case_id'], ev_id, "Evidence Reviewed", user, f"Review state updated to {new_status}")
    conn.commit()
    conn.close()

    return jsonify({"success": True, "review_status": new_status})

# ==========================================
# BROWSER ARTIFACTS ROUTES
# ==========================================

@app.route('/api/cases/<int:case_id>/browser-artifacts', methods=['GET'])
@login_required
def get_browser_artifacts(case_id):
    artifact_type = request.args.get('type')
    browser = request.args.get('browser')
    domain = request.args.get('domain')
    search = request.args.get('search')

    query = "SELECT b.*, e.evidence_number FROM browser_artifacts b LEFT JOIN evidence e ON b.evidence_id = e.id WHERE b.case_id = ?"
    params = [case_id]

    if artifact_type and artifact_type != 'All':
        query += " AND b.artifact_type = ?"
        params.append(artifact_type)
    if browser and browser != 'All':
        query += " AND b.browser = ?"
        params.append(browser)
    if domain and domain != 'All':
        query += " AND b.domain LIKE ?"
        params.append(f"%{domain}%")
    if search:
        query += " AND (b.url LIKE ? OR b.title LIKE ? OR b.domain LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term])

    query += " ORDER BY b.timestamp DESC"

    conn = get_db()
    rows = conn.execute(query, params).fetchall()
    domains = conn.execute("SELECT DISTINCT domain FROM browser_artifacts WHERE case_id = ? AND domain != '' ORDER BY domain ASC", (case_id,)).fetchall()
    conn.close()

    return jsonify({
        "artifacts": [dict(r) for r in rows],
        "available_domains": [d['domain'] for d in domains]
    })

# ==========================================
# LOG ANALYSIS ROUTES
# ==========================================

@app.route('/api/cases/<int:case_id>/logs', methods=['GET'])
@login_required
def get_case_logs(case_id):
    flag = request.args.get('flag')
    severity = request.args.get('severity')
    search = request.args.get('search')

    query = "SELECT l.*, e.evidence_number FROM log_events l LEFT JOIN evidence e ON l.evidence_id = e.id WHERE l.case_id = ?"
    params = [case_id]

    if flag and flag != 'All':
        query += " AND l.suspicious_flag = ?"
        params.append(flag)
    if severity and severity != 'All':
        query += " AND l.severity = ?"
        params.append(severity)
    if search:
        query += " AND (l.message LIKE ? OR l.username LIKE ? OR l.source_ip LIKE ? OR l.event_type LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term, term])

    query += " ORDER BY l.timestamp DESC"

    conn = get_db()
    rows = conn.execute(query, params).fetchall()
    conn.close()

    return jsonify({"logs": [dict(r) for r in rows]})

# ==========================================
# SUSPICIOUS ARTIFACTS ROUTES
# ==========================================

@app.route('/api/cases/<int:case_id>/suspicious-artifacts', methods=['GET'])
@login_required
def get_suspicious_artifacts(case_id):
    conn = get_db()
    query = '''
        SELECT s.*, e.evidence_number, e.name, e.original_location, e.file_size, e.category, e.sha256, e.review_status
        FROM suspicious_artifacts s
        JOIN evidence e ON s.evidence_id = e.id
        WHERE s.case_id = ?
        ORDER BY CASE s.risk_level
            WHEN 'Critical' THEN 1
            WHEN 'High' THEN 2
            WHEN 'Medium' THEN 3
            ELSE 4 END
    '''
    rows = conn.execute(query, (case_id,)).fetchall()
    conn.close()

    result = []
    for r in rows:
        item = dict(r)
        item['reasons'] = json.loads(item['reasons_json']) if item['reasons_json'] else []
        result.append(item)

    return jsonify({"suspicious_artifacts": result})

# ==========================================
# INDICATORS OF INTEREST ROUTES
# ==========================================

@app.route('/api/cases/<int:case_id>/indicators', methods=['GET'])
@login_required
def get_indicators(case_id):
    ind_type = request.args.get('type')
    bookmarked = request.args.get('bookmarked')
    search = request.args.get('search')

    query = "SELECT i.*, e.evidence_number, e.name as evidence_name FROM indicators i LEFT JOIN evidence e ON i.evidence_id = e.id WHERE i.case_id = ?"
    params = [case_id]

    if ind_type and ind_type != 'All':
        query += " AND i.indicator_type = ?"
        params.append(ind_type)
    if bookmarked == 'true':
        query += " AND i.is_bookmarked = 1"
    if search:
        query += " AND (i.indicator_value LIKE ? OR i.tags LIKE ? OR i.notes LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term])

    query += " ORDER BY i.occurrence_count DESC, i.id ASC"

    conn = get_db()
    rows = conn.execute(query, params).fetchall()
    conn.close()

    return jsonify({"indicators": [dict(r) for r in rows]})

@app.route('/api/indicators/<int:ind_id>/bookmark', methods=['POST'])
@login_required
def toggle_indicator_bookmark(ind_id):
    conn = get_db()
    row = conn.execute("SELECT is_bookmarked FROM indicators WHERE id = ?", (ind_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Indicator not found"}), 404

    new_val = 0 if row['is_bookmarked'] == 1 else 1
    conn.execute("UPDATE indicators SET is_bookmarked = ? WHERE id = ?", (new_val, ind_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "is_bookmarked": new_val})

# ==========================================
# TIMELINE ROUTES
# ==========================================

@app.route('/api/cases/<int:case_id>/timeline', methods=['GET'])
@login_required
def get_timeline(case_id):
    category = request.args.get('category')
    search = request.args.get('search')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = "SELECT t.*, e.evidence_number FROM timeline_events t LEFT JOIN evidence e ON t.evidence_id = e.id WHERE t.case_id = ?"
    params = [case_id]

    if category and category != 'All':
        query += " AND t.category = ?"
        params.append(category)
    if start_date:
        query += " AND t.timestamp >= ?"
        params.append(start_date)
    if end_date:
        query += " AND t.timestamp <= ?"
        params.append(end_date)
    if search:
        query += " AND (t.title LIKE ? OR t.description LIKE ? OR t.event_type LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term])

    query += " ORDER BY t.timestamp ASC"

    conn = get_db()
    rows = conn.execute(query, params).fetchall()
    conn.close()

    return jsonify({"events": [dict(r) for r in rows]})

# ==========================================
# RELATIONSHIP GRAPH ROUTE
# ==========================================

@app.route('/api/cases/<int:case_id>/graph', methods=['GET'])
@login_required
def get_graph(case_id):
    conn = get_db()
    graph_data = generate_case_graph(conn, case_id)
    conn.close()
    return jsonify(graph_data)

# ==========================================
# VISUALIZATION DASHBOARD STATS
# ==========================================

@app.route('/api/cases/<int:case_id>/visualization', methods=['GET'])
@login_required
def get_visualization_stats(case_id):
    conn = get_db()

    # 1. Evidence Category Distribution
    cat_rows = conn.execute('''
        SELECT category, COUNT(*) as count FROM evidence WHERE case_id = ? GROUP BY category ORDER BY count DESC
    ''', (case_id,)).fetchall()
    cat_dist = {r['category']: r['count'] for r in cat_rows}

    # 2. Activity Over Time (Grouped by Date/Hour)
    activity_rows = conn.execute('''
        SELECT substr(timestamp, 1, 13) as hour_slot, COUNT(*) as count
        FROM timeline_events WHERE case_id = ?
        GROUP BY hour_slot ORDER BY hour_slot ASC LIMIT 24
    ''', (case_id,)).fetchall()
    activity_over_time = [{"slot": r['hour_slot'], "count": r['count']} for r in activity_rows]

    # 3. Indicator Type Distribution
    ind_rows = conn.execute('''
        SELECT indicator_type, COUNT(*) as count FROM indicators WHERE case_id = ? GROUP BY indicator_type ORDER BY count DESC
    ''', (case_id,)).fetchall()
    ind_dist = {r['indicator_type']: r['count'] for r in ind_rows}

    # 4. Evidence Review / Integrity Status
    status_rows = conn.execute('''
        SELECT review_status, COUNT(*) as count FROM evidence WHERE case_id = ? GROUP BY review_status
    ''', (case_id,)).fetchall()
    review_dist = {r['review_status']: r['count'] for r in status_rows}

    # 5. Timeline Categories
    tl_cat_rows = conn.execute('''
        SELECT category, COUNT(*) as count FROM timeline_events WHERE case_id = ? GROUP BY category
    ''', (case_id,)).fetchall()
    tl_cats = {r['category']: r['count'] for r in tl_cat_rows}

    conn.close()

    return jsonify({
        "evidence_categories": cat_dist,
        "activity_over_time": activity_over_time,
        "indicator_distribution": ind_dist,
        "review_status": review_dist,
        "timeline_categories": tl_cats
    })

# ==========================================
# FINDINGS MANAGEMENT ROUTES
# ==========================================

@app.route('/api/cases/<int:case_id>/findings', methods=['GET'])
@login_required
def get_findings(case_id):
    conn = get_db()
    rows = conn.execute("SELECT * FROM findings WHERE case_id = ? ORDER BY id ASC", (case_id,)).fetchall()
    conn.close()

    findings = []
    for r in rows:
        f = dict(r)
        f['evidence_ids'] = json.loads(f['evidence_ids']) if f['evidence_ids'] else []
        f['indicator_ids'] = json.loads(f['indicator_ids']) if f['indicator_ids'] else []
        findings.append(f)

    return jsonify({"findings": findings})

@app.route('/api/cases/<int:case_id>/findings', methods=['POST'])
@login_required
def create_finding(case_id):
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    if not title:
        return jsonify({"error": "Finding title is required"}), 400

    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM findings WHERE case_id = ?", (case_id,)).fetchone()[0] + 1
    finding_num = f"FND-{count:03d}"

    description = data.get('description', '')
    severity = data.get('severity', 'Medium')
    explainable_basis = data.get('explainable_basis', '')
    investigator = session.get('full_name', 'Investigator')
    evidence_ids = json.dumps(data.get('evidence_ids', []))
    indicator_ids = json.dumps(data.get('indicator_ids', []))

    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO findings (case_id, finding_number, title, description, severity, status, investigator, explainable_basis, evidence_ids, indicator_ids, timeline_ids, created_at)
        VALUES (?, ?, ?, ?, ?, 'Open', ?, ?, ?, ?, '[]', CURRENT_TIMESTAMP)
    ''', (case_id, finding_num, title, description, severity, investigator, explainable_basis, evidence_ids, indicator_ids))
    finding_id = cursor.lastrowid

    # Add timeline event
    cursor.execute('''
        INSERT INTO timeline_events (case_id, timestamp, event_type, title, description, category, source_ref, icon)
        VALUES (?, CURRENT_TIMESTAMP, 'Finding Logged', ?, ?, 'Investigation', ?, 'alert-octagon')
    ''', (case_id, f"Finding {finding_num}: {title}", f"Severity: {severity}", finding_num))

    conn.commit()
    conn.close()

    log_audit(case_id, "Finding Created", "finding", finding_id, f"Logged {finding_num}: {title}")
    return jsonify({"success": True, "finding_id": finding_id, "finding_number": finding_num})

@app.route('/api/findings/<int:finding_id>', methods=['PUT'])
@login_required
def update_finding(finding_id):
    data = request.get_json() or {}
    conn = get_db()
    cursor = conn.cursor()

    fields = []
    params = []
    for k in ['title', 'description', 'severity', 'status', 'explainable_basis', 'notes']:
        if k in data:
            fields.append(f"{k} = ?")
            params.append(data[k])

    if not fields:
        conn.close()
        return jsonify({"error": "No update fields"}), 400

    params.append(finding_id)
    cursor.execute(f"UPDATE findings SET {', '.join(fields)} WHERE id = ?", params)
    conn.commit()
    conn.close()

    return jsonify({"success": True})

# ==========================================
# NOTES & TAGS ROUTES
# ==========================================

@app.route('/api/notes', methods=['GET'])
@login_required
def get_notes():
    target_type = request.args.get('target_type')
    target_id = request.args.get('target_id')
    case_id = request.args.get('case_id')

    conn = get_db()
    if target_type and target_id:
        rows = conn.execute("SELECT * FROM notes WHERE target_type = ? AND target_id = ? ORDER BY created_at DESC", (target_type, target_id)).fetchall()
    elif case_id:
        rows = conn.execute("SELECT * FROM notes WHERE case_id = ? ORDER BY created_at DESC", (case_id,)).fetchall()
    else:
        rows = []
    conn.close()

    return jsonify({"notes": [dict(r) for r in rows]})

@app.route('/api/notes', methods=['POST'])
@login_required
def add_note():
    data = request.get_json() or {}
    case_id = data.get('case_id')
    target_type = data.get('target_type', 'case')
    target_id = data.get('target_id', case_id)
    content = data.get('content', '').strip()
    author = session.get('full_name', 'Investigator')

    if not content:
        return jsonify({"error": "Note content cannot be empty"}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO notes (case_id, target_type, target_id, author, content, created_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ''', (case_id, target_type, target_id, author, content))
    note_id = cursor.lastrowid
    conn.commit()
    conn.close()

    log_audit(case_id, "Note Added", target_type, target_id, f"Added note by {author}")
    return jsonify({"success": True, "note_id": note_id})

@app.route('/api/tags', methods=['GET'])
@login_required
def get_tags():
    case_id = request.args.get('case_id')
    target_type = request.args.get('target_type')
    target_id = request.args.get('target_id')

    query = "SELECT * FROM tags WHERE 1=1"
    params = []
    if case_id:
        query += " AND case_id = ?"
        params.append(case_id)
    if target_type and target_id:
        query += " AND target_type = ? AND target_id = ?"
        params.extend([target_type, target_id])

    conn = get_db()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify({"tags": [dict(r) for r in rows]})

@app.route('/api/tags', methods=['POST'])
@login_required
def add_tag():
    data = request.get_json() or {}
    case_id = data.get('case_id')
    target_type = data.get('target_type')
    target_id = data.get('target_id')
    tag_name = data.get('tag_name', '').strip()

    if not tag_name:
        return jsonify({"error": "Tag name required"}), 400

    conn = get_db()
    conn.execute('''
        INSERT INTO tags (case_id, target_type, target_id, tag_name)
        VALUES (?, ?, ?, ?)
    ''', (case_id, target_type, target_id, tag_name))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

# ==========================================
# CHAIN OF CUSTODY & AUDIT TRAILS
# ==========================================

@app.route('/api/cases/<int:case_id>/chain-of-custody', methods=['GET'])
@login_required
def get_case_custody(case_id):
    conn = get_db()
    rows = conn.execute('''
        SELECT c.*, e.evidence_number, e.name as evidence_name
        FROM chain_of_custody c
        JOIN evidence e ON c.evidence_id = e.id
        WHERE c.case_id = ?
        ORDER BY c.id ASC
    ''', (case_id,)).fetchall()
    conn.close()
    return jsonify({"custody_log": [dict(r) for r in rows]})

@app.route('/api/cases/<int:case_id>/audit-logs', methods=['GET'])
@login_required
def get_case_audit_logs(case_id):
    conn = get_db()
    rows = conn.execute('''
        SELECT * FROM audit_logs WHERE case_id = ? ORDER BY timestamp DESC LIMIT 50
    ''', (case_id,)).fetchall()
    conn.close()
    return jsonify({"audit_logs": [dict(r) for r in rows]})

# ==========================================
# CASE SNAPSHOTS & BOOKMARKS
# ==========================================

@app.route('/api/cases/<int:case_id>/snapshots', methods=['GET'])
@login_required
def get_snapshots(case_id):
    conn = get_db()
    rows = conn.execute("SELECT id, title, created_by, created_at FROM case_snapshots WHERE case_id = ? ORDER BY created_at DESC", (case_id,)).fetchall()
    conn.close()
    return jsonify({"snapshots": [dict(r) for r in rows]})

@app.route('/api/cases/<int:case_id>/snapshots', methods=['POST'])
@login_required
def create_snapshot(case_id):
    data = request.get_json() or {}
    title = data.get('title') or f"Snapshot {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"
    user = session.get('full_name', 'Investigator')

    conn = get_db()
    # Gather snapshot data
    case = dict(conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone())
    findings = [dict(r) for r in conn.execute("SELECT * FROM findings WHERE case_id = ?", (case_id,)).fetchall()]
    ev_count = conn.execute("SELECT COUNT(*) FROM evidence WHERE case_id = ?", (case_id,)).fetchone()[0]
    ind_count = conn.execute("SELECT COUNT(*) FROM indicators WHERE case_id = ?", (case_id,)).fetchone()[0]

    snapshot_payload = {
        "case": case,
        "findings": findings,
        "evidence_count": ev_count,
        "indicator_count": ind_count,
        "created_at": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    }

    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO case_snapshots (case_id, title, snapshot_json, created_by, created_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ''', (case_id, title, json.dumps(snapshot_payload), user))
    snap_id = cursor.lastrowid
    conn.commit()
    conn.close()

    log_audit(case_id, "Snapshot Created", "snapshot", snap_id, f"Created investigation snapshot: {title}")
    return jsonify({"success": True, "snapshot_id": snap_id})

# ==========================================
# REPORT GENERATION & DOWNLOAD
# ==========================================

@app.route('/api/cases/<int:case_id>/reports', methods=['GET'])
@login_required
def get_reports(case_id):
    conn = get_db()
    rows = conn.execute("SELECT * FROM reports WHERE case_id = ? ORDER BY created_at DESC", (case_id,)).fetchall()
    conn.close()
    return jsonify({"reports": [dict(r) for r in rows]})

@app.route('/api/cases/<int:case_id>/reports/generate', methods=['POST'])
@login_required
def generate_report_endpoint(case_id):
    user = session.get('full_name', 'Investigator').strip().title() or 'Investigator'
    conn = get_db()
    try:
        pdf_path = generate_pdf_report(conn, case_id, user)
        # Log to chain of custody
        ev_rows = conn.execute("SELECT id FROM evidence WHERE case_id = ?", (case_id,)).fetchall()
        for ev in ev_rows:
            log_custody_event(conn, case_id, ev['id'], "Evidence Included in Report", user, f"Evidence item incorporated into official forensic report")

        log_audit(case_id, "Report Generated", "report", case_id, f"Generated official PDF report by {user}")
        conn.close()
        return jsonify({"success": True, "message": "Forensic PDF report generated successfully."})
    except Exception as e:
        conn.close()
        return jsonify({"error": f"Report generation failed: {str(e)}"}), 500

@app.route('/api/reports/<int:report_id>/download', methods=['GET'])
@login_required
def download_report(report_id):
    conn = get_db()
    rep = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    conn.close()

    if not rep or not os.path.exists(rep['file_path']):
        return jsonify({"error": "Report PDF not found"}), 404

    return send_file(rep['file_path'], as_attachment=True, download_name=f"{rep['report_number']}.pdf", mimetype="application/pdf")



@app.route('/api/cases/<int:case_id>/reports/generate/docx', methods=['POST'])
@login_required
def generate_docx_endpoint(case_id):
    user = session.get('full_name', 'Investigator').strip().title() or 'Investigator'
    conn = get_db()
    try:
        docx_path = generate_docx_report(conn, case_id, user)
        log_audit(case_id, "DOCX Report Generated", "report", case_id, f"Generated DOCX report by {user}")
        conn.close()
        return jsonify({"success": True, "message": "Word report generated successfully."})
    except Exception as e:
        conn.close()
        return jsonify({"error": f"DOCX generation failed: {str(e)}"}), 500

@app.route('/api/reports/<int:report_id>/download/docx', methods=['GET'])
@login_required
def download_docx_report(report_id):
    conn = get_db()
    rep = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    conn.close()
    docx_path = rep['file_path'].replace('.pdf', '.docx') if rep else None
    if not rep or not docx_path or not os.path.exists(docx_path):
        return jsonify({"error": "DOCX report not found — generate it first"}), 404
    return send_file(docx_path, as_attachment=True, download_name=f"{rep['report_number']}.docx",
                     mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document")

@app.route('/api/cases/<int:case_id>/export/json', methods=['GET'])
@login_required
def export_case_json(case_id):
    conn = get_db()
    case = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not case:
        conn.close()
        return jsonify({"error": "Case not found"}), 404
    evidence = [dict(r) for r in conn.execute("SELECT * FROM evidence WHERE case_id = ?", (case_id,)).fetchall()]
    findings = [dict(r) for r in conn.execute("SELECT * FROM findings WHERE case_id = ?", (case_id,)).fetchall()]
    indicators = [dict(r) for r in conn.execute("SELECT * FROM indicators WHERE case_id = ?", (case_id,)).fetchall()]
    timeline = [dict(r) for r in conn.execute("SELECT * FROM timeline_events WHERE case_id = ?", (case_id,)).fetchall()]
    suspicious = [dict(r) for r in conn.execute("SELECT * FROM suspicious_artifacts WHERE case_id = ?", (case_id,)).fetchall()]
    conn.close()
    payload = {
        "case": dict(case),
        "evidence": evidence,
        "findings": findings,
        "indicators": indicators,
        "timeline": timeline,
        "suspicious_artifacts": suspicious,
        "exported_at": datetime.utcnow().isoformat() + "Z"
    }
    import json as _json
    response = app.response_class(
        response=_json.dumps(payload, indent=2, default=str),
        status=200,
        mimetype='application/json'
    )
    response.headers['Content-Disposition'] = f'attachment; filename=case_{case_id}_export.json'
    return response

@app.route('/api/cases/<int:case_id>/export/csv', methods=['GET'])
@login_required
def export_case_csv(case_id):
    import csv, io
    conn = get_db()
    evidence = conn.execute("SELECT * FROM evidence WHERE case_id = ?", (case_id,)).fetchall()
    conn.close()
    output = io.StringIO()
    if evidence:
        writer = csv.DictWriter(output, fieldnames=evidence[0].keys())
        writer.writeheader()
        for row in evidence:
            writer.writerow(dict(row))
    response = app.response_class(
        response=output.getvalue(),
        status=200,
        mimetype='text/csv'
    )
    response.headers['Content-Disposition'] = f'attachment; filename=case_{case_id}_evidence.csv'
    return response

# ==========================================
# GLOBAL SEARCH
# ==========================================

@app.route('/api/search', methods=['GET'])
@login_required
def global_search():
    q = request.args.get('q', '').strip()
    if not q or len(q) < 2:
        return jsonify({"results": []})

    term = f"%{q}%"
    conn = get_db()

    results = []

    # Cases
    case_rows = conn.execute('''
        SELECT id, case_number, name, investigator FROM cases
        WHERE case_number LIKE ? OR name LIKE ? OR description LIKE ? LIMIT 5
    ''', (term, term, term)).fetchall()
    for c in case_rows:
        results.append({
            "type": "Case",
            "title": f"[{c['case_number']}] {c['name']}",
            "subtitle": f"Lead: {c['investigator']}",
            "target": f"case_{c['id']}",
            "case_id": c['id']
        })

    # Evidence
    ev_rows = conn.execute('''
        SELECT id, case_id, evidence_number, name, sha256 FROM evidence
        WHERE name LIKE ? OR original_filename LIKE ? OR sha256 LIKE ? OR md5 LIKE ? LIMIT 8
    ''', (term, term, term, term)).fetchall()
    for e in ev_rows:
        results.append({
            "type": "Evidence",
            "title": f"[{e['evidence_number']}] {e['name']}",
            "subtitle": f"SHA-256: {e['sha256'][:16]}...",
            "target": f"evidence_{e['id']}",
            "case_id": e['case_id']
        })

    # Indicators
    ind_rows = conn.execute('''
        SELECT id, case_id, indicator_value, indicator_type FROM indicators
        WHERE indicator_value LIKE ? OR tags LIKE ? LIMIT 8
    ''', (term, term)).fetchall()
    for ind in ind_rows:
        results.append({
            "type": "Indicator",
            "title": ind['indicator_value'],
            "subtitle": f"Type: {ind['indicator_type']}",
            "target": f"indicator_{ind['id']}",
            "case_id": ind['case_id']
        })

    # Findings
    find_rows = conn.execute('''
        SELECT id, case_id, finding_number, title, severity FROM findings
        WHERE title LIKE ? OR description LIKE ? LIMIT 5
    ''', (term, term)).fetchall()
    for f in find_rows:
        results.append({
            "type": "Finding",
            "title": f"[{f['finding_number']}] {f['title']}",
            "subtitle": f"Severity: {f['severity']}",
            "target": f"finding_{f['id']}",
            "case_id": f['case_id']
        })

    # Timeline events
    tl_rows = conn.execute('''
        SELECT id, case_id, timestamp, title, category FROM timeline_events
        WHERE title LIKE ? OR description LIKE ? LIMIT 5
    ''', (term, term)).fetchall()
    for tl in tl_rows:
        results.append({
            "type": "Timeline",
            "title": tl['title'],
            "subtitle": f"{tl['timestamp']} ({tl['category']})",
            "target": f"timeline_{tl['id']}",
            "case_id": tl['case_id']
        })

    conn.close()
    return jsonify({"results": results})

# ==========================================
# ROOT APPLICATION ROUTE
# ==========================================

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    init_db()
    # If no cases exist, automatically seed demo case
    conn = get_db()
    if conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 0:
        seed_sample_case(conn)
    conn.close()
    print("ForensiX Platform running at http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)
