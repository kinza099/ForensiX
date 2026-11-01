import sqlite3

def generate_case_graph(conn: sqlite3.Connection, case_id: int) -> dict:
    """
    Builds a comprehensive relationship graph for the case connecting:
    Cases -> Evidence -> Hashes -> Domains -> IPs -> Users -> Findings -> Timeline Events.
    """
    nodes = []
    edges = []
    node_set = set()
    edge_set = set()

    def add_node(node_id: str, label: str, node_type: str, details: dict = None, severity: str = "Informational"):
        if node_id not in node_set:
            node_set.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,
                "severity": severity,
                "details": details or {}
            })

    def add_edge(source_id: str, target_id: str, relation: str):
        edge_key = f"{source_id}->{target_id}:{relation}"
        if edge_key not in edge_set and source_id in node_set and target_id in node_set:
            edge_set.add(edge_key)
            edges.append({
                "source": source_id,
                "target": target_id,
                "label": relation
            })

    cursor = conn.cursor()

    # 1. Case Root Node
    case_row = cursor.execute("SELECT id, case_number, name, investigator, status, priority FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not case_row:
        return {"nodes": [], "edges": []}

    case_node_id = f"case_{case_id}"
    add_node(case_node_id, f"Case {case_row['case_number']}", "case", {
        "Name": case_row["name"],
        "Investigator": case_row["investigator"],
        "Status": case_row["status"],
        "Priority": case_row["priority"]
    }, severity=case_row["priority"])

    # 2. Evidence Nodes & Hashes
    evidence_rows = cursor.execute('''
        SELECT id, evidence_number, name, category, original_location, file_size, md5, sha256, review_status
        FROM evidence WHERE case_id = ?
    ''', (case_id,)).fetchall()

    hash_to_evidence = {}
    for ev in evidence_rows:
        ev_node_id = f"ev_{ev['id']}"
        add_node(ev_node_id, ev["name"], "evidence", {
            "Evidence ID": ev["evidence_number"],
            "Category": ev["category"],
            "Location": ev["original_location"],
            "Size": f"{ev['file_size']:,} bytes",
            "SHA-256": ev["sha256"],
            "Review Status": ev["review_status"]
        })
        add_edge(case_node_id, ev_node_id, "CONTAINS_EVIDENCE")

        # SHA-256 node
        if ev["sha256"] and len(ev["sha256"]) == 64:
            hash_short = ev["sha256"][:12] + "..."
            hash_node_id = f"hash_{ev['sha256']}"
            add_node(hash_node_id, f"SHA256: {hash_short}", "hash", {
                "Full SHA-256": ev["sha256"],
                "Source File": ev["name"]
            })
            add_edge(ev_node_id, hash_node_id, "HAS_HASH")
            
            # Cross-correlation
            if ev["sha256"] not in hash_to_evidence:
                hash_to_evidence[ev["sha256"]] = []
            hash_to_evidence[ev["sha256"]].append(ev_node_id)

    # Correlate shared hashes
    for sha, ev_ids in hash_to_evidence.items():
        if len(ev_ids) > 1:
            for i in range(len(ev_ids)):
                for j in range(i + 1, len(ev_ids)):
                    add_edge(ev_ids[i], ev_ids[j], "IDENTICAL_HASH")

    # 3. Indicators
    indicators = cursor.execute('''
        SELECT id, evidence_id, indicator_value, indicator_type, occurrence_count, tags, notes
        FROM indicators WHERE case_id = ?
    ''', (case_id,)).fetchall()

    for ind in indicators:
        ind_node_id = f"ind_{ind['id']}"
        val_display = ind["indicator_value"]
        if len(val_display) > 28:
            val_display = val_display[:25] + "..."

        ind_type = ind["indicator_type"].lower().replace(" ", "_")
        add_node(ind_node_id, val_display, ind_type, {
            "Full Value": ind["indicator_value"],
            "Type": ind["indicator_type"],
            "Occurrences": ind["occurrence_count"],
            "Tags": ind["tags"],
            "Notes": ind["notes"]
        })

        if ind["evidence_id"]:
            ev_id = f"ev_{ind['evidence_id']}"
            add_edge(ev_id, ind_node_id, "EXTRACTED_INDICATOR")
        else:
            add_edge(case_node_id, ind_node_id, "ASSOCIATED_INDICATOR")

    # 4. Findings
    findings = cursor.execute('''
        SELECT id, finding_number, title, severity, status, explainable_basis, evidence_ids
        FROM findings WHERE case_id = ?
    ''', (case_id,)).fetchall()

    for find in findings:
        f_node_id = f"find_{find['id']}"
        add_node(f_node_id, find["title"], "finding", {
            "Finding ID": find["finding_number"],
            "Severity": find["severity"],
            "Status": find["status"],
            "Explainable Basis": find["explainable_basis"]
        }, severity=find["severity"])
        add_edge(case_node_id, f_node_id, "HAS_FINDING")

        # Link to evidence
        if find["evidence_ids"]:
            try:
                import json
                ev_ids = json.loads(find["evidence_ids"])
                for e_id in ev_ids:
                    ev_target = f"ev_{e_id}"
                    add_edge(f_node_id, ev_target, "EVALUATES_EVIDENCE")
            except Exception:
                pass

    # 5. Suspicious Artifacts
    susp_rows = cursor.execute('''
        SELECT s.id, s.evidence_id, s.risk_level, s.reasons_json, s.entropy, e.name
        FROM suspicious_artifacts s
        JOIN evidence e ON s.evidence_id = e.id
        WHERE s.case_id = ?
    ''', (case_id,)).fetchall()

    for s in susp_rows:
        ev_node_id = f"ev_{s['evidence_id']}"
        if ev_node_id in node_set:
            # Update evidence node severity
            for n in nodes:
                if n["id"] == ev_node_id:
                    n["severity"] = s["risk_level"]
                    n["details"]["Suspicious Status"] = "FLAGGED"
                    n["details"]["Shannon Entropy"] = f"{s['entropy']:.2f}"
                    break

    return {
        "nodes": nodes,
        "edges": edges,
        "total_nodes": len(nodes),
        "total_edges": len(edges)
    }
