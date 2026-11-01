import os
import sqlite3
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from config import REPORTS_DIR

class NumberedCanvas(canvas.Canvas):
    """Adds running headers and footers with page numbers to the PDF."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        if self._pageNumber == 1:
            return  # Suppress headers/footers on cover page

        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#4b5563"))

        # Header
        self.drawString(54, 11 * inch - 36, "FORENSIX DIGITAL FORENSIC INVESTIGATION REPORT | LAW ENFORCEMENT & ENTERPRISE AUDIT")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)

        # Footer
        self.setFont("Helvetica", 8)
        self.drawString(54, 36, "CONFIDENTIAL & PROPRIETARY FORENSIC WORK PRODUCT — CHAIN OF CUSTODY PRESERVED")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * inch - 54, 36, page_text)
        self.line(54, 46, 8.5 * inch - 54, 46)
        self.restoreState()

def generate_pdf_report(conn: sqlite3.Connection, case_id: int, generated_by: str) -> str:
    """
    Generates an authentic, publication-quality forensic investigation PDF report.
    Returns the absolute path to the generated PDF.
    """
    cursor = conn.cursor()
    case = cursor.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not case:
        raise ValueError(f"Case with ID {case_id} not found.")

    report_number = f"REP-{case['case_number']}-{datetime.utcnow().strftime('%Y%m%d%H%M')}"
    filename = f"{report_number}.pdf"
    file_path = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(
        file_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom color palette
    c_primary = colors.HexColor("#0f172a")     # Deep slate navy
    c_accent = colors.HexColor("#0284c7")      # Forensic blue
    c_danger = colors.HexColor("#b91c1c")      # Red
    c_warning = colors.HexColor("#d97706")     # Amber
    c_dark = colors.HexColor("#1e293b")        # Text dark
    c_gray_bg = colors.HexColor("#f8fafc")     # Light gray
    c_border = colors.HexColor("#e2e8f0")

    # Typography styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=c_primary,
        alignment=0
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=c_accent,
        alignment=0
    )
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=c_primary,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )
    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=c_accent,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )
    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=c_dark
    )
    body_bold = ParagraphStyle(
        'Body_Bold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    table_cell = ParagraphStyle(
        'TableCell',
        parent=body_style,
        fontSize=8,
        leading=10
    )
    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=body_bold,
        fontSize=8,
        leading=10,
        textColor=colors.whitesmoke
    )

    story = []

    # ==========================
    # 1. COVER PAGE
    # ==========================
    story.append(Spacer(1, 40))
    story.append(Paragraph("FORENSIX", ParagraphStyle('LogoStyle', fontName='Helvetica-Bold', fontSize=32, leading=36, textColor=c_accent)))
    story.append(Paragraph("DIGITAL FORENSIC INVESTIGATION & EVIDENCE REPORT", title_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph("OFFICIAL FORENSIC EXAMINATION & CHAIN OF CUSTODY RECORD", subtitle_style))
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=3, color=c_accent, spaceBefore=0, spaceAfter=20))

    cover_meta = [
        [Paragraph("<b>Case Number:</b>", body_style), Paragraph(case["case_number"], body_bold)],
        [Paragraph("<b>Case Title:</b>", body_style), Paragraph(case["name"], body_style)],
        [Paragraph("<b>Category:</b>", body_style), Paragraph(case["category"], body_style)],
        [Paragraph("<b>Classification / Priority:</b>", body_style), Paragraph(f"{case['priority']} Priority", body_style)],
        [Paragraph("<b>Investigation Status:</b>", body_style), Paragraph(case["status"], body_style)],
        [Paragraph("<b>Lead Investigator:</b>", body_style), Paragraph(case["investigator"], body_style)],
        [Paragraph("<b>Report Generated By:</b>", body_style), Paragraph(generated_by.strip().title(), body_style)],
        [Paragraph("<b>Generation Timestamp:</b>", body_style), Paragraph(f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", body_style)],
        [Paragraph("<b>Report Identifier:</b>", body_style), Paragraph(report_number, body_style)],
    ]
    t_cover = Table(cover_meta, colWidths=[160, 340])
    t_cover.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_gray_bg),
        ('BOX', (0, 0), (-1, -1), 1, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(t_cover)

    story.append(Spacer(1, 30))
    notice_text = (
        "<b>LEGAL & FORENSIC COMPLIANCE NOTICE:</b> This document contains privileged, forensic examination "
        "findings derived from authorized analysis of digital evidence. All evidence items referenced have been "
        "cryptographically hashed, cataloged in accordance with ISO/IEC 27037 digital evidence standards, and secured "
        "within an immutable forensic chain of custody ledger. Any unauthorized reproduction or distribution is strictly prohibited."
    )
    story.append(Paragraph(notice_text, ParagraphStyle('Notice', parent=body_style, fontSize=8, leading=11, textColor=colors.HexColor("#64748b"))))
    story.append(PageBreak())

    # ==========================
    # 2. EXECUTIVE SUMMARY & STATS
    # ==========================
    story.append(Paragraph("1. Executive Investigation Summary", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceBefore=2, spaceAfter=8))

    desc_text = case["description"] or "Digital forensic triage and root cause analysis initiated upon detection of anomalous activity."
    story.append(Paragraph(f"<b>Case Objective:</b> {desc_text}", body_style))
    story.append(Spacer(1, 8))

    # Fetch stats
    ev_count = cursor.execute("SELECT COUNT(*) FROM evidence WHERE case_id = ?", (case_id,)).fetchone()[0]
    susp_count = cursor.execute("SELECT COUNT(*) FROM suspicious_artifacts WHERE case_id = ?", (case_id,)).fetchone()[0]
    ind_count = cursor.execute("SELECT COUNT(*) FROM indicators WHERE case_id = ?", (case_id,)).fetchone()[0]
    tl_count = cursor.execute("SELECT COUNT(*) FROM timeline_events WHERE case_id = ?", (case_id,)).fetchone()[0]
    find_count = cursor.execute("SELECT COUNT(*) FROM findings WHERE case_id = ?", (case_id,)).fetchone()[0]
    cust_count = cursor.execute("SELECT COUNT(*) FROM chain_of_custody WHERE case_id = ?", (case_id,)).fetchone()[0]

    stats_data = [
        [
            Paragraph(f"<b>Total Evidence Items:</b> {ev_count}", body_style),
            Paragraph(f"<b>Suspicious Artifacts:</b> {susp_count}", body_style),
            Paragraph(f"<b>Indicators of Interest:</b> {ind_count}", body_style)
        ],
        [
            Paragraph(f"<b>Timeline Events:</b> {tl_count}", body_style),
            Paragraph(f"<b>Formal Findings:</b> {find_count}", body_style),
            Paragraph(f"<b>Custody Records:</b> {cust_count}", body_style)
        ]
    ]
    t_stats = Table(stats_data, colWidths=[166, 166, 168])
    t_stats.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ('BOX', (0, 0), (-1, -1), 1, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
        ('PADDING', (0, 0), (-1, -1), 6)
    ]))
    story.append(t_stats)
    story.append(Spacer(1, 14))

    # ==========================
    # 3. EVIDENCE INVENTORY & HASHES
    # ==========================
    story.append(Paragraph("2. Evidence Inventory & Cryptographic Integrity", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceBefore=2, spaceAfter=8))

    ev_rows = cursor.execute('''
        SELECT evidence_number, name, category, file_size, sha256, md5, integrity_status
        FROM evidence WHERE case_id = ? ORDER BY id ASC
    ''', (case_id,)).fetchall()

    if ev_rows:
        ev_table_data = [[
            Paragraph("Item ID", table_cell_bold),
            Paragraph("Evidence Name", table_cell_bold),
            Paragraph("Category", table_cell_bold),
            Paragraph("Size (Bytes)", table_cell_bold),
            Paragraph("SHA-256 Hash", table_cell_bold),
            Paragraph("Integrity", table_cell_bold)
        ]]
        for r in ev_rows:
            hash_display = (r["sha256"][:20] + "...") if r["sha256"] and len(r["sha256"]) == 64 else (r["sha256"] or "Not Calculated")
            ev_table_data.append([
                Paragraph(r["evidence_number"], table_cell),
                Paragraph(r["name"], table_cell),
                Paragraph(r["category"], table_cell),
                Paragraph(f"{r['file_size']:,}", table_cell),
                Paragraph(hash_display, table_cell),
                Paragraph(f"<font color='green'><b>{r['integrity_status']}</b></font>", table_cell)
            ])
        t_ev = Table(ev_table_data, colWidths=[65, 125, 75, 60, 115, 60])
        t_ev.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), c_primary),
            ('BOX', (0, 0), (-1, -1), 0.5, c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_gray_bg]),
            ('PADDING', (0, 0), (-1, -1), 4)
        ]))
        story.append(t_ev)
    else:
        story.append(Paragraph("No evidence items currently logged in this case.", body_style))

    story.append(Spacer(1, 14))

    # ==========================
    # 4. SUSPICIOUS ARTIFACTS
    # ==========================
    story.append(Paragraph("3. Suspicious Artifact Analysis (Explainable Heuristics)", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceBefore=2, spaceAfter=8))

    susp_rows = cursor.execute('''
        SELECT s.risk_level, s.reasons_json, s.entropy, e.evidence_number, e.name, e.original_location
        FROM suspicious_artifacts s
        JOIN evidence e ON s.evidence_id = e.id
        WHERE s.case_id = ?
    ''', (case_id,)).fetchall()

    if susp_rows:
        for s in susp_rows:
            reasons = json.loads(s["reasons_json"]) if s["reasons_json"] else []
            reasons_html = "<br/>".join([f"• {r}" for r in reasons]) or "Heuristic flag triggered."
            story.append(Paragraph(
                f"<b>[{s['evidence_number']}] {s['name']}</b> — Risk Level: <font color='red'><b>{s['risk_level']}</b></font> (Entropy: {s['entropy']:.2f})",
                body_bold
            ))
            story.append(Paragraph(f"<b>Original Path:</b> {s['original_location'] or 'Not Available'}", body_style))
            story.append(Paragraph(f"<b>Explainable Detection Reasons:</b><br/>{reasons_html}", body_style))
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("No artifacts met suspicious heuristic thresholds.", body_style))

    story.append(Spacer(1, 14))

    # ==========================
    # 5. INDICATORS OF INTEREST (IOCs)
    # ==========================
    story.append(Paragraph("4. Key Indicators of Interest (IOCs)", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceBefore=2, spaceAfter=8))

    ind_rows = cursor.execute('''
        SELECT indicator_type, indicator_value, occurrence_count, tags, notes
        FROM indicators WHERE case_id = ? LIMIT 15
    ''', (case_id,)).fetchall()

    if ind_rows:
        ind_table_data = [[
            Paragraph("Type", table_cell_bold),
            Paragraph("Indicator Value", table_cell_bold),
            Paragraph("Hits", table_cell_bold),
            Paragraph("Tags", table_cell_bold),
            Paragraph("Forensic Context", table_cell_bold)
        ]]
        for ind in ind_rows:
            val_display = ind["indicator_value"]
            if len(val_display) > 35:
                val_display = val_display[:32] + "..."
            ind_table_data.append([
                Paragraph(ind["indicator_type"], table_cell),
                Paragraph(val_display, table_cell),
                Paragraph(str(ind["occurrence_count"]), table_cell),
                Paragraph(ind["tags"] or "-", table_cell),
                Paragraph(ind["notes"] or "-", table_cell)
            ])
        t_ind = Table(ind_table_data, colWidths=[70, 150, 40, 80, 160])
        t_ind.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), c_primary),
            ('BOX', (0, 0), (-1, -1), 0.5, c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_gray_bg]),
            ('PADDING', (0, 0), (-1, -1), 4)
        ]))
        story.append(t_ind)
    else:
        story.append(Paragraph("No indicators extracted.", body_style))

    story.append(Spacer(1, 14))

    # ==========================
    # 6. INVESTIGATION FINDINGS
    # ==========================
    story.append(Paragraph("5. Formal Investigation Findings", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceBefore=2, spaceAfter=8))

    find_rows = cursor.execute('''
        SELECT finding_number, title, description, severity, status, explainable_basis, investigator
        FROM findings WHERE case_id = ? ORDER BY id ASC
    ''', (case_id,)).fetchall()

    if find_rows:
        for f in find_rows:
            sev_color = "red" if f["severity"] in ["Critical", "High"] else "orange" if f["severity"] == "Medium" else "blue"
            story.append(Paragraph(
                f"<b>[{f['finding_number']}] {f['title']}</b> &mdash; Severity: <font color='{sev_color}'><b>{f['severity']}</b></font> ({f['status']})",
                body_bold
            ))
            story.append(Paragraph(f"<b>Investigator:</b> {f['investigator']}", body_style))
            story.append(Paragraph(f"<b>Description:</b> {f['description']}", body_style))
            if f["explainable_basis"]:
                story.append(Paragraph(f"<b>Explainable Evidence Basis:</b> {f['explainable_basis']}", body_style))
            story.append(Spacer(1, 8))
    else:
        story.append(Paragraph("No findings formally recorded.", body_style))

    story.append(Spacer(1, 14))

    # ==========================
    # 7. FORENSIC TIMELINE EXCERPT
    # ==========================
    story.append(Paragraph("6. Unified Forensic Timeline Excerpt", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceBefore=2, spaceAfter=8))

    tl_rows = cursor.execute('''
        SELECT timestamp, event_type, title, category, description
        FROM timeline_events WHERE case_id = ? ORDER BY timestamp ASC LIMIT 15
    ''', (case_id,)).fetchall()

    if tl_rows:
        tl_table_data = [[
            Paragraph("Timestamp (UTC)", table_cell_bold),
            Paragraph("Category", table_cell_bold),
            Paragraph("Event Title", table_cell_bold),
            Paragraph("Details", table_cell_bold)
        ]]
        for tl in tl_rows:
            tl_table_data.append([
                Paragraph(tl["timestamp"][:19], table_cell),
                Paragraph(tl["category"], table_cell),
                Paragraph(tl["title"], table_cell),
                Paragraph((tl["description"] or "")[:80], table_cell)
            ])
        t_tl = Table(tl_table_data, colWidths=[100, 70, 140, 190])
        t_tl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), c_primary),
            ('BOX', (0, 0), (-1, -1), 0.5, c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_gray_bg]),
            ('PADDING', (0, 0), (-1, -1), 4)
        ]))
        story.append(t_tl)
    else:
        story.append(Paragraph("No timeline events registered.", body_style))

    story.append(Spacer(1, 14))

    # ==========================
    # 8. CHAIN OF CUSTODY LOG
    # ==========================
    story.append(Paragraph("7. Forensic Chain of Custody Audit Log", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceBefore=2, spaceAfter=8))

    cust_rows = cursor.execute('''
        SELECT c.timestamp, c.action, c.performed_by, c.description, c.integrity_hash, e.evidence_number
        FROM chain_of_custody c
        JOIN evidence e ON c.evidence_id = e.id
        WHERE c.case_id = ? ORDER BY c.id ASC LIMIT 20
    ''', (case_id,)).fetchall()

    if cust_rows:
        cust_table_data = [[
            Paragraph("Timestamp", table_cell_bold),
            Paragraph("Evidence", table_cell_bold),
            Paragraph("Action", table_cell_bold),
            Paragraph("Performed By", table_cell_bold),
            Paragraph("Integrity Hash / Notes", table_cell_bold)
        ]]
        for c in cust_rows:
            hash_snippet = c["integrity_hash"][:24] + "..." if c["integrity_hash"] and len(c["integrity_hash"]) > 28 else (c["integrity_hash"] or "-")
            cust_table_data.append([
                Paragraph(c["timestamp"][:19], table_cell),
                Paragraph(c["evidence_number"], table_cell),
                Paragraph(c["action"], table_cell),
                Paragraph(c["performed_by"], table_cell),
                Paragraph(f"{hash_snippet} ({c['description'][:30]})", table_cell)
            ])
        t_cust = Table(cust_table_data, colWidths=[90, 60, 100, 100, 150])
        t_cust.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), c_primary),
            ('BOX', (0, 0), (-1, -1), 0.5, c_border),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_gray_bg]),
            ('PADDING', (0, 0), (-1, -1), 4)
        ]))
        story.append(t_cust)
    else:
        story.append(Paragraph("No chain of custody records present.", body_style))

    story.append(Spacer(1, 20))

    # ==========================
    # 9. INVESTIGATOR ATTESTATION
    # ==========================
    story.append(KeepTogether([
        Paragraph("8. Investigator Attestation & Verification", h1_style),
        HRFlowable(width="100%", thickness=1, color=c_border, spaceBefore=2, spaceAfter=8),
        Paragraph(
            f"I, <b>{case['investigator']}</b>, hereby certify that the digital evidence items examined in this case "
            "were handled in adherence to standard forensic protocols, ensuring preservation of cryptographic hashes and "
            "verification of evidentiary integrity without modification to original media.",
            body_style
        ),
        Spacer(1, 25),
        Table([
            [Paragraph("____________________________________________", body_style), Paragraph("________________________", body_style)],
            [Paragraph(f"<b>{case['investigator']}</b><br/>Lead Digital Forensics Examiner", body_style), Paragraph(f"<b>Date:</b> {datetime.utcnow().strftime('%Y-%m-%d')}", body_style)]
        ], colWidths=[320, 180])
    ]))

    # Build document
    doc.build(story, canvasmaker=NumberedCanvas)

    # Save to reports table
    cursor.execute('''
        INSERT INTO reports (case_id, title, report_number, file_path, generated_by, created_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ''', (case_id, f"Forensic Report - {case['name']}", report_number, file_path, generated_by))
    conn.commit()

    return file_path


def generate_docx_report(conn, case_id: int, generated_by: str) -> str:
    """
    Generates a forensic investigation report in Microsoft Word (.docx) format.
    Returns the absolute path to the generated file.
    """
    from docx import Document
    from docx.shared import Pt, RGBColor, Inches
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement
    import os

    cursor = conn.cursor()
    case = cursor.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not case:
        raise ValueError(f"Case with ID {case_id} not found.")

    report_number = f"REP-{case['case_number']}-{datetime.utcnow().strftime('%Y%m%d%H%M')}-DOCX"
    filename = f"{report_number}.docx"
    file_path = os.path.join(REPORTS_DIR, filename)

    doc = Document()

    # Page margins
    section = doc.sections[0]
    section.top_margin = Inches(0.75)
    section.bottom_margin = Inches(0.75)
    section.left_margin = Inches(0.9)
    section.right_margin = Inches(0.9)

    def add_heading(text, level=1, color_hex="6366f1"):
        p = doc.add_heading(text, level=level)
        for run in p.runs:
            run.font.color.rgb = RGBColor.from_string(color_hex)
        return p

    def add_kv_row(table, key, val):
        row = table.add_row()
        row.cells[0].text = key
        row.cells[1].text = str(val) if val else "—"
        row.cells[0].paragraphs[0].runs[0].bold = True

    # ── COVER PAGE ──────────────────────────────────────────────────────────
    title_p = doc.add_paragraph()
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title_p.add_run("FORENSIX")
    run.bold = True
    run.font.size = Pt(28)
    run.font.color.rgb = RGBColor(0x63, 0x66, 0xF1)

    sub_p = doc.add_paragraph()
    sub_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub_run = sub_p.add_run("Digital Forensic Investigation & Evidence Report")
    sub_run.font.size = Pt(13)
    sub_run.font.color.rgb = RGBColor(0x94, 0xA3, 0xB8)

    doc.add_paragraph()

    # Cover metadata table
    tbl = doc.add_table(rows=0, cols=2)
    tbl.style = 'Table Grid'
    tbl.columns[0].width = Inches(2.2)
    tbl.columns[1].width = Inches(4.4)

    meta_rows = [
        ("Case Number",      case["case_number"]),
        ("Case Title",       case["name"]),
        ("Category",         case["category"]),
        ("Priority",         case["priority"]),
        ("Status",           case["status"]),
        ("Lead Investigator",case["investigator"]),
        ("Report Generated By", generated_by),
        ("Timestamp (UTC)",  datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
        ("Report ID",        report_number),
    ]
    for k, v in meta_rows:
        add_kv_row(tbl, k, v)

    doc.add_page_break()

    # ── EXECUTIVE SUMMARY ────────────────────────────────────────────────────
    add_heading("1. Executive Summary", level=1)
    doc.add_paragraph(case["description"] or "Digital forensic triage and root cause analysis initiated upon detection of anomalous activity.")

    ev_count   = cursor.execute("SELECT COUNT(*) FROM evidence WHERE case_id=?",          (case_id,)).fetchone()[0]
    susp_count = cursor.execute("SELECT COUNT(*) FROM suspicious_artifacts WHERE case_id=?", (case_id,)).fetchone()[0]
    ind_count  = cursor.execute("SELECT COUNT(*) FROM indicators WHERE case_id=?",        (case_id,)).fetchone()[0]
    find_count = cursor.execute("SELECT COUNT(*) FROM findings WHERE case_id=?",          (case_id,)).fetchone()[0]
    tl_count   = cursor.execute("SELECT COUNT(*) FROM timeline_events WHERE case_id=?",   (case_id,)).fetchone()[0]

    stats_tbl = doc.add_table(rows=0, cols=2)
    stats_tbl.style = 'Table Grid'
    for k, v in [("Evidence Items", ev_count), ("Suspicious Artifacts", susp_count),
                 ("Indicators of Compromise", ind_count), ("Findings", find_count),
                 ("Timeline Events", tl_count)]:
        row = stats_tbl.add_row()
        row.cells[0].text = k
        row.cells[1].text = str(v)
        row.cells[0].paragraphs[0].runs[0].bold = True

    doc.add_paragraph()

    # ── EVIDENCE VAULT ───────────────────────────────────────────────────────
    add_heading("2. Evidence Inventory", level=1)
    ev_rows = cursor.execute(
        "SELECT evidence_number, name, category, file_hash_sha256, size_bytes, status, collected_at FROM evidence WHERE case_id=?",
        (case_id,)
    ).fetchall()

    if ev_rows:
        ev_tbl = doc.add_table(rows=1, cols=5)
        ev_tbl.style = 'Table Grid'
        hdr = ev_tbl.rows[0].cells
        for i, h in enumerate(["#", "Name", "Category", "SHA-256 (truncated)", "Status"]):
            hdr[i].text = h
            hdr[i].paragraphs[0].runs[0].bold = True
        for ev in ev_rows:
            row = ev_tbl.add_row().cells
            row[0].text = ev["evidence_number"]
            row[1].text = ev["name"]
            row[2].text = ev["category"]
            row[3].text = (ev["file_hash_sha256"] or "")[:24] + "..."
            row[4].text = ev["status"]
    else:
        doc.add_paragraph("No evidence items recorded.")

    doc.add_paragraph()

    # ── INDICATORS OF COMPROMISE ──────────────────────────────────────────────
    add_heading("3. Indicators of Compromise (IOCs)", level=1)
    ioc_rows = cursor.execute(
        "SELECT ioc_type, value, confidence, context FROM indicators WHERE case_id=? ORDER BY confidence DESC LIMIT 50",
        (case_id,)
    ).fetchall()

    if ioc_rows:
        ioc_tbl = doc.add_table(rows=1, cols=4)
        ioc_tbl.style = 'Table Grid'
        hdr = ioc_tbl.rows[0].cells
        for i, h in enumerate(["Type", "Value", "Confidence", "Context"]):
            hdr[i].text = h
            hdr[i].paragraphs[0].runs[0].bold = True
        for ioc in ioc_rows:
            row = ioc_tbl.add_row().cells
            row[0].text = ioc["ioc_type"]
            row[1].text = ioc["value"]
            row[2].text = str(ioc["confidence"])
            row[3].text = (ioc["context"] or "")[:80]
    else:
        doc.add_paragraph("No IOCs extracted.")

    doc.add_paragraph()

    # ── FINDINGS ──────────────────────────────────────────────────────────────
    add_heading("4. Forensic Findings", level=1)
    find_rows = cursor.execute(
        "SELECT title, severity, status, description FROM findings WHERE case_id=? ORDER BY severity",
        (case_id,)
    ).fetchall()

    if find_rows:
        f_tbl = doc.add_table(rows=1, cols=4)
        f_tbl.style = 'Table Grid'
        hdr = f_tbl.rows[0].cells
        for i, h in enumerate(["Title", "Severity", "Status", "Description"]):
            hdr[i].text = h
            hdr[i].paragraphs[0].runs[0].bold = True
        for f in find_rows:
            row = f_tbl.add_row().cells
            row[0].text = f["title"]
            row[1].text = f["severity"]
            row[2].text = f["status"]
            row[3].text = (f["description"] or "")[:100]
    else:
        doc.add_paragraph("No findings recorded.")

    doc.add_paragraph()

    # ── ATTESTATION ───────────────────────────────────────────────────────────
    add_heading("5. Investigator Attestation", level=1)
    att_para = doc.add_paragraph()
    att_para.add_run(f"I, ").font.size = Pt(10)
    bold_run = att_para.add_run(case["investigator"])
    bold_run.bold = True
    att_para.add_run(
        ", hereby certify that all digital evidence was handled in accordance with standard forensic protocols, "
        "ensuring preservation of cryptographic integrity without modification to original media."
    )

    doc.add_paragraph()
    doc.add_paragraph(f"Signed: ____________________________________      Date: {datetime.utcnow().strftime('%Y-%m-%d')}")
    doc.add_paragraph(f"{case['investigator']} — Lead Digital Forensics Examiner")

    # ── SAVE ─────────────────────────────────────────────────────────────────
    doc.save(file_path)
    return file_path
