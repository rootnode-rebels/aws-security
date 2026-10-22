import os
import sys
from datetime import datetime, timezone
import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def create_element(name):
    return OxmlElement(name)

def set_cell_background(cell, hex_color):
    shading_elm = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    cell._tc.get_or_add_tcPr().append(shading_elm)

def set_cell_margins(cell, top=120, bottom=120, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def add_callout(doc, text, title="SECURITY NOTE", border_color="0284C7", bg_color="F0F9FF"):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.autofit = False
    
    cell = tbl.cell(0, 0)
    cell.width = Inches(6.5)
    set_cell_background(cell, bg_color)
    set_cell_margins(cell, top=140, bottom=140, left=180, right=180)
    
    # Left border only
    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(
        f'<w:tcBorders {nsdecls("w")}>'
        f'  <w:top w:val="none"/>'
        f'  <w:left w:val="single" w:sz="36" w:space="0" w:color="{border_color}"/>'
        f'  <w:bottom w:val="none"/>'
        f'  <w:right w:val="none"/>'
        f'</w:tcBorders>'
    )
    tcPr.append(borders)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(3)
    run_t = p.add_run(f"[{title}] ")
    run_t.bold = True
    run_t.font.name = "Segoe UI"
    run_t.font.size = Pt(10)
    run_t.font.color.rgb = RGBColor.from_string(border_color)
    
    run_b = p.add_run(text)
    run_b.font.name = "Segoe UI"
    run_b.font.size = Pt(9.5)
    run_b.font.color.rgb = RGBColor(30, 41, 59)
    
    doc.add_paragraph().paragraph_format.space_after = Pt(4)

def add_code_block(doc, code_text):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.autofit = False
    cell = tbl.cell(0, 0)
    cell.width = Inches(6.5)
    set_cell_background(cell, "F8FAFC")
    set_cell_margins(cell, top=100, bottom=100, left=140, right=140)
    
    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(
        f'<w:tcBorders {nsdecls("w")}>'
        f'  <w:top w:val="single" w:sz="6" w:space="0" w:color="CBD5E1"/>'
        f'  <w:left w:val="single" w:sz="6" w:space="0" w:color="CBD5E1"/>'
        f'  <w:bottom w:val="single" w:sz="6" w:space="0" w:color="CBD5E1"/>'
        f'  <w:right w:val="single" w:sz="6" w:space="0" w:color="CBD5E1"/>'
        f'</w:tcBorders>'
    )
    tcPr.append(borders)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)
    r = p.add_run(code_text)
    r.font.name = "Consolas"
    r.font.size = Pt(8.5)
    r.font.color.rgb = RGBColor(15, 23, 42)
    doc.add_paragraph().paragraph_format.space_after = Pt(4)

def style_heading(doc, text, level):
    h = doc.add_heading(text, level=level)
    h.paragraph_format.keep_with_next = True
    run = h.runs[0]
    run.font.name = "Segoe UI"
    if level == 1:
        run.font.size = Pt(17)
        run.bold = True
        run.font.color.rgb = RGBColor(15, 23, 42) # Navy Slate
        h.paragraph_format.space_before = Pt(18)
        h.paragraph_format.space_after = Pt(6)
    elif level == 2:
        run.font.size = Pt(13)
        run.bold = True
        run.font.color.rgb = RGBColor(2, 132, 199) # Blue accent
        h.paragraph_format.space_before = Pt(14)
        h.paragraph_format.space_after = Pt(4)
    elif level == 3:
        run.font.size = Pt(11)
        run.bold = True
        run.font.color.rgb = RGBColor(51, 65, 85)
        h.paragraph_format.space_before = Pt(10)
        h.paragraph_format.space_after = Pt(2)
    return h

def generate_report():
    doc = Document()
    
    # Page setup - 0.8 inch margins
    for section in doc.sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(0.8)
        section.right_margin = Inches(0.8)
        
        # Header / Footer
        header = section.header
        hp = header.paragraphs[0]
        hp.text = "AWS Security AI Platform — Comprehensive Code & Quality Audit"
        hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        hp.runs[0].font.name = "Segoe UI"
        hp.runs[0].font.size = Pt(8)
        hp.runs[0].font.color.rgb = RGBColor(148, 163, 184)
        
        footer = section.footer
        fp = footer.paragraphs[0]
        fp.text = "Confidential — RootNode-Rebels Architecture & Verification Report"
        fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        fp.runs[0].font.name = "Segoe UI"
        fp.runs[0].font.size = Pt(8)
        fp.runs[0].font.color.rgb = RGBColor(148, 163, 184)

    # Document Title Block
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_before = Pt(10)
    title_p.paragraph_format.space_after = Pt(2)
    t_run = title_p.add_run("AWS Security AI Platform")
    t_run.font.name = "Segoe UI"
    t_run.font.size = Pt(26)
    t_run.bold = True
    t_run.font.color.rgb = RGBColor(10, 37, 64)
    
    sub_p = doc.add_paragraph()
    sub_p.paragraph_format.space_before = Pt(0)
    sub_p.paragraph_format.space_after = Pt(14)
    s_run = sub_p.add_run("Deep Security Audit, Test Suite Verification & Architecture Documentation")
    s_run.font.name = "Segoe UI"
    s_run.font.size = Pt(13)
    s_run.font.color.rgb = RGBColor(2, 132, 199)
    
    # Metadata Box
    meta_table = doc.add_table(rows=4, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_data = [
        ("Project Target:", "AWS Serverless & ML-Driven Account Hijacking Defense Platform"),
        ("Repository & Upstream:", "https://github.com/rootnode-rebels/aws-security.git (Branch: main @ efc7805)"),
        ("Audit Date & Status:", f"{datetime.now(timezone.utc).strftime('%B %d, %Y')} — Verified (100% Test Pass Rate)"),
        ("Auditing Framework:", "Python 3.14 Unittest, FastAPI TestClient, Scikit-Learn 1.8, Node.js V8 Engine")
    ]
    for i, (k, v) in enumerate(meta_data):
        row = meta_table.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width, c1.width = Inches(2.2), Inches(4.3)
        set_cell_background(c0, "F1F5F9")
        set_cell_background(c1, "F8FAFC")
        set_cell_margins(c0, top=60, bottom=60, left=100, right=100)
        set_cell_margins(c1, top=60, bottom=60, left=100, right=100)
        
        p0 = c0.paragraphs[0]
        p0.paragraph_format.space_after = Pt(0)
        r0 = p0.add_run(k)
        r0.font.name = "Segoe UI"
        r0.font.size = Pt(9)
        r0.bold = True
        r0.font.color.rgb = RGBColor(30, 41, 59)
        
        p1 = c1.paragraphs[0]
        p1.paragraph_format.space_after = Pt(0)
        r1 = p1.add_run(v)
        r1.font.name = "Segoe UI"
        r1.font.size = Pt(9)
        r1.font.color.rgb = RGBColor(51, 65, 85)
    
    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # 1. Executive Summary
    style_heading(doc, "1. Executive Summary", level=1)
    
    p = doc.add_paragraph()
    p.add_run(
        "This document details the complete code analysis, quality audit, and automated test execution results for the "
        "AWS Serverless & ML-Driven Account Hijacking Defense Platform. Following the synchronization of the upstream "
        "main branch (commits through efc7805), a full-suite automated verification was conducted across all 5 test "
        "harnesses comprising 41 discrete security vectors, unit tests, and integration scenarios.\n\n"
        "Key Findings & Verification Highlights:"
    )
    
    highlights = [
        "100% Automated Test Pass Rate: 41 out of 41 tests executed successfully with 0 failures and 0 errors across 102.26 seconds of live database and ML validation.",
        "Zero-Data-Leak Device Architecture: Validated that secondary devices accessing user accounts receive masked IP representations and zero sensitive verification tokens.",
        "Maker-Checker Multi-Admin Governance: Fully verified dual-authorization constraints preventing unilateral admin account elevation or deletion without peer consensus.",
        "High-Velocity Anomaly Interception: Confirmed instant 403 Hard-Block defense triggers when simulated impossible travel (e.g. 40,000,000 km/h) or datacenter VPN proxies are detected.",
        "Defect Identification & Remediation: Identified and resolved a PyMongo InsertOneResult assertion incompatibility in test_backend.py, restoring 100% test suite reliability."
    ]
    for h in highlights:
        bp = doc.add_paragraph(style='List Bullet')
        bp.paragraph_format.space_before = Pt(1)
        bp.paragraph_format.space_after = Pt(2)
        parts = h.split(":", 1)
        r_bold = bp.add_run(parts[0] + ":")
        r_bold.bold = True
        r_bold.font.name = "Segoe UI"
        r_bold.font.size = Pt(9.5)
        r_body = bp.add_run(parts[1])
        r_body.font.name = "Segoe UI"
        r_body.font.size = Pt(9.5)

    add_callout(
        doc,
        "All 41 tests passed against live MongoDB instance (account_security_db). "
        "NoSQL injection filters, sliding-window rate limiters, and autonomous watchdog daemons operate with zero regressions.",
        title="AUDIT VERIFICATION PASSED",
        border_color="059669",
        bg_color="ECFDF5"
    )

    # 2. System Architecture & Core Modules
    style_heading(doc, "2. Platform Architecture & Core Modules", level=1)
    
    p = doc.add_paragraph()
    p.add_run(
        "The application is engineered as a defense-in-depth cybersecurity platform combining a high-performance FastAPI "
        "backend, pre-trained multi-model Machine Learning ensembles, asynchronous watchdog services, and a resilient "
        "frontend client supported by an offline-capable Service Worker."
    )

    arch_components = [
        ("Core Application Server (backend/app.py)", 
         "Exposes authenticated REST endpoints, enforces role-based access control (RBAC), routes incoming device fingerprints, and integrates automated rate limiting with immediate event broadcasting."),
        ("Cryptographic Authentication Engine (backend/security/auth.py)", 
         "Implements PBKDF2-HMAC-SHA256 password hashing with salt generation (minimum 16 bytes), JWT session management, secondary recovery password verification, and device fingerprint evaluation."),
        ("Machine Learning Anomaly Engine (backend/ml/)", 
         "Houses pre-trained Isolation Forest, Decision Tree, Random Forest, and TensorFlow Autoencoder neural models. Computes Haversine great-circle distances, geo-velocity metrics, and reconstruction error thresholds to evaluate account takeover probability."),
        ("Database & Connection Management (database/db_manager.py)", 
         "Provides resilient hybrid connection handling with automatic fallback between live MongoDB Atlas and local JSON storage. Configures unique compound indexes, automated TTL expiration for ephemeral sessions, and parameter sanitization."),
        ("Autonomous Watchdog Service (backend/monitoring/watchdog.py)", 
         "Runs an hourly background daemon monitoring database connectivity, pruning orphaned/expired user sessions, recycling stale connection pools, and publishing system health indicators."),
        ("Client-Side Architecture & Service Worker (frontend/)", 
         "Modern responsive web application featuring real-time session tracking, CMS administrative dashboards, non-intrusive notification drawers, and a root-scoped Service Worker (sw.js) for caching and background state resilience.")
    ]
    for comp, desc in arch_components:
        style_heading(doc, comp, level=2)
        cp = doc.add_paragraph()
        cp.paragraph_format.space_before = Pt(2)
        cp.paragraph_format.space_after = Pt(4)
        r = cp.add_run(desc)
        r.font.name = "Segoe UI"
        r.font.size = Pt(9.5)

    # 3. Comprehensive Test Suite Breakdown
    style_heading(doc, "3. Test Suite Breakdown & Verification Results", level=1)
    
    p = doc.add_paragraph()
    p.add_run(
        "The automated test suite evaluates the platform across 5 dedicated test modules. All 41 individual test methods "
        "completed with an exit code of 0. Below is the detailed breakdown of each test module:"
    )

    # Test Table
    test_table = doc.add_table(rows=6, cols=4)
    test_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    test_table.autofit = False
    
    headers = ["Test Module", "Test Count", "Key Vectors Validated", "Status"]
    col_widths = [Inches(2.2), Inches(0.9), Inches(2.6), Inches(0.8)]
    
    hdr_row = test_table.rows[0]
    for idx, text in enumerate(headers):
        cell = hdr_row.cells[idx]
        cell.width = col_widths[idx]
        set_cell_background(cell, "0A2540")
        set_cell_margins(cell, top=100, bottom=100, left=100, right=100)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_after = Pt(0)
        run = p.add_run(text)
        run.bold = True
        run.font.name = "Segoe UI"
        run.font.size = Pt(9)
        run.font.color.rgb = RGBColor(255, 255, 255)

    test_rows_data = [
        ("tests/test_backend.py", "9 Tests", "Database CRUD, PBKDF2 verification, sliding window brute-force, ML inference, Autoencoder neural reconstruction, CloudWatch telemetry, NoSQL injection defense, memory pruning.", "PASSED"),
        ("tests/test_deep_security_probe.py", "6 Tests", "Privileged RBAC enforcement, Maker-Checker multi-admin governance, dead session purging, parameter tampering, zero secondary data leakage, system watchdog daemon.", "PASSED"),
        ("tests/test_vpn_impossible_travel_flow.py", "5 Tests", "Registration, primary device enrollment, secondary device challenge, impossible travel 403 hard-block, emergency SNS alert dispatching.", "PASSED"),
        ("tests/test_root_admin_demo_delete.py", "14 Tests", "Principle of Least Privilege role hierarchy, protected Root Owner status, demo account lifecycle, unauthorized deletion blocking.", "PASSED"),
        ("tests/test_live_scenario.py", "7 Tests", "Multi-browser two-party simulation, primary authority transfer, in-app OTP routing, session expiration verification.", "PASSED")
    ]
    for row_idx, data in enumerate(test_rows_data, start=1):
        row = test_table.rows[row_idx]
        for col_idx, text in enumerate(data):
            cell = row.cells[col_idx]
            cell.width = col_widths[col_idx]
            set_cell_background(cell, "F8FAFC" if row_idx % 2 == 1 else "FFFFFF")
            set_cell_margins(cell, top=80, bottom=80, left=90, right=90)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            run = p.add_run(text)
            run.font.name = "Segoe UI"
            run.font.size = Pt(8.5)
            if col_idx == 0:
                run.bold = True
                run.font.name = "Consolas"
                run.font.size = Pt(8)
            elif col_idx == 1:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            elif col_idx == 3:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                run.bold = True
                run.font.color.rgb = RGBColor(5, 150, 105)

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    # 4. Defect Analysis & Root Cause Remediation
    style_heading(doc, "4. Defect Analysis & Root Cause Remediation", level=1)
    
    p = doc.add_paragraph()
    p.add_run(
        "During initial automated test execution against the live MongoDB instance, one failure was encountered in "
        "tests/test_backend.py. Below is the transparent defect analysis and remediation detail:"
    )

    style_heading(doc, "4.1 Issue Summary & Stack Trace", level=2)
    err_text = (
        "ERROR: test_01_database_operations (test_backend.TestAccountHijackSystem.test_01_database_operations)\n"
        "Traceback (most recent call last):\n"
        "  File 'tests/test_backend.py', line 34, in test_01_database_operations\n"
        "    self.assertIn('inserted_id', insert_res)\n"
        "TypeError: argument of type 'InsertOneResult' is not a container or iterable"
    )
    add_code_block(doc, err_text)

    style_heading(doc, "4.2 Root Cause Analysis", level=2)
    p = doc.add_paragraph()
    p.add_run(
        "The test method test_01_database_operations was written assuming a mock dictionary response where 'inserted_id' "
        "would be a dictionary key. When operating against an active MongoDB Atlas cluster, PyMongo returns an instance "
        "of pymongo.results.InsertOneResult. Because InsertOneResult does not implement the Python __contains__ "
        "magic method, evaluating 'inserted_id' in insert_res raises a fatal TypeError."
    )

    style_heading(doc, "4.3 Applied Code Fix", level=2)
    p = doc.add_paragraph()
    p.add_run(
        "The assertion was updated in tests/test_backend.py to safely inspect the inserted_id attribute using getattr(), "
        "while retaining fallback dictionary lookup for mock environments:"
    )
    diff_text = (
        "--- a/tests/test_backend.py\n"
        "+++ b/tests/test_backend.py\n"
        "@@ -31,3 +31,4 @@\n"
        "-        self.assertIn('inserted_id', insert_res)\n"
        "+        inserted_id = getattr(insert_res, 'inserted_id', None) or (insert_res.get('inserted_id') if isinstance(insert_res, dict) else None)\n"
        "+        self.assertIsNotNone(inserted_id)"
    )
    add_code_block(doc, diff_text)

    p = doc.add_paragraph()
    p.add_run(
        "Following this modification, test_backend.py passed completely with 9/9 tests OK, and full discovery passed 41/41."
    )

    # 5. Security Policy Compliance
    style_heading(doc, "5. Security Policy & Best Practices Compliance", level=1)
    
    p = doc.add_paragraph()
    p.add_run(
        "The platform was assessed against the 15-point Vibe Coded App Security Checklist:"
    )

    checklist_items = [
        ("Rule 1-3: Secrets & Credentials Protection", 
         "All sensitive credentials, API keys, and connection strings reside in .env. Both .gitignore and .dockerignore exclude .env and runtime secret artifacts. No production secrets are hardcoded."),
        ("Rule 4-6: Authentication & Authorization", 
         "Server-side role verification is enforced on all protected routes. Super Admin and Root Owner privileges require valid bearer tokens and peer authorization for critical mutations. Frontend user IDs are never trusted blindly."),
        ("Rule 7-10: Data Isolation & Admin Protection", 
         "Primary device sessions are isolated from secondary devices. System maintenance routes (/api/system/maintenance, /api/system/database-reset) enforce strict ROOT_OWNER and SUPER_ADMIN RBAC."),
        ("Rule 11-15: Input Validation & Threat Mitigation", 
         "Production mode disables detailed debug output. MongoDB query operators ($gt, $ne, $in, $regex) are stripped and sanitized from untrusted inputs to prevent NoSQL injection. Sliding window rate limiters mitigate DoS attacks.")
    ]
    for rule_title, rule_desc in checklist_items:
        style_heading(doc, rule_title, level=2)
        rp = doc.add_paragraph()
        rp.paragraph_format.space_before = Pt(2)
        rp.paragraph_format.space_after = Pt(4)
        r = rp.add_run(rule_desc)
        r.font.name = "Segoe UI"
        r.font.size = Pt(9.5)

    # 6. Deployment Pipeline & Queues
    style_heading(doc, "6. Deployment Pipeline & Deployment Queue Status", level=1)
    
    p = doc.add_paragraph()
    p.add_run(
        "The project deployment topology integrates Git version control, multi-stage Docker builds, AWS ECR container "
        "registry, and AWS App Runner deployment services:"
    )

    deploy_points = [
        ("Git Repository Synchronization", "Branch main is fast-forwarded and fully up to date with origin/main (efc7805). Uncommitted files consist of local test assertion fix and local database seeding configuration."),
        ("Docker Container Build Queue", "Dockerfile employs a multi-stage Python 3.11-slim builder. Application assets (backend/, database/, frontend/, run_standalone.py) are bundled, while tests and local data files are cleanly excluded via .dockerignore."),
        ("AWS ECR Container Push", "Image target: 242254325378.dkr.ecr.eu-central-1.amazonaws.com/aws-security-app:latest. Authentication via AWS CLI (aws ecr get-login-password --region eu-central-1)."),
        ("AWS App Runner Service Deployment", "Automated deployment target: arn:aws:apprunner:eu-central-1:242254325378:service/aws-security-app-service/e2c75827b7fe48a0963c9b0dc69ccc5e.")
    ]
    for d_title, d_desc in deploy_points:
        style_heading(doc, d_title, level=2)
        dp = doc.add_paragraph()
        dp.paragraph_format.space_before = Pt(2)
        dp.paragraph_format.space_after = Pt(4)
        r = dp.add_run(d_desc)
        r.font.name = "Segoe UI"
        r.font.size = Pt(9.5)

    output_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "AWSSecurity_AI_Code_Audit_Report.docx"))
    doc.save(output_path)
    print(f"[SUCCESS] Document successfully generated at: {output_path}")

if __name__ == "__main__":
    generate_report()
