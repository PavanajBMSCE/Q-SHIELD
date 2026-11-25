"""
Q-SHIELD Module 6: PDF security audit reporting.

Creates a downloadable PDF using stored project scan results, cryptographic
inventory, readiness assessment, PQC recommendations, and migration benchmarks.
"""

import io
import json
import sqlite3
from datetime import datetime, timezone

from flask import Blueprint, jsonify, send_file
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether
)

from database.db import get_db_connection

reports_bp = Blueprint("reports", __name__)


def _rows(connection, query, params=()):
    return [dict(row) for row in connection.execute(query, params).fetchall()]


def collect_report_data(project_id):
    connection = get_db_connection()
    try:
        project_rows = _rows(
            connection,
            "SELECT id, project_name, filename, created_at FROM projects WHERE id = ?",
            (project_id,)
        )
        if not project_rows:
            return None

        project = project_rows[0]
        findings = _rows(connection, """
            SELECT file_name, line_number, algorithm, algorithm_type,
                   detected_usage, severity, finding, created_at
            FROM scan_results
            WHERE project_id = ?
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                file_name, line_number
        """, (project_id,))

        inventory = _rows(connection, """
            SELECT algorithm, algorithm_type, key_size, file_name,
                   purpose, assessment, migration_priority
            FROM crypto_inventory
            WHERE project_id = ?
            ORDER BY file_name, algorithm
        """, (project_id,))

        assessments = _rows(connection, """
            SELECT readiness_score, risk_level, summary, created_at
            FROM assessments
            WHERE project_id = ?
            ORDER BY id DESC
            LIMIT 1
        """, (project_id,))

        recommendations = _rows(connection, """
            SELECT source_algorithm, recommended_algorithm, reason,
                   priority, standard_reference
            FROM recommendations
            WHERE project_id = ?
            ORDER BY
                CASE priority
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                source_algorithm
        """, (project_id,))

        benchmarks = _rows(connection, """
            SELECT algorithm, mode, operation, key_size, ciphertext_size,
                   execution_time, created_at
            FROM benchmark_results
            ORDER BY id DESC
            LIMIT 300
        """)

        jobs = _rows(connection, """
            SELECT mode, algorithm, operation, input_size, output_size,
                   execution_time, success, created_at
            FROM migration_jobs
            ORDER BY id DESC
            LIMIT 300
        """)

        return {
            "project": project,
            "findings": findings,
            "inventory": inventory,
            "assessment": assessments[0] if assessments else None,
            "recommendations": recommendations,
            "benchmarks": benchmarks,
            "migration_jobs": jobs,
        }
    finally:
        connection.close()


def _safe(value, default="—"):
    if value is None or value == "":
        return default
    return str(value)


def _make_table(data, widths, header=True, font_size=7):
    table = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    commands = [
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("FONTSIZE", (0, 0), (-1, -1), font_size),
    ]
    if header:
        commands.extend([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17324D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ])
    table.setStyle(TableStyle(commands))
    return table


def build_audit_pdf(data):
    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=17 * mm,
        bottomMargin=17 * mm,
        title=f"Q-SHIELD Security Audit - {data['project']['project_name']}",
        author="Q-SHIELD"
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", parent=styles["Title"],
        fontName="Helvetica-Bold", fontSize=21,
        leading=25, alignment=TA_CENTER,
        textColor=colors.HexColor("#17324D"), spaceAfter=7
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", parent=styles["Heading2"],
        fontName="Helvetica-Bold", fontSize=12,
        leading=15, textColor=colors.HexColor("#17324D"),
        spaceBefore=12, spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        name="SmallCell", parent=styles["BodyText"],
        fontName="Helvetica", fontSize=6.7, leading=8.2
    ))
    styles.add(ParagraphStyle(
        name="SmallCellWhite", parent=styles["BodyText"],
        fontName="Helvetica-Bold", fontSize=6.7, leading=8.2,
        textColor=colors.white
    ))
    styles.add(ParagraphStyle(
        name="ReportNote", parent=styles["BodyText"],
        fontSize=8, leading=11, textColor=colors.HexColor("#475569")
    ))

    def cell(value, white=False):
        style = styles["SmallCellWhite"] if white else styles["SmallCell"]
        text = _safe(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return Paragraph(text, style)

    story = []
    project = data["project"]
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    story.append(Paragraph("Q-SHIELD", styles["ReportTitle"]))
    story.append(Paragraph(
        "Post-Quantum Cryptographic Security Audit Report",
        styles["Heading2"]
    ))
    story.append(Spacer(1, 4))
    metadata = [
        ["Project", _safe(project.get("project_name")),
         "Project ID", _safe(project.get("id"))],
        ["Source archive", _safe(project.get("filename")),
         "Generated", generated_at],
    ]
    meta_table = Table(metadata, colWidths=[27*mm, 62*mm, 25*mm, 58*mm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8EEF5")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#E8EEF5")),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)

    assessment = data["assessment"]
    story.append(Paragraph("1. Executive Summary", styles["SectionHeading"]))
    if assessment:
        summary_data = [
            ["Readiness score", "Risk level", "Findings", "Inventory entries", "Recommendations"],
            [
                _safe(assessment.get("readiness_score")),
                _safe(assessment.get("risk_level")),
                str(len(data["findings"])),
                str(len(data["inventory"])),
                str(len(data["recommendations"]))
            ]
        ]
        story.append(_make_table(summary_data, [32*mm, 30*mm, 30*mm, 35*mm, 40*mm]))
        story.append(Spacer(1, 7))

        # Present the assessment's stored risk breakdown as a compact table
        # instead of exposing its serialized JSON in the PDF.
        try:
            assessment_summary = assessment.get("summary") or "{}"
            if isinstance(assessment_summary, str):
                assessment_summary = json.loads(assessment_summary)
            risk_breakdown = assessment_summary.get("risk_breakdown", {})
        except (TypeError, ValueError, AttributeError):
            risk_breakdown = {}

        risk_labels = {
            "quantum_vulnerable": "Quantum-vulnerable cryptography",
            "deprecated_algorithms": "Deprecated algorithms",
            "critical_findings": "Critical security findings",
            "weak_configurations": "Weak configurations",
        }
        risk_rows = [[
            cell("Risk category", True),
            cell("Count", True),
            cell("Points deducted", True),
        ]]
        total_count = 0
        total_deduction = 0
        for risk_key, label in risk_labels.items():
            detail = risk_breakdown.get(risk_key, {})
            count = int(detail.get("count", 0) or 0)
            deduction = int(detail.get("deduction", 0) or 0)
            total_count += count
            total_deduction += deduction
            risk_rows.append([cell(label), cell(count), cell(deduction)])

        risk_rows.append([
            cell("Total", True),
            cell(total_count, True),
            cell(total_deduction, True),
        ])
        story.append(_make_table(risk_rows, [105*mm, 28*mm, 42*mm]))
        story.append(Spacer(1, 5))

        readiness_label = assessment_summary.get("readiness_label")
        if readiness_label:
            story.append(Paragraph(
                f"<b>Assessment:</b> {readiness_label}",
                styles["ReportNote"]
            ))
    else:
        story.append(Paragraph(
            "No readiness assessment has been generated for this project. "
            "Generate the assessment before interpreting the readiness status.",
            styles["ReportNote"]
        ))

    story.append(Paragraph("2. Cryptographic Inventory", styles["SectionHeading"]))
    if data["inventory"]:
        rows = [[cell(x, True) for x in (
            "Algorithm", "Type", "Key size", "File", "Purpose", "Assessment", "Priority"
        )]]
        for item in data["inventory"]:
            rows.append([cell(item.get(k)) for k in (
                "algorithm", "algorithm_type", "key_size", "file_name",
                "purpose", "assessment", "migration_priority"
            )])
        story.append(_make_table(
            rows, [22*mm, 18*mm, 16*mm, 34*mm, 32*mm, 25*mm, 20*mm]
        ))
    else:
        story.append(Paragraph("No cryptographic inventory records found.", styles["ReportNote"]))

    story.append(Paragraph("3. Scanner Findings", styles["SectionHeading"]))
    if data["findings"]:
        rows = [[cell(x, True) for x in (
            "Severity", "Algorithm", "File", "Line", "Finding"
        )]]
        for item in data["findings"]:
            rows.append([
                cell(item.get("severity")), cell(item.get("algorithm")),
                cell(item.get("file_name")), cell(item.get("line_number")),
                cell(item.get("finding") or item.get("detected_usage"))
            ])
        story.append(_make_table(rows, [20*mm, 23*mm, 35*mm, 13*mm, 76*mm]))
    else:
        story.append(Paragraph("No scanner findings found.", styles["ReportNote"]))

    story.append(Paragraph("4. PQC Migration Recommendations", styles["SectionHeading"]))
    if data["recommendations"]:
        rows = [[cell(x, True) for x in (
            "Current", "Recommended", "Priority", "Standard", "Rationale"
        )]]
        for item in data["recommendations"]:
            rows.append([
                cell(item.get("source_algorithm")),
                cell(item.get("recommended_algorithm")),
                cell(item.get("priority")),
                cell(item.get("standard_reference")),
                cell(item.get("reason"))
            ])
        story.append(_make_table(rows, [22*mm, 35*mm, 17*mm, 31*mm, 62*mm]))
    else:
        story.append(Paragraph(
            "No migration recommendations found. Generate recommendations first.",
            styles["ReportNote"]
        ))

    story.append(Paragraph("5. Migration Demonstration and Benchmarks", styles["SectionHeading"]))
    if data["benchmarks"]:
        rows = [[cell(x, True) for x in (
            "Mode", "Algorithm", "Operation", "Key size (B)",
            "Ciphertext (B)", "Time (s)"
        )]]
        for item in data["benchmarks"]:
            rows.append([
                cell(item.get("mode")), cell(item.get("algorithm")),
                cell(item.get("operation")), cell(item.get("key_size")),
                cell(item.get("ciphertext_size")),
                cell(f"{float(item.get('execution_time') or 0):.6f}")
            ])
        story.append(_make_table(rows, [20*mm, 48*mm, 25*mm, 23*mm, 25*mm, 26*mm]))
    else:
        story.append(Paragraph(
            "No migration benchmark records are available yet.",
            styles["ReportNote"]
        ))

    story.append(Paragraph("6. Methodology and Limitations", styles["SectionHeading"]))
    limitations = (
        "This report summarizes automated source-code pattern detection and "
        "the project's stored inventory, assessment, recommendations and "
        "demonstration measurements. Static scanning can produce false positives "
        "and false negatives; findings require human review. The readiness score "
        "is a project-specific heuristic and is not a NIST certification. "
        "ML-KEM is a key-encapsulation mechanism; AES-256-GCM performs file "
        "encryption. Hybrid measurements are from the project's demonstrator "
        "construction and should not be interpreted as a standardized hybrid "
        "protocol or a production deployment recommendation. Benchmark results "
        "depend on hardware, runtime, file size and system load."
    )
    story.append(Paragraph(limitations, styles["ReportNote"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "Generated by Q-SHIELD – Post-Quantum Cryptographic Security Auditor "
        "&amp; Migration Demonstrator.",
        styles["ReportNote"]
    ))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawString(15 * mm, 9 * mm, "Q-SHIELD | Security Audit Report")
        canvas.drawRightString(A4[0] - 15 * mm, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    buffer.seek(0)
    return buffer


@reports_bp.route("/api/reports/<int:project_id>/pdf", methods=["GET"])
def download_project_report(project_id):
    try:
        data = collect_report_data(project_id)
        if data is None:
            return jsonify({"error": "Project not found."}), 404

        pdf_buffer = build_audit_pdf(data)
        filename = f"Q-SHIELD_Audit_Report_Project_{project_id}.pdf"
        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename
        )
    except sqlite3.Error:
        from flask import current_app
        current_app.logger.exception("Database error while generating PDF report")
        return jsonify({"error": "Could not retrieve project audit data."}), 500
    except Exception:
        from flask import current_app
        current_app.logger.exception("PDF report generation failed")
        return jsonify({"error": "PDF report generation failed. Check backend logs."}), 500


@reports_bp.route("/api/reports/<int:project_id>/summary", methods=["GET"])
def get_project_report_summary(project_id):
    try:
        data = collect_report_data(project_id)
        if data is None:
            return jsonify({"error": "Project not found."}), 404

        assessment = data["assessment"]
        return jsonify({
            "project": data["project"],
            "readiness_assessment": assessment,
            "finding_count": len(data["findings"]),
            "inventory_count": len(data["inventory"]),
            "recommendation_count": len(data["recommendations"]),
            "benchmark_record_count": len(data["benchmarks"]),
            "migration_job_count": len(data["migration_jobs"]),
            "pdf_endpoint": f"/api/reports/{project_id}/pdf"
        }), 200
    except sqlite3.Error:
        from flask import current_app
        current_app.logger.exception("Could not create report summary")
        return jsonify({"error": "Could not retrieve report summary."}), 500
