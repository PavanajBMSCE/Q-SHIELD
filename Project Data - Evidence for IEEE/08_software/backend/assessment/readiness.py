
import json

from flask import Blueprint, jsonify
from database.db import get_db_connection
from assessment.scoring import calculate_readiness_metrics


assessment_bp = Blueprint("assessment", __name__)


def calculate_readiness(project_id):
    connection = get_db_connection()

    try:
        project = connection.execute("""
            SELECT id, project_name
            FROM projects
            WHERE id = ?
        """, (project_id,)).fetchone()

        if not project:
            return None, "Project not found"

        inventory = connection.execute("""
            SELECT algorithm, file_name, migration_priority
            FROM crypto_inventory
            WHERE project_id = ?
        """, (project_id,)).fetchall()

        findings = connection.execute("""
            SELECT file_name, line_number, algorithm, severity, finding
            FROM scan_results
            WHERE project_id = ?
        """, (project_id,)).fetchall()

        if not inventory and not findings:
            return None, "No scan or inventory data found for this project"

        inventory = [dict(row) for row in inventory]
        findings = [dict(row) for row in findings]

        # Use the shared scoring engine also used by Project Comparison and Module 7.10.
        metrics = calculate_readiness_metrics(inventory, findings)
        readiness_score = metrics["readiness_score"]
        risk_level = metrics["risk_level"]
        readiness_label = metrics["readiness_label"]
        summary = {
            **metrics,
            "recommendations": [
                "Plan migration of RSA and ECC key exchange or signature use to suitable post-quantum standards.",
                "Replace MD5, SHA-1 and DES where used for security-sensitive purposes.",
                "Investigate and remove hardcoded credentials.",
                "Review weak encryption modes and legacy TLS configurations.",
                "Validate cryptographic usage and dependencies before production migration."
            ],
            "limitations": [
                "The score is a prototype heuristic, not a formal compliance certification.",
                "The scanner may not identify every cryptographic use or dependency.",
                "A high score does not prove that a project is quantum-safe."
            ]
        }

        cursor = connection.execute("""
            INSERT INTO assessments (
                project_id,
                readiness_score,
                risk_level,
                summary
            )
            VALUES (?, ?, ?, ?)
        """, (
            project_id,
            readiness_score,
            risk_level,
            json.dumps(summary)
        ))

        assessment_id = cursor.lastrowid
        connection.commit()

        return {
            "assessment_id": assessment_id,
            "project_id": project_id,
            "project_name": project["project_name"],
            "readiness_score": readiness_score,
            "risk_level": risk_level,
            "summary": summary
        }, None

    finally:
        connection.close()


def get_latest_assessment(project_id):
    connection = get_db_connection()

    try:
        project = connection.execute("""
            SELECT id, project_name
            FROM projects
            WHERE id = ?
        """, (project_id,)).fetchone()

        if not project:
            return None, "Project not found"

        row = connection.execute("""
            SELECT *
            FROM assessments
            WHERE project_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT 1
        """, (project_id,)).fetchone()

        if not row:
            return None, "No assessment found. Generate an assessment first."

        result = dict(row)

        try:
            result["summary"] = json.loads(result["summary"])
        except (TypeError, json.JSONDecodeError):
            result["summary"] = {}

        result["project_name"] = project["project_name"]

        return result, None

    finally:
        connection.close()


@assessment_bp.route(
    "/api/assessment/<int:project_id>/generate",
    methods=["POST"]
)
def generate_assessment(project_id):
    result, error = calculate_readiness(project_id)

    if error:
        status = 404 if error == "Project not found" else 400
        return jsonify({"error": error}), status

    return jsonify({
        "message": "PQC readiness assessment generated successfully",
        "assessment": result
    }), 201


@assessment_bp.route(
    "/api/assessment/<int:project_id>",
    methods=["GET"]
)
def fetch_assessment(project_id):
    result, error = get_latest_assessment(project_id)

    if error:
        status = 404 if error == "Project not found" else 400
        return jsonify({"error": error}), status

    return jsonify({
        "message": "Latest PQC readiness assessment retrieved",
        "assessment": result
    }), 200
