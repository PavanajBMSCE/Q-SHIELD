
from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException
from flask_cors import CORS
from config import Config
from database.db import initialize_database, get_db_connection

import os
import zipfile
import io
import stat
import shutil
from pathlib import PurePosixPath

from scanner.crypto_detector import scan_file, SUPPORTED_EXTENSIONS
from assessment.readiness import assessment_bp
from recommendations.engine import recommendation_bp
from migration.engine import migration_bp
from reports.audit_report import reports_bp
from project_migration.engine import project_migration_bp
from comparison.engine import comparison_bp
from crypto_lab.engine import crypto_lab_bp
from signature_migration.engine import signature_migration_bp
from signature_demo import signature_demo_bp
from certificate_migration.engine import certificate_migration_bp
from hybrid_signatures.engine import hybrid_signature_bp
from migration_policy.engine import migration_policy_bp
from end_to_end_audit.engine import end_to_end_audit_bp
from benchmarking.engine import benchmark_bp


app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

initialize_database()
app.register_blueprint(assessment_bp)
app.register_blueprint(recommendation_bp)
app.register_blueprint(migration_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(project_migration_bp)
app.register_blueprint(comparison_bp)
app.register_blueprint(crypto_lab_bp)
app.register_blueprint(signature_migration_bp)
app.register_blueprint(signature_demo_bp)
app.register_blueprint(certificate_migration_bp)
app.register_blueprint(hybrid_signature_bp)
app.register_blueprint(migration_policy_bp)
app.register_blueprint(end_to_end_audit_bp)
app.register_blueprint(benchmark_bp)


# ==========================================
# GENERAL ROUTES
# ==========================================

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "application": "Q-SHIELD",
        "description": "Post-Quantum Cryptographic Security Auditor",
        "version": "1.0.0",
        "status": "running"
    })


@app.route("/api/health", methods=["GET"])
def health_check():
    connection = None
    try:
        connection = get_db_connection()
        connection.execute("SELECT 1")
        return jsonify({
            "status": "healthy",
            "backend": "Flask",
            "database": "connected",
            "application": "Q-SHIELD"
        }), 200
    except Exception:
        app.logger.exception("Health check failed")
        return jsonify({
            "status": "unhealthy",
            "error": "Database connection failed"
        }), 500
    finally:
        if connection:
            connection.close()


@app.route("/api/workspace/clear-all", methods=["POST"])
def clear_all_workspace_data():
    """Delete persisted workspace data and generated artifacts, preserving schemas/source."""
    payload = request.get_json(silent=True) or {}
    if payload.get("confirmation") != "CLEAR_ALL_QSHIELD_DATA":
        return jsonify({"error": "Explicit confirmation is required to clear all Q-SHIELD workspace data."}), 400

    connection = None
    try:
        connection = get_db_connection()
        # Turn FK enforcement off before starting the delete transaction so
        # parent/child table ordering cannot make a full reset fail.
        connection.execute("PRAGMA foreign_keys = OFF")
        table_rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        table_names = [row["name"] for row in table_rows]
        connection.execute("BEGIN")
        for table_name in table_names:
            escaped_name = table_name.replace('"', '""')
            connection.execute(f'DELETE FROM "{escaped_name}"')
        connection.commit()
        try:
            connection.execute("DELETE FROM sqlite_sequence")
            connection.commit()
        except Exception:
            connection.rollback()
        connection.execute("PRAGMA foreign_keys = ON")
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Could not clear Q-SHIELD database workspace")
        return jsonify({"error": "Could not clear the workspace database. Check the Flask terminal."}), 500
    finally:
        if connection:
            connection.close()

    upload_root = os.path.abspath(app.config["UPLOAD_FOLDER"])
    os.makedirs(upload_root, exist_ok=True)
    try:
        for entry in os.scandir(upload_root):
            path = os.path.join(upload_root, entry.name)
            if entry.is_dir(follow_symlinks=False):
                shutil.rmtree(path)
            elif entry.is_file(follow_symlinks=False) or entry.is_symlink():
                os.remove(path)
    except Exception:
        app.logger.exception("Database cleared, but some generated upload artifacts could not be removed")
        return jsonify({
            "message": "Database records cleared, but some generated files could not be removed.",
            "warning": True
        }), 207

    return jsonify({
        "message": "Q-SHIELD workspace cleared successfully.",
        "cleared": [
            "project scans, findings, inventory, assessments and recommendations",
            "benchmark and migration history",
            "project comparisons and generated evidence",
            "assisted migration and end-to-end audit history",
            "generated files under the backend uploads directory"
        ]
    }), 200


@app.route("/api/projects", methods=["GET"])
def get_projects():
    connection = get_db_connection()
    try:
        projects = connection.execute("""
            SELECT * FROM projects
            ORDER BY created_at DESC
        """).fetchall()
        return jsonify([dict(project) for project in projects])
    finally:
        connection.close()


@app.route("/api/projects", methods=["POST"])
def create_project():
    data = request.get_json(silent=True) or {}
    project_name = data.get("project_name", "").strip()

    if not project_name:
        return jsonify({"error": "Project name is required"}), 400

    connection = get_db_connection()
    try:
        cursor = connection.execute("""
            INSERT INTO projects (project_name)
            VALUES (?)
        """, (project_name,))
        project_id = cursor.lastrowid
        connection.commit()

        return jsonify({
            "message": "Project created successfully",
            "project_id": project_id,
            "project_name": project_name
        }), 201
    finally:
        connection.close()


# ==========================================
# MODULE 1 - CRYPTOGRAPHIC SCANNER
# ==========================================

MAX_FILES = 500
MAX_ARCHIVE_SIZE = 20 * 1024 * 1024
MAX_UNCOMPRESSED_SIZE = 50 * 1024 * 1024
MAX_SINGLE_FILE_SIZE = 2 * 1024 * 1024
GENERATED_ARTIFACT_NAMES = {
    "qshield_migration_report.json", "qshield_migration_readme.md",
    "qshield_comparison_report.json", "qshield_pqc_migration_report.json",
    "qshield_pqc_migration_readme.md", "qshield_module8_report.json",
    "qshield_module710_report.json", "qshield_audit_report.json",
    "comparison_report.json", "migration_report.json",
    "assisted_patch_report.json", "qshield_assisted_patch_report.json",
}
GENERATED_ARTIFACT_DIRS = {"__pycache__", ".git", "node_modules", "dist", "build", ".qshield", "qshield_reports", ".venv", "venv", "target", ".idea", ".vscode"}

def is_generated_artifact(filename):
    path = PurePosixPath(filename)
    parts = tuple(part.lower() for part in path.parts)
    return path.name.lower() in GENERATED_ARTIFACT_NAMES or any(
        part in GENERATED_ARTIFACT_DIRS for part in parts[:-1]
    )

INVENTORY_ALGORITHMS = {
    "RSA", "ECC", "AES", "DES",
    "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"
}


def validate_zip_file(zip_file):
    try:
        archive = zipfile.ZipFile(zip_file)
    except zipfile.BadZipFile:
        raise ValueError("Invalid ZIP file")

    members = archive.infolist()
    if getattr(zip_file, "seek", None):
        try:
            zip_file.seek(0, io.SEEK_END)
            compressed_size = zip_file.tell()
            zip_file.seek(0)
            if compressed_size > MAX_ARCHIVE_SIZE:
                archive.close()
                raise ValueError("ZIP exceeds the 20 MB compressed upload limit")
        except (OSError, AttributeError):
            pass

    if len(members) > MAX_FILES:
        archive.close()
        raise ValueError("ZIP contains too many files")

    total_size = 0

    for member in members:
        if member.is_dir():
            continue

        path = PurePosixPath(member.filename)

        if path.is_absolute() or ".." in path.parts:
            archive.close()
            raise ValueError("Unsafe file path detected")

        if "\\" in member.filename or ":" in member.filename:
            archive.close()
            raise ValueError("Unsafe archive path detected")

        unix_mode = member.external_attr >> 16
        if stat.S_ISLNK(unix_mode):
            archive.close()
            raise ValueError("Symbolic links are not allowed")

        total_size += member.file_size

        if member.file_size > MAX_SINGLE_FILE_SIZE:
            archive.close()
            raise ValueError("ZIP contains a file larger than the 2 MB per-file limit")

        if total_size > MAX_UNCOMPRESSED_SIZE:
            archive.close()
            raise ValueError("ZIP exceeds extraction size limit")

        if member.file_size > 0 and member.compress_size == 0:
            archive.close()
            raise ValueError("Invalid compressed file")

        if (
            member.compress_size > 0
            and member.file_size / member.compress_size > 100
        ):
            archive.close()
            raise ValueError("Suspicious ZIP compression ratio")

    return archive


# ==========================================
# MODULE 2 - CRYPTOGRAPHIC INVENTORY
# ==========================================

def extract_key_size(algorithm, source_text):
    if algorithm == "RSA":
        match = __import__("re").search(
            r"key_size\s*[:=]\s*(\d+)",
            source_text,
            __import__("re").IGNORECASE
        )
        return f"{match.group(1)} bits" if match else "Unknown"

    if algorithm == "ECC":
        re = __import__("re")
        match = re.search(r"SECP(\d+)[RK]?\d*", source_text, re.IGNORECASE)
        if match:
            return f"{match.group(1)}-bit curve"
        if re.search(r"\bX25519\b|\bEd25519\b", source_text, re.IGNORECASE):
            return "255-bit curve"
        if re.search(r"\bX448\b|\bEd448\b", source_text, re.IGNORECASE):
            return "448-bit curve"
        return "Unknown"

    if algorithm == "AES":
        re = __import__("re")
        match = re.search(r"\bAES[-_ ]?(\d{3})\b", source_text, re.IGNORECASE)
        return f"{match.group(1)} bits" if match else "Unknown"

    digest_sizes = {
        "SHA-256": "256-bit digest",
        "SHA-384": "384-bit digest",
        "SHA-512": "512-bit digest",
        "SHA-1": "160-bit digest",
        "MD5": "128-bit digest",
        "DES": "56 effective bits"
    }
    return digest_sizes.get(algorithm, "Unknown")


def determine_purpose(algorithm, findings):
    usages = " ".join(
        str(item.get("detected_usage", ""))
        for item in findings
    ).lower()

    if algorithm == "RSA":
        if "sign" in usages:
            return "Digital signature / asymmetric cryptography"
        if "encrypt" in usages:
            return "Asymmetric encryption"
        return "Asymmetric key generation or cryptographic operation"

    if algorithm == "ECC":
        if "ecdh" in usages:
            return "Elliptic-curve key agreement"
        if "ecdsa" in usages:
            return "Elliptic-curve digital signature"
        return "Elliptic-curve cryptography"

    if algorithm == "AES":
        return "Symmetric encryption"
    if algorithm == "DES":
        return "Legacy symmetric encryption"
    if algorithm in ("MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"):
        return "Cryptographic hashing"
    return "Cryptographic operation"


def determine_inventory_assessment(algorithm, findings):
    descriptions = " ".join(
        str(item.get("finding", ""))
        for item in findings
    ).lower()

    severities = {
        str(item.get("severity", "")).upper()
        for item in findings
    }

    if "CRITICAL" in severities:
        return "Critical security issue detected"
    if algorithm in ("MD5", "SHA-1", "DES"):
        return "Deprecated or weak algorithm"
    if algorithm in ("RSA", "ECC"):
        return "Quantum-vulnerable; post-quantum migration required"
    if algorithm == "AES" and "cbc" in descriptions:
        return "Review encryption mode and authentication"
    if algorithm == "AES":
        return "Generally retain; verify secure mode and key management"
    return "Requires security review"


def determine_migration_priority(algorithm, findings):
    severities = {
        str(item.get("severity", "")).upper()
        for item in findings
    }

    if "CRITICAL" in severities:
        return "CRITICAL"
    if algorithm in ("RSA", "ECC", "MD5", "SHA-1", "DES"):
        return "HIGH"
    if "HIGH" in severities:
        return "HIGH"
    if algorithm == "AES":
        return "MEDIUM" if "MEDIUM" in severities else "LOW"
    return "MEDIUM"


def generate_inventory(connection, project_id, file_contents):
    connection.execute(
        "DELETE FROM crypto_inventory WHERE project_id = ?",
        (project_id,)
    )

    rows = connection.execute("""
        SELECT *
        FROM scan_results
        WHERE project_id = ?
        ORDER BY file_name, line_number
    """, (project_id,)).fetchall()

    grouped = {}

    for row in rows:
        algorithm = row["algorithm"]
        file_name = row["file_name"]

        if algorithm not in INVENTORY_ALGORITHMS:
            continue

        grouped.setdefault((file_name, algorithm), []).append(dict(row))

    for (file_name, algorithm), findings in grouped.items():
        source_text = file_contents.get(file_name, "")

        connection.execute("""
            INSERT INTO crypto_inventory (
                project_id, algorithm, algorithm_type, key_size,
                file_name, purpose, assessment, migration_priority
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            project_id,
            algorithm,
            findings[0].get("algorithm_type", "Unknown"),
            extract_key_size(algorithm, source_text),
            file_name,
            determine_purpose(algorithm, findings),
            determine_inventory_assessment(algorithm, findings),
            determine_migration_priority(algorithm, findings)
        ))


@app.route("/api/scanner/upload", methods=["POST"])
def upload_project():
    if "file" not in request.files:
        return jsonify({"error": "No ZIP file uploaded"}), 400

    uploaded_file = request.files["file"]

    if not uploaded_file.filename:
        return jsonify({"error": "Filename is required"}), 400

    if not uploaded_file.filename.lower().endswith(".zip"):
        return jsonify({"error": "Only ZIP files are supported"}), 400

    project_name = request.form.get(
        "project_name",
        uploaded_file.filename[:-4]
    ).strip()

    if not project_name:
        return jsonify({"error": "Project name is required"}), 400

    connection = None
    archive = None

    try:
        file_bytes = uploaded_file.read()
        if not file_bytes:
            return jsonify({"error": "Uploaded ZIP is empty"}), 400

        archive = validate_zip_file(io.BytesIO(file_bytes))

        findings = []
        file_contents = {}
        scanned_files = 0
        skipped_files = 0

        for member in archive.infolist():
            if member.is_dir():
                continue

            path = PurePosixPath(member.filename)

            # Generated Q-SHIELD evidence is retained in the uploaded archive but
            # excluded from source scanning to avoid self-referential findings.
            if is_generated_artifact(member.filename):
                skipped_files += 1
                continue

            if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                skipped_files += 1
                continue

            with archive.open(member) as file:
                content = file.read()

            scanned_files += 1
            file_contents[member.filename] = content.decode(
                "utf-8", errors="replace"
            )
            findings.extend(scan_file(member.filename, content))

        connection = get_db_connection()

        cursor = connection.execute("""
            INSERT INTO projects (project_name, filename)
            VALUES (?, ?)
        """, (project_name, uploaded_file.filename))

        project_id = cursor.lastrowid

        for finding in findings:
            connection.execute("""
                INSERT INTO scan_results (
                    project_id, file_name, line_number, algorithm,
                    algorithm_type, detected_usage, severity, finding
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                project_id,
                finding.get("file_name"),
                finding.get("line_number"),
                finding.get("algorithm"),
                finding.get("algorithm_type"),
                finding.get("detected_usage"),
                finding.get("severity"),
                finding.get("finding")
            ))

        generate_inventory(connection, project_id, file_contents)
        connection.commit()

        inventory_count = connection.execute("""
            SELECT COUNT(*) AS count
            FROM crypto_inventory
            WHERE project_id = ?
        """, (project_id,)).fetchone()["count"]

        return jsonify({
            "message": "Cryptographic scan and inventory generation completed",
            "project_id": project_id,
            "project_name": project_name,
            "statistics": {
                "files_scanned": scanned_files,
                "files_skipped": skipped_files,
                "total_findings": len(findings),
                "critical": sum(f["severity"] == "CRITICAL" for f in findings),
                "high": sum(f["severity"] == "HIGH" for f in findings),
                "medium": sum(f["severity"] == "MEDIUM" for f in findings),
                "low": sum(f["severity"] == "LOW" for f in findings),
                "info": sum(f["severity"] == "INFO" for f in findings),
                "inventory_records": inventory_count
            },
            "findings": findings
        }), 201

    except ValueError as error:
        if connection:
            connection.rollback()
        return jsonify({"error": str(error)}), 400

    except zipfile.BadZipFile:
        if connection:
            connection.rollback()
        return jsonify({"error": "Invalid ZIP archive"}), 400

    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Scanner or inventory generation failed")
        return jsonify({
            "error": "Scanner failed. Check backend logs."
        }), 500

    finally:
        if connection:
            connection.close()
        if archive:
            archive.close()


@app.route("/api/scanner/results/<int:project_id>", methods=["GET"])
def get_scan_results(project_id):
    connection = get_db_connection()
    try:
        results = connection.execute("""
            SELECT * FROM scan_results
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
        """, (project_id,)).fetchall()

        return jsonify({
            "project_id": project_id,
            "total_findings": len(results),
            "findings": [dict(row) for row in results]
        })
    finally:
        connection.close()


@app.route("/api/scanner/summary/<int:project_id>", methods=["GET"])
def scanner_summary(project_id):
    connection = get_db_connection()
    try:
        project = connection.execute("""
            SELECT id, project_name FROM projects WHERE id = ?
        """, (project_id,)).fetchone()

        if not project:
            return jsonify({"error": "Project not found"}), 404

        rows = connection.execute("""
            SELECT severity, COUNT(*) AS count
            FROM scan_results
            WHERE project_id = ?
            GROUP BY severity
        """, (project_id,)).fetchall()

        total = connection.execute("""
            SELECT COUNT(*) AS count
            FROM scan_results WHERE project_id = ?
        """, (project_id,)).fetchone()["count"]

        severity_counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
            "LOW": 0, "INFO": 0
        }

        for row in rows:
            severity_counts[row["severity"]] = row["count"]

        return jsonify({
            "project": dict(project),
            "total_findings": total,
            "severity_breakdown": severity_counts
        })
    finally:
        connection.close()


# ==========================================
# MODULE 2 - INVENTORY API
# ==========================================

@app.route("/api/inventory/<int:project_id>", methods=["GET"])
def get_inventory(project_id):
    connection = get_db_connection()
    try:
        project = connection.execute("""
            SELECT id, project_name FROM projects WHERE id = ?
        """, (project_id,)).fetchone()

        if not project:
            return jsonify({"error": "Project not found"}), 404

        rows = connection.execute("""
            SELECT * FROM crypto_inventory
            WHERE project_id = ?
            ORDER BY
                CASE migration_priority
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                file_name, algorithm
        """, (project_id,)).fetchall()

        return jsonify({
            "project": dict(project),
            "project_id": project_id,
            "total_inventory_records": len(rows),
            "inventory": [dict(row) for row in rows]
        })
    finally:
        connection.close()


@app.route("/api/inventory/summary/<int:project_id>", methods=["GET"])
def inventory_summary(project_id):
    connection = get_db_connection()
    try:
        project = connection.execute("""
            SELECT id, project_name FROM projects WHERE id = ?
        """, (project_id,)).fetchone()

        if not project:
            return jsonify({"error": "Project not found"}), 404

        total = connection.execute("""
            SELECT COUNT(*) AS count
            FROM crypto_inventory WHERE project_id = ?
        """, (project_id,)).fetchone()["count"]

        algorithm_rows = connection.execute("""
            SELECT algorithm, COUNT(*) AS count
            FROM crypto_inventory
            WHERE project_id = ?
            GROUP BY algorithm
            ORDER BY count DESC, algorithm
        """, (project_id,)).fetchall()

        priority_rows = connection.execute("""
            SELECT migration_priority, COUNT(*) AS count
            FROM crypto_inventory
            WHERE project_id = ?
            GROUP BY migration_priority
        """, (project_id,)).fetchall()

        priority_counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
        }

        for row in priority_rows:
            priority_counts[row["migration_priority"]] = row["count"]

        return jsonify({
            "project": dict(project),
            "project_id": project_id,
            "total_inventory_records": total,
            "algorithm_breakdown": {
                row["algorithm"]: row["count"]
                for row in algorithm_rows
            },
            "migration_priority_breakdown": priority_counts
        })
    finally:
        connection.close()


# ==========================================
# ERROR HANDLERS
# ==========================================

@app.errorhandler(413)
def file_too_large(error):
    return jsonify({
        "error": "File exceeds the 20 MB upload limit"
    }), 413


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "API endpoint not found"}), 404




@app.errorhandler(Exception)
def handle_unexpected_error(error):
    """Return JSON for API failures so the React client can show actionable errors."""
    if isinstance(error, HTTPException):
        return jsonify({"error": error.description}), error.code
    app.logger.exception("Unhandled Q-SHIELD API error")
    return jsonify({"error": "Internal server error. Check the Flask terminal for the traceback."}), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
