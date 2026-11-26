"""
Q-SHIELD – Module 4: PQC Recommendation Engine.

Generates transparent, standards-based migration recommendations from the
project's cryptographic inventory and scanner findings.
"""

import logging
import sqlite3

from flask import Blueprint, jsonify

from database.db import get_db_connection

logger = logging.getLogger(__name__)
recommendation_bp = Blueprint("recommendations", __name__)


def classify_asymmetric_purpose(purpose):
    """Classify an RSA/ECC use without confusing signatures and KEMs."""
    value = (purpose or "").lower()

    if any(term in value for term in ("signature", "signing", "ecdsa", "digital signature")):
        return "signature"

    if any(term in value for term in ("ecdh", "key agreement", "key exchange", "key establishment")):
        return "key_establishment"

    if "asymmetric encryption" in value or "encrypt" in value:
        return "encryption"

    return "ambiguous"


def build_inventory_recommendations(inventory_row):
    algorithm = (inventory_row["algorithm"] or "").upper()
    purpose = inventory_row["purpose"] or ""
    file_name = inventory_row["file_name"] or "Unknown file"
    priority = (inventory_row["migration_priority"] or "MEDIUM").upper()
    results = []

    if algorithm in ("RSA", "ECC"):
        usage = classify_asymmetric_purpose(purpose)

        if usage == "signature":
            results.append({
                "source_algorithm": algorithm,
                "recommended_algorithm": "ML-DSA-65",
                "reason": (
                    f"{algorithm} is used for digital signatures. Migrate to "
                    "ML-DSA-65, the NIST-standardized post-quantum signature "
                    "algorithm. Validate interoperability and signature sizes."
                ),
                "priority": priority,
                "standard_reference": "NIST FIPS 204"
            })
        elif usage == "key_establishment":
            results.append({
                "source_algorithm": algorithm,
                "recommended_algorithm": "ML-KEM-768",
                "reason": (
                    f"{algorithm} is used for key agreement or establishment. "
                    "Replace the key-establishment function with ML-KEM-768 "
                    "and use an authenticated symmetric cipher such as AES-256-GCM "
                    "for bulk data encryption."
                ),
                "priority": priority,
                "standard_reference": "NIST FIPS 203"
            })
        elif usage == "encryption":
            results.append({
                "source_algorithm": algorithm,
                "recommended_algorithm": "ML-KEM-768 + AES-256-GCM",
                "reason": (
                    f"{algorithm} appears to be used for asymmetric encryption. "
                    "Do not replace direct data encryption with ML-KEM alone. "
                    "Redesign as hybrid/envelope encryption: use ML-KEM-768 "
                    "to establish a shared secret, then AES-256-GCM to encrypt "
                    "the data. Confirm the exact protocol before migration."
                ),
                "priority": priority,
                "standard_reference": "NIST FIPS 203; NIST SP 800-38D"
            })
        else:
            results.append({
                "source_algorithm": algorithm,
                "recommended_algorithm": "ML-KEM-768 or ML-DSA-65 (usage-dependent)",
                "reason": (
                    f"The detected {algorithm} usage in {file_name} is not "
                    "specific enough to determine whether it provides key "
                    "establishment or digital signatures. Confirm its purpose: "
                    "use ML-KEM-768 for key establishment or ML-DSA-65 for "
                    "digital signatures."
                ),
                "priority": priority,
                "standard_reference": "NIST FIPS 203; NIST FIPS 204"
            })

    elif algorithm == "MD5":
        results.append({
            "source_algorithm": "MD5",
            "recommended_algorithm": "SHA-256",
            "reason": (
                "MD5 is cryptographically broken and unsuitable for security "
                "sensitive integrity or signature workflows. Replace it with "
                "SHA-256 or a stronger approved hash appropriate to the protocol."
            ),
            "priority": "HIGH",
            "standard_reference": "NIST FIPS 180-4"
        })

    elif algorithm == "SHA-1":
        results.append({
            "source_algorithm": "SHA-1",
            "recommended_algorithm": "SHA-256 or SHA-384",
            "reason": (
                "SHA-1 is deprecated for collision-resistant security uses. "
                "Migrate to SHA-256 or SHA-384 after checking protocol compatibility."
            ),
            "priority": "HIGH",
            "standard_reference": "NIST FIPS 180-4"
        })

    elif algorithm == "DES":
        results.append({
            "source_algorithm": "DES",
            "recommended_algorithm": "AES-256-GCM",
            "reason": (
                "DES has an inadequate effective key length. Replace it with "
                "authenticated encryption using AES-256-GCM and appropriate "
                "nonce management."
            ),
            "priority": "HIGH",
            "standard_reference": "NIST SP 800-38D"
        })

    return results


def build_finding_recommendation(finding):
    detected = " ".join(str(finding.get(field) or "") for field in (
        "algorithm", "detected_usage", "finding"
    )).lower()
    severity = (finding.get("severity") or "MEDIUM").upper()
    file_name = finding.get("file_name") or "Unknown file"
    line_number = finding.get("line_number")

    if "tlsv1.0" in detected or "tls 1.0" in detected or "tlsv1.1" in detected or "tls 1.1" in detected:
        return {
            "source_algorithm": "Legacy TLS",
            "recommended_algorithm": "TLS 1.2 or TLS 1.3",
            "reason": (
                f"Legacy TLS was detected in {file_name}"
                + (f" at line {line_number}" if line_number else "")
                + ". Disable obsolete protocol versions and configure modern "
                  "TLS with secure cipher suites and certificate validation."
            ),
            "priority": severity,
            "standard_reference": "NIST SP 800-52 Rev. 2"
        }

    if "verify=false" in detected or "certificate verification disabled" in detected:
        return {
            "source_algorithm": "Disabled TLS certificate verification",
            "recommended_algorithm": "TLS certificate verification enabled",
            "reason": (
                f"Certificate verification appears disabled in {file_name}"
                + (f" at line {line_number}" if line_number else "")
                + ". Enable certificate and hostname validation; do not suppress "
                  "verification errors in production."
            ),
            "priority": severity,
            "standard_reference": "NIST SP 800-52 Rev. 2"
        }

    if "hardcoded" in detected and any(word in detected for word in ("secret", "key", "token", "password", "credential")):
        return {
            "source_algorithm": "Hardcoded secret",
            "recommended_algorithm": "Managed secret storage and credential rotation",
            "reason": (
                f"A possible hardcoded credential was detected in {file_name}"
                + (f" at line {line_number}" if line_number else "")
                + ". Remove it from source control, rotate the exposed credential, "
                  "and load secrets from a protected secret manager or environment."
            ),
            "priority": "HIGH" if severity not in ("CRITICAL", "HIGH") else severity,
            "standard_reference": "NIST SP 800-57; secure secret-management practice"
        }

    if ("aes" in detected and ("cbc" in detected or "ecb" in detected)):
        return {
            "source_algorithm": "AES-CBC/ECB",
            "recommended_algorithm": "AES-256-GCM",
            "reason": (
                f"AES is used with a mode that does not provide authenticated "
                f"encryption by itself in {file_name}"
                + (f" at line {line_number}" if line_number else "")
                + ". Prefer AES-GCM with unique nonces and authenticated "
                  "associated data where applicable."
            ),
            "priority": severity,
            "standard_reference": "NIST SP 800-38D"
        }

    return None


def generate_recommendations(project_id):
    connection = get_db_connection()

    try:
        project = connection.execute(
            "SELECT id, project_name FROM projects WHERE id = ?",
            (project_id,)
        ).fetchone()

        if not project:
            return None

        inventory_rows = connection.execute("""
            SELECT algorithm, algorithm_type, key_size, file_name,
                   purpose, assessment, migration_priority
            FROM crypto_inventory
            WHERE project_id = ?
            ORDER BY file_name, algorithm
        """, (project_id,)).fetchall()

        finding_rows = connection.execute("""
            SELECT file_name, line_number, algorithm, algorithm_type,
                   detected_usage, severity, finding
            FROM scan_results
            WHERE project_id = ?
            ORDER BY file_name, line_number
        """, (project_id,)).fetchall()

        generated = []
        seen = set()

        def add_recommendation(item):
            key = (
                item["source_algorithm"],
                item["recommended_algorithm"],
                item["reason"]
            )
            if key not in seen:
                seen.add(key)
                generated.append(item)

        for row in inventory_rows:
            for item in build_inventory_recommendations(dict(row)):
                add_recommendation(item)

        for row in finding_rows:
            item = build_finding_recommendation(dict(row))
            if item:
                add_recommendation(item)

        connection.execute(
            "DELETE FROM recommendations WHERE project_id = ?",
            (project_id,)
        )

        for item in generated:
            connection.execute("""
                INSERT INTO recommendations (
                    project_id, source_algorithm, recommended_algorithm,
                    reason, priority, standard_reference
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                project_id,
                item["source_algorithm"],
                item["recommended_algorithm"],
                item["reason"],
                item["priority"],
                item["standard_reference"]
            ))

        connection.commit()

        saved_rows = connection.execute("""
            SELECT id, project_id, source_algorithm, recommended_algorithm,
                   reason, priority, standard_reference
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
                source_algorithm, recommended_algorithm
        """, (project_id,)).fetchall()

        recommendations = [dict(row) for row in saved_rows]
        priority_counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
        }
        for item in recommendations:
            priority = item["priority"].upper()
            if priority in priority_counts:
                priority_counts[priority] += 1

        return {
            "project": dict(project),
            "project_id": project_id,
            "total_recommendations": len(recommendations),
            "priority_breakdown": priority_counts,
            "recommendations": recommendations
        }

    except sqlite3.Error:
        connection.rollback()
        logger.exception("Database error while generating recommendations")
        raise
    finally:
        connection.close()


@recommendation_bp.route(
    "/api/recommendations/<int:project_id>/generate",
    methods=["POST"]
)
def generate_project_recommendations(project_id):
    try:
        result = generate_recommendations(project_id)
        if result is None:
            return jsonify({"error": "Project not found"}), 404
        return jsonify({
            "message": "PQC migration recommendations generated successfully",
            **result
        }), 200
    except Exception:
        logger.exception("Recommendation generation failed")
        return jsonify({
            "error": "Recommendation generation failed. Check backend logs."
        }), 500


@recommendation_bp.route(
    "/api/recommendations/<int:project_id>",
    methods=["GET"]
)
def get_project_recommendations(project_id):
    connection = get_db_connection()
    try:
        project = connection.execute(
            "SELECT id, project_name FROM projects WHERE id = ?",
            (project_id,)
        ).fetchone()

        if not project:
            return jsonify({"error": "Project not found"}), 404

        rows = connection.execute("""
            SELECT id, project_id, source_algorithm, recommended_algorithm,
                   reason, priority, standard_reference
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
                source_algorithm, recommended_algorithm
        """, (project_id,)).fetchall()

        recommendations = [dict(row) for row in rows]
        priority_counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
        }
        for item in recommendations:
            priority = (item["priority"] or "").upper()
            if priority in priority_counts:
                priority_counts[priority] += 1

        return jsonify({
            "project": dict(project),
            "project_id": project_id,
            "total_recommendations": len(recommendations),
            "priority_breakdown": priority_counts,
            "recommendations": recommendations
        }), 200
    except sqlite3.Error:
        logger.exception("Could not retrieve recommendations")
        return jsonify({"error": "Could not retrieve recommendations"}), 500
    finally:
        connection.close()
