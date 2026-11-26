"""Module 7.9: PQC migration policy evaluation and human decision workflow."""
import io
import json
import os
import re
import stat
import uuid
import zipfile
from datetime import datetime, timezone, date
from pathlib import PurePosixPath

from flask import Blueprint, jsonify, request, current_app
from scanner.crypto_detector import scan_file, SUPPORTED_EXTENSIONS

migration_policy_bp = Blueprint(
    "migration_policy", __name__, url_prefix="/api/crypto-lab/migration-policy"
)
MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_FILES = 1000
MAX_UNPACKED_BYTES = 100 * 1024 * 1024
SKIP_PARTS = {"node_modules", "venv", ".venv", "__pycache__", ".git", "dist", "build", ".qshield", "qshield_reports"}
GENERATED_ARTIFACT_NAMES = {
    "qshield_migration_report.json", "qshield_migration_readme.md",
    "qshield_comparison_report.json", "qshield_pqc_migration_report.json",
    "qshield_pqc_migration_readme.md", "qshield_module8_report.json",
    "qshield_module710_report.json", "qshield_audit_report.json",
    "comparison_report.json", "migration_report.json",
    "assisted_patch_report.json", "qshield_assisted_patch_report.json",
}

POLICY_CATALOG = {
    "profile_options": ["TRANSITION", "STRICT"],
    "algorithm_policies": {
        "RSA": {
            "action": "PLAN_PQC_MIGRATION",
            "target": "ML-KEM for key establishment; ML-DSA for signatures",
            "priority": "HIGH",
            "rationale": "Classify the RSA operation first; do not perform a blind algorithm substitution."
        },
        "ECC": {
            "action": "PLAN_PQC_MIGRATION",
            "target": "ML-KEM for key establishment; ML-DSA for signatures",
            "priority": "HIGH",
            "rationale": "Classify ECDH, ECDSA and other ECC uses before selecting a PQC replacement."
        },
        "DES": {
            "action": "REMEDIATE_LEGACY_CRYPTO",
            "target": "AES-256-GCM where symmetric authenticated encryption is required",
            "priority": "CRITICAL",
            "rationale": "DES/3DES is legacy; migration requires reviewing mode, key handling and data format."
        },
        "MD5": {
            "action": "REVIEW_HASH_CONTEXT",
            "target": "SHA-256/384 for general integrity; Argon2id for password storage",
            "priority": "HIGH",
            "rationale": "Do not replace password hashing with a fast digest; determine the use case."
        },
        "SHA-1": {
            "action": "REVIEW_HASH_CONTEXT",
            "target": "SHA-256/384 for collision-resistant hashing",
            "priority": "HIGH",
            "rationale": "Confirm the use case and compatibility requirements before changing digest algorithms."
        },
        "AES": {
            "action": "REVIEW_SYMMETRIC_CONFIGURATION",
            "target": "AES-256-GCM with unique nonces and authenticated-tag validation",
            "priority": "MEDIUM",
            "rationale": "AES itself is not a PQC-vulnerable public-key algorithm; inspect mode and key management."
        },
        "Weak Configuration": {
            "action": "REMEDIATE_CONFIGURATION",
            "target": "Remove weak protocol/configuration and validate secure defaults",
            "priority": "HIGH",
            "rationale": "Weak configuration needs direct remediation and regression testing."
        },
        "Hardcoded Secret": {
            "action": "ROTATE_AND_EXTERNALIZE_SECRET",
            "target": "Secret manager or protected environment injection; rotate exposed credential",
            "priority": "CRITICAL",
            "rationale": "Treat possible exposed credentials as compromised until investigated."
        },
        "SHA-256": {
            "action": "RETAIN_AND_REVIEW_USAGE",
            "target": "Retain for suitable integrity/hash use; use Argon2id for passwords",
            "priority": "INFO",
            "rationale": "SHA-256 is not itself a PQC migration finding."
        },
        "SHA-384": {
            "action": "RETAIN_AND_REVIEW_USAGE",
            "target": "Retain for suitable integrity/hash use",
            "priority": "INFO",
            "rationale": "SHA-384 is not itself a PQC migration finding."
        },
        "SHA-512": {
            "action": "RETAIN_AND_REVIEW_USAGE",
            "target": "Retain for suitable integrity/hash use",
            "priority": "INFO",
            "rationale": "SHA-512 is not itself a PQC migration finding."
        },
    },
}

def _store_dir():
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], "migration_policy")
    os.makedirs(path, exist_ok=True)
    return path

def _save_job(job):
    path = os.path.join(_store_dir(), job["job_id"] + ".json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(job, handle, indent=2)
    return path

def _load_job(job_id):
    if not re.fullmatch(r"[0-9a-f-]{36}", str(job_id)):
        return None
    path = os.path.join(_store_dir(), job_id + ".json")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)

def _safe_zip_scan(file_bytes):
    if len(file_bytes) > MAX_ARCHIVE_BYTES:
        raise ValueError("ZIP exceeds the 25 MiB upload limit")
    try:
        archive = zipfile.ZipFile(io.BytesIO(file_bytes))
    except (zipfile.BadZipFile, OSError):
        raise ValueError("Uploaded file is not a valid ZIP archive")
    findings = []
    scanned_files = []
    total = 0
    entries = archive.infolist()
    if len(entries) > MAX_FILES:
        raise ValueError("ZIP contains more than 1000 entries")
    for entry in entries:
        name = entry.filename.replace("\\", "/")
        path = PurePosixPath(name)
        mode = entry.external_attr >> 16
        if path.is_absolute() or ".." in path.parts or stat.S_ISLNK(mode):
            raise ValueError("ZIP contains an unsafe path or symbolic link")
        if entry.is_dir():
            continue
        if any(part.lower() in SKIP_PARTS for part in path.parts):
            continue
        if path.name.lower() in GENERATED_ARTIFACT_NAMES:
            continue
        ext = os.path.splitext(name)[1].lower()
        if ext not in SUPPORTED_EXTENSIONS:
            continue
        total += entry.file_size
        if total > MAX_UNPACKED_BYTES:
            raise ValueError("ZIP expands beyond the 100 MiB limit")
        if entry.file_size > MAX_UNPACKED_BYTES:
            raise ValueError("ZIP entry exceeds the unpacked size limit")
        content = archive.read(entry)
        file_findings = scan_file(name, content)
        scanned_files.append(name)
        for item in file_findings:
            findings.append({
                "finding_id": "F-" + uuid.uuid4().hex[:10].upper(),
                "file": name,
                "line_number": item.get("line_number"),
                "algorithm": item.get("algorithm", "Unknown"),
                "algorithm_type": item.get("algorithm_type", "Unknown"),
                "severity": item.get("severity", "INFO"),
                "finding": item.get("finding", ""),
                "recommendation": item.get("recommendation", ""),
            })
    return scanned_files, findings

def _priority_rank(value):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(value, 3)

def _policy_for(finding, profile):
    """Apply the selected governance profile without changing scanner detections."""
    profile = (profile or "TRANSITION").upper()
    algorithm = finding["algorithm"]
    policy = POLICY_CATALOG["algorithm_policies"].get(algorithm)
    if not policy:
        policy = {
            "action": "MANUAL_REVIEW",
            "target": finding.get("recommendation") or "Review finding and determine migration requirements",
            "priority": finding.get("severity", "MEDIUM"),
            "rationale": "No dedicated rule exists in the current Q-SHIELD policy catalog."
        }

    action = policy["action"]
    severity = finding.get("severity", "INFO")

    # A policy profile changes the compliance decision, not the underlying
    # scanner finding count. Transition allows a managed migration plan for
    # public-key and symmetric-configuration findings. Strict requires these
    # to remain open as explicit policy-review obligations until reviewed.
    if severity == "INFO" and action == "RETAIN_AND_REVIEW_USAGE":
        status = "COMPLIANT_OR_INFORMATIONAL"
    elif profile == "STRICT" and action in {
        "PLAN_PQC_MIGRATION",
        "REVIEW_HASH_CONTEXT",
        "REVIEW_SYMMETRIC_CONFIGURATION",
        "MANUAL_REVIEW",
    }:
        status = "POLICY_REVIEW_REQUIRED"
    elif action in {
        "ROTATE_AND_EXTERNALIZE_SECRET",
        "REMEDIATE_LEGACY_CRYPTO",
        "REMEDIATE_CONFIGURATION",
        "REVIEW_HASH_CONTEXT",
    }:
        status = "REMEDIATION_REQUIRED"
    elif action in {
        "PLAN_PQC_MIGRATION",
        "REVIEW_SYMMETRIC_CONFIGURATION",
        "MANUAL_REVIEW",
    }:
        status = "MIGRATION_PLAN_REQUIRED"
    else:
        status = "COMPLIANT_OR_INFORMATIONAL"

    return {
        **finding,
        "policy_profile": profile,
        "policy_action": action,
        "target_guidance": policy["target"],
        "policy_priority": policy["priority"],
        "policy_rationale": policy["rationale"],
        "policy_status": status,
        "policy_status_explanation": (
            "Strict policy requires an explicit governance review before this item can be accepted."
            if profile == "STRICT" and status == "POLICY_REVIEW_REQUIRED"
            else "Transition policy permits a managed migration plan for this finding."
            if profile == "TRANSITION" and status == "MIGRATION_PLAN_REQUIRED"
            else "Direct remediation is required before this finding can be closed."
            if status == "REMEDIATION_REQUIRED"
            else "Informational or compliant classification; retain context and review usage."
        ),
        "decision": "PENDING",
        "decision_note": None,
        "exception_expiry": None,
    }


def _summary(items):
    counts = {}
    for item in items:
        counts[item["policy_status"]] = counts.get(item["policy_status"], 0) + 1
    return {
        "total_findings": len(items),
        "status_counts": counts,
        "pending_decisions": sum(1 for item in items if item["decision"] == "PENDING"),
        "critical_or_high": sum(1 for item in items if item["policy_priority"] in {"CRITICAL", "HIGH"}),
    }

@migration_policy_bp.get("/catalog")
def policy_catalog():
    return jsonify({
        "policy_name": "Q-SHIELD PQC Migration Governance Policy",
        "version": "1.0",
        "catalog": POLICY_CATALOG,
        "decision_types": ["APPROVE_REMEDIATION_PLAN", "ACCEPT_TIME_BOUND_EXCEPTION", "DEFER_WITH_RATIONALE"],
        "note": "Policy evaluation is advisory governance support; it is not a compliance certification."
    })

@migration_policy_bp.post("/evaluate")
def evaluate_policy():
    upload = request.files.get("file")
    profile = (request.form.get("policy_profile") or "TRANSITION").upper()
    if not upload or not upload.filename:
        return jsonify(error="A project ZIP is required in multipart field 'file'"), 400
    if profile not in POLICY_CATALOG["profile_options"]:
        return jsonify(error="policy_profile must be TRANSITION or STRICT"), 400
    data = upload.read(MAX_ARCHIVE_BYTES + 1)
    try:
        scanned_files, raw_findings = _safe_zip_scan(data)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    if not scanned_files:
        return jsonify(error="No supported source files were found in the ZIP"), 400
    items = [_policy_for(item, profile) for item in raw_findings]
    items.sort(key=lambda x: (_priority_rank(x["policy_priority"]), x["file"], x["line_number"] or 0))
    now = datetime.now(timezone.utc).isoformat()
    job = {
        "job_id": str(uuid.uuid4()),
        "created_at": now,
        "policy_name": "Q-SHIELD PQC Migration Governance Policy",
        "policy_version": "1.0",
        "policy_profile": profile,
        "source_filename": os.path.basename(upload.filename),
        "source_sha256": __import__("hashlib").sha256(data).hexdigest(),
        "source_modified": False,
        "scanned_files": scanned_files,
        "findings": items,
        "summary": _summary(items),
        "audit_events": [{
            "event": "POLICY_EVALUATED",
            "timestamp": now,
            "actor": "system",
            "details": "Static findings evaluated against the selected migration policy."
        }],
        "limitations": [
            "Static scanner findings are candidates and may include false positives or miss runtime behavior.",
            "RSA/ECC findings require operation classification: key establishment, signatures and other uses have different migration targets.",
            "No source code is changed by this policy workflow.",
            "Exceptions require a rationale, accountable owner and future expiry date.",
            "This workflow is not a certification or a substitute for a full cryptographic inventory and security review."
        ]
    }
    _save_job(job)
    return jsonify(job), 201

@migration_policy_bp.get("/<job_id>")
def get_policy_job(job_id):
    job = _load_job(job_id)
    if not job:
        return jsonify(error="Policy evaluation job not found"), 404
    return jsonify(job)

@migration_policy_bp.post("/<job_id>/decisions")
def record_decisions(job_id):
    job = _load_job(job_id)
    if not job:
        return jsonify(error="Policy evaluation job not found"), 404
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("decisions"), list):
        return jsonify(error="JSON body must contain a decisions array"), 400
    if not data["decisions"] or len(data["decisions"]) > 500:
        return jsonify(error="Provide between 1 and 500 decisions"), 400
    actor = data.get("actor", "reviewer")
    if not isinstance(actor, str) or not actor.strip() or len(actor) > 120:
        return jsonify(error="actor must be a non-empty string up to 120 characters"), 400
    by_id = {item["finding_id"]: item for item in job["findings"]}
    seen = set()
    now = datetime.now(timezone.utc).isoformat()
    accepted = []
    for decision in data["decisions"]:
        if not isinstance(decision, dict):
            return jsonify(error="Each decision must be an object"), 400
        fid = decision.get("finding_id")
        action = decision.get("decision")
        if fid not in by_id or fid in seen:
            return jsonify(error="Unknown or duplicate finding_id: " + str(fid)), 400
        if action not in {"APPROVE_REMEDIATION_PLAN", "ACCEPT_TIME_BOUND_EXCEPTION", "DEFER_WITH_RATIONALE"}:
            return jsonify(error="Unsupported decision for " + str(fid)), 400
        note = decision.get("note")
        if not isinstance(note, str) or len(note.strip()) < 8 or len(note) > 1000:
            return jsonify(error="Each decision requires a rationale of 8 to 1000 characters"), 400
        expiry = decision.get("exception_expiry")
        if action == "ACCEPT_TIME_BOUND_EXCEPTION":
            try:
                parsed = date.fromisoformat(expiry)
            except (TypeError, ValueError):
                return jsonify(error="Exception requires exception_expiry in YYYY-MM-DD format"), 400
            if parsed <= date.today():
                return jsonify(error="Exception expiry must be a future date"), 400
        elif expiry is not None:
            return jsonify(error="exception_expiry is only valid for time-bound exceptions"), 400
        seen.add(fid)
        accepted.append((by_id[fid], action, note.strip(), expiry))
    for item, action, note, expiry in accepted:
        item["decision"] = action
        item["decision_note"] = note
        item["exception_expiry"] = expiry
        item["decision_actor"] = actor.strip()
        item["decision_timestamp"] = now
        job["audit_events"].append({
            "event": action, "finding_id": item["finding_id"],
            "timestamp": now, "actor": actor.strip(), "details": note,
            "exception_expiry": expiry
        })
    job["summary"] = _summary(job["findings"])
    _save_job(job)
    return jsonify({"job_id": job_id, "recorded": len(accepted),
                    "summary": job["summary"], "source_modified": False,
                    "audit_events": job["audit_events"]}), 200
