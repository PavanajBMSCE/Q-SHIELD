"""Module 7.5: ML-DSA signature migration assessment and human review.

This module performs static inspection only. It never executes uploaded code
and never rewrites cryptographic signing operations automatically.
"""
import io
import json
import re
import stat
import zipfile
from pathlib import PurePosixPath
from uuid import uuid4
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, send_file

signature_migration_bp = Blueprint(
    "signature_migration", __name__, url_prefix="/api/project-migration/signature"
)

MAX_UPLOAD = 25 * 1024 * 1024
MAX_FILES = 1000
MAX_UNPACKED = 100 * 1024 * 1024
SOURCE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".h",
                     ".cpp", ".hpp", ".cs", ".go", ".php", ".rb"}
SKIP_PARTS = {".git", "venv", ".venv", "node_modules", "__pycache__", "dist", "build"}
JOBS = {}

RULES = [
    ("PY_RSA_SIGN", re.compile(r"\b(?:private_key|key)\.sign\s*\(", re.I),
     "RSA/EC signing call", "HIGH",
     "Determine the signature algorithm and protocol. For a post-quantum signature design, evaluate ML-DSA-65 (FIPS 204), including key distribution, signature format, verifier rollout and trust/certificate migration."),
    ("PY_ECDSA", re.compile(r"\b(?:ec\.ECDSA|ECDSA)\s*\(", re.I),
     "ECDSA signature operation", "HIGH",
     "Evaluate ML-DSA-65 (FIPS 204) as a post-quantum signature alternative. Do not replace ECDSA blindly: update key formats, signed-data formats, certificates, verifiers and interoperability."),
    ("JAVA_SIGNATURE", re.compile(r"Signature\.getInstance\s*\(", re.I),
     "Java Signature API", "HIGH",
     "Inspect the selected signature algorithm and its consumers. Plan an ML-DSA-65 migration with compatible provider, key encoding, signature encoding and verifier support."),
    ("NODE_SIGN", re.compile(r"\b(?:crypto\.)?(?:sign|createSign)\s*\(", re.I),
     "Node.js signing API", "HIGH",
     "Identify the key type and signature scheme. ML-DSA migration requires a compatible provider and coordinated signer/verifier/key-format changes."),
    ("OPENSSL_SIGN", re.compile(r"\b(?:EVP_DigestSignInit|EVP_PKEY_sign)\s*\(", re.I),
     "OpenSSL signing API", "HIGH",
     "Identify the EVP key type and provider support. Plan ML-DSA-65 provider, key encoding and verification interoperability before migration."),
    ("RSA_KEYGEN", re.compile(r"\b(?:rsa\.generate_private_key|generateKeyPairSync\s*\(\s*['\"]rsa)", re.I),
     "RSA key generation", "REVIEW",
     "RSA key generation alone does not prove signature usage. Establish whether the key signs, encrypts or transports keys before selecting ML-DSA or ML-KEM."),
]

def _scan_zip(raw):
    if len(raw) > MAX_UPLOAD:
        raise ValueError("Upload exceeds 25 MiB limit")
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise ValueError("Invalid ZIP archive") from exc
    infos = zf.infolist()
    if len(infos) > MAX_FILES:
        raise ValueError("Archive contains too many entries")
    total = 0
    findings = []
    files_scanned = 0
    for info in infos:
        if info.is_dir():
            continue
        p = PurePosixPath(info.filename)
        if p.is_absolute() or ".." in p.parts or "\\" in info.filename or ":" in info.filename:
            raise ValueError("Unsafe archive path detected")
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise ValueError("Symbolic links are not allowed")
        total += info.file_size
        if total > MAX_UNPACKED:
            raise ValueError("Archive exceeds 100 MiB uncompressed limit")
        if any(part.lower() in SKIP_PARTS for part in p.parts):
            continue
        if p.suffix.lower() not in SOURCE_EXTENSIONS or info.file_size > 2 * 1024 * 1024:
            continue
        try:
            content = zf.read(info).decode("utf-8", errors="replace")
        except Exception:
            continue
        files_scanned += 1
        # Avoid comment-only matches for common line-comment syntaxes.
        for line_no, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "*")):
                continue
            for rule_id, pattern, title, severity, guidance in RULES:
                if pattern.search(line):
                    findings.append({
                        "finding_id": f"F{len(findings)+1:03d}",
                        "rule_id": rule_id, "file": info.filename,
                        "line": line_no, "title": title, "severity": severity,
                        "status": "REVIEW_REQUIRED",
                        "recommended_design": guidance,
                        "automatic_patch_available": False,
                        "reason": "Signature migration changes key formats and verifier interoperability; no generic source rewrite is safe."
                    })
    zf.close()
    return files_scanned, findings

@signature_migration_bp.post("/analyze")
def analyze_signature_migration():
    upload = request.files.get("file")
    if not upload:
        return jsonify(error="ZIP file field 'file' is required"), 400
    try:
        raw = upload.read()
        scanned, findings = _scan_zip(raw)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    job_id = str(uuid4())
    report = {
        "product": "Q-SHIELD", "module": "7.5",
        "workflow": "ML_DSA_SIGNATURE_MIGRATION_REVIEW",
        "job_id": job_id, "created_at": datetime.now(timezone.utc).isoformat(),
        "original_filename": upload.filename or "project.zip",
        "source_files_scanned": scanned, "finding_count": len(findings),
        "patchable_count": 0, "guidance_only_count": len(findings),
        "decisions": [], "findings": findings,
        "limitations": [
            "Uploaded source code is inspected but never executed.",
            "Static matches are candidate locations, not proof of runtime signature use.",
            "No RSA/ECDSA source is automatically rewritten.",
            "ML-DSA-65 migration requires coordinated signer, verifier, key-format, certificate and protocol changes.",
            "ML-DSA is for digital signatures; ML-KEM is for key establishment."
        ]
    }
    JOBS[job_id] = {"report": report, "source": raw}
    return jsonify(report), 200

@signature_migration_bp.get("/<job_id>")
def get_signature_review(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify(error="Signature migration review not found"), 404
    return jsonify(job["report"]), 200

@signature_migration_bp.post("/<job_id>/decisions")
def record_signature_decisions(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify(error="Signature migration review not found"), 404
    data = request.get_json(silent=True) or {}
    decisions = data.get("decisions")
    if not isinstance(decisions, list) or not decisions:
        return jsonify(error="A non-empty decisions array is required"), 400
    valid_ids = {f["finding_id"] for f in job["report"]["findings"]}
    recorded = []
    for item in decisions:
        if not isinstance(item, dict):
            return jsonify(error="Each decision must be an object"), 400
        fid, decision = item.get("finding_id"), item.get("decision")
        if fid not in valid_ids or decision not in {"approve_migration_plan", "defer"}:
            return jsonify(error="Invalid finding_id or decision"), 400
        if any(d["finding_id"] == fid for d in job["report"]["decisions"]):
            return jsonify(error=f"Decision already recorded for {fid}"), 409
        entry = {"finding_id": fid, "decision": decision,
                 "recorded_at": datetime.now(timezone.utc).isoformat(),
                 "effect": "Human-approved migration planning only; no source patch applied."}
        job["report"]["decisions"].append(entry)
        recorded.append(entry)
    return jsonify(job_id=job_id, decisions_recorded=recorded,
                   source_modified=False,
                   message="Human decisions recorded. No cryptographic source code was rewritten."), 200

@signature_migration_bp.get("/<job_id>/report")
def download_signature_report(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify(error="Signature migration review not found"), 404
    payload = json.dumps(job["report"], indent=2).encode("utf-8")
    return send_file(io.BytesIO(payload), mimetype="application/json",
                     as_attachment=True, download_name=f"QSHIELD_MLDSA_Review_{job_id}.json")
