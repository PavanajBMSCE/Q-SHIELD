"""
Q-SHIELD Module 5: cryptographic migration demonstrator.

This module uses:
- Conventional: RSA-3072 OAEP key transport + AES-256-GCM
- PQC: NIST ML-KEM-768 + AES-256-GCM
- Hybrid demo: RSA-3072 OAEP secret + ML-KEM-768 secret, combined with HKDF,
  then AES-256-GCM

The hybrid construction is an educational demonstrator, not a standardized
hybrid protocol profile. Keys are ephemeral and are discarded after the
encrypt/decrypt round-trip. Do not use this endpoint as production key storage.
"""

import base64
import json
import os
import re
import sqlite3
import time
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

from flask import Blueprint, current_app, jsonify, request, send_file
from werkzeug.utils import secure_filename

from config import Config
from database.db import get_db_connection

migration_bp = Blueprint("migration", __name__)

VALID_MODES = {"conventional", "pqc", "hybrid"}
MAX_FILE_BYTES = 10 * 1024 * 1024
RSA_BITS = 3072
AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12


def _derive_aes_key(secret_material, mode):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BYTES,
        salt=None,
        info=("Q-SHIELD-Migration-Demo-" + mode).encode("utf-8"),
    ).derive(secret_material)


def _safe_output_name(filename):
    name = secure_filename(filename or "uploaded_file")
    return name or "uploaded_file"


def _save_artifacts(job_id, original_filename, package_bytes, decrypted_bytes):
    output_dir = Path(Config.UPLOAD_FOLDER) / "migration_outputs"
    output_dir.mkdir(parents=True, exist_ok=True)

    safe_name = _safe_output_name(original_filename)
    package_path = output_dir / f"{job_id}.qspkg"
    decrypted_path = output_dir / f"{job_id}_{safe_name}.decrypted"

    package_path.write_bytes(package_bytes)
    decrypted_path.write_bytes(decrypted_bytes)
    return package_path, decrypted_path


def _record_measurements(mode, algorithm_label, input_size, output_size,
                         timings, key_size, ciphertext_size, success):
    connection = get_db_connection()
    try:
        # One migration_jobs row per measured stage makes the timing history
        # queryable without changing the existing database schema.
        for operation, elapsed in timings.items():
            connection.execute(
                """
                INSERT INTO migration_jobs
                    (mode, algorithm, operation, input_size, output_size,
                     execution_time, success)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (mode, algorithm_label, operation, input_size, output_size,
                 float(elapsed), 1 if success else 0),
            )
            connection.execute(
                """
                INSERT INTO benchmark_results
                    (algorithm, mode, operation, key_size, ciphertext_size,
                     execution_time)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (algorithm_label, mode, operation, int(key_size),
                 int(ciphertext_size), float(elapsed)),
            )
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
        raise
    finally:
        connection.close()


def run_demonstration(file_bytes, original_filename, mode):
    if mode not in VALID_MODES:
        raise ValueError("Mode must be conventional, pqc, or hybrid.")
    if not isinstance(file_bytes, bytes) or not file_bytes:
        raise ValueError("Upload a non-empty file.")
    if len(file_bytes) > MAX_FILE_BYTES:
        raise ValueError("File exceeds the 10 MB migration-demo limit.")

    timings = {}
    rsa_private = None
    mlkem_private = None
    rsa_secret = None
    kem_secret = None
    rsa_wrapped_secret = None
    kem_ciphertext = None
    public_key_size = 0

    # Generate only the keys needed for the selected demonstration mode.
    started = time.perf_counter()
    if mode in ("conventional", "hybrid"):
        rsa_private = rsa.generate_private_key(
            public_exponent=65537, key_size=RSA_BITS
        )
        rsa_public = rsa_private.public_key()
        public_key_size += len(
            rsa_public.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    if mode in ("pqc", "hybrid"):
        mlkem_private = MLKEM768PrivateKey.generate()
        # ML-KEM-768 public key size is fixed by FIPS 203.
        public_key_size += 1184
    timings["key_generation"] = time.perf_counter() - started

    # Encapsulate / transport fresh random key material.
    started = time.perf_counter()
    if mode in ("conventional", "hybrid"):
        rsa_secret = os.urandom(32)
        rsa_wrapped_secret = rsa_public.encrypt(
            rsa_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    if mode in ("pqc", "hybrid"):
        kem_secret, kem_ciphertext = mlkem_private.public_key().encapsulate()
    timings["key_encapsulation"] = time.perf_counter() - started

    if mode == "conventional":
        key_material = rsa_secret
        algorithm_label = "RSA-3072-OAEP + AES-256-GCM"
    elif mode == "pqc":
        key_material = kem_secret
        algorithm_label = "ML-KEM-768 + AES-256-GCM"
    else:
        # Domain-separated HKDF combines independent classical and PQC secrets.
        key_material = (
            len(rsa_secret).to_bytes(2, "big") + rsa_secret
            + len(kem_secret).to_bytes(2, "big") + kem_secret
        )
        algorithm_label = "RSA-3072 + ML-KEM-768 + HKDF + AES-256-GCM"

    started = time.perf_counter()
    aes_key = _derive_aes_key(key_material, mode)
    nonce = os.urandom(GCM_NONCE_BYTES)
    aad = b"Q-SHIELD-v1|" + mode.encode("ascii")
    encrypted = AESGCM(aes_key).encrypt(nonce, file_bytes, aad)
    timings["encryption"] = time.perf_counter() - started

    # Decrypt using the matching private keys and freshly recovered secrets.
    started = time.perf_counter()
    if mode in ("conventional", "hybrid"):
        recovered_rsa_secret = rsa_private.decrypt(
            rsa_wrapped_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    if mode in ("pqc", "hybrid"):
        recovered_kem_secret = mlkem_private.decapsulate(kem_ciphertext)

    if mode == "conventional":
        recovered_material = recovered_rsa_secret
    elif mode == "pqc":
        recovered_material = recovered_kem_secret
    else:
        recovered_material = (
            len(recovered_rsa_secret).to_bytes(2, "big") + recovered_rsa_secret
            + len(recovered_kem_secret).to_bytes(2, "big") + recovered_kem_secret
        )

    recovered_key = _derive_aes_key(recovered_material, mode)
    decrypted = AESGCM(recovered_key).decrypt(nonce, encrypted, aad)
    timings["decryption"] = time.perf_counter() - started

    started = time.perf_counter()
    integrity_verified = decrypted == file_bytes
    timings["integrity_verification"] = time.perf_counter() - started
    if not integrity_verified:
        raise RuntimeError("Decrypted file did not match the original.")

    job_id = str(uuid4())
    package = {
        "format": "Q-SHIELD encrypted demonstration package",
        "format_version": 1,
        "job_id": job_id,
        "mode": mode,
        "algorithm": algorithm_label,
        "original_filename": _safe_output_name(original_filename),
        "input_size_bytes": len(file_bytes),
        "nonce_base64": base64.b64encode(nonce).decode("ascii"),
        "aad_base64": base64.b64encode(aad).decode("ascii"),
        "ciphertext_base64": base64.b64encode(encrypted).decode("ascii"),
        "rsa_wrapped_secret_base64": (
            base64.b64encode(rsa_wrapped_secret).decode("ascii")
            if rsa_wrapped_secret else None
        ),
        "mlkem768_ciphertext_base64": (
            base64.b64encode(kem_ciphertext).decode("ascii")
            if kem_ciphertext else None
        ),
        "note": (
            "Demonstration artifact only. Ephemeral private keys are discarded "
            "after the verified round-trip; this package cannot be independently "
            "decrypted later."
        ),
    }
    package_bytes = json.dumps(package, indent=2).encode("utf-8")
    package_path, decrypted_path = _save_artifacts(
        job_id, original_filename, package_bytes, decrypted
    )

    ciphertext_size = len(encrypted)
    key_size = public_key_size
    _record_measurements(
        mode, algorithm_label, len(file_bytes), ciphertext_size,
        timings, key_size, ciphertext_size, integrity_verified
    )

    return {
        "job_id": job_id,
        "mode": mode,
        "algorithm": algorithm_label,
        "success": True,
        "integrity_verified": integrity_verified,
        "input_size_bytes": len(file_bytes),
        "encrypted_payload_size_bytes": ciphertext_size,
        "encrypted_package_size_bytes": len(package_bytes),
        "public_key_material_size_bytes": public_key_size,
        "rsa_wrapped_secret_size_bytes": len(rsa_wrapped_secret or b""),
        "mlkem768_ciphertext_size_bytes": len(kem_ciphertext or b""),
        "timings_seconds": timings,
        "encrypted_download": f"/api/migration/download/{job_id}/encrypted",
        "decrypted_download": f"/api/migration/download/{job_id}/decrypted",
        "security_note": package["note"],
    }


@migration_bp.route("/api/migration/demonstrate", methods=["POST"])
def demonstrate_migration():
    uploaded = request.files.get("file")
    mode = (request.form.get("mode") or "").strip().lower()

    if uploaded is None:
        return jsonify({"error": "Missing file field. Use multipart field 'file'."}), 400
    if mode not in VALID_MODES:
        return jsonify({
            "error": "Invalid mode.",
            "allowed_modes": sorted(VALID_MODES)
        }), 400

    file_bytes = uploaded.read(MAX_FILE_BYTES + 1)
    try:
        result = run_demonstration(file_bytes, uploaded.filename, mode)
        return jsonify({
            "message": "Encryption, decryption and integrity verification completed.",
            **result
        }), 200
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        current_app.logger.exception("Migration demonstration failed")
        return jsonify({
            "error": "Migration demonstration failed. Check the backend log."
        }), 500


@migration_bp.route(
    "/api/migration/download/<job_id>/<artifact>",
    methods=["GET"]
)
def download_migration_artifact(job_id, artifact):
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", job_id):
        return jsonify({"error": "Invalid job ID."}), 400

    output_dir = Path(Config.UPLOAD_FOLDER) / "migration_outputs"
    if artifact == "encrypted":
        path = output_dir / f"{job_id}.qspkg"
        download_name = f"qshield_{job_id}.qspkg"
    elif artifact == "decrypted":
        matches = list(output_dir.glob(f"{job_id}_*.decrypted"))
        path = matches[0] if matches else None
        download_name = path.name if path else "decrypted_file"
    else:
        return jsonify({"error": "Artifact must be encrypted or decrypted."}), 400

    if path is None or not path.is_file():
        return jsonify({"error": "Artifact not found."}), 404

    return send_file(path, as_attachment=True, download_name=download_name)


@migration_bp.route("/api/migration/benchmarks", methods=["GET"])
def get_migration_benchmarks():
    connection = get_db_connection()
    try:
        rows = connection.execute("""
            SELECT id, algorithm, mode, operation, key_size,
                   ciphertext_size, execution_time, created_at
            FROM benchmark_results
            ORDER BY id DESC
            LIMIT 300
        """).fetchall()
        return jsonify({
            "total": len(rows),
            "benchmarks": [dict(row) for row in rows]
        }), 200
    except sqlite3.Error:
        current_app.logger.exception("Could not retrieve migration benchmarks")
        return jsonify({"error": "Could not retrieve migration benchmarks."}), 500
    finally:
        connection.close()


@migration_bp.route("/api/migration/jobs", methods=["GET"])
def get_migration_jobs():
    connection = get_db_connection()
    try:
        rows = connection.execute("""
            SELECT id, mode, algorithm, operation, input_size, output_size,
                   execution_time, success, created_at
            FROM migration_jobs
            ORDER BY id DESC
            LIMIT 300
        """).fetchall()
        return jsonify({
            "total": len(rows),
            "jobs": [dict(row) for row in rows]
        }), 200
    except sqlite3.Error:
        current_app.logger.exception("Could not retrieve migration jobs")
        return jsonify({"error": "Could not retrieve migration jobs."}), 500
    finally:
        connection.close()
