"""Module 7.6: Classical versus ML-DSA-65 signature migration demonstrator.

Fresh ephemeral keys are generated per request. This is a local demonstration,
not a production key-management, certificate, trust, or migration service.
"""
import base64
import time

from flask import Blueprint, jsonify, request
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding

signature_demo_bp = Blueprint(
    "signature_demo", __name__, url_prefix="/api/crypto-lab/signature-migration"
)


def _mldsa65_class():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        return mldsa.MLDSA65PrivateKey
    except (ImportError, AttributeError) as exc:
        raise RuntimeError("ML-DSA-65 is unavailable in the active cryptography provider") from exc


def _public_der(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _verify_rejects(verify_fn):
    try:
        verify_fn()
        return False
    except InvalidSignature:
        return True


def _exercise(name, key_type, message, context):
    # Key generation is included in its own metric, not in sign/verify timings.
    key_start = time.perf_counter_ns()
    if key_type == "RSA-3072":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        public_key = private_key.public_key()
        public_bytes = _public_der(public_key)
        def sign(payload):
            return private_key.sign(payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                  salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        def verify(sig, payload):
            public_key.verify(sig, payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        params = {"key_size_bits": 3072, "scheme": "RSA-PSS-SHA256"}
    elif key_type == "ECDSA-P256":
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        public_bytes = _public_der(public_key)
        def sign(payload):
            return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        def verify(sig, payload):
            public_key.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
        params = {"curve": "P-256", "scheme": "ECDSA-SHA256"}
    else:
        MLDSA65PrivateKey = _mldsa65_class()
        private_key = MLDSA65PrivateKey.generate()
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes_raw()
        def sign(payload):
            return private_key.sign(payload, context=context)
        def verify(sig, payload):
            public_key.verify(sig, payload, context=context)
        params = {"parameter_set": "ML-DSA-65", "standard": "FIPS 204", "context": context.decode("utf-8")}
    keygen_ms = (time.perf_counter_ns() - key_start) / 1_000_000

    start = time.perf_counter_ns()
    signature = sign(message)
    sign_ms = (time.perf_counter_ns() - start) / 1_000_000

    start = time.perf_counter_ns()
    verify(signature, message)
    verify_ms = (time.perf_counter_ns() - start) / 1_000_000

    changed_message = message + b"\x00Q-SHIELD-TAMPER"
    message_tamper_rejected = _verify_rejects(lambda: verify(signature, changed_message))
    altered_signature = bytearray(signature)
    altered_signature[len(altered_signature) // 2] ^= 0x01
    signature_tamper_rejected = _verify_rejects(lambda: verify(bytes(altered_signature), message))

    return {
        "algorithm": name,
        "parameters": params,
        "public_key_bytes": len(public_bytes),
        "signature_bytes": len(signature),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "public_key_b64": base64.b64encode(public_bytes).decode("ascii"),
        "key_generation_ms": round(keygen_ms, 4),
        "signing_ms": round(sign_ms, 4),
        "verification_ms": round(verify_ms, 4),
        "valid_signature_accepted": True,
        "tampered_message_rejected": message_tamper_rejected,
        "tampered_signature_rejected": signature_tamper_rejected,
        "all_checks_passed": bool(message_tamper_rejected and signature_tamper_rejected),
    }


@signature_demo_bp.get("/provider-self-test")
def signature_migration_provider_test():
    try:
        cls = _mldsa65_class()
        private_key = cls.generate()
        public_key = private_key.public_key()
        message = b"Q-SHIELD Module 7.6 provider test"
        signature = private_key.sign(message, context=b"qshield-module-7.6")
        public_key.verify(signature, message, context=b"qshield-module-7.6")
        return jsonify(available=True, provider="cryptography ML-DSA-65", standard="FIPS 204",
                       public_key_bytes=len(public_key.public_bytes_raw()),
                       signature_bytes=len(signature), verified=True,
                       private_key_disclosed=False), 200
    except (RuntimeError, UnsupportedAlgorithm) as exc:
        return jsonify(available=False, verified=False, error=str(exc)), 503
    except Exception:
        return jsonify(available=False, verified=False,
                       error="Provider self-test failed; inspect backend logs"), 500


@signature_demo_bp.post("/round-trip")
def signature_migration_round_trip():
    data = request.get_json(silent=True) or {}
    message, context = data.get("message"), data.get("context", "qshield-migration-demo-v1")
    if not isinstance(message, str) or not isinstance(context, str):
        return jsonify(error="message and context must be strings"), 400
    message_bytes, context_bytes = message.encode("utf-8"), context.encode("utf-8")
    if not message_bytes:
        return jsonify(error="message must not be empty"), 400
    if len(message_bytes) > 1024 * 1024 or len(context_bytes) > 255:
        return jsonify(error="message exceeds 1 MiB or context exceeds 255 bytes"), 400

    try:
        results = [
            _exercise("RSA-3072", "RSA-3072", message_bytes, context_bytes),
            _exercise("ECDSA-P-256", "ECDSA-P256", message_bytes, context_bytes),
            _exercise("ML-DSA-65", "ML-DSA-65", message_bytes, context_bytes),
        ]
        return jsonify(
            module="7.6", workflow="CLASSICAL_VS_ML_DSA_SIGNATURE_DEMONSTRATION",
            message_bytes=len(message_bytes), context=context,
            results=results,
            all_algorithms_passed=all(item["all_checks_passed"] for item in results),
            private_keys_disclosed=False, demo_only=True,
            benchmark_note="Single-request local timings include fresh key generation separately. Results vary by hardware, provider, runtime and load; they are not universal performance claims.",
            limitations=[
                "Fresh ephemeral keys are generated for every request; no keys are persisted.",
                "This demonstrates signing and verification only; it does not migrate uploaded application code.",
                "Public-key and signature byte counts use each algorithm's returned encoding and are not certificate sizes.",
                "Production deployment requires key custody, identity binding, certificate or trust-store updates, protocol negotiation, verifier compatibility and lifecycle planning.",
                "ML-DSA-65 is a post-quantum digital signature scheme (FIPS 204); ML-KEM is for key establishment (FIPS 203)."
            ]
        ), 200
    except (RuntimeError, UnsupportedAlgorithm) as exc:
        return jsonify(error=str(exc), all_algorithms_passed=False), 503
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Signature migration demonstration failed")
        return jsonify(error="Signature demonstration failed; inspect backend logs"), 500
