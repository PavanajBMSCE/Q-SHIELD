"""Module 7.8: Educational dual-signature policy demonstrator.

Creates independent RSA-PSS-SHA256 and ML-DSA-65 signatures over the same
canonical message envelope. Verification policies are evaluated separately.
This is NOT a standardized hybrid signature protocol or production PKI.
"""
import base64
import hashlib
import json
import time

from flask import Blueprint, jsonify, request
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

hybrid_signature_bp = Blueprint(
    "hybrid_signature", __name__,
    url_prefix="/api/crypto-lab/hybrid-signatures"
)


def _mldsa_class():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        return mldsa.MLDSA65PrivateKey
    except (ImportError, AttributeError) as exc:
        raise RuntimeError("ML-DSA-65 is unavailable in the active cryptography provider") from exc


def _canonical_message(message, context):
    envelope = {
        "schema": "qshield-dual-signature-envelope-v1",
        "context": context,
        "message": message,
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _verify_rsa(public_key, signature, payload):
    try:
        public_key.verify(
            signature, payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def _verify_mldsa(public_key, signature, payload, context):
    try:
        public_key.verify(signature, payload, context=context.encode("utf-8"))
        return True
    except InvalidSignature:
        return False


def _policy_result(policy, classical_valid, pqc_valid):
    if policy == "DUAL_REQUIRED":
        accepted = classical_valid and pqc_valid
        reason = "Both classical and post-quantum signatures must verify."
    elif policy == "CLASSICAL_ONLY":
        accepted = classical_valid
        reason = "Only the classical RSA-PSS signature is required by this demonstration policy."
    elif policy == "PQC_ONLY":
        accepted = pqc_valid
        reason = "Only the ML-DSA-65 signature is required by this demonstration policy."
    else:
        raise ValueError("Unsupported policy")
    return {"policy": policy, "accepted": accepted, "reason": reason}


def _run_demo(message, context):
    payload = _canonical_message(message, context)

    rsa_start = time.perf_counter_ns()
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    rsa_public = rsa_private.public_key()
    rsa_keygen_ms = (time.perf_counter_ns() - rsa_start) / 1_000_000

    MLDSA65PrivateKey = _mldsa_class()
    pq_start = time.perf_counter_ns()
    pq_private = MLDSA65PrivateKey.generate()
    pq_public = pq_private.public_key()
    pq_keygen_ms = (time.perf_counter_ns() - pq_start) / 1_000_000

    sign_start = time.perf_counter_ns()
    rsa_signature = rsa_private.sign(
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    rsa_sign_ms = (time.perf_counter_ns() - sign_start) / 1_000_000

    sign_start = time.perf_counter_ns()
    pq_signature = pq_private.sign(payload, context=context.encode("utf-8"))
    pq_sign_ms = (time.perf_counter_ns() - sign_start) / 1_000_000

    verify_start = time.perf_counter_ns()
    rsa_valid = _verify_rsa(rsa_public, rsa_signature, payload)
    rsa_verify_ms = (time.perf_counter_ns() - verify_start) / 1_000_000
    verify_start = time.perf_counter_ns()
    pq_valid = _verify_mldsa(pq_public, pq_signature, payload, context)
    pq_verify_ms = (time.perf_counter_ns() - verify_start) / 1_000_000

    # Tamper the canonical message envelope.
    tampered_payload = _canonical_message(message + " [TAMPERED]", context)
    tampered_rsa_valid = _verify_rsa(rsa_public, rsa_signature, tampered_payload)
    tampered_pq_valid = _verify_mldsa(pq_public, pq_signature, tampered_payload, context)

    # Tamper each signature independently.
    bad_rsa = bytearray(rsa_signature)
    bad_rsa[len(bad_rsa) // 2] ^= 1
    bad_pq = bytearray(pq_signature)
    bad_pq[len(bad_pq) // 2] ^= 1

    bad_rsa_valid = _verify_rsa(rsa_public, bytes(bad_rsa), payload)
    bad_pq_valid = _verify_mldsa(pq_public, bytes(bad_pq), payload, context)

    # Evaluate policy behavior for a valid message and controlled failure states.
    policy_cases = {
        "both_valid": {
            "classical_valid": rsa_valid,
            "pqc_valid": pq_valid,
        },
        "classical_signature_invalid": {
            "classical_valid": bad_rsa_valid,
            "pqc_valid": pq_valid,
        },
        "pqc_signature_invalid": {
            "classical_valid": rsa_valid,
            "pqc_valid": bad_pq_valid,
        },
    }
    policies = {}
    for case, state in policy_cases.items():
        policies[case] = {
            policy: _policy_result(policy, state["classical_valid"], state["pqc_valid"])
            for policy in ("DUAL_REQUIRED", "CLASSICAL_ONLY", "PQC_ONLY")
        }

    checks = {
        "rsa_valid_signature_accepted": rsa_valid,
        "mldsa_valid_signature_accepted": pq_valid,
        "tampered_message_rejected_by_rsa": not tampered_rsa_valid,
        "tampered_message_rejected_by_mldsa": not tampered_pq_valid,
        "tampered_rsa_signature_rejected": not bad_rsa_valid,
        "tampered_mldsa_signature_rejected": not bad_pq_valid,
        "dual_policy_accepts_both_valid": policies["both_valid"]["DUAL_REQUIRED"]["accepted"],
        "dual_policy_rejects_classical_failure": not policies["classical_signature_invalid"]["DUAL_REQUIRED"]["accepted"],
        "dual_policy_rejects_pqc_failure": not policies["pqc_signature_invalid"]["DUAL_REQUIRED"]["accepted"],
        "classical_only_accepts_when_pqc_fails": policies["pqc_signature_invalid"]["CLASSICAL_ONLY"]["accepted"],
        "pqc_only_accepts_when_classical_fails": policies["classical_signature_invalid"]["PQC_ONLY"]["accepted"],
    }

    from cryptography.hazmat.primitives import serialization
    rsa_public_der = rsa_public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pq_public_raw = pq_public.public_bytes_raw()
    return {
        "module": "7.8",
        "workflow": "EDUCATIONAL_DUAL_CLASSICAL_AND_PQC_SIGNATURE_POLICY_DEMONSTRATION",
        "demo_only": True,
        "all_checks_passed": all(checks.values()),
        "message_sha256": hashlib.sha256(payload).hexdigest(),
        "message_bytes": len(payload),
        "checks": checks,
        "policies": policies,
        "algorithms": {
            "classical": {
                "name": "RSA-3072",
                "scheme": "RSA-PSS-SHA256",
                "public_key_bytes": len(rsa_public_der),
                "signature_bytes": len(rsa_signature),
                "key_generation_ms": round(rsa_keygen_ms, 4),
                "signing_ms": round(rsa_sign_ms, 4),
                "verification_ms": round(rsa_verify_ms, 4),
                "public_key_b64": _b64(rsa_public_der),
                "signature_b64": _b64(rsa_signature),
            },
            "post_quantum": {
                "name": "ML-DSA-65",
                "standard": "FIPS 204",
                "context": context,
                "public_key_bytes": len(pq_public_raw),
                "signature_bytes": len(pq_signature),
                "key_generation_ms": round(pq_keygen_ms, 4),
                "signing_ms": round(pq_sign_ms, 4),
                "verification_ms": round(pq_verify_ms, 4),
                "public_key_b64": _b64(pq_public_raw),
                "signature_b64": _b64(pq_signature),
            },
        },
        "private_keys_disclosed": False,
        "limitations": [
            "This is an educational dual-signature construction, not a standardized hybrid signature protocol.",
            "RSA-PSS and ML-DSA signatures are independent signatures over the same canonical envelope.",
            "Policies are demonstration rules and do not establish signer identity, certificate trust, key custody or protocol negotiation.",
            "Fresh ephemeral keys are generated for every request and are not persisted.",
            "Production use requires interoperable protocol design, identity binding, key and certificate lifecycle, downgrade protection, verifier rollout and security review.",
            "ML-DSA-65 is for digital signatures; ML-KEM is for key establishment."
        ],
    }


@hybrid_signature_bp.get("/provider-self-test")
def provider_self_test():
    try:
        cls = _mldsa_class()
        private = cls.generate()
        public = private.public_key()
        message = b"Q-SHIELD Module 7.8 provider self-test"
        context = b"qshield-hybrid-signature-v1"
        signature = private.sign(message, context=context)
        public.verify(signature, message, context=context)
        return jsonify(
            available=True, provider="cryptography ML-DSA-65",
            standard="FIPS 204", verified=True,
            public_key_bytes=len(public.public_bytes_raw()),
            signature_bytes=len(signature),
            private_key_disclosed=False,
        ), 200
    except (RuntimeError, UnsupportedAlgorithm) as exc:
        return jsonify(available=False, verified=False, error=str(exc)), 503
    except Exception:
        return jsonify(available=False, verified=False,
                       error="Provider self-test failed; inspect backend logs"), 500


@hybrid_signature_bp.post("/demonstrate")
def demonstrate():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="JSON request body must be an object"), 400
    message = data.get("message")
    context = data.get("context", "qshield-hybrid-signature-v1")
    if not isinstance(message, str) or not message.strip():
        return jsonify(error="message must be a non-empty string"), 400
    if not isinstance(context, str) or not context.strip():
        return jsonify(error="context must be a non-empty string"), 400
    if len(message.encode("utf-8")) > 16_384 or len(context.encode("utf-8")) > 255:
        return jsonify(error="message or context exceeds the demonstration size limit"), 400
    try:
        return jsonify(_run_demo(message, context)), 200
    except (RuntimeError, UnsupportedAlgorithm) as exc:
        return jsonify(error=str(exc), all_checks_passed=False), 503
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Hybrid signature demonstration failed")
        return jsonify(error="Hybrid signature demonstration failed; inspect backend logs"), 500
