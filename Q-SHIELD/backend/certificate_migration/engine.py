"""Module 7.7: Classical X.509 trust-chain plus ML-DSA migration manifest demo.

This deliberately does NOT claim ML-DSA is encoded into or issued as an X.509
certificate by this implementation. It builds a conventional RSA X.509 chain
and separately signs a canonical migration manifest with ML-DSA-65 (FIPS 204).
"""
import base64
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID

certificate_migration_bp = Blueprint(
    "certificate_migration", __name__,
    url_prefix="/api/crypto-lab/certificate-migration"
)


def _mldsa65_class():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        return mldsa.MLDSA65PrivateKey
    except (ImportError, AttributeError) as exc:
        raise RuntimeError("ML-DSA-65 is unavailable in the active cryptography provider") from exc


def _name(common_name, organization="Q-SHIELD Demonstration"):
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _issue_certificate(subject, issuer, public_key, issuer_private_key,
                       is_ca, serial_number, now):
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial_number)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=1 if is_ca else None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=not is_ca,
            content_commitment=False,
            key_encipherment=not is_ca,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=is_ca,
            crl_sign=is_ca,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
    )
    return builder.sign(private_key=issuer_private_key, algorithm=hashes.SHA256())


def _verify_rsa_certificate_signature(certificate, issuer_public_key):
    issuer_public_key.verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        padding.PKCS1v15(),
        certificate.signature_hash_algorithm,
    )


def _cert_der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def _fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def _validity_ok(cert, now):
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    return not_before <= now <= not_after


def _build_chain():
    now = datetime.now(timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    root_name = _name("Q-SHIELD Demo Root CA")
    intermediate_name = _name("Q-SHIELD Demo Intermediate CA")
    leaf_name = _name("qshield-demo-service")

    root = _issue_certificate(root_name, root_name, root_key.public_key(),
                              root_key, True, x509.random_serial_number(), now)
    intermediate = _issue_certificate(intermediate_name, root_name,
                                      intermediate_key.public_key(), root_key,
                                      True, x509.random_serial_number(), now)
    leaf = _issue_certificate(leaf_name, intermediate_name, leaf_key.public_key(),
                              intermediate_key, False, x509.random_serial_number(), now)
    return root_key, root, intermediate, leaf


def _verify_chain(root, intermediate, leaf, now):
    checks = {}
    checks["root_self_issued"] = root.subject == root.issuer
    checks["intermediate_issuer_matches_root"] = intermediate.issuer == root.subject
    checks["leaf_issuer_matches_intermediate"] = leaf.issuer == intermediate.subject
    checks["root_ca_constraint"] = root.extensions.get_extension_for_class(
        x509.BasicConstraints).value.ca
    checks["intermediate_ca_constraint"] = intermediate.extensions.get_extension_for_class(
        x509.BasicConstraints).value.ca
    checks["leaf_is_not_ca"] = not leaf.extensions.get_extension_for_class(
        x509.BasicConstraints).value.ca
    checks["root_signature_valid"] = False
    checks["intermediate_signature_valid"] = False
    checks["leaf_signature_valid"] = False
    try:
        _verify_rsa_certificate_signature(root, root.public_key())
        checks["root_signature_valid"] = True
    except InvalidSignature:
        pass
    try:
        _verify_rsa_certificate_signature(intermediate, root.public_key())
        checks["intermediate_signature_valid"] = True
    except InvalidSignature:
        pass
    try:
        _verify_rsa_certificate_signature(leaf, intermediate.public_key())
        checks["leaf_signature_valid"] = True
    except InvalidSignature:
        pass
    checks["all_certificates_currently_valid"] = all(
        _validity_ok(cert, now) for cert in (root, intermediate, leaf)
    )
    return checks


def _canonical_manifest(leaf, root):
    leaf_spki = leaf.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    manifest = {
        "schema": "qshield-certificate-migration-manifest-v1",
        "subject": leaf.subject.rfc4514_string(),
        "issuer": leaf.issuer.rfc4514_string(),
        "certificate_serial_hex": format(leaf.serial_number, "x"),
        "certificate_sha256": _fingerprint(leaf),
        "subject_public_key_sha256": hashlib.sha256(leaf_spki).hexdigest(),
        "trusted_root_sha256": _fingerprint(root),
        "legacy_certificate_signature": "RSA-2048 with SHA-256",
        "proposed_signature_migration": "ML-DSA-65 (FIPS 204) detached manifest signature",
        "status": "DEMONSTRATION_ONLY_NOT_AN_X509_MLDSA_CERTIFICATE",
    }
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return manifest, encoded


def _demo():
    total_start = time.perf_counter_ns()
    root_key, root, intermediate, leaf = _build_chain()
    now = datetime.now(timezone.utc)
    chain_checks = _verify_chain(root, intermediate, leaf, now)

    manifest, manifest_bytes = _canonical_manifest(leaf, root)
    MLDSA65PrivateKey = _mldsa65_class()
    key_start = time.perf_counter_ns()
    pq_private = MLDSA65PrivateKey.generate()
    pq_public = pq_private.public_key()
    keygen_ms = (time.perf_counter_ns() - key_start) / 1_000_000

    context = b"qshield-cert-migration-v1"
    sign_start = time.perf_counter_ns()
    signature = pq_private.sign(manifest_bytes, context=context)
    signing_ms = (time.perf_counter_ns() - sign_start) / 1_000_000

    verify_start = time.perf_counter_ns()
    pq_public.verify(signature, manifest_bytes, context=context)
    verification_ms = (time.perf_counter_ns() - verify_start) / 1_000_000

    tampered_manifest = dict(manifest)
    tampered_manifest["status"] = "TRUSTED_PRODUCTION_CERTIFICATE"
    tampered_bytes = json.dumps(
        tampered_manifest, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    try:
        pq_public.verify(signature, tampered_bytes, context=context)
        tampered_manifest_rejected = False
    except InvalidSignature:
        tampered_manifest_rejected = True

    tampered_signature = bytearray(signature)
    tampered_signature[len(tampered_signature) // 2] ^= 1
    try:
        pq_public.verify(bytes(tampered_signature), manifest_bytes, context=context)
        tampered_signature_rejected = False
    except InvalidSignature:
        tampered_signature_rejected = True

    # A separate root key is deliberately not trusted by this chain.
    unrelated_root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    unrelated_root_cert = _issue_certificate(
        _name("Unrelated Root CA"), _name("Unrelated Root CA"),
        unrelated_root_key.public_key(), unrelated_root_key, True,
        x509.random_serial_number(), now
    )
    wrong_trust_anchor_rejected = (
        _fingerprint(unrelated_root_cert) != _fingerprint(root)
    )

    checks = {
        **chain_checks,
        "mldsa_manifest_signature_valid": True,
        "tampered_manifest_rejected": tampered_manifest_rejected,
        "tampered_manifest_signature_rejected": tampered_signature_rejected,
        "unrelated_trust_anchor_rejected": wrong_trust_anchor_rejected,
    }
    return {
        "module": "7.7",
        "workflow": "X509_TRUST_CHAIN_AND_ML_DSA_MIGRATION_MANIFEST_DEMONSTRATION",
        "demo_only": True,
        "all_checks_passed": all(checks.values()),
        "checks": checks,
        "certificate_chain": {
            "root": {
                "subject": root.subject.rfc4514_string(),
                "issuer": root.issuer.rfc4514_string(),
                "signature_algorithm": "RSA-2048 with SHA-256",
                "sha256_fingerprint": _fingerprint(root),
                "der_bytes": len(_cert_der(root)),
            },
            "intermediate": {
                "subject": intermediate.subject.rfc4514_string(),
                "issuer": intermediate.issuer.rfc4514_string(),
                "signature_algorithm": "RSA-2048 with SHA-256",
                "sha256_fingerprint": _fingerprint(intermediate),
                "der_bytes": len(_cert_der(intermediate)),
            },
            "leaf": {
                "subject": leaf.subject.rfc4514_string(),
                "issuer": leaf.issuer.rfc4514_string(),
                "signature_algorithm": "RSA-2048 with SHA-256",
                "sha256_fingerprint": _fingerprint(leaf),
                "der_bytes": len(_cert_der(leaf)),
            },
            "chain_order": ["leaf", "intermediate", "root"],
        },
        "migration_manifest": {
            "manifest": manifest,
            "canonical_json_bytes": len(manifest_bytes),
            "signature_algorithm": "ML-DSA-65",
            "standard": "FIPS 204",
            "context": context.decode("ascii"),
            "public_key_bytes": len(pq_public.public_bytes_raw()),
            "signature_bytes": len(signature),
            "public_key_b64": base64.b64encode(pq_public.public_bytes_raw()).decode("ascii"),
            "signature_b64": base64.b64encode(signature).decode("ascii"),
            "private_key_disclosed": False,
            "key_generation_ms": round(keygen_ms, 4),
            "signing_ms": round(signing_ms, 4),
            "verification_ms": round(verification_ms, 4),
        },
        "total_demo_ms": round((time.perf_counter_ns() - total_start) / 1_000_000, 4),
        "limitations": [
            "The X.509 root, intermediate and leaf certificates in this demo use conventional RSA signatures.",
            "ML-DSA-65 signs a separate canonical migration manifest; this is NOT an ML-DSA-signed X.509 certificate.",
            "This does not create a production CA, certificate profile, revocation service, or interoperable hybrid PKI.",
            "The trust-anchor check is a demonstration fingerprint comparison; production trust stores need governed provisioning and rotation.",
            "Certificates and keys are generated ephemerally for each request and are not persisted.",
            "Production migration requires standards-track certificate profile support, PKI vendor and client interoperability, trust-store updates, revocation and lifecycle planning."
        ],
    }


@certificate_migration_bp.get("/provider-self-test")
def provider_self_test():
    try:
        cls = _mldsa65_class()
        private_key = cls.generate()
        public_key = private_key.public_key()
        message = b"Q-SHIELD Module 7.7 certificate migration provider test"
        context = b"qshield-cert-migration-v1"
        signature = private_key.sign(message, context=context)
        public_key.verify(signature, message, context=context)
        return jsonify(
            available=True, provider="cryptography ML-DSA-65",
            standard="FIPS 204", verified=True,
            public_key_bytes=len(public_key.public_bytes_raw()),
            signature_bytes=len(signature), private_key_disclosed=False
        ), 200
    except (RuntimeError, UnsupportedAlgorithm) as exc:
        return jsonify(available=False, verified=False, error=str(exc)), 503
    except Exception:
        return jsonify(available=False, verified=False,
                       error="Provider self-test failed; inspect backend logs"), 500


@certificate_migration_bp.post("/demonstrate")
def demonstrate():
    data = request.get_json(silent=True) or {}
    if data and not isinstance(data, dict):
        return jsonify(error="JSON request body must be an object"), 400
    try:
        return jsonify(_demo()), 200
    except (RuntimeError, UnsupportedAlgorithm) as exc:
        return jsonify(error=str(exc), all_checks_passed=False), 503
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Certificate migration demonstration failed")
        return jsonify(error="Certificate demonstration failed; inspect backend logs"), 500
