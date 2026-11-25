"""Executable AES-256-GCM and Argon2id demonstrations for Q-SHIELD.

The AES endpoint returns a demo key to enable a self-contained round trip.
Never return encryption keys from a production service; use a KMS/HSM or
managed key-encryption design. Passwords and hashes are never logged.
"""
import base64
import binascii
import os
from flask import Blueprint, jsonify, request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import UnsupportedAlgorithm
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

crypto_lab_bp = Blueprint("crypto_lab", __name__, url_prefix="/api/crypto-lab")
_password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)

def _b64decode(value, field):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field} is not valid base64") from exc

@crypto_lab_bp.post("/aes-gcm/encrypt")
def aes_gcm_encrypt():
    data = request.get_json(silent=True) or {}
    plaintext = data.get("plaintext")
    aad = data.get("aad", "")
    if not isinstance(plaintext, str) or not isinstance(aad, str):
        return jsonify(error="plaintext and aad must be strings"), 400
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)  # 96-bit nonce; unique per key is mandatory.
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad.encode("utf-8") if aad else None)
    return jsonify(algorithm="AES-256-GCM", key_b64=base64.b64encode(key).decode(),
                   nonce_b64=base64.b64encode(nonce).decode(),
                   ciphertext_b64=base64.b64encode(ciphertext).decode(), aad=aad,
                   tag_included=True, demo_only=True,
                   warning="Demo only: key is returned for round-trip testing. Never expose production keys."), 200

@crypto_lab_bp.post("/aes-gcm/decrypt")
def aes_gcm_decrypt():
    data = request.get_json(silent=True) or {}
    try:
        key = _b64decode(data.get("key_b64"), "key_b64")
        nonce = _b64decode(data.get("nonce_b64"), "nonce_b64")
        ciphertext = _b64decode(data.get("ciphertext_b64"), "ciphertext_b64")
        aad = data.get("aad", "")
        if len(key) != 32: raise ValueError("AES-256 key must be exactly 32 bytes")
        if len(nonce) != 12: raise ValueError("GCM nonce must be exactly 12 bytes")
        if not isinstance(aad, str): raise ValueError("aad must be a string")
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad.encode("utf-8") if aad else None)
        return jsonify(verified=True, plaintext=plaintext.decode("utf-8"), algorithm="AES-256-GCM"), 200
    except ValueError as exc:
        return jsonify(verified=False, error=str(exc)), 400
    except Exception:
        # Includes InvalidTag: do not disclose cryptographic internals.
        return jsonify(verified=False, error="Authentication failed: ciphertext, key, nonce or AAD is invalid"), 400

@crypto_lab_bp.post("/password/hash")
def password_hash():
    data = request.get_json(silent=True) or {}
    password = data.get("password")
    if not isinstance(password, str) or not password:
        return jsonify(error="password must be a non-empty string"), 400
    if len(password.encode("utf-8")) > 1024:
        return jsonify(error="password exceeds the 1024-byte limit"), 400
    encoded = _password_hasher.hash(password)
    return jsonify(algorithm="Argon2id", encoded_hash=encoded,
                   parameters={"time_cost": 3, "memory_cost_kib": 65536, "parallelism": 2},
                   demo_only=True), 200

@crypto_lab_bp.post("/password/verify")
def password_verify():
    data = request.get_json(silent=True) or {}
    password, encoded = data.get("password"), data.get("encoded_hash")
    if not isinstance(password, str) or not isinstance(encoded, str) or not password or not encoded:
        return jsonify(error="password and encoded_hash are required strings"), 400
    try:
        valid = _password_hasher.verify(encoded, password)
        return jsonify(verified=bool(valid), algorithm="Argon2id",
                       needs_rehash=_password_hasher.check_needs_rehash(encoded)), 200
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return jsonify(verified=False, algorithm="Argon2id"), 200


# MODULE 7.3 - ML-KEM-768 + HKDF-SHA256 + AES-256-GCM
# This is a self-contained interoperability/functional demonstration.
# It does not modify uploaded projects or define a production wire protocol.

def _mlkem_provider():
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem
        return mlkem.MLKEM768PrivateKey
    except (ImportError, AttributeError) as exc:
        raise RuntimeError(
            "ML-KEM-768 is unavailable in this cryptography provider. "
            "Install the pinned Q-SHIELD cryptography dependency and verify provider support."
        ) from exc

def _derive_pqc_aead_key(shared_secret: bytes, aad: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"Q-SHIELD-MODULE-7.3-ML-KEM-768-AES-256-GCM-v1\x00" + aad
    ).derive(shared_secret)

@crypto_lab_bp.post("/ml-kem/round-trip")
def mlkem_round_trip():
    data = request.get_json(silent=True) or {}
    plaintext, aad = data.get("plaintext"), data.get("aad", "")
    if not isinstance(plaintext, str) or not isinstance(aad, str):
        return jsonify(error="plaintext and aad must be strings"), 400
    if len(plaintext.encode("utf-8")) > 1024 * 1024 or len(aad.encode("utf-8")) > 16384:
        return jsonify(error="plaintext or aad exceeds the demonstration size limit"), 400
    try:
        MLKEM768 = _mlkem_provider()
        # Initiator creates a key pair; responder encapsulates to its public key.
        recipient_private = MLKEM768.generate()
        recipient_public = recipient_private.public_key()
        initiator_secret, kem_ciphertext = recipient_public.encapsulate()
        responder_secret = recipient_private.decapsulate(kem_ciphertext)
        secrets_match = (initiator_secret == responder_secret)
        if not secrets_match:
            raise RuntimeError("ML-KEM shared-secret agreement failed")

        aad_bytes = aad.encode("utf-8")
        aead_key = _derive_pqc_aead_key(initiator_secret, aad_bytes)
        nonce = os.urandom(12)
        encrypted = AESGCM(aead_key).encrypt(nonce, plaintext.encode("utf-8"), aad_bytes or None)

        responder_key = _derive_pqc_aead_key(responder_secret, aad_bytes)
        recovered = AESGCM(responder_key).decrypt(nonce, encrypted, aad_bytes or None)
        plaintext_match = (recovered == plaintext.encode("utf-8"))

        return jsonify(
            algorithm="ML-KEM-768 + HKDF-SHA256 + AES-256-GCM",
            kem="ML-KEM-768 (FIPS 203)", kdf="HKDF-SHA256", aead="AES-256-GCM",
            public_key_bytes=len(recipient_public.public_bytes_raw()),
            kem_ciphertext_bytes=len(kem_ciphertext), shared_secret_bytes=len(initiator_secret),
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            ciphertext_b64=base64.b64encode(encrypted).decode("ascii"),
            aad=aad, shared_secrets_match=secrets_match,
            plaintext_recovered=recovered.decode("utf-8"), plaintext_match=plaintext_match,
            verified=bool(secrets_match and plaintext_match), demo_only=True,
            private_key_disclosed=False, shared_secret_disclosed=False,
            warning="Demonstration only. This endpoint performs both roles in one process; it is not a production protocol or a migration of uploaded application code."
        ), 200
    except RuntimeError as exc:
        return jsonify(error=str(exc), verified=False), 503
    except Exception:
        app_logger = __import__("logging").getLogger(__name__)
        app_logger.exception("ML-KEM demonstration failed")
        return jsonify(error="ML-KEM demonstration failed; inspect server logs"), 500

@crypto_lab_bp.get("/ml-kem/provider-self-test")
def mlkem_provider_self_test():
    try:
        MLKEM768 = _mlkem_provider()
        private_key = MLKEM768.generate()
        public_key = private_key.public_key()
        encapsulated, ciphertext = public_key.encapsulate()
        decapsulated = private_key.decapsulate(ciphertext)
        return jsonify(
            provider="cryptography ML-KEM-768", available=True,
            public_key_bytes=len(public_key.public_bytes_raw()),
            kem_ciphertext_bytes=len(ciphertext), shared_secret_bytes=len(encapsulated),
            shared_secrets_match=(encapsulated == decapsulated),
            verified=(encapsulated == decapsulated), private_key_disclosed=False
        ), 200
    except RuntimeError as exc:
        return jsonify(provider="cryptography ML-KEM-768", available=False, error=str(exc)), 503
    except Exception:
        __import__("logging").getLogger(__name__).exception("ML-KEM provider self-test failed")
        return jsonify(available=False, error="ML-KEM provider self-test failed; inspect server logs"), 500


# MODULE 7.4 - ML-DSA-65 DIGITAL SIGNATURE DEMONSTRATION (FIPS 204)
# This is a functional signature demonstration, not an automatic rewrite
# of uploaded RSA/ECDSA applications or a production certificate system.

def _mldsa65_provider():
    """Return the cryptography ML-DSA-65 private-key class or fail explicitly."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        return mldsa.MLDSA65PrivateKey
    except (ImportError, AttributeError) as exc:
        raise RuntimeError(
            "ML-DSA-65 is unavailable in this cryptography provider. "
            "Verify that the active environment exposes cryptography.hazmat.primitives.asymmetric.mldsa."
        ) from exc


def _validate_mldsa_message_context(message, context):
    if not isinstance(message, str):
        raise ValueError("message must be a string")
    if not isinstance(context, str):
        raise ValueError("context must be a string")
    message_bytes = message.encode("utf-8")
    context_bytes = context.encode("utf-8")
    if len(message_bytes) > 1024 * 1024:
        raise ValueError("message exceeds the 1 MiB demonstration limit")
    if len(context_bytes) > 255:
        raise ValueError("ML-DSA context must not exceed 255 bytes")
    return message_bytes, context_bytes


@crypto_lab_bp.get("/ml-dsa/provider-self-test")
def mldsa_provider_self_test():
    try:
        MLDSA65PrivateKey = _mldsa65_provider()
        private_key = MLDSA65PrivateKey.generate()
        public_key = private_key.public_key()
        message = b"Q-SHIELD ML-DSA-65 provider self-test"
        context = b"qshield-self-test-v1"
        signature = private_key.sign(message, context=context)
        public_key.verify(signature, message, context=context)
        return jsonify(
            provider="cryptography ML-DSA-65", standard="FIPS 204",
            available=True, verified=True,
            public_key_bytes=len(public_key.public_bytes_raw()),
            signature_bytes=len(signature), private_key_disclosed=False
        ), 200
    except (RuntimeError, UnsupportedAlgorithm) as exc:
        return jsonify(provider="cryptography ML-DSA-65", available=False,
                       verified=False, error=str(exc)), 503
    except Exception:
        __import__("logging").getLogger(__name__).exception("ML-DSA provider self-test failed")
        return jsonify(available=False, verified=False,
                       error="ML-DSA provider self-test failed; inspect server logs"), 500


@crypto_lab_bp.post("/ml-dsa/signature-round-trip")
def mldsa_signature_round_trip():
    data = request.get_json(silent=True) or {}
    message, context = data.get("message"), data.get("context", "")
    try:
        message_bytes, context_bytes = _validate_mldsa_message_context(message, context)
        MLDSA65PrivateKey = _mldsa65_provider()
        private_key = MLDSA65PrivateKey.generate()
        public_key = private_key.public_key()
        signature = private_key.sign(message_bytes, context=context_bytes)
        public_key.verify(signature, message_bytes, context=context_bytes)
        return jsonify(
            algorithm="ML-DSA-65", standard="FIPS 204",
            public_key_b64=base64.b64encode(public_key.public_bytes_raw()).decode("ascii"),
            signature_b64=base64.b64encode(signature).decode("ascii"),
            public_key_bytes=len(public_key.public_bytes_raw()),
            signature_bytes=len(signature), context=context,
            verified=True, demo_only=True, private_key_disclosed=False,
            warning=("Demonstration only: a fresh ephemeral key is generated for this request. "
                     "This does not migrate uploaded RSA/ECDSA code or establish a certificate/trust system.")
        ), 200
    except ValueError as exc:
        return jsonify(verified=False, error=str(exc)), 400
    except (RuntimeError, UnsupportedAlgorithm) as exc:
        return jsonify(verified=False, error=str(exc)), 503
    except Exception:
        __import__("logging").getLogger(__name__).exception("ML-DSA signature demonstration failed")
        return jsonify(verified=False, error="ML-DSA signature demonstration failed; inspect server logs"), 500


@crypto_lab_bp.post("/ml-dsa/verify")
def mldsa_verify_external_signature():
    data = request.get_json(silent=True) or {}
    message, context = data.get("message"), data.get("context", "")
    try:
        message_bytes, context_bytes = _validate_mldsa_message_context(message, context)
        public_key_bytes = _b64decode(data.get("public_key_b64"), "public_key_b64")
        signature = _b64decode(data.get("signature_b64"), "signature_b64")
        if len(public_key_bytes) != 1952:
            raise ValueError("ML-DSA-65 public key must be exactly 1952 bytes")
        if len(signature) != 3309:
            raise ValueError("ML-DSA-65 signature must be exactly 3309 bytes")
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa
            public_key = mldsa.MLDSA65PublicKey.from_public_bytes(public_key_bytes)
        except (ImportError, AttributeError) as exc:
            raise RuntimeError(
                "ML-DSA-65 is unavailable in this cryptography provider."
            ) from exc
        from cryptography.exceptions import InvalidSignature
        try:
            public_key.verify(signature, message_bytes, context=context_bytes)
            valid = True
        except InvalidSignature:
            valid = False
        return jsonify(algorithm="ML-DSA-65", verified=valid,
                       result="VALID" if valid else "INVALID_SIGNATURE"), 200
    except ValueError as exc:
        return jsonify(verified=False, error=str(exc)), 400
    except (RuntimeError, UnsupportedAlgorithm) as exc:
        return jsonify(verified=False, error=str(exc)), 503
    except Exception:
        __import__("logging").getLogger(__name__).exception("ML-DSA verification failed")
        return jsonify(verified=False, error="Signature verification failed; inspect server logs"), 500
