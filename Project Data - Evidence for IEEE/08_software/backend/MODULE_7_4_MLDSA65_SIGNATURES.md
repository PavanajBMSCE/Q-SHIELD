# Q-SHIELD Module 7.4 — ML-DSA-65 Digital Signature Demonstration

## Purpose
Adds ML-DSA-65 (FIPS 204) key generation, signing, verification, provider self-test, and tamper-detection demonstrations to the existing Module 7.3 project. This is not an automatic migration of uploaded RSA/ECDSA applications.

## Endpoints
- `GET /api/crypto-lab/ml-dsa/provider-self-test` — generate an ephemeral ML-DSA-65 key, sign a test message, and verify it. Returns 503 explicitly if the active provider does not expose ML-DSA.
- `POST /api/crypto-lab/ml-dsa/signature-round-trip` — accepts JSON `{ "message": "...", "context": "..." }`, generates an ephemeral key, signs and verifies, and returns public key and signature only. Private key is not returned.
- `POST /api/crypto-lab/ml-dsa/verify` — verifies a supplied raw public key and signature (base64), message, and optional context. Invalid signatures return `verified: false`.

## Sizes for ML-DSA-65
- Raw public key: 1952 bytes
- Signature: 3309 bytes
- Context: at most 255 bytes

## Local test
Stop Flask before installing/updating files. Preserve the existing database, uploads, and virtual environment. The package retains the prior Module 7.3 ML-KEM, Module 7.2 AES-GCM/Argon2id and earlier modules.

```powershell
python -c "from cryptography.hazmat.primitives.asymmetric import mldsa; k=mldsa.MLDSA65PrivateKey.generate(); p=k.public_key(); m=b'Q-SHIELD ML-DSA test'; c=b'qshield-test'; s=k.sign(m, context=c); p.verify(s,m,context=c); print('Public key:',len(p.public_bytes_raw())); print('Signature:',len(s)); print('Signature verified: True')"
python -m unittest tests.test_module74_mldsa -v
```

If the import fails, do not report ML-DSA as working; check the active Python interpreter and provider support. Tests explicitly skip the signing round-trip when the provider returns 503.

## Security boundaries
- Each demonstration request creates an ephemeral private key. The private key is never returned. This is not persistent signing-key management, certificate issuance, identity validation, revocation, or a production trust framework.
- Context strings must be agreed by both signer and verifier and are limited to 255 UTF-8 bytes.
- A valid signature proves verification against the supplied public key; it does not prove who owns that key.
- ML-DSA replaces signature operations only after application-specific key formats, protocols, certificates, and trust workflows are migrated. ML-KEM is for key establishment and is not a signature replacement.
