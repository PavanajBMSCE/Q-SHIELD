# Module 7.6 — Classical vs ML-DSA-65 Signature Migration Demonstrator

## Purpose
Demonstrate classical RSA-3072 and ECDSA P-256 signatures alongside post-quantum ML-DSA-65 (FIPS 204), including successful verification and rejection of modified messages/signatures.

## APIs
- `GET /api/crypto-lab/signature-migration/provider-self-test`
- `POST /api/crypto-lab/signature-migration/round-trip`

Example request:
```json
{"message":"Q-SHIELD signature migration test","context":"qshield-migration-demo-v1"}
```

The response includes public key and signature byte counts, base64-encoded public keys/signatures, key-generation/signing/verification timings, and tamper-rejection results for RSA-3072, ECDSA-P-256 and ML-DSA-65.

## Security and interpretation
- A fresh ephemeral key is generated for each algorithm on each request. Private keys are never returned or persisted.
- RSA uses RSA-PSS with SHA-256. ECDSA uses P-256 with SHA-256. ML-DSA-65 uses the provider's FIPS 204 implementation and the supplied context string.
- Modified-message and modified-signature checks must both fail verification for each algorithm.
- Timings are local observations, not universal performance comparisons. Key-generation timing is reported separately.
- Encoded public-key sizes are not certificate sizes; RSA/ECDSA use DER SubjectPublicKeyInfo while ML-DSA uses its raw public-key encoding.
- This is not an automatic source-code migration, production key-management service, certificate authority, or trust-chain implementation.
- A real migration requires coordinated signer/verifier deployment, identity binding, certificate/trust-store and protocol changes, key lifecycle controls, and interoperability testing.
- ML-DSA is for digital signatures. ML-KEM is for key establishment.

## Validation
Run from `backend` with the project's active virtual environment:
```powershell
python -m unittest tests.test_module76_signature_demo -v
```
