# Q-SHIELD Module 7.3 — ML-KEM-768 Hybrid Demonstrator

## Endpoints
- `GET /api/crypto-lab/ml-kem/provider-self-test` — provider capability and encapsulation/decapsulation check.
- `POST /api/crypto-lab/ml-kem/round-trip` — one-process demonstration of ML-KEM-768, HKDF-SHA256 and AES-256-GCM.

Example JSON: `{"plaintext":"Q-SHIELD test","aad":"qshield-demo-v1"}`.

## Design
The responder creates an ML-KEM-768 key pair. The initiator encapsulates to its public key. Both sides derive the AES-256-GCM key independently using HKDF-SHA256 with a domain-separated `info` value and the caller-provided AAD as context. AES-GCM encrypts and authenticates the message. The demonstration decapsulates and decrypts within the same process, then compares secrets and recovered plaintext. Private keys and shared secrets are never returned.

## Important limitations
This is a functional cryptographic demonstration, not a production network protocol, key lifecycle, signature scheme, or automatic transformation of uploaded projects. The endpoint performs both protocol roles in one process. Production deployment requires authenticated peer identity, signed/transcript-bound protocol messages, replay and downgrade protection, key storage/rotation, protocol versioning, error handling, and interoperability testing. ML-KEM is for key establishment; it does not replace RSA/ECDSA signatures. Use ML-DSA for a separately designed signature migration.

## Test
Run from `backend` with the project virtual environment activated:
`python -m unittest tests.test_module73_mlkem -v`

## Provider API compatibility correction

For `cryptography==50.0.2`, import `mlkem` from `cryptography.hazmat.primitives.asymmetric` and use `MLKEM768PrivateKey`. `encapsulate()` returns `(shared_secret, ciphertext)` in that order. The integration uses this documented API.
