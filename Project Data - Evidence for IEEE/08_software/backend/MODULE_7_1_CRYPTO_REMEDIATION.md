# Q-SHIELD Module 7.1 — Cryptographic Remediation Plans

This update enriches the existing human-approved Assisted Migration proposals with operation-aware remediation plans. It does not automatically rewrite cryptographic operations.

## Supported guidance categories
- RSA key establishment redesign using ML-KEM-768 + HKDF-SHA256 + AES-256-GCM (RSA signatures are a separate problem).
- Password hashing migration to Argon2id (not plain SHA-256).
- AES key management and rotation.
- AES-CBC to authenticated AES-GCM with nonce/tag/AAD and ciphertext versioning.
- DES removal and stored-data re-encryption planning.
- SHA-1 use-case review and compatible migration.
- TLS 1.0 removal and negotiated-protocol verification.
- Integration of certificate and hostname verification into real network calls.

## Existing workflow remains unchanged
1. POST `/api/project-migration/assisted/prepare` with ZIP field `file`.
2. Review `recommended_design`, `severity`, and `validation_requirements` for guidance-only proposals.
3. Submit decisions only for `patch_available: true` proposals. Guidance-only items cannot be approved as automatic patches.
4. Download approved archive using the existing download endpoint.

## Safety boundary
Uploaded project code is never executed. This update does not claim that guidance-only findings are fixed. It deliberately avoids token replacement for RSA, password hashes, AES modes, DES, SHA-1, and TLS protocol settings because their real operation and compatibility context cannot be inferred safely from isolated source matches. Static checks do not replace integration, interoperability, or security testing.
