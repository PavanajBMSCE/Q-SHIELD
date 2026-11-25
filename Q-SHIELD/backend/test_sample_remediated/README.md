# Q-SHIELD Remediated Test Project

This is a controlled after-migration comparison fixture derived from Q-SHIELD's original four-file `test_sample` project.

## Changes represented

- `config.js`: AES-256-GCM profile label, SHA-256 digest label, TLS 1.3 label and environment-based API key lookup.
- `ecc_test.py`: complete ML-KEM-768 + HKDF-SHA256 + AES-256-GCM demonstration previously executed successfully in the user's environment.
- `main.py`: RSA-3072 retained as a classical baseline (not quantum-safe); password derivation uses salted scrypt; AES-256-GCM authenticated round-trip; API key loaded from environment.
- `security.py`: SHA-256 conventional digest, AES-256-GCM profile label, TLS verification enabled and 3072-bit classical RSA baseline documented.

## Important boundaries

- RSA remains intentionally present in `main.py` because the original key's purpose was not sufficiently specified to safely choose between ML-KEM key establishment and ML-DSA signatures. This is the remaining actionable finding and requires protocol-purpose review.
- The `config.js` AES-GCM and TLS 1.3 values are configuration labels; the application must enforce the corresponding runtime behavior.
- Set `API_KEY` in the environment and rotate any previously embedded value.
- The scrypt example is a demonstration. A real password-storage system must persist the salt and KDF parameters with the verifier and implement verification/rehash logic.
- This fixture is for Q-SHIELD comparison and demonstration, not production deployment.
