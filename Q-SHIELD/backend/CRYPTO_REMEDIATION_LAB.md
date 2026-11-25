# Q-SHIELD Cryptographic Remediation Lab

## Included executable demonstrations
- AES-256-GCM encryption/decryption with a fresh 96-bit nonce, authentication tag (included by AESGCM), and optional AAD. Tampering is rejected.
- Argon2id password hashing and verification using argon2-cffi. Encoded hashes carry salt and parameters; wrong passwords fail verification.

## Local setup
From `backend` with the project virtual environment activated:
```powershell
pip install -r requirements.txt
python -m unittest tests.test_crypto_lab -v
python app.py
```

## API examples
`POST /api/crypto-lab/aes-gcm/encrypt` JSON: `{"plaintext":"hello","aad":"context"}`
`POST /api/crypto-lab/aes-gcm/decrypt` with returned `key_b64`, `nonce_b64`, `ciphertext_b64`, and `aad`.
`POST /api/crypto-lab/password/hash` JSON: `{"password":"example"}`
`POST /api/crypto-lab/password/verify` JSON: `{"password":"example","encoded_hash":"..."}`

## Security boundaries
The AES endpoint returns its generated key solely to make the classroom round-trip demonstrable. This is **not production key management**. Production systems must protect keys using a KMS/HSM or equivalent, never return them to clients, ensure nonce uniqueness for every encryption under a key, version ciphertext envelopes, and plan re-encryption of legacy ciphertext.

Argon2id is a password-hashing function, not a general-purpose digest. The parameters here are demonstration defaults and must be benchmarked on the deployment hardware. Existing MD5 hashes cannot be converted to Argon2id without the original password; use gradual rehash after successful authentication or a password reset.

These endpoints are isolated demonstrations. They do not automatically rewrite uploaded applications or migrate their stored data. No uploaded source code is executed. ML-KEM integration, RSA signature migration, TLS deployment, DES removal and legacy data migration remain separate tasks.
