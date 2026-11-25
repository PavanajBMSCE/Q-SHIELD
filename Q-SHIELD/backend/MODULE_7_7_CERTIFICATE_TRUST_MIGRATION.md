# Module 7.7 — X.509 Trust-Chain and ML-DSA Migration Demonstrator

## Purpose
Demonstrate a conventional three-level X.509 chain (root CA → intermediate CA → leaf certificate), validate issuer relationships, CA constraints, certificate signatures and validity windows, and separately sign a canonical migration manifest with ML-DSA-65 (FIPS 204).

**Critical scope distinction:** the root, intermediate and leaf certificates in this implementation are conventionally RSA-signed X.509 certificates. ML-DSA-65 signs a separate manifest that binds the leaf certificate fingerprint, subject, issuer, serial number, public-key fingerprint and migration status. This is not an ML-DSA-signed X.509 certificate and is not a production or hybrid PKI.

## APIs
- `GET /api/crypto-lab/certificate-migration/provider-self-test`
- `POST /api/crypto-lab/certificate-migration/demonstrate`

Example:
```powershell
$body = '{}' 
Invoke-RestMethod `
  -Uri "http://127.0.0.1:5000/api/crypto-lab/certificate-migration/demonstrate" `
  -Method POST -ContentType "application/json" -Body $body |
  ConvertTo-Json -Depth 12
```

The demonstration returns:
- Root, intermediate and leaf certificate subjects, issuers, SHA-256 fingerprints and DER sizes.
- Chain-order, issuer-name, CA-constraint, certificate-signature and validity checks.
- Canonical migration manifest and ML-DSA-65 public-key/signature sizes.
- ML-DSA manifest verification, tampered-manifest rejection, tampered-signature rejection and unrelated trust-anchor rejection.
- Local key-generation, signing and verification timings.

## Tests
Run from `backend`:
```powershell
python -m unittest tests.test_module77_certificate_migration -v
```

## Security and limitations
- RSA-2048 is used for the illustrative X.509 chain; it is not a post-quantum certificate chain.
- ML-DSA-65 (FIPS 204) signs a detached migration manifest only. No ML-DSA X.509 certificate encoding or CA interoperability is claimed.
- All keys and certificates are generated ephemerally per request. Private keys are not returned or persisted.
- The unrelated-anchor check demonstrates fingerprint mismatch detection only; it does not provision a production trust store.
- No certificate revocation, OCSP, CRL, policy constraints, path-length enforcement beyond basic CA flags, name constraints, or production identity validation is implemented.
- Production migration requires supported certificate profiles, CA/vendor/client interoperability, trust-store governance, revocation, key custody, rotation, and lifecycle planning.
- ML-DSA is for signatures; ML-KEM is for key establishment.
