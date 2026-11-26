# Module 7.8 — Hybrid Signature & Migration Policy Demonstrator

## Purpose
Generate independent RSA-PSS-SHA256 and ML-DSA-65 (FIPS 204) signatures over the same canonical message envelope, verify them independently, and demonstrate three policy modes:
- `DUAL_REQUIRED`: both signatures must verify.
- `CLASSICAL_ONLY`: RSA-PSS must verify.
- `PQC_ONLY`: ML-DSA-65 must verify.

The demo tests valid signatures, modified messages, modified signatures, and policy outcomes when one signature is invalid.

**Scope:** This is an educational dual-signature construction, not a standardized hybrid signature protocol. The signatures are independent signatures over a common canonical envelope. It does not establish signer identity, certificate trust, downgrade protection or production interoperability.

## APIs
- `GET /api/crypto-lab/hybrid-signatures/provider-self-test`
- `POST /api/crypto-lab/hybrid-signatures/demonstrate`

Example PowerShell request:
```powershell
$body = @{
    message = "Q-SHIELD dual signature demonstration"
    context = "qshield-module-7.8"
} | ConvertTo-Json -Compress

$response = Invoke-RestMethod `
    -Uri "http://127.0.0.1:5000/api/crypto-lab/hybrid-signatures/demonstrate" `
    -Method POST -ContentType "application/json" -Body $body

$response | ConvertTo-Json -Depth 12
```

## Tests
From `backend`:
```powershell
python -m unittest tests.test_module78_hybrid_signatures -v
```

## Security limitations
- RSA-PSS-SHA256 and ML-DSA-65 are separate signatures, not a standardized composite signature format.
- Policy modes are educational examples. In particular, `CLASSICAL_ONLY` and `PQC_ONLY` illustrate acceptance behavior and are not safe production downgrade fallbacks without a rigorously designed transition policy.
- Keys are generated ephemerally for each request; private keys are never returned or persisted.
- Production deployment needs authenticated signer identity, certificate and trust-store integration, protocol negotiation, downgrade resistance, key custody, rotation, verifier rollout and independent security review.
- ML-DSA is for digital signatures; ML-KEM is for key establishment.
