# Q-SHIELD Module 7.5 — ML-DSA Signature Migration Review

This module adds static detection and human review for candidate RSA/ECDSA signing
operations. It deliberately does not rewrite signing code: migration requires
coordinated signer/verifier changes, key and signature formats, certificates,
provider support and interoperability validation.

## Endpoints
- `POST /api/project-migration/signature/analyze` — multipart ZIP field `file`
- `GET /api/project-migration/signature/<job_id>` — retrieve review
- `POST /api/project-migration/signature/<job_id>/decisions` — record
  `approve_migration_plan` or `defer` for finding IDs
- `GET /api/project-migration/signature/<job_id>/report` — download JSON report

An approval records approval of a migration plan only. It does not modify source.
Uploaded code is never executed. Findings are static candidates, not proof of
runtime usage. ML-DSA is for signatures; ML-KEM is for key establishment.

## Tests
`python -m unittest tests.test_module75_signature_review -v`
