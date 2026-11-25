# Module 7.9 — PQC Migration Policy Enforcement

## Purpose
Module 7.9 adds a policy-governance layer over the existing static cryptographic scanner. It evaluates a ZIP project's detected findings against a versioned Q-SHIELD policy catalog, assigns a recommended action and status, and records human review decisions in an auditable job record.

## API endpoints
- `GET /api/crypto-lab/migration-policy/catalog`
- `POST /api/crypto-lab/migration-policy/evaluate` — multipart ZIP field `file`; optional `policy_profile` (`TRANSITION` or `STRICT`)
- `GET /api/crypto-lab/migration-policy/<job_id>`
- `POST /api/crypto-lab/migration-policy/<job_id>/decisions`

## Decision types
- `APPROVE_REMEDIATION_PLAN`
- `ACCEPT_TIME_BOUND_EXCEPTION` — requires a rationale and future `exception_expiry` (`YYYY-MM-DD`)
- `DEFER_WITH_RATIONALE`

Decisions require an actor and a meaningful rationale. Each decision is recorded in the job's audit event list. The workflow does not change uploaded source files and reports `source_modified: false`.

## Example PowerShell usage
```powershell
curl.exe -X GET "http://127.0.0.1:5000/api/crypto-lab/migration-policy/catalog"

curl.exe -X POST "http://127.0.0.1:5000/api/crypto-lab/migration-policy/evaluate" `
  -F "file=@E:\path\to\project.zip" `
  -F "policy_profile=TRANSITION"
```

To record decisions, first retrieve the job and its `finding_id` values:
```powershell
$job = Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/crypto-lab/migration-policy/JOB_ID"
$fid = $job.findings[0].finding_id
$body = @{
  actor = "security-reviewer"
  decisions = @(@{
    finding_id = $fid
    decision = "APPROVE_REMEDIATION_PLAN"
    note = "Approved for remediation planning and controlled testing."
  })
} | ConvertTo-Json -Depth 5 -Compress

Invoke-RestMethod `
  -Uri "http://127.0.0.1:5000/api/crypto-lab/migration-policy/JOB_ID/decisions" `
  -Method POST -ContentType "application/json" -Body $body
```

## Policy interpretation
- RSA/ECC: plan a use-case-specific PQC migration. ML-KEM is for key establishment; ML-DSA is for signatures. No blind RSA/ECC substitution is performed.
- DES/3DES: critical legacy-cryptography remediation planning.
- MD5/SHA-1: review context; password hashing must migrate to a password KDF such as Argon2id, not a fast digest.
- AES: review mode and key management; AES-GCM is a symmetric authenticated-encryption option, not a PQC algorithm.
- Hardcoded secrets: rotate and externalize.
- SHA-256/384/512: generally informational, not automatically a PQC migration finding.

## Security and limitations
- ZIP uploads are limited to 25 MiB, 1000 entries and 100 MiB expanded content; traversal paths and symlinks are rejected.
- Source code is scanned statically and never executed.
- Scanner results may contain false positives or miss runtime use.
- RSA/ECC findings do not identify the precise cryptographic operation; reviewers must classify key establishment versus signing and other uses.
- `STRICT` and `TRANSITION` are demonstrator policy profiles, not a legal or regulatory standard.
- Human decisions are audit records, not source patches or proof that remediation was deployed.
- Jobs are stored as JSON files under `backend/uploads/migration_policy`; protect this directory and add authentication/authorization before multi-user or production deployment.
