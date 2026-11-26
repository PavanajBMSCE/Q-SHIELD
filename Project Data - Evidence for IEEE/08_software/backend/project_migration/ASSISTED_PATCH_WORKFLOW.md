# Q-SHIELD Module 7 — Human-Approved Assisted Patch Workflow

## API

### 1. Prepare a review
`POST /api/project-migration/assisted/prepare`

Multipart field: `file` (ZIP archive).

Returns a job ID and proposals. Each proposal is either:
- `PENDING_REVIEW`: a narrowly matched source patch is available.
- `GUIDANCE_ONLY`: no source patch is offered because static evidence is insufficient to infer a safe implementation.

### 2. Retrieve the review
`GET /api/project-migration/assisted/<job_id>`

### 3. Submit individual decisions
`POST /api/project-migration/assisted/<job_id>/decisions`

JSON body:
```json
{
  "decisions": [
    {"proposal_id": "P001", "decision": "approve"},
    {"proposal_id": "P002", "decision": "reject"}
  ]
}
```

Only patchable proposals can be approved or rejected. Decisions are immutable. The output is rebuilt from the immutable original archive, applying all approved patches; rejected and pending patches are not applied.

### 4. Download approved output
`GET /api/project-migration/assisted/<job_id>/download`

An output ZIP is created after at least one valid decision batch is submitted.

## Current patch scope

- Exact Python `verify = False` assignments can be proposed as `verify = True`. This does not configure a CA trust store or prove hostname validation; application integration tests are still required.
- Narrow literal API-key/token assignments supported by the existing secret externalization helper can be proposed for environment-variable lookup. Previously exposed credentials must still be rotated and environment values securely provisioned.
- RSA/ECC, DES, AES mode/ciphertext, password hashing and other protocol-sensitive changes are guidance-only. They are not rewritten based on token detection alone.

## Safety and validation

- Uploaded project code is never executed.
- ZIP paths and archive sizes use the existing Module 7 validation.
- Proposal diffs redact literal API-key/token values.
- Source hashes are recorded in proposals.
- Approved Python patches are checked with `ast.parse`; unsupported languages are marked `NOT_RUN`.
- Syntax validation is not runtime, interoperability or security validation.
- Original source archives are retained separately; generated output does not overwrite them.

## Example PowerShell usage

```powershell
curl.exe -X POST "http://127.0.0.1:5000/api/project-migration/assisted/prepare" `
  -F "file=@uploads/comparisons/Original_Project.zip;type=application/zip"
```

Use the returned job ID and proposal IDs to submit decisions:

```powershell
$jobId = "PASTE_JOB_ID"
$body = @{
  decisions = @(
    @{ proposal_id = "P001"; decision = "approve" }
  )
} | ConvertTo-Json -Depth 5

Invoke-RestMethod `
  -Uri "http://127.0.0.1:5000/api/project-migration/assisted/$jobId/decisions" `
  -Method Post -ContentType "application/json" -Body $body
```

Download:

```powershell
curl.exe -L `
  "http://127.0.0.1:5000/api/project-migration/assisted/$jobId/download" `
  -o ".\uploads\comparisons\QSHIELD_Assisted_Approved.zip"
```
