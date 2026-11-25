"""
Q-SHIELD Module 7: multi-language project migration assistant.

Supported source scanning: Python, JavaScript/TypeScript, Java, C/C++,
C#, Go, PHP, Ruby, JSON, YAML, TOML, INI, XML and common properties files.

Safety model:
- Never executes uploaded project code.
- Rejects unsafe ZIP paths, symlinks, oversized archives and unsupported files.
- Automatic mode applies only narrow, explicit digest API substitutions.
- Complex public-key, encryption-mode, TLS and secret-management changes
  are reported as assisted/manual actions; they are never blindly rewritten.
- The generated ZIP preserves project files and adds migration documentation.
"""

import io
import json
import ast
import difflib
import hashlib
import xml.etree.ElementTree as ET
import os
import re
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import PurePosixPath
from uuid import uuid4

from flask import Blueprint, current_app, jsonify, request, send_file
from werkzeug.utils import secure_filename

from config import Config

project_migration_bp = Blueprint("project_migration", __name__)

MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_EXTRACTED_BYTES = 100 * 1024 * 1024
MAX_FILES = 1500
MAX_FILE_BYTES = 2 * 1024 * 1024

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cc", ".cpp",
    ".h", ".hpp", ".cs", ".go", ".php", ".rb", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml"
}
SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", "dist",
    "build", ".idea", ".vscode", "target"
}

# Exact API-level substitutions with relatively predictable intent.
# No generic replacement of the words MD5/SHA1 in arbitrary prose.
AUTO_RULES = [
    (
        "PY_MD5",
        re.compile(r"\bhashlib\.md5(?=\s*\()"),
        "hashlib.sha256",
        "Python hashlib.md5() → hashlib.sha256()",
        "SHA-256 is a modern collision-resistant digest; check protocol compatibility."
    ),
    (
        "PY_SHA1",
        re.compile(r"\bhashlib\.sha1(?=\s*\()"),
        "hashlib.sha256",
        "Python hashlib.sha1() → hashlib.sha256()",
        "SHA-256 is a modern collision-resistant digest; check protocol compatibility."
    ),
    (
        "JS_MD5",
        re.compile(r"""(\bcreateHash\s*\(\s*['"])md5(['"]\s*\))""", re.IGNORECASE),
        r"\1sha256\2",
        "Node.js createHash('md5') → createHash('sha256')",
        "Confirm that the protocol and stored digest format can be upgraded."
    ),
    (
        "JS_SHA1",
        re.compile(r"""(\bcreateHash\s*\(\s*['"])sha-?1(['"]\s*\))""", re.IGNORECASE),
        r"\1sha256\2",
        "Node.js createHash('sha1') → createHash('sha256')",
        "Confirm that the protocol and stored digest format can be upgraded."
    ),
    (
        "JAVA_MD5",
        re.compile(r"""(MessageDigest\s*\.\s*getInstance\s*\(\s*")MD5("\s*\))"""),
        r"\1SHA-256\2",
        'Java MessageDigest.getInstance("MD5") → "SHA-256"',
        "Check interoperability with systems expecting the old digest."
    ),
    (
        "JAVA_SHA1",
        re.compile(r"""(MessageDigest\s*\.\s*getInstance\s*\(\s*")SHA-?1("\s*\))""", re.IGNORECASE),
        r"\1SHA-256\2",
        'Java MessageDigest.getInstance("SHA-1") → "SHA-256"',
        "Check interoperability with systems expecting the old digest."
    ),
    (
        "OPENSSL_MD5",
        re.compile(r"\bEVP_md5\s*(?=\()"),
        "EVP_sha256",
        "OpenSSL EVP_md5() → EVP_sha256()",
        "Check API compatibility and digest-size assumptions."
    ),
    (
        "OPENSSL_SHA1",
        re.compile(r"\bEVP_sha1\s*(?=\()"),
        "EVP_sha256",
        "OpenSSL EVP_sha1() → EVP_sha256()",
        "Check API compatibility and digest-size assumptions."
    ),
    (
        "JS_AES_CBC_CONFIG",
        re.compile(r"(\b(?:const|let|var)\s+\w*(?:algorithm|cipher)\w*\s*=\s*['\"])AES-256-CBC(['\"])", re.I),
        r"\1AES-256-GCM\2",
        "JavaScript AES-256-CBC configuration label → AES-256-GCM",
        "Configuration label only: update the actual encryption/decryption implementation, nonce handling, tag handling and stored ciphertext format before deployment."
    ),
    (
        "JS_MD5_CONFIG",
        re.compile(r"(\b(?:const|let|var)\s+(?:hash|hashAlgorithm)\s*=\s*['\"])MD5(['\"])", re.I),
        r"\1SHA-256\2",
        "JavaScript MD5 digest configuration label → SHA-256",
        "Confirm protocol compatibility. This is not suitable for password storage; use a password-hashing KDF for passwords."
    ),
    (
        "JS_TLS_LEGACY_CONFIG",
        re.compile(r"(\b(?:const|let|var)\s+(?:tlsVersion|tls_version|protocol)\s*=\s*['\"])TLSv?1\.[01](['\"])", re.I),
        r"\1TLSv1.3\2",
        "JavaScript legacy TLS configuration label → TLSv1.3",
        "Configuration label only: ensure the actual TLS client/server enforces TLS 1.3 and has a compatible certificate/trust configuration."
    ),
]

PATTERNS = [
    ("RSA", re.compile(r"\bRSA\b|rsa\.generate_private_key|RSA\.generate", re.I),
     "Asymmetric cryptography", "Plan key-establishment migration to ML-KEM-768 or signature migration to ML-DSA-65 based on actual use."),
    ("ECC/ECDH/ECDSA", re.compile(r"\b(ECC|ECDH|ECDSA|EllipticCurve|ec\.generate_private_key)\b", re.I),
     "Asymmetric cryptography", "Use ML-KEM-768 for key establishment or ML-DSA-65 for signatures; confirm the operation before changing code."),
    ("DES/3DES", re.compile(r"\b(DES|3DES|TripleDES)\b", re.I),
     "Symmetric encryption", "Replace legacy encryption with authenticated encryption such as AES-256-GCM; update nonce, tag and serialization handling."),
    ("AES-CBC/ECB", re.compile(r"\bAES\b.{0,50}\b(CBC|ECB)\b|\b(AES|CBC|ECB)\b.{0,50}\b(AES|CBC|ECB)\b", re.I),
     "Symmetric encryption mode", "Consider AES-256-GCM; migration must correctly handle nonce generation, authentication tags and existing ciphertext formats."),
    ("MD5/SHA-1", re.compile(r"\b(MD5|SHA[-_]?1)\b", re.I),
     "Hash function", "Review whether a safe automatic digest API substitution is available and check protocol compatibility."),
    ("TLS verification disabled", re.compile(r"(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)", re.I),
     "Transport security", "Enable certificate and hostname verification; install the correct trust chain."),
    ("Hardcoded secret candidate", re.compile(r"(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]", re.I),
     "Secret management", "Move credentials to a secret manager or protected environment configuration and rotate exposed values."),
]


def _safe_member_name(name):
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or not path.parts:
        return False
    if any(part in ("..", "") for part in path.parts):
        return False
    if ":" in path.parts[0]:
        return False
    if any(part.lower() in SKIP_DIRS for part in path.parts[:-1]):
        return False
    return True


def _read_archive(upload):
    raw = upload.read(MAX_ARCHIVE_BYTES + 1)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError("ZIP exceeds the 25 MB upload limit.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise ValueError("The uploaded file is not a valid ZIP archive.")

    files = {}
    total_size = 0
    infos = archive.infolist()
    if len(infos) > MAX_FILES:
        raise ValueError(f"Archive contains too many entries (maximum {MAX_FILES}).")

    for info in infos:
        if info.is_dir():
            continue
        if not _safe_member_name(info.filename):
            raise ValueError(f"Unsafe ZIP path rejected: {info.filename}")
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise ValueError(f"Symbolic link rejected: {info.filename}")
        if info.file_size > MAX_FILE_BYTES:
            raise ValueError(f"File exceeds 2 MB limit: {info.filename}")
        total_size += info.file_size
        if total_size > MAX_EXTRACTED_BYTES:
            raise ValueError("Expanded archive exceeds the 100 MB limit.")
        content = archive.read(info)
        files[info.filename.replace("\\", "/")] = content
    archive.close()
    if not files:
        raise ValueError("The ZIP archive contains no files.")
    return files


def _inspect_text(path, text):
    ext = PurePosixPath(path).suffix.lower()
    if ext not in SOURCE_EXTENSIONS:
        return None
    findings = []
    for algorithm, pattern, category, action in PATTERNS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append({
                "algorithm": algorithm,
                "category": category,
                "line": line,
                "evidence": match.group(0)[:100],
                "recommended_action": action,
                "automatic_candidate": False,
            })
    return findings


def analyze_files(files):
    result = []
    file_count = 0
    for path, content in files.items():
        ext = PurePosixPath(path).suffix.lower()
        if ext not in SOURCE_EXTENSIONS:
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            continue
        file_count += 1
        findings = _inspect_text(path, text) or []
        result.extend({"file": path, **finding} for finding in findings)
    return {
        "scanned_source_files": file_count,
        "finding_count": len(result),
        "findings": result,
    }


def _line_diff(original, updated):
    """Return machine-readable changed-line details and a unified diff."""
    old_lines = original.splitlines()
    new_lines = updated.splitlines()
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines)
    changes = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        changes.append({
            "change_type": tag,
            "original_line_start": i1 + 1 if i1 < i2 else None,
            "original_line_end": i2 if i1 < i2 else None,
            "migrated_line_start": j1 + 1 if j1 < j2 else None,
            "migrated_line_end": j2 if j1 < j2 else None,
            "original_lines": old_lines[i1:i2],
            "migrated_lines": new_lines[j1:j2],
        })
    unified = "\n".join(difflib.unified_diff(
        old_lines, new_lines, fromfile="original", tofile="migrated", lineterm=""
    ))
    return changes, unified


def _validate_changed_file(path, content):
    """Perform safe parser checks only; never execute uploaded code."""
    ext = PurePosixPath(path).suffix.lower()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return {"file": path, "validator": "UTF-8", "status": "SKIPPED", "message": "Changed file is not UTF-8 text."}
    try:
        if ext == ".py":
            ast.parse(text, filename=path)
            return {"file": path, "validator": "Python AST parser", "status": "PASS", "message": "Python syntax parsed successfully; code was not executed."}
        if ext == ".json":
            json.loads(text)
            return {"file": path, "validator": "JSON parser", "status": "PASS", "message": "Valid JSON."}
        if ext == ".xml":
            ET.fromstring(text)
            return {"file": path, "validator": "XML parser", "status": "PASS", "message": "Valid XML."}
        if ext == ".toml":
            import tomllib
            tomllib.loads(text)
            return {"file": path, "validator": "TOML parser", "status": "PASS", "message": "Valid TOML."}
        return {"file": path, "validator": "Not available", "status": "NOT_RUN", "message": "No language compiler/parser is bundled. Run the project's native build and test commands."}
    except Exception as exc:
        return {"file": path, "validator": ext.lstrip(".").upper() + " parser", "status": "FAIL", "message": str(exc)[:300]}


def _dependency_review(files):
    """Inspect common dependency manifests and provide conservative review notes."""
    results = []
    manifest_names = {"requirements.txt", "pyproject.toml", "package.json", "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "composer.json", "gemfile"}
    for path, raw in files.items():
        name = PurePosixPath(path).name.lower()
        if name not in manifest_names:
            continue
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        notes = []
        if name in {"requirements.txt", "pyproject.toml"}:
            if re.search(r"\b(cryptography|pycryptodome|pyopenssl)\b", content, re.I):
                notes.append("Review the cryptography library version and confirm support for the required NIST PQC algorithms and APIs; pin and test a compatible version.")
            if re.search(r"\b(pycryptodome|pycrypto)\b", content, re.I):
                notes.append("Review whether the project relies on legacy or non-PQC APIs; plan a tested library/API migration rather than a blind package replacement.")
        elif name == "package.json":
            try:
                manifest = json.loads(content)
                deps = {**manifest.get("dependencies", {}), **manifest.get("devDependencies", {})}
                if any(k in deps for k in ("crypto-js", "node-forge", "jsonwebtoken")):
                    notes.append("Review cryptographic package versions, maintenance status and PQC roadmap; validate API compatibility before upgrading.")
            except Exception:
                notes.append("Manifest JSON could not be parsed; validate package.json before dependency changes.")
        elif name == "pom.xml":
            if re.search(r"bcprov|bouncycastle|bcpkix|tink|conscrypt", content, re.I):
                notes.append("Review provider/library versions and verify required PQC algorithm availability in the target Java runtime.")
        elif name in {"build.gradle", "build.gradle.kts", "go.mod", "composer.json", "gemfile"}:
            notes.append("Review cryptographic dependencies for maintained versions, PQC support and runtime compatibility; run the native dependency audit/build.")
        if not notes:
            notes.append("Dependency manifest found. Review cryptographic dependencies and lockfile compatibility as part of migration.")
        results.append({"file": path, "status": "REVIEW_REQUIRED", "recommendations": notes})
    if not results:
        results.append({"file": None, "status": "NOT_FOUND", "recommendations": ["No common dependency manifest was detected. Confirm dependencies manually and add a lockfile/manifest before production migration."]})
    return results


def _apply_secret_environment_migration(path, text):
    """Move narrowly matched literal API-key assignments to environment lookups."""
    changes = []
    ext = PurePosixPath(path).suffix.lower()
    if ext in {".js", ".jsx", ".ts", ".tsx"}:
        pattern = re.compile(
            r"(?m)^(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*)(['\"])[^'\"\r\n]{8,}\3"
        )
        def replace_js(match):
            name = match.group(2)
            if not re.search(r"API[_-]?KEY|ACCESS[_-]?TOKEN|SECRET[_-]?KEY", name, re.I):
                return match.group(0)
            changes.append({"file": path, "rule": "JS_SECRET_TO_ENV", "description": f"{name} literal moved to process.env.{name}", "replacements": 1, "validation_note": "Set the environment variable in deployment and rotate any previously exposed credential."})
            return match.group(1) + f"process.env.{name}"
        text = pattern.sub(replace_js, text)
    elif ext == ".py":
        pattern = re.compile(
            r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['\"])[^'\"\r\n]{8,}\3"
        )
        def replace_py(match):
            name = match.group(2)
            if not re.search(r"API[_-]?KEY|ACCESS[_-]?TOKEN|SECRET[_-]?KEY", name, re.I):
                return match.group(0)
            changes.append({"file": path, "rule": "PY_SECRET_TO_ENV", "description": f"{name} literal moved to os.environ.get({name!r})", "replacements": 1, "validation_note": "Set the environment variable before running and rotate any previously exposed credential."})
            return f"{match.group(1)}{name} = os.environ.get({name!r})"
        updated = pattern.sub(replace_py, text)
        if updated != text and not re.search(r"^\s*import\s+os\b|^\s*from\s+os\s+import\b", updated, re.M):
            lines = updated.splitlines(keepends=True)
            insert_at = 0
            # Preserve shebang and encoding declarations.
            if lines and lines[0].startswith("#!"):
                insert_at = 1
            for index in range(min(2, len(lines))):
                if re.search(r"coding[:=]\s*[-\w.]+", lines[index]):
                    insert_at = max(insert_at, index + 1)
            try:
                tree = ast.parse(updated)
                body = list(tree.body)
                if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) and isinstance(getattr(body[0].value, "value", None), str):
                    insert_at = max(insert_at, body[0].end_lineno or body[0].lineno)
                    for node in body[1:]:
                        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                            insert_at = max(insert_at, node.end_lineno or node.lineno)
                        else:
                            break
                else:
                    for node in body:
                        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                            insert_at = max(insert_at, node.end_lineno or node.lineno)
                        elif node.lineno > insert_at:
                            break
            except SyntaxError:
                pass
            lines.insert(insert_at, "import os\n")
            updated = "".join(lines)
        text = updated
    return text, changes


def _is_password_hash_context(line):
    return bool(re.search(r"password|passwd|pwd|passphrase", line, re.I))


def migrate_files(files, mode):
    if mode not in ("automatic", "assisted"):
        raise ValueError("Mode must be 'automatic' or 'assisted'.")

    output = dict(files)
    changes = []
    manual_actions = []
    scanned = 0
    diff_details = []
    validation_results = []

    for path, content in files.items():
        ext = PurePosixPath(path).suffix.lower()
        if ext not in SOURCE_EXTENSIONS:
            continue
        try:
            original = content.decode("utf-8")
        except UnicodeDecodeError:
            continue
        scanned += 1
        text = original
        findings = _inspect_text(path, original) or []

        if mode == "automatic":
            for rule_id, pattern, replacement, label, caution in AUTO_RULES:
                if rule_id == "PY_MD5" and any(
                    _is_password_hash_context(line)
                    for line in text.splitlines() if pattern.search(line)
                ):
                    continue
                updated, count = pattern.subn(replacement, text)
                if count:
                    text = updated
                    changes.append({
                        "file": path,
                        "rule": rule_id,
                        "description": label,
                        "replacements": count,
                        "validation_note": caution,
                    })
            text, secret_changes = _apply_secret_environment_migration(path, text)
            changes.extend(secret_changes)
        for finding in findings:
            source_lines = original.splitlines()
            password_context = (
                finding.get("algorithm") == "MD5/SHA-1"
                and 0 < finding.get("line", 0) <= len(source_lines)
                and _is_password_hash_context(source_lines[finding.get("line", 1) - 1])
            )
            applied_rule_ids = {item.get("rule") for item in changes if item.get("file") == path}
            if password_context:
                manual_actions.append({
                    "file": path,
                    "line": finding["line"],
                    "detected": "Password hashing with a fast digest",
                    "category": "Password storage",
                    "action": "Replace with Argon2id, scrypt or PBKDF2 using a unique random salt and stored parameters; implement verification and migrate existing hashes safely.",
                    "status": "REVIEW_REQUIRED",
                })
            elif finding["algorithm"] not in ("MD5/SHA-1",):
                # If a narrowly-scoped transformation already moved a literal
                # secret, retain only the mandatory credential-rotation action.
                if finding["algorithm"] == "Hardcoded secret candidate" and applied_rule_ids.intersection({"JS_SECRET_TO_ENV", "PY_SECRET_TO_ENV"}):
                    manual_actions.append({
                        "file": path,
                        "line": finding["line"],
                        "detected": "Previously embedded credential",
                        "category": "Credential rotation",
                        "action": "Rotate/revoke the previously embedded credential and confirm the replacement environment variable is configured securely.",
                        "status": "ROTATION_REQUIRED",
                    })
                    continue
                if finding["algorithm"] == "AES-CBC/ECB" and "JS_AES_CBC_CONFIG" in applied_rule_ids:
                    # The configuration label was updated, but actual crypto
                    # implementation and ciphertext migration still need tests.
                    manual_actions.append({
                        "file": path,
                        "line": finding["line"],
                        "detected": "AES-CBC implementation/configuration review",
                        "category": "Ciphertext compatibility",
                        "action": "Confirm the runtime uses AES-GCM, update nonce/tag serialization, and migrate or retire existing CBC ciphertext. The label-only change is not proof of implementation migration.",
                        "status": "IMPLEMENTATION_VALIDATION_REQUIRED",
                    })
                    continue
                manual_actions.append({
                    "file": path,
                    "line": finding["line"],
                    "detected": finding["algorithm"],
                    "category": finding["category"],
                    "action": finding["recommended_action"],
                    "status": "REVIEW_REQUIRED",
                })
            elif mode == "assisted":
                manual_actions.append({
                    "file": path,
                    "line": finding["line"],
                    "detected": finding["algorithm"],
                    "category": finding["category"],
                    "action": finding["recommended_action"],
                    "status": "PROPOSED_NOT_APPLIED",
                })

        migrated_content = text.encode("utf-8")
        # Validate every scanned source file in BOTH modes. Validation is
        # deliberately independent of whether migration changed the file.
        validation = _validate_changed_file(path, migrated_content)
        validation["changed_by_migration"] = text != original
        validation["sha256"] = hashlib.sha256(migrated_content).hexdigest()
        validation_results.append(validation)

        if text != original:
            output[path] = migrated_content
            line_changes, unified_diff = _line_diff(original, text)
            diff_details.append({
                "file": path,
                "change_count": len(line_changes),
                "line_changes": line_changes,
                "unified_diff": unified_diff,
                "original_sha256": hashlib.sha256(content).hexdigest(),
                "migrated_sha256": hashlib.sha256(migrated_content).hexdigest(),
            })

    dependency_review = _dependency_review(files)
    report = {
        "product": "Q-SHIELD",
        "module": 7,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "scanned_source_files": scanned,
        "modified_files": sorted({
            item["file"] for item in changes
        }),
        "automatic_changes": changes,
        "diff_summary": {
            "changed_file_count": len(diff_details),
            "changed_line_block_count": sum(item["change_count"] for item in diff_details),
        },
        "file_diffs": diff_details,
        "syntax_validation": {
            "summary": {
                "total_scanned": len(validation_results),
                "pass": sum(1 for item in validation_results if item["status"] == "PASS"),
                "fail": sum(1 for item in validation_results if item["status"] == "FAIL"),
                "not_run": sum(1 for item in validation_results if item["status"] == "NOT_RUN"),
                "skipped": sum(1 for item in validation_results if item["status"] == "SKIPPED"),
            },
            "results": validation_results,
            "scope_note": "Every scanned UTF-8 source file is assessed in both automatic and assisted modes. Only safe parsers are used; no uploaded code is executed. NOT_RUN means no bundled parser/compiler is available and the project's native build/test suite is required.",
        },
        "dependency_review": dependency_review,
        "manual_intervention_checklist": [
            "Review each RSA/ECC use and classify it as key establishment, signature or direct encryption before selecting ML-KEM/ML-DSA migration.",
            "Replace legacy DES and review AES-CBC/ECB use; design authenticated encryption and update nonce/tag/ciphertext handling.",
            "Enable TLS certificate and hostname verification and validate the trust chain.",
            "Move hardcoded credentials to protected configuration/secret management and rotate exposed credentials.",
            "Review dependency versions, runtime support, lockfiles and transitive dependencies.",
            "Run native compiler/build, unit tests, integration tests and interoperability tests.",
            "Perform security review and verify key/ciphertext formats before deployment.",
        ],
        "manual_review_items": manual_actions,
        "limitations": [
            "No uploaded source code is executed.",
            "Only narrowly matched digest API calls and exact JavaScript configuration/secret assignment patterns are automatically rewritten.",
            "Password-hash calls are deliberately not changed from MD5 to SHA-256; they require a salted password-hashing KDF migration and stored-hash format redesign.",
            "TLS and cipher configuration-label changes do not prove that the underlying runtime enforces the selected settings.",
            "RSA/ECC to ML-KEM/ML-DSA migration requires protocol-aware redesign and is not blindly rewritten.",
            "DES/AES mode, TLS, secret-management, dependency and key-format migrations require developer review.",
            "A generated project must pass its own build, tests, interoperability checks and security review before deployment.",
            "The hybrid construction in Q-SHIELD Module 5 is a demonstrator, not a standardized hybrid protocol profile."
        ],
    }
    return output, report


def _build_output_zip(files, report, project_name):
    buffer = io.BytesIO()
    report_bytes = json.dumps(report, indent=2).encode("utf-8")
    readme = f"""# {project_name} – Q-SHIELD Migration Output

Migration mode: {report['mode']}

## Contents
- Original project structure preserved where possible.
- `QSHIELD_MIGRATION_REPORT.json` contains findings, exact line diffs, parser validation, dependency review and a manual intervention checklist.
- This README describes validation requirements.

## Validation summary
- Source files scanned: {report['scanned_source_files']}
- Files modified: {len(report['modified_files'])}
- Syntax/parser checks: {report['syntax_validation']['summary']['pass']} PASS, {report['syntax_validation']['summary']['fail']} FAIL, {report['syntax_validation']['summary']['not_run']} NOT_RUN, {report['syntax_validation']['summary']['skipped']} SKIPPED
- Syntax validation runs in both automatic and assisted modes, including unchanged files.

## Important
This output is a migration starting point, not a guarantee of a production-ready
PQC application. Review all manual actions in the JSON report. Run the project's
own tests, build, interoperability checks and security review before deployment.

Q-SHIELD does not execute uploaded project code.
"""
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, content in files.items():
            archive.writestr(path, content)
        archive.writestr("QSHIELD_MIGRATION_REPORT.json", report_bytes)
        archive.writestr("QSHIELD_MIGRATION_README.md", readme.encode("utf-8"))
    buffer.seek(0)
    return buffer


def _job_directory():
    path = os.path.join(Config.UPLOAD_FOLDER, "project_migrations")
    os.makedirs(path, exist_ok=True)
    return path


def _store_job(job_id, report, zip_buffer):
    folder = _job_directory()
    with open(os.path.join(folder, f"{job_id}.json"), "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    with open(os.path.join(folder, f"{job_id}.zip"), "wb") as handle:
        handle.write(zip_buffer.getvalue())


def _load_report(job_id):
    if not re.fullmatch(r"[0-9a-f-]{36}", job_id):
        return None
    path = os.path.join(_job_directory(), f"{job_id}.json")
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


@project_migration_bp.route("/api/project-migration/analyze", methods=["POST"])
def analyze_project_archive():
    uploaded = request.files.get("file")
    if uploaded is None:
        return jsonify({"error": "Upload a ZIP using multipart field 'file'."}), 400
    if not uploaded.filename or not uploaded.filename.lower().endswith(".zip"):
        return jsonify({"error": "Only ZIP project archives are supported."}), 400
    try:
        files = _read_archive(uploaded)
        result = analyze_files(files)
        return jsonify({
            "message": "Project analysis completed.",
            "project_filename": secure_filename(uploaded.filename),
            **result,
        }), 200
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        current_app.logger.exception("Project migration analysis failed")
        return jsonify({"error": "Project analysis failed. Check backend logs."}), 500


@project_migration_bp.route("/api/project-migration/migrate", methods=["POST"])
def migrate_project_archive():
    uploaded = request.files.get("file")
    mode = (request.form.get("mode") or "").strip().lower()
    if uploaded is None:
        return jsonify({"error": "Upload a ZIP using multipart field 'file'."}), 400
    if not uploaded.filename or not uploaded.filename.lower().endswith(".zip"):
        return jsonify({"error": "Only ZIP project archives are supported."}), 400
    if mode not in ("automatic", "assisted"):
        return jsonify({"error": "Mode must be automatic or assisted."}), 400

    try:
        files = _read_archive(uploaded)
        migrated_files, report = migrate_files(files, mode)
        job_id = str(uuid4())
        report["job_id"] = job_id
        report["original_project_filename"] = secure_filename(uploaded.filename)
        zip_buffer = _build_output_zip(
            migrated_files, report,
            PurePosixPath(secure_filename(uploaded.filename)).stem or "Migrated_Project"
        )
        _store_job(job_id, report, zip_buffer)
        return jsonify({
            "message": "Project migration package generated.",
            "job_id": job_id,
            "mode": mode,
            "scanned_source_files": report["scanned_source_files"],
            "modified_file_count": len(report["modified_files"]),
            "modified_files": report["modified_files"],
            "manual_review_count": len(report["manual_review_items"]),
            "manual_review_items": report["manual_review_items"],
            "download_endpoint": f"/api/project-migration/download/{job_id}",
            "report_endpoint": f"/api/project-migration/report/{job_id}",
            "important_note": "Review the migration report and run the project's tests before deployment."
        }), 200
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        current_app.logger.exception("Project migration failed")
        return jsonify({"error": "Project migration failed. Check backend logs."}), 500


@project_migration_bp.route("/api/project-migration/report/<job_id>", methods=["GET"])
def get_project_migration_report(job_id):
    report = _load_report(job_id)
    if report is None:
        return jsonify({"error": "Migration job not found."}), 404
    return jsonify(report), 200


@project_migration_bp.route("/api/project-migration/download/<job_id>", methods=["GET"])
def download_migrated_project(job_id):
    if not re.fullmatch(r"[0-9a-f-]{36}", job_id):
        return jsonify({"error": "Invalid migration job ID."}), 400
    path = os.path.join(_job_directory(), f"{job_id}.zip")
    if not os.path.isfile(path):
        return jsonify({"error": "Migrated project package not found."}), 404
    return send_file(
        path,
        as_attachment=True,
        download_name=f"QSHIELD_Migrated_Project_{job_id[:8]}.zip",
        mimetype="application/zip"
    )


# ---------------------------------------------------------------------------
# Assisted migration review workflow (proposal -> human decision -> apply)
# ---------------------------------------------------------------------------

import copy

def _assisted_store_dir():
    path = os.path.join(Config.UPLOAD_FOLDER, "assisted_reviews")
    os.makedirs(path, exist_ok=True)
    return path


def _assisted_job_path(job_id, suffix):
    if not re.fullmatch(r"[0-9a-f-]{36}", job_id):
        raise ValueError("Invalid assisted migration job ID.")
    return os.path.join(_assisted_store_dir(), f"{job_id}.{suffix}")


def _proposal_diff(path, original, proposed):
    old = original.decode("utf-8", errors="replace").splitlines()
    new = proposed.decode("utf-8", errors="replace").splitlines()
    diff = "\n".join(difflib.unified_diff(old, new, fromfile=f"original/{path}", tofile=f"proposed/{path}", lineterm=""))
    # Never echo literal credentials into the review API response or report.
    diff = re.sub(
        r'''(?im)^(-.*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|SECRET[_-]?KEY)\s*[:=]\s*)['"][^'"]*['"]''',
        r"\1'<REDACTED>'",
        diff,
    )
    return diff


def _build_assisted_proposals(files):
    """Create conservative, reviewable patches; complex crypto redesigns stay guidance-only."""
    proposals = []
    seen = set()

    for path, raw in files.items():
        ext = PurePosixPath(path).suffix.lower()
        if ext not in SOURCE_EXTENSIONS:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue

        # Exact Python TLS flag is a small, reviewable patch. Trust-chain setup
        # remains a deployment responsibility and is never inferred.
        if ext == ".py" and re.search(r"(?m)^(\s*verify\s*=\s*)False(\s*(?:#.*)?)$", text):
            proposed_text = re.sub(
                r"(?m)^(\s*verify\s*=\s*)False(\s*(?:#.*)?)$",
                r"\1True\2",
                text,
                count=1,
            )
            if proposed_text != text:
                key = (path, "tls_verify")
                if key not in seen:
                    seen.add(key)
                    proposed = proposed_text.encode("utf-8")
                    proposals.append({
                        "proposal_id": f"P{len(proposals)+1:03d}",
                        "file": path,
                        "title": "Enable TLS certificate verification",
                        "category": "Transport security",
                        "rationale": "Changes the exact verify=False assignment to verify=True. The application must still use a valid CA trust store and hostname verification.",
                        "patch_available": True,
                        "patch_kind": "tls_verify",
                        "status": "PENDING_REVIEW",
                        "original_sha256": hashlib.sha256(raw).hexdigest(),
                        "proposed_sha256": hashlib.sha256(proposed).hexdigest(),
                        "diff": _proposal_diff(path, raw, proposed),
                        "validation_note": "Python AST parsing is run after approval. Network trust-chain and hostname behavior require application integration tests.",
                    })

        # Environment externalization can be proposed only for explicit
        # credential variable assignments already supported by the narrow
        # migration helper. Do not include the original secret in the proposal.
        if ext in {".py", ".js", ".jsx", ".ts", ".tsx"}:
            proposed_text, secret_changes = _apply_secret_environment_migration(path, text)
            if secret_changes and proposed_text != text:
                key = (path, "secret_env")
                if key not in seen:
                    seen.add(key)
                    proposed = proposed_text.encode("utf-8")
                    proposals.append({
                        "proposal_id": f"P{len(proposals)+1:03d}",
                        "file": path,
                        "title": "Externalize embedded credential",
                        "category": "Secret management",
                        "rationale": "Moves a narrowly matched API key/token assignment to an environment variable. Previously exposed credentials still require rotation.",
                        "patch_available": True,
                        "patch_kind": "secret_env",
                        "status": "PENDING_REVIEW",
                        "original_sha256": hashlib.sha256(raw).hexdigest(),
                        "proposed_sha256": hashlib.sha256(proposed).hexdigest(),
                        "diff": _proposal_diff(path, raw, proposed),
                        "validation_note": "Set the named environment variable securely and rotate any previously exposed credential.",
                    })

    # Every detected issue receives an explicit review record, even where a
    # safe source patch cannot be inferred from static evidence.
    analysis = analyze_files(files)
    represented = {(p["file"], p["category"]) for p in proposals}
    for finding in analysis["findings"]:
        key = (finding["file"], finding["category"])
        if key in represented:
            continue
        represented.add(key)
        proposals.append({
            "proposal_id": f"P{len(proposals)+1:03d}",
            "file": finding["file"],
            "title": f"Review {finding['algorithm']} migration",
            "category": finding["category"],
            "rationale": finding["recommended_action"],
            "patch_available": False,
            "patch_kind": None,
            "status": "GUIDANCE_ONLY",
            "original_sha256": hashlib.sha256(files[finding["file"]]).hexdigest(),
            "proposed_sha256": None,
            "diff": "",
            "validation_note": "No source patch is generated because the cryptographic operation or protocol context cannot be safely inferred.",
        })
    # Module 7.1 enriches guidance-only proposals with operation-aware
    # remediation plans. It deliberately does not rewrite cryptographic
    # operations when key lifecycle, protocol context, or data format is unknown.
    plans = [
        {"match": ("main.py", "RSA"), "id": "RSA_KEY_ESTABLISHMENT", "severity": "HIGH",
         "title": "Redesign RSA key establishment using ML-KEM",
         "design": "For new key establishment, use ML-KEM-768 to encapsulate a shared secret, derive an AES-256-GCM key with HKDF-SHA256, and authenticate protocol context. ML-KEM does not replace RSA signatures.",
         "checks": ["Identify whether RSA is used for encryption, key transport, or signatures.", "Define versioned message formats and key identifiers.", "Test interoperability, key rotation, downgrade resistance, and failure handling."]},
        {"match": ("main.py", "MD5"), "id": "PASSWORD_HASHING", "severity": "CRITICAL",
         "title": "Replace password MD5 with a password-hashing scheme",
         "design": "Use Argon2id with a unique random salt and deployment-calibrated memory/time parameters. Store algorithm and parameters with each hash and support gradual rehash on successful login. Do not substitute plain SHA-256.",
         "checks": ["Trace the value to confirm it is a password, not a checksum.", "Use a vetted password-hashing library.", "Test verification, legacy-hash upgrade, rate limiting, and parameter migration."]},
        {"match": ("main.py", "AES"), "id": "AES_KEY_MANAGEMENT", "severity": "CRITICAL",
         "title": "Remove embedded AES key material",
         "design": "Generate keys with a cryptographically secure random generator and load them through a secrets manager or protected runtime configuration. Never commit key bytes. Plan rotation and key identifiers.",
         "checks": ["Determine whether the sample key is used in production paths.", "Rotate any previously exposed key.", "Test missing-key failure, rotation, access control, and backup/recovery."]},
        {"match": ("config.js", "AES"), "id": "AES_AUTHENTICATED_ENCRYPTION", "severity": "HIGH",
         "title": "Migrate CBC encryption to authenticated encryption",
         "design": "Use AES-256-GCM with a unique nonce per key, retain the authentication tag, authenticate relevant metadata as AAD, and version the ciphertext envelope. Define a controlled decrypt-and-re-encrypt path for existing data.",
         "checks": ["Locate encryption and decryption call sites.", "Specify nonce, tag, AAD, and envelope format.", "Test tamper rejection, nonce uniqueness, old-data migration, and interoperability."]},
        {"match": ("security.py", "DES"), "id": "DES_REMOVAL", "severity": "HIGH",
         "title": "Remove DES cryptography",
         "design": "Replace actual DES encryption with an authenticated modern construction such as AES-256-GCM. If this is only a label or comment, remove misleading legacy references rather than inventing a transformation.",
         "checks": ["Find actual DES encrypt/decrypt operations and stored data formats.", "Plan data re-encryption and key rotation.", "Test decrypt compatibility and tamper detection."]},
        {"match": ("security.py", "SHA-1"), "id": "SHA1_REVIEW", "severity": "HIGH",
         "title": "Replace security-sensitive SHA-1 usage",
         "design": "Use SHA-256 or SHA-384 for general-purpose integrity and digest use. If used in signatures, certificates, or protocol identifiers, follow the applicable format and trust-chain migration rather than changing the digest token alone.",
         "checks": ["Identify whether SHA-1 is used for passwords, signatures, identifiers, or checksums.", "Preserve compatibility where required and version stored values.", "Test verification and migration of existing records."]},
        {"match": ("config.js", "TLS"), "id": "TLS_PROTOCOL", "severity": "HIGH",
         "title": "Remove TLS 1.0 protocol configuration",
         "design": "Require TLS 1.2 or TLS 1.3 according to deployment compatibility, with modern cipher suites and certificate/hostname verification. A configuration string alone does not prove negotiated protocol security.",
         "checks": ["Locate the actual TLS client/server configuration.", "Verify negotiated protocol and certificate chain in integration tests.", "Test hostname mismatch, expired certificate, and untrusted CA rejection."]},
        {"match": ("security.py", "TLS"), "id": "TLS_INTEGRATION", "severity": "HIGH",
         "title": "Connect certificate verification to real network calls",
         "design": "Pass the verified setting to the actual HTTP/TLS client, use a valid CA trust store, retain hostname verification, and fail closed. The current standalone verify=True assignment is not evidence of an enforced connection policy.",
         "checks": ["Find every network call and its TLS client.", "Confirm verify=True or equivalent is passed at the call site.", "Test untrusted CA and hostname mismatch failures."]},
    ]
    for plan in plans:
        filename, token = plan["match"]
        for proposal in proposals:
            # Preserve narrowly matched, reviewable source patches (for example,
            # an exact Python verify=False assignment). Operation-aware plans
            # should enrich guidance-only findings, not silently downgrade a
            # patch that already has a concrete, human-approved transformation.
            if (
                not proposal.get("patch_available")
                and proposal.get("file", "").endswith(filename)
                and token.lower() in (
                    proposal.get("title", "") + " " + proposal.get("category", "")
                ).lower()
            ):
                proposal.update({
                    "module": "7.1", "remediation_id": plan["id"],
                    "severity": plan["severity"], "title": plan["title"],
                    "recommended_design": plan["design"],
                    "validation_requirements": plan["checks"],
                    "patch_available": False, "patch_kind": None,
                    "status": "GUIDANCE_ONLY",
                    "validation_note": "Operation-aware guidance only. No source transformation is safe without confirming usage and integration context.",
                })
    return proposals


def _apply_assisted_proposal(files, proposal):
    path = proposal["file"]
    if path not in files:
        raise ValueError(f"Proposal source file is missing: {path}")
    original = files[path]
    text = original.decode("utf-8")
    if proposal["patch_kind"] == "tls_verify":
        updated, count = re.subn(
            r"(?m)^(\s*verify\s*=\s*)False(\s*(?:#.*)?)$",
            r"\1True\2",
            text,
            count=1,
        )
        if count != 1:
            raise ValueError(f"TLS patch no longer matches source: {path}")
    elif proposal["patch_kind"] == "secret_env":
        updated, changes = _apply_secret_environment_migration(path, text)
        if not changes:
            raise ValueError(f"Credential patch no longer matches source: {path}")
    else:
        raise ValueError("Unsupported assisted patch type.")
    content = updated.encode("utf-8")
    validation = _validate_changed_file(path, content)
    if validation["status"] == "FAIL":
        raise ValueError(f"Approved patch failed syntax validation: {path}: {validation['message']}")
    files[path] = content
    return {
        "file": path,
        "proposal_id": proposal["proposal_id"],
        "patch_kind": proposal["patch_kind"],
        "validation": validation,
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _load_assisted_job(job_id):
    try:
        report_path = _assisted_job_path(job_id, "json")
        source_path = _assisted_job_path(job_id, "source.zip")
    except ValueError:
        return None, None, None
    if not os.path.isfile(report_path) or not os.path.isfile(source_path):
        return None, None, None
    with open(report_path, "r", encoding="utf-8") as handle:
        report = json.load(handle)
    with open(source_path, "rb") as handle:
        raw = handle.read()
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
        files = {}
        for info in archive.infolist():
            if not info.is_dir():
                if not _safe_member_name(info.filename):
                    raise ValueError("Unsafe path in stored source archive.")
                files[info.filename.replace("\\", "/")] = archive.read(info)
        archive.close()
    except Exception:
        return None, None, None
    return report, files, raw


@project_migration_bp.route("/api/project-migration/assisted/prepare", methods=["POST"])
def prepare_assisted_migration():
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename or not uploaded.filename.lower().endswith(".zip"):
        return jsonify({"error": "Upload a ZIP using multipart field 'file'."}), 400
    try:
        files = _read_archive(uploaded)
        proposals = _build_assisted_proposals(files)
        job_id = str(uuid4())
        report = {
            "product": "Q-SHIELD",
            "module": 7,
            "workflow": "HUMAN_APPROVED_ASSISTED_PATCHES",
            "job_id": job_id,
            "original_project_filename": secure_filename(uploaded.filename),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "scanned_source_files": analyze_files(files)["scanned_source_files"],
            "proposal_count": len(proposals),
            "patchable_count": sum(1 for item in proposals if item["patch_available"]),
            "guidance_only_count": sum(1 for item in proposals if not item["patch_available"]),
            "proposals": proposals,
            "decisions": [],
            "applied_patches": [],
            "limitations": [
                "Uploaded project code is never executed.",
                "Only narrowly matched TLS verification flags and supported credential assignments receive source patches.",
                "RSA/ECC, DES, AES mode, password hashing and protocol redesign remain guidance-only unless a future language- and operation-specific transformer is added.",
                "Syntax validation is not a substitute for integration, interoperability or security testing.",
            ],
        }
        folder = _assisted_store_dir()
        with zipfile.ZipFile(os.path.join(folder, f"{job_id}.source.zip"), "w", zipfile.ZIP_DEFLATED) as archive:
            for path, content in files.items():
                archive.writestr(path, content)
        with open(os.path.join(folder, f"{job_id}.json"), "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        return jsonify(report), 201
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        current_app.logger.exception("Assisted patch preparation failed")
        return jsonify({"error": "Assisted patch preparation failed. Check backend logs."}), 500


@project_migration_bp.route("/api/project-migration/assisted/<job_id>", methods=["GET"])
def get_assisted_migration(job_id):
    report, _, _ = _load_assisted_job(job_id)
    if report is None:
        return jsonify({"error": "Assisted migration job not found."}), 404
    return jsonify(report), 200


@project_migration_bp.route("/api/project-migration/assisted/<job_id>/decisions", methods=["POST"])
def decide_assisted_migration(job_id):
    report, source_files, _ = _load_assisted_job(job_id)
    if report is None:
        return jsonify({"error": "Assisted migration job not found."}), 404
    payload = request.get_json(silent=True) or {}
    decisions = payload.get("decisions")
    if not isinstance(decisions, list) or not decisions:
        return jsonify({"error": "Provide a non-empty decisions array."}), 400

    proposal_map = {item["proposal_id"]: item for item in report["proposals"]}
    accepted = []
    for decision in decisions:
        if not isinstance(decision, dict):
            return jsonify({"error": "Each decision must be an object."}), 400
        proposal_id = decision.get("proposal_id")
        choice = decision.get("decision")
        proposal = proposal_map.get(proposal_id)
        if proposal is None:
            return jsonify({"error": f"Unknown proposal: {proposal_id}"}), 400
        if choice not in ("approve", "reject"):
            return jsonify({"error": f"Decision for {proposal_id} must be approve or reject."}), 400
        if not proposal["patch_available"]:
            return jsonify({"error": f"{proposal_id} is guidance-only and cannot be approved as a source patch."}), 400
        if proposal["status"] != "PENDING_REVIEW":
            return jsonify({"error": f"{proposal_id} has already been decided."}), 409
        proposal["status"] = "APPROVED" if choice == "approve" else "REJECTED"
        report["decisions"].append({
            "proposal_id": proposal_id,
            "decision": choice,
            "decided_at": datetime.now(timezone.utc).isoformat(),
        })

    # Rebuild from the immutable source archive and apply every approved patch.
    applied = []
    try:
        for proposal in report["proposals"]:
            if proposal["status"] == "APPROVED":
                applied.append(_apply_assisted_proposal(source_files, proposal))
    except ValueError as error:
        return jsonify({"error": str(error)}), 409

    report["applied_patches"] = applied
    report["modified_files"] = sorted({item["file"] for item in applied})
    report["modified_file_count"] = len(report["modified_files"])
    report["pending_patch_count"] = sum(1 for item in report["proposals"] if item["status"] == "PENDING_REVIEW")
    report["rejected_patch_count"] = sum(1 for item in report["proposals"] if item["status"] == "REJECTED")
    report["approved_patch_count"] = sum(1 for item in report["proposals"] if item["status"] == "APPROVED")

    output_buffer = io.BytesIO()
    with zipfile.ZipFile(output_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, content in source_files.items():
            archive.writestr(path, content)
        archive.writestr("QSHIELD_ASSISTED_PATCH_REPORT.json", json.dumps(report, indent=2).encode("utf-8"))
        readme = (
            "# Q-SHIELD Human-Approved Assisted Migration\n\n"
            f"Approved patches: {report['approved_patch_count']}\n"
            f"Rejected patches: {report['rejected_patch_count']}\n"
            f"Pending patch reviews: {report['pending_patch_count']}\n\n"
            "Only explicitly approved, narrowly matched patches were applied. "
            "Guidance-only items remain unchanged. Run project tests and security review before deployment.\n"
        )
        archive.writestr("QSHIELD_ASSISTED_PATCH_README.md", readme.encode("utf-8"))
    output_buffer.seek(0)
    with open(_assisted_job_path(job_id, "output.zip"), "wb") as handle:
        handle.write(output_buffer.getvalue())
    with open(_assisted_job_path(job_id, "json"), "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    return jsonify({
        "message": "Human decisions recorded; approved patches applied to a separate output archive.",
        "job_id": job_id,
        "approved_patch_count": report["approved_patch_count"],
        "rejected_patch_count": report["rejected_patch_count"],
        "pending_patch_count": report["pending_patch_count"],
        "modified_files": report["modified_files"],
        "download_endpoint": f"/api/project-migration/assisted/{job_id}/download",
        "report": report,
    }), 200


@project_migration_bp.route("/api/project-migration/assisted/<job_id>/download", methods=["GET"])
def download_assisted_migration(job_id):
    try:
        path = _assisted_job_path(job_id, "output.zip")
    except ValueError:
        return jsonify({"error": "Invalid assisted migration job ID."}), 400
    if not os.path.isfile(path):
        return jsonify({"error": "No approved-patch output exists yet. Submit review decisions first."}), 404
    return send_file(path, as_attachment=True, download_name=f"QSHIELD_Assisted_Approved_{job_id[:8]}.zip", mimetype="application/zip")
