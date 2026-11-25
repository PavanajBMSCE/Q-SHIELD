
import difflib
import hashlib
import io
import json
import os
import re
import uuid
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import PurePosixPath

from flask import Blueprint, jsonify, request, send_file
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Preformatted, KeepTogether
)

from assessment.scoring import calculate_readiness_metrics
from scanner.crypto_detector import (
    scan_file, SUPPORTED_EXTENSIONS,
    _remove_python_comments, _remove_other_comments, _mask_strings
)

comparison_bp = Blueprint("comparison", __name__)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE_DIR = os.path.join(BASE_DIR, "uploads", "comparisons")
os.makedirs(STORE_DIR, exist_ok=True)

MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_EXPANDED_BYTES = 50 * 1024 * 1024
MAX_FILES = 500
MAX_SINGLE_FILE = 2 * 1024 * 1024

# Generated migration evidence describes algorithms; it is not application source.
GENERATED_ARTIFACT_NAMES = {
    "qshield_migration_report.json",
    "qshield_migration_readme.md",
    "qshield_comparison_report.json",
    "qshield_pqc_migration_report.json",
    "qshield_pqc_migration_readme.md",
    "qshield_module8_report.json",
    "qshield_module710_report.json",
    "qshield_audit_report.json",
    "qshield_assisted_patch_report.json",
    "assisted_patch_report.json",
    "migration_report.json",
    "comparison_report.json",
}
GENERATED_ARTIFACT_DIRS = {"__pycache__", ".git", "node_modules", "dist", "build", ".venv", "venv", "target", ".idea", ".vscode", ".qshield", "qshield_reports"}

PQC_PATTERNS = {
    "ML-KEM": re.compile(r"\bML[\-_]?KEM(?:[\-_]?(?:512|768|1024))?\b|\bMLKEM(?:512|768|1024)PrivateKey\b|\bKyber\b", re.I),
    "ML-DSA": re.compile(r"\bML[\-_]?DSA(?:[\-_]?(?:44|65|87))?\b|\bDilithium\b", re.I),
    "SLH-DSA": re.compile(r"\bSLH[\-_]?DSA\b|\bSPHINCS\+?\b", re.I),
    "FALCON": re.compile(r"\bFalcon(?:[\-_]?\d+)?\b", re.I),
    "HQC": re.compile(r"\bHQC(?:[\-_]?\d+)?\b", re.I),
}
CLASSICAL = {"RSA", "ECC", "MD5", "SHA-1", "DES"}
ALGO_RE = {
    "RSA": re.compile(r"\bRSA\b|rsa\.", re.I),
    "ECC": re.compile(r"\b(?:ECDH|ECDSA|ECC|X25519|X448|Ed25519|Ed448)\b|EllipticCurve", re.I),
    "AES": re.compile(r"\bAES(?:[-_ ]?\d+)?\b|AESGCM", re.I),
    "DES": re.compile(r"\bDES\b|3DES|TripleDES", re.I),
    "MD5": re.compile(r"\bMD5\b|md5", re.I),
    "SHA-1": re.compile(r"\bSHA[-_]?1\b|sha1", re.I),
    "SHA-256": re.compile(r"\bSHA[-_]?256\b|sha256", re.I),
    "SHA-384": re.compile(r"\bSHA[-_]?384\b|sha384", re.I),
    "SHA-512": re.compile(r"\bSHA[-_]?512\b|sha512", re.I),
}

def _safe_read_zip(upload):
    raw = upload.read()
    if not raw or len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError("ZIP must be non-empty and no larger than 20 MB.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise ValueError("Uploaded file is not a valid ZIP archive.")
    members = archive.infolist()
    if len(members) > MAX_FILES:
        raise ValueError("ZIP contains more than 500 entries.")
    total = 0
    files = {}
    file_members = [m for m in members if not m.is_dir()]
    first_parts = [PurePosixPath(m.filename).parts for m in file_members]
    common_root = None
    if first_parts and all(len(parts) > 1 for parts in first_parts):
        roots = {parts[0] for parts in first_parts}
        if len(roots) == 1:
            common_root = next(iter(roots))
    for member in members:
        if member.is_dir():
            continue
        path = PurePosixPath(member.filename)
        mode = member.external_attr >> 16
        if path.is_absolute() or ".." in path.parts or "\\" in member.filename or ":" in member.filename:
            raise ValueError("Unsafe path detected in ZIP.")
        if (mode & 0o170000) == 0o120000:
            raise ValueError("Symbolic links are not allowed in ZIP uploads.")
        total += member.file_size
        if total > MAX_EXPANDED_BYTES or member.file_size > MAX_SINGLE_FILE:
            raise ValueError("ZIP exceeds expanded-size or per-file limits.")
        if member.file_size and member.compress_size == 0:
            raise ValueError("Invalid compressed entry.")
        if member.compress_size and member.file_size / member.compress_size > 100:
            raise ValueError("Suspicious compression ratio detected.")
        # Never treat Q-SHIELD-generated reports, documentation or build output
        # as application code. Keep the archive intact for the evidence bundle.
        lowered_parts = tuple(part.lower() for part in path.parts)
        if any(part in GENERATED_ARTIFACT_DIRS for part in lowered_parts[:-1]):
            continue
        if path.name.lower() in GENERATED_ARTIFACT_NAMES:
            continue
        if path.suffix.lower() in SUPPORTED_EXTENSIONS:
            data = archive.read(member)
            try:
                source = data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            normalized = path.as_posix()
            # Strip a common enclosing project directory when every archive file shares it.
            parts = normalized.split("/")
            if common_root and parts[0] == common_root:
                normalized = "/".join(parts[1:])
            files[normalized] = source
    archive.close()
    if not files:
        raise ValueError("No supported UTF-8 source files were found in the ZIP.")
    return files, hashlib.sha256(raw).hexdigest(), len(raw)

def _analyse(files):
    findings = []
    algorithms = Counter()
    pqc = Counter()
    pqc_evidence = []
    file_summaries = {}

    for filename, source in sorted(files.items()):
        raw_findings = scan_file(filename, source)
        for item in raw_findings:
            finding = dict(item)
            finding["file_name"] = filename
            findings.append(finding)
            # Algorithm inventory is one record per algorithm per source file;
            # multiple scanner occurrences in the same file must not inflate inventory.

        # PQC evidence is collected from code/configuration rather than comments
        # or docstrings, preventing documentation text from inflating adoption.
        # A callable/class-like API expression is a stronger candidate, but still needs review.
        extension = PurePosixPath(filename).suffix.lower()
        if extension == ".py":
            evidence_source = _mask_strings(_remove_python_comments(source), True)
        else:
            evidence_source = _mask_strings(_remove_other_comments(source), False)
        for line_number, line in enumerate(evidence_source.splitlines(), start=1):
            for name, pattern in PQC_PATTERNS.items():
                for match in pattern.finditer(line):
                    token = match.group(0)
                    # Count a source-level API candidate only for recognizable callable
                    # API identifiers; comments/docstrings/reports are not implementation proof.
                    api_candidate = bool(re.search(
                        r"\b(?:MLKEM(?:512|768|1024)PrivateKey|MLDSA(?:44|65|87)PrivateKey)"
                        r"\s*(?:\.|\()|\b(?:encapsulate|decapsulate|keypair|generate_keypair)\s*\(|"
                        r"oqs\.(?:KeyEncapsulation|Signature)\s*\(|pqcrypto\.(?:kem|sign)\.",
                        line, re.I
                    ))
                    pqc[name] += 1
                    pqc_evidence.append({
                        "algorithm": name,
                        "token": token,
                        "file": filename,
                        "line": line_number,
                        "classification": "API_USAGE_CANDIDATE" if api_candidate else "TOKEN_REFERENCE",
                        "verification": "UNVERIFIED",
                        "note": "Static source evidence only; run the dedicated verifier for functional evidence."
                    })

        file_summaries[filename] = {
            "lines": len(source.splitlines()),
            "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "bytes": len(source.encode("utf-8"))
        }

    # Inventory distribution is unique per algorithm/source file, not raw occurrence count.
    for filename, source in sorted(files.items()):
        extension = PurePosixPath(filename).suffix.lower()
        inventory_source = (_remove_python_comments(source) if extension == ".py"
                            else _remove_other_comments(source))
        for name, pattern in ALGO_RE.items():
            if pattern.search(inventory_source):
                algorithms[name] += 1

    severity = Counter(str(x.get("severity", "INFO")).upper() for x in findings)
    inventory_records = [{"algorithm": algorithm} for algorithm, count in algorithms.items()
                         for _ in range(max(0, int(count)))]
    readiness_metrics = calculate_readiness_metrics(inventory_records, findings)
    score = readiness_metrics["readiness_score"]
    level = readiness_metrics["risk_level"]
    return {
        "file_count": len(files), "total_findings": len(findings),
        "severity": {k: severity.get(k, 0) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")},
        "algorithms": dict(algorithms), "pqc_algorithms": dict(pqc),
        "pqc_evidence": pqc_evidence,
        "pqc_verification_note": "Detected names and API-shaped expressions are evidence candidates only; no PQC implementation is marked verified automatically.",
        "classical_algorithm_findings": sum(algorithms.get(k, 0) for k in CLASSICAL),
        "readiness": {**readiness_metrics, "method": readiness_metrics["scoring_method"]},
        "findings": findings, "files": file_summaries,
        "source_bytes": sum(x["bytes"] for x in file_summaries.values())
    }

def _severity_key(item):
    return (item.get("file_name",""), str(item.get("algorithm","")), str(item.get("finding","")))

def _is_modern_algorithm_adoption(item):
    """Modern digest and AEAD profiles are adoption evidence, not vulnerabilities."""
    algorithm = str(item.get("algorithm", "")).upper()
    finding = str(item.get("finding", "")).lower()
    return (
        algorithm == "SHA-256" and finding in {"review", "modern algorithm detected", "modern digest adoption"}
    ) or (
        algorithm == "AES" and finding == "authenticated encryption adoption"
    )


def _is_informational_inventory(item):
    """API-presence notices are inventory context, not security findings."""
    return (
        str(item.get("algorithm", "")).lower() == "cryptographic api"
        and str(item.get("severity", "")).upper() == "INFO"
    )


def _compare(before, after, before_files, after_files):
    before_info = [x for x in before["findings"] if _is_informational_inventory(x)]
    after_info = [x for x in after["findings"] if _is_informational_inventory(x)]
    before_findings = {
        _severity_key(x): x for x in before["findings"]
        if not _is_modern_algorithm_adoption(x) and not _is_informational_inventory(x)
    }
    after_findings = {
        _severity_key(x): x for x in after["findings"]
        if not _is_modern_algorithm_adoption(x) and not _is_informational_inventory(x)
    }
    modern_adoptions = []
    for filename, source in sorted(after_files.items()):
        for line_no, line in enumerate(source.splitlines(), 1):
            if re.search(r"(?:hashlib\.sha256|hashes\.SHA256)\s*\(", line, re.I) or re.search(r"(?:hash|hashAlgorithm)\s*=\s*['\"]SHA-256['\"]", line, re.I):
                context = "Password-storage context requires a password-hashing KDF review." if re.search(r"password|passwd|pwd", line, re.I) else "Modern digest configuration/API detected; confirm intended use and protocol compatibility."
                modern_adoptions.append({"file": filename, "line": line_no, "algorithm": "SHA-256", "classification": "MODERN_ALGORITHM_ADOPTED", "review_note": context})
            if re.search(r"AESGCM|AES[-_ ]?256[-_ ]?GCM", line, re.I):
                modern_adoptions.append({"file": filename, "line": line_no, "algorithm": "AES-256-GCM", "classification": "AUTHENTICATED_ENCRYPTION_ADOPTED", "review_note": "Verify unique nonce generation, authentication-tag handling, associated data and ciphertext format compatibility."})
    resolved_keys = sorted(set(before_findings) - set(after_findings))
    remaining_keys = sorted(set(before_findings) & set(after_findings))
    new_keys = sorted(set(after_findings) - set(before_findings))
    before_names, after_names = set(before_files), set(after_files)
    common = sorted(before_names & after_names)
    renamed = []
    removed = sorted(before_names - after_names)
    added = sorted(after_names - before_names)
    # Hash-based rename hints are informational only.
    after_hash_map = {}
    for name in added:
        after_hash_map.setdefault(after["files"][name]["sha256"], []).append(name)
    for old in list(removed):
        candidates = after_hash_map.get(before["files"][old]["sha256"], [])
        if candidates:
            renamed.append({"from": old, "to": candidates.pop(0), "match": "identical SHA-256"})
            removed.remove(old)
            added.remove(renamed[-1]["to"])
    diffs = []
    for name in common:
        a, b = before_files[name], after_files[name]
        if a != b:
            udiff = list(difflib.unified_diff(a.splitlines(), b.splitlines(),
                       fromfile=f"before/{name}", tofile=f"after/{name}", lineterm=""))
            changed = sum(1 for line in udiff if line.startswith("+") and not line.startswith("+++"))
            deleted = sum(1 for line in udiff if line.startswith("-") and not line.startswith("---"))
            diffs.append({"file": name, "added_lines": changed, "removed_lines": deleted,
                          "diff": "\n".join(udiff)[:30000]})
    # Use unique security-finding signatures for resolution/effectiveness math.
    # Preserve raw scanner occurrence counts separately for transparent reporting.
    before_total = len(before_findings)
    after_total = len(after_findings)
    resolved = len(resolved_keys)
    effectiveness = round((resolved / before_total) * 100, 2) if before_total else 100.0
    return {
        "findings": {
            "resolved": [before_findings[k] for k in resolved_keys],
            "remaining": [before_findings[k] for k in remaining_keys],
            "new": [after_findings[k] for k in new_keys],
            "informational": {"before": before_info, "after": after_info},
            "counts": {"before": before_total, "after": after_total,
                       "raw_scanner_before": len(before["findings"]), "raw_scanner_after": len(after["findings"]),
                       "informational_before": len(before_info), "informational_after": len(after_info),
                       "resolved": resolved, "remaining": len(remaining_keys), "new": len(new_keys)}
        },
        "files": {"common": len(common), "added": added, "removed": removed, "renamed_identical_hash": renamed},
        "code_diffs": diffs,
        "migration_effectiveness_percent": effectiveness,
        "modern_algorithm_adoptions": modern_adoptions,
        "conventional_hardening_count": len(modern_adoptions),
        "pqc_migration_status": "PQC_API_CANDIDATE_UNVERIFIED" if any(x.get("classification") == "API_USAGE_CANDIDATE" for x in after.get("pqc_evidence", [])) else ("PQC_TOKEN_REFERENCE_ONLY" if after.get("pqc_evidence") else "NO_PQC_EVIDENCE_DETECTED"),
        "effectiveness_note": "Resolved security finding signatures / original security finding signatures. Modern algorithm adoptions are reported separately; heuristic comparison; review context and false positives."
    }

def _load_benchmarks():
    """
    Return historical benchmark observations from both supported storage models.

    Older Module 5 records are stored row-by-row in benchmark_results.
    The current comparative benchmark runner stores complete JSON reports in
    comparative_benchmark_runs. Normalize both formats for the comparison UI.
    """
    from database.db import get_db_connection

    conn = get_db_connection()
    try:
        benchmarks = []

        # Legacy Module 5 records (one row per algorithm/operation).
        legacy_rows = conn.execute("""
            SELECT algorithm, mode, operation, key_size, ciphertext_size,
                   execution_time, created_at
            FROM benchmark_results
            ORDER BY created_at DESC, id DESC
            LIMIT 200
        """).fetchall()

        for row in legacy_rows:
            item = dict(row)
            item.update({
                "source": "Module 5 historical record",
                "mean_ms": item.get("execution_time"),
                "median_ms": None,
                "p95_ms": None,
                "samples": None,
            })
            benchmarks.append(item)

        # Current comparative benchmark sessions (one JSON report per run).
        run_rows = conn.execute("""
            SELECT benchmark_id, repetitions, warmups, report_json, created_at
            FROM comparative_benchmark_runs
            ORDER BY created_at DESC, id DESC
            LIMIT 100
        """).fetchall()

        for row in run_rows:
            run = dict(row)
            try:
                report = json.loads(run["report_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                # Preserve the rest of the comparison if one historical report
                # is malformed, but do not fabricate measurements for it.
                continue

            for result in report.get("results", []):
                if not isinstance(result, dict):
                    continue
                sizes = result.get("sizes_bytes") or {}
                operations = result.get("operations") or {}
                for operation, stats in operations.items():
                    if not isinstance(stats, dict):
                        continue
                    benchmarks.append({
                        "algorithm": result.get("algorithm", "Unknown"),
                        "mode": result.get("family", "unspecified"),
                        "operation": operation,
                        "key_size": sizes.get("public_key"),
                        "ciphertext_size": sizes.get("ciphertext"),
                        "execution_time": stats.get("mean_ms"),
                        "mean_ms": stats.get("mean_ms"),
                        "median_ms": stats.get("median_ms"),
                        "p95_ms": stats.get("p95_ms"),
                        "samples": stats.get("samples", run.get("repetitions")),
                        "created_at": run.get("created_at"),
                        "benchmark_id": run.get("benchmark_id"),
                        "source": "Comparative benchmark session",
                        "standard": result.get("standard"),
                        "family": result.get("family"),
                    })

        # Newest first. Keep all observations; do not collapse distinct runs
        # into one record because historical measurements are evidence.
        benchmarks.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        return benchmarks[:300]
    finally:
        conn.close()

def _build_pdf(report):
    from xml.sax.saxutils import escape
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=16*mm, leftMargin=16*mm,
                            topMargin=16*mm, bottomMargin=16*mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontSize=23,
                              leading=28, textColor=colors.HexColor("#12345A"), alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], textColor=colors.HexColor("#176B87"),
                              spaceBefore=12, spaceAfter=7))
    styles.add(ParagraphStyle(name="SmallCode", fontName="Courier", fontSize=6.5, leading=8))
    story = []
    story += [Spacer(1, 22*mm), Paragraph("Q-SHIELD", styles["CoverTitle"]),
              Paragraph("CLASSICAL vs POST-QUANTUM CRYPTOGRAPHY", styles["Heading2"]),
              Paragraph("Comparative Migration Audit Report", styles["Heading1"]),
              Spacer(1, 8*mm),
              Paragraph(f"Comparison ID: {escape(str(report['comparison_id']))}", styles["BodyText"]),
              Paragraph(f"Generated: {report['created_at']}", styles["BodyText"]),
              Paragraph(f"Original: {escape(str(report['before']['project_name']))}", styles["BodyText"]),
              Paragraph(f"Migrated: {escape(str(report['after']['project_name']))}", styles["BodyText"]),
              PageBreak()]
    story += [Paragraph("1. Executive Summary", styles["Section"])]
    f = report["comparison"]["findings"]["counts"]
    summary = [
        ["Metric", "Before", "After", "Change"],
        ["Source files", report["before"]["analysis"]["file_count"], report["after"]["analysis"]["file_count"],
         report["after"]["analysis"]["file_count"] - report["before"]["analysis"]["file_count"]],
        ["Scanner findings (raw occurrences)", f.get("raw_scanner_before", f["before"]), f.get("raw_scanner_after", f["after"]), f.get("raw_scanner_after", f["after"]) - f.get("raw_scanner_before", f["before"])],
        ["Unique actionable security finding signatures", f["before"], f["after"], f["after"] - f["before"]],
        ["Informational cryptographic API references", f.get("informational_before", 0), f.get("informational_after", 0), f.get("informational_after", 0) - f.get("informational_before", 0)],
        ["PQC readiness score", report["before"]["analysis"]["readiness"]["score"],
         report["after"]["analysis"]["readiness"]["score"],
         report["after"]["analysis"]["readiness"]["score"] - report["before"]["analysis"]["readiness"]["score"]],
        ["PQC algorithms detected", sum(report["before"]["analysis"]["pqc_algorithms"].values()),
         sum(report["after"]["analysis"]["pqc_algorithms"].values()), "—"],
        ["Migration effectiveness", "—", f"{report['comparison']['migration_effectiveness_percent']}%", "—"],
        ["Conventional hardening adoptions", "—", report["comparison"].get("conventional_hardening_count", 0), "Reported separately"],
        ["PQC migration evidence", "—", report["comparison"].get("pqc_migration_status", "NOT_ASSESSED"), "Not proof of implementation"],
    ]
    t = Table(summary, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#12345A")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.4,colors.HexColor("#CCD5E0")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#F1F5F9")]),
        ("PADDING",(0,0),(-1,-1),7),("VALIGN",(0,0),(-1,-1),"MIDDLE")]))
    story += [t, Spacer(1,5*mm)]
    story += [Paragraph("2. Cryptographic Algorithm Inventory", styles["Section"])]
    keys = sorted(set(report["before"]["analysis"]["algorithms"]) | set(report["after"]["analysis"]["algorithms"]))
    rows = [["Algorithm","Before occurrences","After occurrences"]]
    for key in keys:
        rows.append([key, report["before"]["analysis"]["algorithms"].get(key,0),
                     report["after"]["analysis"]["algorithms"].get(key,0)])
    if len(rows) == 1: rows.append(["No algorithms detected",0,0])
    t = Table(rows, repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#176B87")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.4,colors.grey),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#F1F5F9")]),
        ("PADDING",(0,0),(-1,-1),6)]))
    story.append(t)
    story += [Paragraph("2.1 Post-Quantum Detection Evidence", styles["Section"])]
    pqc_evidence = report["after"]["analysis"].get("pqc_evidence", [])
    if pqc_evidence:
        evidence_rows = [["Algorithm", "File", "Line", "Evidence", "Status"]]
        for item in pqc_evidence[:60]:
            evidence_rows.append([str(item.get("algorithm", "—")), str(item.get("file", "—")),
                                  str(item.get("line", "—")), str(item.get("classification", "—")),
                                  str(item.get("verification", "UNVERIFIED"))])
        evidence_table = Table(evidence_rows, repeatRows=1)
        evidence_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#176B87")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("GRID", (0,0), (-1,-1), .3, colors.grey),
            ("FONTSIZE", (0,0), (-1,-1), 7),
            ("PADDING", (0,0), (-1,-1), 5),
        ]))
        story.append(evidence_table)
    else:
        story.append(Paragraph("No PQC tokens were detected in supported application source/configuration files. Generated migration reports and README files are excluded from this analysis.", styles["BodyText"]))
    story.append(Paragraph("Detection evidence is not proof of a correct PQC implementation. All detections remain unverified pending manual review of API semantics, parameter sets, key handling, protocol integration and test evidence.", styles["BodyText"]))
    story += [Paragraph("2.2 Conventional Cryptographic Hardening", styles["Section"])]
    adoptions = report["comparison"].get("modern_algorithm_adoptions", [])
    if adoptions:
        adoption_rows = [["File", "Line", "Algorithm", "Review note"]]
        for item in adoptions[:50]:
            adoption_rows.append([str(item["file"]), str(item["line"]), item["algorithm"], item["review_note"]])
        adoption_table = Table(adoption_rows, repeatRows=1, colWidths=[42*mm, 12*mm, 25*mm, 95*mm])
        adoption_table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#176B87")),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.3,colors.grey),
            ("FONTSIZE",(0,0),(-1,-1),7),("PADDING",(0,0),(-1,-1),5),
            ("VALIGN",(0,0),(-1,-1),"TOP")]))
        story.append(adoption_table)
    else:
        story.append(Paragraph("No conventional hardening adoption was identified separately from security findings.", styles["BodyText"]))
    story.append(Paragraph("PQC migration status: " + escape(str(report["comparison"].get("pqc_migration_status", "NOT_ASSESSED"))) + ". A token or API-shaped reference is not proof of a correct PQC implementation.", styles["BodyText"]))
    verification = report.get("pqc_verification")
    if verification:
        story += [Paragraph("2.3 PQC Implementation Verification", styles["Section"])]
        story.append(Paragraph("Verification level: " + escape(str(verification.get("verification_level"))), styles["BodyText"]))
        checks = verification.get("source_checks", {})
        check_rows = [["Source check", "Result"]] + [[escape(k.replace("_", " ")), "PASS" if v else "NOT DETECTED"] for k, v in checks.items()]
        check_table = Table(check_rows, repeatRows=1)
        check_table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#176B87")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.3,colors.grey),("PADDING",(0,0),(-1,-1),5)]))
        story.append(check_table)
        runtime = verification.get("runtime_self_test", {})
        story.append(Paragraph("Q-SHIELD provider self-test: " + escape(str(runtime.get("status", "NOT_RUN"))) + " — " + escape(str(runtime.get("detail", ""))), styles["BodyText"]))
        story.append(Paragraph("Uploaded project source was statically inspected and never executed. The provider self-test, when available, tests the Q-SHIELD server cryptography installation only.", styles["BodyText"]))
    story += [Paragraph("3. Security Findings", styles["Section"])]
    rows = [["Finding status","Count"],["Resolved",f["resolved"]],["Remaining",f["remaining"]],["New",f["new"]]]
    t=Table(rows, repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#12345A")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.4,colors.grey),
        ("PADDING",(0,0),(-1,-1),6)]))
    story.append(t)
    info_counts = f
    story.append(Paragraph(
        f"Informational cryptographic API references are reported separately and excluded from remediation effectiveness: "
        f"{info_counts.get('informational_before', 0)} before; {info_counts.get('informational_after', 0)} after. "
        "These entries indicate API presence for reviewer context and are not classified as vulnerabilities by themselves.",
        styles["BodyText"]
    ))
    for label, key in [("Resolved","resolved"),("Remaining","remaining"),("New","new")]:
        story.append(Paragraph(f"{label} findings (up to 40)", styles["Heading3"]))
        items=report["comparison"]["findings"][key][:40]
        if not items: story.append(Paragraph("None detected.", styles["BodyText"]))
        for item in items:
            story.append(Paragraph(
                f"{escape(str(item.get('file_name')))} : line {escape(str(item.get('line_number')))} — "
                f"{escape(str(item.get('algorithm')))} — {escape(str(item.get('finding')))} ({escape(str(item.get('severity')))})",
                styles["BodyText"]))
    story += [Paragraph("4. Source Code Changes", styles["Section"])]
    if not report["comparison"]["code_diffs"]:
        story.append(Paragraph("No common-path source changes were detected.", styles["BodyText"]))
    for diff in report["comparison"]["code_diffs"][:20]:
        story.append(Paragraph(f"{diff['file']} (+{diff['added_lines']} / -{diff['removed_lines']})", styles["Heading3"]))
        story.append(Preformatted(diff["diff"][:5000] or "No textual diff", styles["SmallCode"]))
    story += [Paragraph("5. Benchmark Evidence (Module 5)", styles["Section"])]
    benchmarks = report.get("benchmarks", [])
    if benchmarks:
        rows=[["Algorithm","Mode","Operation","Time (ms)","Key (B)","Ciphertext (B)"]]
        for b in benchmarks[:40]:
            rows.append([str(b.get("algorithm") or "—"),str(b.get("mode") or "—"),
                         str(b.get("operation") or "—"),str(b.get("execution_time") or "—"),
                         str(b.get("key_size") or "—"),str(b.get("ciphertext_size") or "—")])
        t=Table(rows, repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#176B87")),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.3,colors.grey),
            ("FONTSIZE",(0,0),(-1,-1),7),("PADDING",(0,0),(-1,-1),4)]))
        story.append(t)
    else:
        story.append(Paragraph("No Module 5 benchmark records were available at report generation time. No benchmark values have been inferred.", styles["BodyText"]))
    story += [Paragraph("6. Methodology and Limitations", styles["Section"]),
        Paragraph("Both ZIP archives were independently scanned using the Q-SHIELD cryptographic scanner. Generated Q-SHIELD migration reports/readmes and common build/dependency output directories are excluded from source analysis, while remaining preserved in the uploaded evidence archives. PQC library identifiers are detected in supported source/configuration files and classified as token references or API-usage candidates; neither classification proves a correct implementation. File matching uses normalized relative paths; identical SHA-256 content can suggest a rename. Finding matching is heuristic and can be affected by changed file names, line context, scanner coverage and false positives.", styles["BodyText"]),
        Paragraph("The readiness values are comparative heuristic indicators, not NIST certification, formal compliance results or proof of quantum resistance. Algorithm presence does not establish correct implementation. PQC detections remain UNVERIFIED until a reviewer checks API semantics, parameter sets, key handling, protocol integration and test evidence. ML-KEM is a key-establishment mechanism; ML-DSA and SLH-DSA are signature schemes. AES remains symmetric cryptography. Benchmark records are historical Module 5 results and are not attributed to either uploaded ZIP unless independently linked.", styles["BodyText"])]
    doc.build(story)
    output.seek(0)
    return output

def _persist(report, before_bytes, after_bytes):
    """Persist comparison JSON/evidence first; PDF rendering is a non-blocking extra."""
    cid = report["comparison_id"]
    os.makedirs(STORE_DIR, exist_ok=True)
    report_path = os.path.join(STORE_DIR, cid + ".json")
    evidence_path = os.path.join(STORE_DIR, cid + "_evidence.zip")
    pdf_path = os.path.join(STORE_DIR, cid + ".pdf")

    # These two artifacts are the authoritative comparison record and uploaded evidence.
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    with zipfile.ZipFile(evidence_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("comparison_report.json", json.dumps(report, indent=2, ensure_ascii=False))
        archive.writestr("original_project.zip", before_bytes)
        archive.writestr("migrated_project.zip", after_bytes)
        for index, diff in enumerate(report.get("comparison", {}).get("code_diffs", []), 1):
            safe_name = os.path.basename(str(diff.get("file", "source.diff")))
            archive.writestr(
                f"diffs/{index:03d}_{safe_name}.diff",
                str(diff.get("diff", ""))
            )

    artifact_warnings = []
    try:
        pdf = _build_pdf(report)
        with open(pdf_path, "wb") as handle:
            handle.write(pdf.getvalue())
    except Exception as exc:
        import logging
        logging.exception("Comparison saved, but PDF generation failed")
        artifact_warnings.append(
            "Comparison and evidence ZIP were saved, but PDF generation failed: "
            + type(exc).__name__ + ": " + str(exc)[:240]
        )

    try:
        from database.db import get_db_connection
        conn = get_db_connection()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO comparison_jobs
                (comparison_id, before_name, after_name, before_sha256,
                 after_sha256, report_path, pdf_path, evidence_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cid, report["before"]["project_name"], report["after"]["project_name"],
                report["before"]["archive_sha256"], report["after"]["archive_sha256"],
                report_path, pdf_path, evidence_path
            ))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        import logging
        logging.exception("Comparison artifacts saved, but SQLite history registration failed")

    return artifact_warnings


@comparison_bp.route("/api/comparison/analyze", methods=["POST"])
def analyze_comparison():
    if "before_file" not in request.files or "after_file" not in request.files:
        return jsonify({"error":"Upload both before_file and after_file ZIP archives."}),400
    before_upload=request.files["before_file"]; after_upload=request.files["after_file"]
    if not before_upload.filename.lower().endswith(".zip") or not after_upload.filename.lower().endswith(".zip"):
        return jsonify({"error":"Both uploads must be ZIP files."}),400
    stage = "reading uploaded ZIP archives"
    try:
        before_bytes=before_upload.read(); after_bytes=after_upload.read()
        stage = "validating original ZIP archive"
        before_files, before_hash, before_size = _safe_read_zip(io.BytesIO(before_bytes))
        stage = "validating migrated ZIP archive"
        after_files, after_hash, after_size = _safe_read_zip(io.BytesIO(after_bytes))
        stage = "scanning original project"
        before_analysis=_analyse(before_files)
        stage = "scanning migrated project"
        after_analysis=_analyse(after_files)
        stage = "comparing cryptographic findings and source changes"
        comparison=_compare(before_analysis,after_analysis,before_files,after_files)
        # Use the same source verifier for the initial comparison and the explicit
        # verification action. This prevents the status card from relying on a
        # narrower token-only heuristic while the Overview uses deeper checks.
        stage = "checking migrated PQC source evidence"
        pqc_verification = _verify_pqc_source(after_files, run_provider_self_test=False)
        report_status = pqc_verification.get("verification_level", "NO_SOURCE_EVIDENCE")
        if report_status == "INTEGRATION_STRUCTURE_PRESENT":
            comparison["pqc_migration_status"] = "PQC_INTEGRATION_STRUCTURE_PRESENT"
        elif report_status == "FUNCTIONAL_KEM_SOURCE_PRESENT":
            comparison["pqc_migration_status"] = "PQC_FUNCTIONAL_KEM_SOURCE_PRESENT"
        elif report_status == "PARTIAL_OR_TOKEN_ONLY":
            comparison["pqc_migration_status"] = "PQC_PARTIAL_OR_TOKEN_ONLY"
        else:
            comparison["pqc_migration_status"] = "NO_PQC_EVIDENCE_DETECTED"
        report={
            "product":"Q-SHIELD","module":8,"comparison_id":str(uuid.uuid4()),
            "created_at":datetime.now(timezone.utc).isoformat(),
            "before":{"project_name":request.form.get("before_name") or before_upload.filename,
                      "filename":before_upload.filename,"archive_bytes":before_size,
                      "archive_sha256":before_hash,"analysis":before_analysis},
            "after":{"project_name":request.form.get("after_name") or after_upload.filename,
                     "filename":after_upload.filename,"archive_bytes":after_size,
                     "archive_sha256":after_hash,"analysis":after_analysis},
            "comparison":comparison,"pqc_verification":pqc_verification,"benchmarks":_load_benchmarks(),
            "benchmark_note":"Module 5 historical benchmark records; not asserted to originate from these two uploaded projects."
        }
        stage = "saving comparison report and evidence"
        artifact_warnings = _persist(report,before_bytes,after_bytes)
        return jsonify({"message":"Classical vs PQC comparison completed.","comparison_id":report["comparison_id"],
                        "artifact_warnings":artifact_warnings,
                        "summary":{"before_findings":before_analysis["total_findings"],
                                   "after_findings":after_analysis["total_findings"],
                                   "resolved":comparison["findings"]["counts"]["resolved"],
                                   "remaining":comparison["findings"]["counts"]["remaining"],
                                   "new":comparison["findings"]["counts"]["new"],
                                   "migration_effectiveness_percent":comparison["migration_effectiveness_percent"],
                                   "before_readiness":before_analysis["readiness"],
                                   "after_readiness":after_analysis["readiness"],
                                   "before_pqc_algorithms":before_analysis["pqc_algorithms"],
                                   "after_pqc_algorithms":after_analysis["pqc_algorithms"],
                                   "conventional_hardening_count":comparison.get("conventional_hardening_count", 0),
                                   "pqc_migration_status":comparison.get("pqc_migration_status", "NOT_ASSESSED")},
                        "endpoints":{"report":f"/api/comparison/{report['comparison_id']}",
                                     "diff":f"/api/comparison/{report['comparison_id']}/diff",
                                     "pdf":f"/api/comparison/{report['comparison_id']}/pdf",
                                     "evidence":f"/api/comparison/{report['comparison_id']}/download"}}),201
    except ValueError as e:
        return jsonify({"error":str(e)}),400
    except Exception as exc:
        import logging
        logging.exception("Module 8 comparison failed during stage: %s", stage)
        return jsonify({
            "error": "Comparison failed during " + stage + ": "
                     + type(exc).__name__ + ": " + str(exc)[:350],
            "stage": stage,
            "hint": "Check the Flask terminal traceback for the full stack trace. Uploaded project code is never executed."
        }),500

def _get_report(cid):
    if not re.fullmatch(r"[0-9a-fA-F-]{36}",cid or ""): return None
    path=os.path.join(STORE_DIR,cid+".json")
    if not os.path.isfile(path): return None
    with open(path,encoding="utf-8") as f: return json.load(f)

@comparison_bp.route("/api/comparison/<comparison_id>",methods=["GET"])
def get_comparison(comparison_id):
    report=_get_report(comparison_id)
    return (jsonify(report),200) if report else (jsonify({"error":"Comparison not found"}),404)

@comparison_bp.route("/api/comparison/<comparison_id>/diff",methods=["GET"])
def get_comparison_diff(comparison_id):
    report=_get_report(comparison_id)
    if not report: return jsonify({"error":"Comparison not found"}),404
    return jsonify({"comparison_id":comparison_id,"code_diffs":report["comparison"]["code_diffs"],
                    "file_changes":report["comparison"]["files"]})

@comparison_bp.route("/api/comparison/<comparison_id>/pdf",methods=["GET"])
def download_comparison_pdf(comparison_id):
    report=_get_report(comparison_id)
    if not report: return jsonify({"error":"Comparison not found"}),404
    path=os.path.join(STORE_DIR,comparison_id+".pdf")
    return send_file(path,as_attachment=True,download_name="QSHIELD_Classical_vs_PQC_Report.pdf",mimetype="application/pdf")

@comparison_bp.route("/api/comparison/<comparison_id>/download",methods=["GET"])
def download_comparison_evidence(comparison_id):
    report=_get_report(comparison_id)
    if not report: return jsonify({"error":"Comparison not found"}),404
    path=os.path.join(STORE_DIR,comparison_id+"_evidence.zip")
    return send_file(path,as_attachment=True,download_name="QSHIELD_Comparison_Evidence.zip",mimetype="application/zip")

# ---------------------------------------------------------------------------
# Module 8.3 - source-level and functional PQC verification
# ---------------------------------------------------------------------------
def _run_qshield_provider_self_test():
    """Exercise Q-SHIELD's installed crypto provider; never execute uploaded code."""
    try:
        from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import os

        private = MLKEM768PrivateKey.generate()
        public = private.public_key()
        sender_secret, ciphertext = public.encapsulate()
        receiver_secret = private.decapsulate(ciphertext)
        if sender_secret != receiver_secret:
            return {"status": "FAIL", "detail": "ML-KEM-768 sender and recipient shared secrets differ.", "shared_secret_match": False}

        salt = os.urandom(16)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"Q-SHIELD provider self-test v1").derive(sender_secret)
        nonce = os.urandom(12)
        plaintext = b"Q-SHIELD ML-KEM/HKDF/AES-GCM provider self-test"
        aad = b"Q-SHIELD verification"
        encrypted = AESGCM(key).encrypt(nonce, plaintext, aad)
        decrypted = AESGCM(key).decrypt(nonce, encrypted, aad)
        if decrypted != plaintext:
            return {"status": "FAIL", "detail": "AES-256-GCM provider round-trip did not reproduce the plaintext.", "shared_secret_match": True, "aes_gcm_round_trip": False}

        return {
            "status": "PASS",
            "detail": "Q-SHIELD provider self-test passed: ML-KEM-768 encapsulation/decapsulation, HKDF-SHA256 derivation, and AES-256-GCM authenticated round-trip.",
            "public_key_bytes": len(public.public_bytes_raw()),
            "ciphertext_bytes": len(ciphertext),
            "shared_secret_bytes": len(sender_secret),
            "shared_secret_match": True,
            "aes_gcm_round_trip": True,
        }
    except Exception as exc:
        return {"status": "UNAVAILABLE", "detail": f"Q-SHIELD provider self-test unavailable: {type(exc).__name__}: {str(exc)[:240]}"}


def _verify_pqc_source(files, run_provider_self_test=True):
    """Inspect source statically; candidates are not treated as verified application behavior.
    Provider self-test is optional so ordinary comparison remains fast and deterministic.
    """
    source_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".h", ".cpp", ".go", ".rs", ".php", ".cs"}
    inspected = {}
    for filename, source in files.items():
        ext = PurePosixPath(filename).suffix.lower()
        lowered = filename.lower()
        if ext not in source_extensions or any(x in lowered for x in ("readme", "report", "changelog", "manifest")):
            continue
        if ext == ".py":
            cleaned = _remove_python_comments(source)
        else:
            cleaned = _remove_other_comments(source)
        inspected[filename] = cleaned
    aggregate = "\n".join(inspected.values())

    kem_class = r"(?:MLKEM(?:512|768|1024)PrivateKey|ML\s*[-_]?\s*KEM(?:[-_ ]?(?:512|768|1024))?)"
    oqs_kem = r"oqs\.KeyEncapsulation\s*\("
    pqcrypto_kem = r"pqcrypto\.kem\.ml_kem_"
    kem_provider = bool(re.search(kem_class + r"|"+oqs_kem+r"|"+pqcrypto_kem, aggregate, re.I))
    checks = {
        "mlkem_key_generation": bool(re.search(kem_class + r".{0,160}(?:generate|generate_keypair)|" + oqs_kem + r"|" + pqcrypto_kem, aggregate, re.I | re.S)),
        "mlkem_public_key": bool(re.search(r"\.public_key\s*\(", aggregate) or re.search(r"generate_keypair\s*\(", aggregate, re.I)),
        "mlkem_encapsulation": bool(re.search(r"\.encapsulate\s*\(|KeyEncapsulation.{0,160}encap_secret|\.encrypt\s*\(", aggregate, re.I | re.S) and kem_provider),
        "mlkem_decapsulation": bool(re.search(r"\.decapsulate\s*\(|KeyEncapsulation.{0,160}decap_secret|\.decrypt\s*\(", aggregate, re.I | re.S) and kem_provider),
        "shared_secret_equality_assertion": bool(re.search(r"assert\s+\w+\s*==\s*\w+", aggregate) and re.search(r"decapsulate|decap_secret|decrypt", aggregate, re.I)),
        "hkdf_key_derivation": bool(re.search(r"HKDF\s*\(", aggregate) and re.search(r"SHA256|SHA_256", aggregate, re.I)),
        "aes_gcm_encryption": bool(re.search(r"AESGCM\s*\(", aggregate) and re.search(r"\.encrypt\s*\(", aggregate)),
        "aes_gcm_decryption": bool(re.search(r"AESGCM\s*\(", aggregate) and re.search(r"\.decrypt\s*\(", aggregate)),
    }
    evidence = []
    for filename, source in sorted(inspected.items()):
        for lineno, line in enumerate(source.splitlines(), 1):
            if re.search(r"MLKEM|ML[-_ ]?KEM|KeyEncapsulation|pqcrypto\.kem|encapsulate|decapsulate", line, re.I):
                evidence.append({"file": filename, "line": lineno, "evidence": line.strip()[:240]})

    passed_core = all(checks[k] for k in (
        "mlkem_key_generation", "mlkem_public_key", "mlkem_encapsulation",
        "mlkem_decapsulation", "shared_secret_equality_assertion"
    ))
    integrated = passed_core and all(checks[k] for k in (
        "hkdf_key_derivation", "aes_gcm_encryption", "aes_gcm_decryption"
    ))
    runtime = (_run_qshield_provider_self_test() if run_provider_self_test else {
        "status": "NOT_RUN",
        "detail": "Provider self-test was not run during static comparison; use the explicit verification action to run it."
    })
    return {
        "verification_level": "INTEGRATION_STRUCTURE_PRESENT" if integrated else "FUNCTIONAL_KEM_SOURCE_PRESENT" if passed_core else "PARTIAL_OR_TOKEN_ONLY" if evidence else "NO_SOURCE_EVIDENCE",
        "source_checks": checks,
        "source_checks_passed": sum(1 for value in checks.values() if value),
        "source_checks_total": len(checks),
        "source_evidence": evidence,
        "runtime_self_test": runtime,
        "classical_residuals": {
            "RSA": bool(re.search(r"\bRSA\b|rsa\.", aggregate, re.I)),
            "ECC_ECDH_ECDSA": bool(re.search(r"ECDH|ECDSA|EllipticCurve|ec\.", aggregate, re.I)),
        },
        "limitations": [
            "Uploaded source is statically inspected and never executed.",
            "Runtime self-test independently exercises Q-SHIELD's installed cryptography provider, not uploaded application code.",
            "Source pattern checks are evidence, not a formal code audit or proof of protocol interoperability.",
            "A passing provider self-test does not imply that the uploaded project uses the provider or is fully migrated.",
            "Production migration still requires protocol design, key lifecycle, authentication, error handling, dependency and deployment review."
        ]
    }

@comparison_bp.route("/api/comparison/<comparison_id>/verify-pqc", methods=["POST", "GET"])
def verify_comparison_pqc(comparison_id):
    report = _get_report(comparison_id)
    if not report:
        return jsonify({"error": "Comparison not found. Re-run the before/after comparison and try again."}), 404

    evidence_path = os.path.join(STORE_DIR, comparison_id + "_evidence.zip")
    if not os.path.isfile(evidence_path):
        return jsonify({"error": "The saved comparison evidence archive is missing. Re-run the comparison to recreate it."}), 404

    try:
        with zipfile.ZipFile(evidence_path, "r") as archive:
            required = {"migrated_project.zip"}
            missing = required.difference(archive.namelist())
            if missing:
                return jsonify({"error": "Comparison evidence is incomplete; migrated_project.zip is missing. Re-run comparison."}), 409
            after_bytes = archive.read("migrated_project.zip")

        after_files, _, _ = _safe_read_zip(io.BytesIO(after_bytes))
        if not isinstance(after_files, dict) or not after_files:
            return jsonify({"error": "No supported source files were found in the saved migrated archive."}), 422

        # Uploaded application code is only inspected as text. The optional provider
        # test exercises Q-SHIELD's own installed library and is isolated from the app.
        verification = _verify_pqc_source(after_files, run_provider_self_test=True)
        report["pqc_verification"] = verification
        report.setdefault("comparison", {})
        runtime_status = verification.get("runtime_self_test", {}).get("status", "NOT_RUN")
        level = verification.get("verification_level", "NO_SOURCE_EVIDENCE")
        if level == "INTEGRATION_STRUCTURE_PRESENT":
            status = "PQC_INTEGRATION_STRUCTURE_PRESENT_PROVIDER_" + str(runtime_status)
        elif level == "FUNCTIONAL_KEM_SOURCE_PRESENT":
            status = "PQC_FUNCTIONAL_KEM_SOURCE_PRESENT_PROVIDER_" + str(runtime_status)
        elif level == "PARTIAL_OR_TOKEN_ONLY":
            status = "PQC_PARTIAL_OR_TOKEN_ONLY_PROVIDER_" + str(runtime_status)
        else:
            status = "NO_PQC_EVIDENCE_DETECTED_PROVIDER_" + str(runtime_status)
        report["comparison"]["pqc_migration_status"] = status

        # Only annotate source detections when the core KEM source checks corroborate them.
        checks = verification.get("source_checks", {})
        source_verified = all(checks.get(key) for key in (
            "mlkem_key_generation", "mlkem_public_key", "mlkem_encapsulation",
            "mlkem_decapsulation", "shared_secret_equality_assertion"
        ))
        for item in report.get("after", {}).get("analysis", {}).get("pqc_evidence", []):
            if item.get("algorithm") == "ML-KEM" and source_verified:
                item["verification"] = "STATIC_KEM_PATTERN_CHECKS_PASS"
                item["classification"] = "FUNCTIONAL_API_PATTERN"
                item["note"] = (
                    "Core ML-KEM source patterns were detected. Uploaded code was not executed; "
                    "protocol correctness and production readiness are not certified."
                )

        # Save the authoritative JSON first. PDF/evidence refresh is secondary: a
        # report-rendering issue must not turn successful source verification into HTTP 500.
        report_path = os.path.join(STORE_DIR, comparison_id + ".json")
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)

        artifact_warnings = []
        try:
            pdf = _build_pdf(report)
            with open(os.path.join(STORE_DIR, comparison_id + ".pdf"), "wb") as handle:
                handle.write(pdf.getvalue())
        except Exception as exc:
            import logging
            logging.exception("PQC verification succeeded but comparison PDF refresh failed")
            artifact_warnings.append("Verification saved, but PDF refresh failed: " + type(exc).__name__)

        try:
            before_bytes = None
            with zipfile.ZipFile(evidence_path, "r") as archive:
                if "original_project.zip" in archive.namelist():
                    before_bytes = archive.read("original_project.zip")
            if before_bytes is not None:
                temp_path = evidence_path + ".tmp"
                with zipfile.ZipFile(temp_path, "w", zipfile.ZIP_DEFLATED) as out:
                    out.writestr("comparison_report.json", json.dumps(report, indent=2))
                    out.writestr("original_project.zip", before_bytes)
                    out.writestr("migrated_project.zip", after_bytes)
                    for index, item in enumerate(report.get("comparison", {}).get("code_diffs", []), 1):
                        out.writestr("diffs/" + str(index).zfill(3) + "_" + os.path.basename(item.get("file", "source.diff")) + ".diff", item.get("diff", ""))
                os.replace(temp_path, evidence_path)
        except Exception as exc:
            import logging
            logging.exception("PQC verification succeeded but evidence ZIP refresh failed")
            artifact_warnings.append("Verification saved, but evidence ZIP refresh failed: " + type(exc).__name__)

        return jsonify({
            "comparison_id": comparison_id,
            "pqc_verification": verification,
            "pqc_migration_status": status,
            "artifact_warnings": artifact_warnings,
            "pdf_endpoint": f"/api/comparison/{comparison_id}/pdf"
        }), 200
    except (zipfile.BadZipFile, KeyError, ValueError) as exc:
        import logging
        logging.exception("Invalid saved comparison evidence during PQC verification")
        return jsonify({"error": "Could not read saved comparison evidence: " + str(exc)}), 422
    except Exception as exc:
        import logging
        logging.exception("PQC verification failed")
        return jsonify({
            "error": "PQC verification failed: " + type(exc).__name__ + ": " + str(exc)[:300],
            "hint": "Check the Flask terminal traceback. The uploaded application was not executed."
        }), 500


# ---------------------------------------------------------------------------
# Module 8.2 - explicit, narrowly-scoped PQC migration demonstrator
# ---------------------------------------------------------------------------
PQC_DEMO_PYTHON = '''"""Q-SHIELD ML-KEM-768 + HKDF-SHA256 + AES-256-GCM demonstration.

ML-KEM-768 key establishment follows NIST FIPS 203. AES-GCM is symmetric
authenticated encryption; it is not a post-quantum algorithm. This example
is educational and is not a complete application protocol.
"""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Receiver creates an ML-KEM-768 key pair.
recipient_private_key = MLKEM768PrivateKey.generate()
recipient_public_key = recipient_private_key.public_key()

# Sender establishes a shared secret using encapsulation.
shared_secret_sender, kem_ciphertext = recipient_public_key.encapsulate()

# Receiver obtains the same secret using decapsulation.
shared_secret_recipient = recipient_private_key.decapsulate(kem_ciphertext)
assert shared_secret_sender == shared_secret_recipient

# Derive an independent 256-bit AES key from the KEM shared secret.
salt = os.urandom(16)
aead_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    info=b"Q-SHIELD ML-KEM-768 demo v1",
).derive(shared_secret_sender)

# Encrypt and authenticate a sample message using AES-256-GCM.
nonce = os.urandom(12)
associated_data = b"Q-SHIELD demo metadata v1"
plaintext = b"Q-SHIELD post-quantum migration demonstration"
aesgcm = AESGCM(aead_key)
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
recovered = aesgcm.decrypt(nonce, ciphertext, associated_data)
assert recovered == plaintext

print("ML-KEM-768 key generation: PASS")
print("ML-KEM-768 encapsulation/decapsulation: PASS")
print("Shared-secret equality: PASS")
print("HKDF-SHA256 key derivation: PASS")
print("AES-256-GCM authenticated encryption/decryption: PASS")
print(f"ML-KEM ciphertext bytes: {len(kem_ciphertext)}")
print(f"AES-GCM ciphertext bytes (including tag): {len(ciphertext)}")
print(f"Recovered plaintext matches: {recovered == plaintext}")
'''


@comparison_bp.route("/api/comparison/pqc-migrate", methods=["POST"])
def create_pqc_migration_demo():
    """Transform only a clearly demonstrative, unused Python ECDH stub.

    Real ECDH exchange flows and RSA/signature flows are not rewritten; they
    receive manual migration actions because safe migration needs protocol context.
    """
    upload = request.files.get("file")
    if upload is None or not upload.filename or not upload.filename.lower().endswith(".zip"):
        return jsonify({"error": "Upload a classical project ZIP using multipart field 'file'."}), 400
    try:
        raw = upload.read()
        _safe_read_zip(io.BytesIO(raw))  # validate limits, paths, symlinks and source content
        archive_hash = hashlib.sha256(raw).hexdigest()
        with zipfile.ZipFile(io.BytesIO(raw)) as source_zip:
            all_entries = [(info, source_zip.read(info)) for info in source_zip.infolist() if not info.is_dir()]
        output = io.BytesIO()
        modified = []
        manual = []
        transformed = False
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as target_zip:
            for info, data in all_entries:
                path = info.filename.replace("\\", "/")
                if path.lower().endswith(".py"):
                    try:
                        text = data.decode("utf-8")
                    except UnicodeDecodeError:
                        text = None
                    if text is not None:
                        has_ecdh_demo = bool(
                            re.search(r"ec\.ECDH\s*\(\)", text)
                            and re.search(r"ec\.generate_private_key", text)
                        )
                        performs_exchange = bool(re.search(r"\.exchange\s*\(", text))
                        is_demo = bool(re.search(r"demo|test|example", path + " " + text, re.I))
                        if has_ecdh_demo and not performs_exchange and is_demo and not transformed:
                            data = PQC_DEMO_PYTHON.encode("utf-8")
                            modified.append({
                                "file": path,
                                "from": "Unused ECDH demonstration stub",
                                "to": "ML-KEM-768 + HKDF-SHA256 + AES-256-GCM demonstration with shared-secret and plaintext round-trip assertions",
                                "status": "TRANSFORMED_DEMO",
                                "note": "Only the non-operational demo stub was replaced; no live exchange protocol was rewritten."
                            })
                            transformed = True
                        elif re.search(r"ec\.ECDH|ec\.generate_private_key|rsa\.generate_private_key|ECDSA|RSA", text, re.I):
                            manual.append({
                                "file": path,
                                "status": "MANUAL_MIGRATION_REQUIRED",
                                "reason": "Real key agreement, RSA encryption or signature semantics require protocol-aware redesign; source was not rewritten."
                            })
                target_zip.writestr(info, data)
            report = {
                "product": "Q-SHIELD", "module": "8.3", "profile": "Python ECDH demo to ML-KEM-768 + HKDF-SHA256 + AES-256-GCM",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "original_archive_sha256": archive_hash,
                "modified_files": modified,
                "manual_migration_actions": manual,
                "pqc_status": "ML-KEM-768_DEMO_SCAFFOLD_ADDED" if transformed else "MANUAL_MIGRATION_REQUIRED",
                "pqc_algorithm": "ML-KEM-768 (NIST FIPS 203)",
                "syntax_validation": "Python source template is AST-validated by the Q-SHIELD test harness; execute only in a controlled test environment with a compatible cryptography release.",
                "limitations": [
                    "Only a demonstrative Python ECDH stub with no exchange() call is transformed.",
                    "RSA encryption and RSA/ECDSA signatures are not automatically converted.",
                    "ML-KEM is key establishment, not a digital-signature replacement.",
                    "AES-256-GCM is symmetric authenticated encryption and is not a PQC algorithm.",
                    "The generated demo requires cryptography>=50.0.0 with ML-KEM support.",
                    "This is not a production protocol or a claim of complete application PQC migration.",
                    "The generated demo includes ML-KEM key establishment, HKDF-SHA256, and AES-256-GCM authenticated encryption/decryption; verify the source and run it only in a controlled environment."
                ]
            }
            target_zip.writestr("QSHIELD_PQC_MIGRATION_REPORT.json", json.dumps(report, indent=2))
            target_zip.writestr("QSHIELD_PQC_MIGRATION_README.md", "# Q-SHIELD PQC migration output\n\nThis package contains a narrowly-scoped ML-KEM-768 + HKDF-SHA256 + AES-256-GCM demonstration migration. The demo verifies ML-KEM shared-secret equality and AES-GCM plaintext round-trip. AES-GCM is conventional authenticated encryption, not a PQC algorithm. Review QSHIELD_PQC_MIGRATION_REPORT.json. Install a compatible cryptography release (>=50.0.0), run the demo in an isolated test environment, and complete protocol, key-management, interoperability and security reviews before production use.\n")
        output.seek(0)
        job_id = str(uuid.uuid4())
        base = os.path.join(STORE_DIR, "pqc_migrations")
        os.makedirs(base, exist_ok=True)
        with open(os.path.join(base, job_id + ".zip"), "wb") as handle:
            handle.write(output.getvalue())
        with open(os.path.join(base, job_id + ".json"), "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        return jsonify({
            "message": "PQC migration package generated.", "job_id": job_id, "report": report,
            "download_endpoint": f"/api/comparison/pqc-migrate/{job_id}/download",
            "report_endpoint": f"/api/comparison/pqc-migrate/{job_id}/report"
        }), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        import logging
        logging.exception("PQC migration generation failed")
        return jsonify({"error": "PQC migration failed. Check backend logs."}), 500


@comparison_bp.route("/api/comparison/pqc-migrate/<job_id>/report", methods=["GET"])
def get_pqc_migration_report(job_id):
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", job_id or ""):
        return jsonify({"error": "Invalid migration job ID."}), 400
    path = os.path.join(STORE_DIR, "pqc_migrations", job_id + ".json")
    if not os.path.isfile(path):
        return jsonify({"error": "PQC migration job not found."}), 404
    with open(path, encoding="utf-8") as handle:
        return jsonify(json.load(handle))


@comparison_bp.route("/api/comparison/pqc-migrate/<job_id>/download", methods=["GET"])
def download_pqc_migration(job_id):
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", job_id or ""):
        return jsonify({"error": "Invalid migration job ID."}), 400
    path = os.path.join(STORE_DIR, "pqc_migrations", job_id + ".zip")
    if not os.path.isfile(path):
        return jsonify({"error": "PQC migration package not found."}), 404
    return send_file(path, as_attachment=True, download_name="QSHIELD_PQC_Migrated_Project.zip", mimetype="application/zip")
