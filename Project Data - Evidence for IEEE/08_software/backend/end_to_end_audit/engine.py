"""Q-SHIELD Module 7.10: unified PQC migration audit orchestration."""
import hashlib, io, json, os, re, uuid, zipfile
from datetime import datetime, timezone, date
from xml.sax.saxutils import escape
from flask import Blueprint, current_app, jsonify, request, send_file
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from migration_policy.engine import _safe_zip_scan, _policy_for, _summary
from assessment.scoring import calculate_readiness_metrics
from scanner.crypto_detector import _remove_python_comments, _remove_other_comments

end_to_end_audit_bp = Blueprint("end_to_end_audit", __name__, url_prefix="/api/end-to-end-audit")
MAX_UPLOAD = 25 * 1024 * 1024

def _dir():
    p=os.path.join(current_app.config["UPLOAD_FOLDER"],"end_to_end_audits"); os.makedirs(p,exist_ok=True); return p

def _save(job):
    with open(os.path.join(_dir(),job["audit_id"]+".json"),"w",encoding="utf-8") as f: json.dump(job,f,indent=2)

def _load(aid):
    if not re.fullmatch(r"[0-9a-f-]{36}",str(aid)): return None
    p=os.path.join(_dir(),aid+".json")
    if not os.path.isfile(p): return None
    with open(p,encoding="utf-8") as f: return json.load(f)

def _readiness(findings, algorithm_inventory):
    inventory = [{"algorithm": name} for name, count in (algorithm_inventory or {}).items()
                 for _ in range(max(0, int(count)))]
    metrics = calculate_readiness_metrics(inventory, findings)
    return {**metrics, "method": metrics["scoring_method"]}

def _profile_comparison(raw_findings):
    """Evaluate the exact same raw detections under both policy profiles."""
    evaluated = {
        profile: [_policy_for(item, profile) for item in raw_findings]
        for profile in ("TRANSITION", "STRICT")
    }
    distributions = {}
    for profile, items in evaluated.items():
        counts = {}
        for item in items:
            status = item["policy_status"]
            counts[status] = counts.get(status, 0) + 1
        distributions[profile] = {
            "total_findings": len(items),
            "status_counts": counts,
        }

    strict_by_id = {item["finding_id"]: item for item in evaluated["STRICT"]}
    changed = []
    for transition_item in evaluated["TRANSITION"]:
        strict_item = strict_by_id[transition_item["finding_id"]]
        if transition_item["policy_status"] != strict_item["policy_status"]:
            changed.append({
                "finding_id": transition_item["finding_id"],
                "algorithm": transition_item["algorithm"],
                "file": transition_item["file"],
                "line_number": transition_item.get("line_number"),
                "transition_status": transition_item["policy_status"],
                "strict_status": strict_item["policy_status"],
                "policy_action": transition_item["policy_action"],
            })
    return {
        "profiles": distributions,
        "changed_findings_count": len(changed),
        "changed_findings": changed,
        "interpretation": (
            "Both profiles use the same scanner detections. The profile changes governance "
            "classification and required action, not the source findings or readiness heuristic."
        ),
    }


def _decision_counts(findings):
    mapping = {
        "PENDING": "PENDING",
        "APPROVE_REMEDIATION_PLAN": "APPROVED",
        "ACCEPT_TIME_BOUND_EXCEPTION": "EXCEPTION",
        "DEFER_WITH_RATIONALE": "DEFERRED",
    }
    counts = {"PENDING": 0, "APPROVED": 0, "EXCEPTION": 0, "DEFERRED": 0}
    for item in findings:
        key = mapping.get(item.get("decision", "PENDING"), "PENDING")
        counts[key] += 1
    return counts


def _policy_recommendations(findings, comparison):
    """Group recommendations by both action and selected-profile status."""
    transition = {x["finding_id"]: x["transition_status"]
                  for x in comparison["changed_findings"]}
    strict = {x["finding_id"]: x["strict_status"]
              for x in comparison["changed_findings"]}
    groups = {}
    for item in findings:
        key = (item["policy_status"], item["policy_action"], item["target_guidance"])
        if key not in groups:
            groups[key] = {
                "policy_status": item["policy_status"],
                "policy_action": item["policy_action"],
                "target_guidance": item["target_guidance"],
                "priority": item["policy_priority"],
                "affected_findings": 0,
                "affected_finding_ids": [],
                "transition_status": transition.get(item["finding_id"], item["policy_status"]),
                "strict_status": strict.get(item["finding_id"], item["policy_status"]),
            }
        groups[key]["affected_findings"] += 1
        groups[key]["affected_finding_ids"].append(item["finding_id"])
    return sorted(groups.values(), key=lambda x: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x["priority"], 5),
        x["policy_status"], x["policy_action"]
    ))


def _transition_roadmap(findings):
    """Build actionable, source-linked migration guidance for Transition profile."""
    actionable = [x for x in findings if x.get("policy_status") in {
        "MIGRATION_PLAN_REQUIRED", "REMEDIATION_REQUIRED"
    }]
    by_algorithm = {}
    for item in actionable:
        algorithm = str(item.get("algorithm", "Unknown")).upper()
        entry = by_algorithm.setdefault(algorithm, {"algorithm": algorithm, "files": set(), "finding_ids": [], "priority": item.get("policy_priority", "MEDIUM")})
        entry["files"].add(str(item.get("file", "unknown")))
        entry["finding_ids"].append(item.get("finding_id"))
    targets = {
        "RSA": ("ML-KEM for key establishment; ML-DSA for signatures where signing is required",
                "Identify whether RSA is used for key transport, encryption or signatures before selecting a replacement."),
        "ECC": ("ML-KEM for key establishment; ML-DSA for signatures where signing is required",
                "Separate ECDH/ECDHE key agreement from ECDSA signatures; they have different replacement workflows."),
        "AES": ("Retain AES where appropriate; prefer authenticated modes such as AES-GCM",
                "Review mode, nonce/IV uniqueness, authentication-tag handling and key management; AES itself is not a public-key PQC algorithm."),
        "MD5": ("SHA-256 or SHA-3 for modern digest use; HMAC for keyed authentication",
                "Determine whether MD5 is used for integrity, identifiers or password storage; password storage needs a dedicated password-hashing design."),
        "SHA-1": ("SHA-256 or SHA-3 for modern digest use",
                  "Check protocol and signature dependencies before replacing SHA-1."),
        "DES": ("AES-128/256 in an authenticated mode such as GCM",
                "Replace legacy DES/3DES encryption and validate interoperability and key handling."),
        "3DES": ("AES-128/256 in an authenticated mode such as GCM",
                 "Replace legacy 3DES encryption and validate interoperability and key handling."),
    }
    phases = [
        {"phase": 1, "name": "Discover and classify", "goal": "Confirm each detected use before changing code.",
         "tasks": ["Inspect the listed source locations and trace each cryptographic call to its protocol purpose.", "Separate key establishment, digital signatures, symmetric encryption, hashing and password storage.", "Record dependent peers, stored data, certificate formats, key sizes and protocol constraints."],
         "exit_criteria": "Every finding has an owner, a confirmed use case and an approved target design."},
        {"phase": 2, "name": "Prepare compatibility and dependencies", "goal": "Prepare libraries, interfaces and rollout controls.",
         "tasks": ["Select maintained cryptographic providers with support for the required standardized algorithms.", "Check language/runtime versions, provider APIs, key and ciphertext sizes, network limits and interoperability.", "Design versioned message formats and a rollback plan; do not silently change wire formats."],
         "exit_criteria": "Provider support and peer compatibility are demonstrated in a non-production environment."},
        {"phase": 3, "name": "Migrate in controlled stages", "goal": "Replace vulnerable public-key operations and remediate legacy primitives.",
         "tasks": ["For key establishment, prototype ML-KEM encapsulation/decapsulation and authenticated shared-secret derivation.", "For signatures, evaluate ML-DSA separately; do not substitute a KEM for a signature algorithm.", "For symmetric encryption, use authenticated encryption and enforce unique nonces/IVs with correct tag verification.", "Replace deprecated hashes according to their actual use; do not use a general digest as a password-hashing substitute.", "Use a documented hybrid transition only where protocol design and peer support explicitly permit it."],
         "exit_criteria": "Changes pass unit, integration, interoperability and negative tests; no unreviewed cryptographic downgrade is introduced."},
        {"phase": 4, "name": "Verify, benchmark and deploy", "goal": "Collect evidence before production rollout.",
         "tasks": ["Test key generation, encapsulation, decapsulation and shared-secret agreement for KEM workflows.", "Test signature generation and verification independently for signature workflows.", "Test authenticated encryption/decryption, nonce handling, tamper rejection and error paths.", "Benchmark latency, throughput, memory and message sizes on target hardware.", "Deploy behind feature flags or staged rollout, monitor failures and retain a rollback procedure."],
         "exit_criteria": "Test evidence, benchmark results, compatibility approval and operational rollback readiness are recorded."}
    ]
    algorithm_plans = []
    for item in sorted(by_algorithm.values(), key=lambda x: ({"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x["priority"],4), x["algorithm"])):
        target, rationale = targets.get(item["algorithm"], (
            "Review the detected primitive and select a current, standards-aligned replacement based on its actual purpose.",
            "The scanner label alone does not establish the protocol role; confirm source-level usage before choosing a replacement."
        ))
        algorithm_plans.append({
            "algorithm": item["algorithm"], "priority": item["priority"],
            "files": sorted(item["files"]), "finding_ids": item["finding_ids"],
            "suggested_target": target, "implementation_guidance": rationale
        })
    return {
        "title": "Transition migration roadmap",
        "purpose": "A staged, source-linked plan for moving from detected classical or legacy cryptography toward quantum-resistant designs where applicable.",
        "phases": phases,
        "algorithm_plans": algorithm_plans,
        "governance": ["Assign an owner and target date to each finding.", "Require security review for protocol, key lifecycle and format changes.", "Treat scanner detections as leads that require source and design confirmation."],
        "limitations": ["This roadmap is guidance, not an automatic code rewrite.", "ML-KEM is for key establishment, not digital signatures; ML-DSA is a signature scheme.", "AES is symmetric cryptography and is not itself a PQC algorithm.", "Do not deploy hybrid or replacement protocols without peer interoperability and cryptographic design review."]
    }


def _source_contents_from_archive(raw_archive, scanned_files):
    """Return source text for exactly the entries accepted by _safe_zip_scan.

    _safe_zip_scan returns (scanned filenames, findings), not source contents.
    Module 8's verifier needs a {filename: source_text} mapping. Re-open the
    already-validated in-memory archive and read only those accepted paths.
    """
    accepted = set(scanned_files or [])
    source_contents = {}
    with zipfile.ZipFile(io.BytesIO(raw_archive), "r") as archive:
        for entry in archive.infolist():
            name = entry.filename.replace("\\\\", "/")
            if entry.is_dir() or name not in accepted:
                continue
            try:
                source_contents[name] = archive.read(entry).decode("utf-8-sig")
            except UnicodeDecodeError:
                # Keep analysis resilient for source files with a legacy encoding.
                source_contents[name] = archive.read(entry).decode("utf-8", errors="replace")
    return source_contents


def _verification(files):
    """Use Module 8's canonical source verifier so every module classifies the
    same uploaded source consistently. `files` must map paths to source text.
    The uploaded project is never executed.
    """
    from comparison.engine import _verify_pqc_source
    if not isinstance(files, dict):
        raise TypeError("PQC verifier requires a filename-to-source-text mapping")
    result = _verify_pqc_source(files, run_provider_self_test=False)
    checks = result.get("source_checks", {})
    evidence = []
    for item in result.get("source_evidence", []):
        line = item.get("evidence", "")
        algorithm = "ML-KEM" if re.search(r"MLKEM|ML[-_ ]?KEM|KeyEncapsulation|pqcrypto\\.kem", line, re.I) else (
            "ML-DSA" if re.search(r"MLDSA|ML[-_ ]?DSA|Signature", line, re.I) else "PQC"
        )
        evidence.append({
            "algorithm": algorithm,
            "file": item.get("file"),
            "line": item.get("line"),
            "classification": "API_USAGE_CANDIDATE" if re.search(
                r"MLKEM|ML[-_ ]?KEM|KeyEncapsulation|pqcrypto\\.kem|encapsulate|decapsulate", line, re.I
            ) else "TOKEN_REFERENCE"
        })
    presence = {
        "ML-KEM": any(bool(v) for k, v in checks.items() if k.startswith("mlkem_")),
        "ML-DSA": any(re.search(r"MLDSA|ML[-_ ]?DSA|Signature", x.get("evidence", ""), re.I)
                      for x in result.get("source_evidence", [])),
        "SLH-DSA": any(re.search(r"SLH[-_ ]?DSA|SPHINCS", x.get("evidence", ""), re.I)
                       for x in result.get("source_evidence", []))
    }
    return {
        "static_source_presence": presence,
        "source_evidence": evidence,
        "verification_level": result.get("verification_level", "NOT_ASSESSED"),
        "source_checks": checks,
        "source_checks_passed": result.get("source_checks_passed", 0),
        "source_checks_total": result.get("source_checks_total", len(checks)),
        "provider_self_test": {
            "status": "NOT_RUN",
            "note": "Provider self-test is separate and does not execute or verify the uploaded application."
        },
        "uploaded_code_executed": False,
        "interpretation": "Static source checks are shared with Project Comparison. They do not prove correct parameters, key lifecycle, protocol integration, interoperability or runtime behavior."
    }

def _pdf(job):
    out=io.BytesIO(); doc=SimpleDocTemplate(out,pagesize=A4,rightMargin=14*mm,leftMargin=14*mm,topMargin=14*mm,bottomMargin=14*mm)
    s=getSampleStyleSheet(); s.add(ParagraphStyle(name="QSmall",parent=s["BodyText"],fontSize=8,leading=10))
    story=[Paragraph("Q-SHIELD — End-to-End PQC Migration Audit",s["Title"]),Paragraph("Module 7.10 · Consolidated evidence and governance",s["Heading2"]),Spacer(1,5*mm)]
    su=job["summary"]; rows=[["Audit ID",escape(job["audit_id"])],["Source",escape(job["source_filename"])],["SHA-256",escape(job["source_sha256"]) ],["Created UTC",job["created_at"]],["Policy",job["policy_profile"]],["Scanned files",str(su["scanned_files"])],["Findings",str(su["total_findings"])],["Critical / High",str(su["critical_or_high"])],["Readiness",f'{job["readiness"]["score"]}/100 · {job["readiness"]["risk_level"]}']]
    t=Table(rows,colWidths=[38*mm,132*mm]); t.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),colors.HexColor("#e9f1f6")),("GRID",(0,0),(-1,-1),.3,colors.grey),("FONTSIZE",(0,0),(-1,-1),8),("VALIGN",(0,0),(-1,-1),"TOP")])); story += [t,Spacer(1,4*mm),Paragraph("Policy status counts",s["Heading2"])]
    status_rows = [["Policy status", "Count"]]
    for k,v in sorted(su["status_counts"].items()):
        status_rows.append([escape(str(k).replace("_", " ")), str(v)])
    if len(status_rows) > 1:
        st = Table(status_rows, repeatRows=1, colWidths=[105*mm, 25*mm])
        st.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#15384b")),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("GRID",(0,0),(-1,-1),.25,colors.grey),
            ("FONTSIZE",(0,0),(-1,-1),8),
        ]))
        story.append(st)
    comparison = job.get("policy_profile_comparison", {})
    profiles = comparison.get("profiles", {})
    if profiles:
        story += [Spacer(1,4*mm), Paragraph("Transition vs Strict policy impact",s["Heading2"])]
        story.append(Paragraph(
            f'Findings whose governance classification changes: {comparison.get("changed_findings_count", 0)}',
            s["BodyText"]
        ))
        profile_rows = [["Status", "Transition", "Strict"]]
        all_statuses = sorted(set(
            list(profiles.get("TRANSITION", {}).get("status_counts", {}).keys()) +
            list(profiles.get("STRICT", {}).get("status_counts", {}).keys())
        ))
        for status in all_statuses:
            profile_rows.append([
                escape(status.replace("_", " ")),
                str(profiles.get("TRANSITION", {}).get("status_counts", {}).get(status, 0)),
                str(profiles.get("STRICT", {}).get("status_counts", {}).get(status, 0)),
            ])
        pt = Table(profile_rows, repeatRows=1, colWidths=[88*mm, 35*mm, 35*mm])
        pt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#15384b")),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("GRID",(0,0),(-1,-1),.25,colors.grey),
            ("FONTSIZE",(0,0),(-1,-1),7.5),
        ]))
        story.append(pt)
        delta_rows = [["Finding", "Algorithm", "Transition", "Strict"]]
        for item in comparison.get("changed_findings", [])[:100]:
            delta_rows.append([
                escape(f'{item["file"]}:{item.get("line_number") or "?"}'),
                escape(str(item["algorithm"])),
                escape(item["transition_status"].replace("_", " ")),
                escape(item["strict_status"].replace("_", " ")),
            ])
        if len(delta_rows) > 1:
            story += [Spacer(1,2*mm), Paragraph("Finding-level policy changes",s["Heading3"])]
            dt = Table(delta_rows, repeatRows=1, colWidths=[54*mm, 27*mm, 39*mm, 39*mm])
            dt.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#15384b")),
                ("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("GRID",(0,0),(-1,-1),.25,colors.grey),
                ("FONTSIZE",(0,0),(-1,-1),6.5),
                ("VALIGN",(0,0),(-1,-1),"TOP"),
            ]))
            story.append(dt)
    recommendations = job.get("recommendations", [])
    if recommendations:
        story += [Spacer(1,4*mm), Paragraph("Policy recommendations",s["Heading2"])]
        rec_rows = [["Policy status", "Required action", "Affected"]]
        for rec in recommendations[:40]:
            rec_rows.append([
                escape(str(rec.get("policy_status", "—")).replace("_", " ")),
                escape(str(rec.get("policy_action", "—"))),
                str(rec.get("affected_findings", 0)),
            ])
        rt = Table(rec_rows, repeatRows=1, colWidths=[52*mm, 90*mm, 20*mm])
        rt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#15384b")),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("GRID",(0,0),(-1,-1),.25,colors.grey),
            ("FONTSIZE",(0,0),(-1,-1),6.5),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
        ]))
        story.append(rt)
    roadmap = job.get("transition_roadmap")
    if roadmap:
        story += [Spacer(1,5*mm), Paragraph("Transition migration roadmap",s["Heading2"]),
                  Paragraph(escape(roadmap.get("purpose", "")),s["BodyText"])]
        for phase in roadmap.get("phases", []):
            story += [Spacer(1,2*mm), Paragraph(
                f'Phase {phase["phase"]}: {escape(phase["name"])}',s["Heading3"]),
                Paragraph(escape(phase["goal"]),s["BodyText"])]
            for task in phase.get("tasks", []):
                story.append(Paragraph("• " + escape(task),s["QSmall"]))
            story.append(Paragraph("<b>Exit criteria:</b> " + escape(phase["exit_criteria"]),s["QSmall"]))
        if roadmap.get("algorithm_plans"):
            story += [Spacer(1,2*mm), Paragraph("Algorithm-specific migration guidance",s["Heading3"])]
            for plan in roadmap["algorithm_plans"]:
                story.append(Paragraph(
                    f'<b>{escape(plan["algorithm"])} · {escape(plan["priority"])}</b> — '
                    f'{escape(plan["suggested_target"])}',s["QSmall"]))
                story.append(Paragraph(
                    f'Files: {escape(", ".join(plan["files"]))}. '
                    f'{escape(plan["implementation_guidance"])}',s["QSmall"]))
        for limitation in roadmap.get("limitations", []):
            story.append(Paragraph("• " + escape(limitation),s["QSmall"]))
    story += [Spacer(1,3*mm),Paragraph("Findings (first 100)",s["Heading2"])]
    fr=[["ID","Severity","Algorithm","File : line","Status"]]
    for x in job["findings"][:100]: fr.append([escape(str(x["finding_id"])),escape(str(x["severity"])),escape(str(x["algorithm"])),escape(f'{x["file"]}:{x.get("line_number") or "?"}'),escape(str(x["policy_status"]))])
    if len(fr)==1: fr.append(["—","—","No findings","—","—"])
    ft=Table(fr,repeatRows=1,colWidths=[23*mm,20*mm,30*mm,55*mm,42*mm]); ft.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#15384b")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.25,colors.grey),("FONTSIZE",(0,0),(-1,-1),6.5),("VALIGN",(0,0),(-1,-1),"TOP")])); story += [ft,Spacer(1,4*mm),Paragraph("Evidence and limitations",s["Heading2"])]
    decision_counts = su.get("decision_counts", {})
    if decision_counts:
        story += [Spacer(1,3*mm), Paragraph(
            "Governance decisions — " + escape(", ".join(f"{k}: {v}" for k, v in decision_counts.items())),
            s["QSmall"]
        )]
    story += [Spacer(1,4*mm), Paragraph("PQC implementation source evidence",s["Heading2"])]
    ve=job.get("verification_evidence",{})
    story.append(Paragraph("Verification level: "+escape(str(ve.get("verification_level","NOT_ASSESSED"))),s["BodyText"]))
    checks=ve.get("static_source_presence",{})
    story.append(Paragraph("Detected source references: "+escape(", ".join(k for k,v in checks.items() if v) or "None"),s["BodyText"]))
    evidence_rows=[["Algorithm","Source file","Line","Classification"]]
    for item in ve.get("source_evidence",[])[:30]:
        evidence_rows.append([escape(str(item.get("algorithm","—"))),escape(str(item.get("file","—"))),str(item.get("line","—")),escape(str(item.get("classification","—")))])
    if len(evidence_rows)>1:
        et=Table(evidence_rows,repeatRows=1,colWidths=[32*mm,70*mm,18*mm,52*mm])
        et.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#15384b")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.25,colors.grey),("FONTSIZE",(0,0),(-1,-1),7),("VALIGN",(0,0),(-1,-1),"TOP")]))
        story.append(et)
    else:
        story.append(Paragraph("No PQC source tokens or API candidates were found in inspected source files.",s["BodyText"]))
    notes=job["limitations"]+[ve.get("interpretation","")]
    for n in notes:
        if n: story.append(Paragraph(escape(n),s["QSmall"]))
    doc.build(story); return out.getvalue()

@end_to_end_audit_bp.post("/run")
def run_audit():
    upload=request.files.get("file"); profile=(request.form.get("policy_profile") or "TRANSITION").upper()
    if not upload or not upload.filename: return jsonify(error="A project ZIP is required in multipart field 'file'"),400
    if profile not in {"TRANSITION","STRICT"}: return jsonify(error="policy_profile must be TRANSITION or STRICT"),400
    raw=upload.read(MAX_UPLOAD+1)
    if len(raw)>MAX_UPLOAD: return jsonify(error="ZIP exceeds the 25 MiB upload limit"),400
    try: files,raw_findings=_safe_zip_scan(raw)
    except ValueError as e: return jsonify(error=str(e)),400
    if not files: return jsonify(error="No supported source files were found in the ZIP"),400
    source_contents = _source_contents_from_archive(raw, files)
    try:
        verification_evidence = _verification(source_contents)
    except Exception:
        current_app.logger.exception("Module 7.10 failed during PQC source verification")
        return jsonify(
            error="PQC source verification failed while analysing the uploaded archive. "
                  "Check the Flask terminal for the detailed traceback.",
            stage="pqc_source_verification",
        ), 500
    profile_comparison = _profile_comparison(raw_findings)
    findings=[_policy_for(x,profile) for x in raw_findings]
    rank={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}; findings.sort(key=lambda x:(rank.get(x.get("policy_priority"),3),x["file"],x.get("line_number") or 0))
    now=datetime.now(timezone.utc).isoformat(); aid=str(uuid.uuid4()); summary=_summary(findings)
    decision_counts = _decision_counts(findings)
    summary["decision_counts"] = decision_counts
    algorithm_inventory={}
    algorithm_file_pairs={(str(item.get("algorithm","Unknown")),str(item.get("file",""))) for item in findings
                          if str(item.get("algorithm","")).upper() not in ("WEAK CONFIGURATION","CRYPTOGRAPHIC API")}
    for algorithm, filename in algorithm_file_pairs:
        algorithm_inventory[algorithm]=algorithm_inventory.get(algorithm,0)+1
    recommendations = _policy_recommendations(findings, profile_comparison)
    transition_roadmap = _transition_roadmap(findings) if profile == "TRANSITION" else None
    job={"audit_id":aid,"module":"7.10","workflow":"Q-SHIELD_END_TO_END_PQC_MIGRATION_AUDIT","created_at":now,"status":"REVIEW_REQUIRED" if findings else "COMPLETED_WITH_NO_FINDINGS","source_filename":os.path.basename(upload.filename),"source_sha256":hashlib.sha256(raw).hexdigest(),"source_retained":False,"source_modified":False,"policy_profile":profile,"scanned_files":files,"algorithm_inventory":algorithm_inventory,"readiness":_readiness(findings,algorithm_inventory),"recommendations":recommendations,"transition_roadmap":transition_roadmap,"policy_profile_comparison":profile_comparison,"findings":findings,"verification_evidence":verification_evidence,"summary":{**summary,"scanned_files":len(files),"policy_profile":profile},"audit_events":[{"event":"END_TO_END_AUDIT_CREATED","timestamp":now,"actor":"system","details":"Static scan, inventory aggregation, policy recommendations, readiness heuristic and evidence aggregation completed."}],"limitations":["Static analysis only; uploaded project code is never executed.","Readiness score is a heuristic and is not certification.","Findings may include false positives or false negatives.","No source files are modified; uploaded source is not retained.","Runtime provider self-tests and detailed ML-KEM/ML-DSA verification remain separate evidence sources.","Human decisions are governance records, not source remediation."]}
    _save(job); return jsonify(job),201

@end_to_end_audit_bp.get("/history")
def history():
    items=[]
    for n in os.listdir(_dir()):
        if n.endswith(".json"):
            try:
                with open(os.path.join(_dir(),n),encoding="utf-8") as f: j=json.load(f)
                items.append({k:j[k] for k in ("audit_id","created_at","source_filename","status","summary","readiness")})
            except (OSError,ValueError,KeyError): pass
    items.sort(key=lambda x:x["created_at"],reverse=True); return jsonify({"audits":items[:100],"count":len(items)})

@end_to_end_audit_bp.get("/<audit_id>")
def get_audit(audit_id):
    j=_load(audit_id); return (jsonify(j),200) if j else (jsonify(error="End-to-end audit not found"),404)

@end_to_end_audit_bp.post("/<audit_id>/decisions")
def decisions(audit_id):
    j=_load(audit_id)
    if not j:return jsonify(error="End-to-end audit not found"),404
    body=request.get_json(silent=True) or {}; ds=body.get("decisions"); actor=body.get("actor","reviewer")
    if not isinstance(ds,list) or not 1<=len(ds)<=500:return jsonify(error="Provide a decisions array containing 1–500 decisions"),400
    if not isinstance(actor,str) or not actor.strip() or len(actor)>120:return jsonify(error="actor must be 1–120 characters"),400
    index={x["finding_id"]:x for x in j["findings"]}; seen=set(); staged=[]
    for d in ds:
        if not isinstance(d,dict):return jsonify(error="Each decision must be an object"),400
        fid=d.get("finding_id"); action=d.get("decision"); note=d.get("note",""); expiry=d.get("exception_expiry")
        if fid not in index or fid in seen:return jsonify(error=f"Unknown or duplicate finding_id: {fid}"),400
        if index[fid]["decision"]!="PENDING":return jsonify(error=f"Finding {fid} already has a decision"),409
        if action not in {"APPROVE_REMEDIATION_PLAN","ACCEPT_TIME_BOUND_EXCEPTION","DEFER_WITH_RATIONALE"}:return jsonify(error="Unsupported decision"),400
        if not isinstance(note,str) or len(note)>2000:return jsonify(error="note must be a string up to 2000 characters"),400
        if action=="ACCEPT_TIME_BOUND_EXCEPTION":
            try: exp=date.fromisoformat(expiry)
            except (TypeError,ValueError):return jsonify(error="A valid future exception_expiry (YYYY-MM-DD) is required"),400
            if exp<=datetime.now(timezone.utc).date():return jsonify(error="exception_expiry must be in the future"),400
            if len(note.strip())<8:return jsonify(error="An exception rationale of at least 8 characters is required"),400
        if action=="DEFER_WITH_RATIONALE" and len(note.strip())<8:return jsonify(error="A deferral rationale of at least 8 characters is required"),400
        seen.add(fid); staged.append((index[fid],action,note.strip(),expiry))
    now=datetime.now(timezone.utc).isoformat()
    for item,action,note,expiry in staged:
        item.update(decision=action,decision_note=note or None,exception_expiry=expiry if action=="ACCEPT_TIME_BOUND_EXCEPTION" else None)
        j["audit_events"].append({"event":"FINDING_DECISION_RECORDED","timestamp":now,"actor":actor.strip(),"finding_id":item["finding_id"],"decision":action,"note":note or None,"exception_expiry":item["exception_expiry"]})
    counts = _decision_counts(j["findings"])
    j["summary"]["decision_counts"] = counts
    j["summary"]["pending_decisions"] = counts["PENDING"]; j["status"]="REVIEW_IN_PROGRESS" if counts["PENDING"] else "GOVERNANCE_REVIEW_RECORDED"
    _save(j); return jsonify({"message":"Audit decisions recorded","audit":j}),200

@end_to_end_audit_bp.get("/<audit_id>/report")
def report_json(audit_id):
    j=_load(audit_id); return (jsonify(j),200) if j else (jsonify(error="End-to-end audit not found"),404)

@end_to_end_audit_bp.get("/<audit_id>/pdf")
def report_pdf(audit_id):
    j=_load(audit_id)
    if not j:return jsonify(error="End-to-end audit not found"),404
    return send_file(io.BytesIO(_pdf(j)),mimetype="application/pdf",as_attachment=True,download_name=f"QSHIELD_EndToEnd_Audit_{audit_id[:8]}.pdf")

@end_to_end_audit_bp.get("/<audit_id>/evidence")
def evidence(audit_id):
    j=_load(audit_id)
    if not j:return jsonify(error="End-to-end audit not found"),404
    pdf=_pdf(j); manifest={"audit_id":audit_id,"source_sha256":j["source_sha256"],"report_pdf_sha256":hashlib.sha256(pdf).hexdigest(),"source_archive_included":False}; out=io.BytesIO()
    with zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED) as z:
        z.writestr("audit_report.json",json.dumps(j,indent=2)); z.writestr("audit_report.pdf",pdf); z.writestr("evidence_manifest.json",json.dumps(manifest,indent=2)); z.writestr("README.txt","Q-SHIELD Module 7.10 evidence bundle. Original source archive is not included. Uploaded code was never executed or retained.\n")
    out.seek(0); return send_file(out,mimetype="application/zip",as_attachment=True,download_name=f"QSHIELD_EndToEnd_Evidence_{audit_id[:8]}.zip")
