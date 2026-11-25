"""Shared Q-SHIELD heuristic readiness scoring.

This is a project-specific risk heuristic, not a certification or proof of quantum safety.
"""
from collections import Counter


def calculate_readiness_metrics(inventory, findings):
    inventory = [dict(x) for x in (inventory or [])]
    findings = [dict(x) for x in (findings or [])]

    quantum = [x for x in inventory if str(x.get("algorithm", "")).upper() in ("RSA", "ECC")]
    deprecated = [x for x in inventory if str(x.get("algorithm", "")).upper() in ("MD5", "SHA-1", "DES")]

    critical = {}
    weak = {}
    for row in findings:
        severity = str(row.get("severity", "INFO")).upper()
        if severity == "CRITICAL":
            critical[(row.get("file_name", row.get("file")), row.get("line_number"), row.get("algorithm"))] = row
        if str(row.get("algorithm", "")).lower() == "weak configuration":
            weak[(row.get("file_name", row.get("file")), row.get("line_number"), row.get("finding"))] = row

    breakdown = {
        "quantum_vulnerable": {"count": len(quantum), "deduction": min(40, len(quantum) * 20)},
        "deprecated_algorithms": {"count": len(deprecated), "deduction": min(30, len(deprecated) * 10)},
        "critical_findings": {"count": len(critical), "deduction": min(15, len(critical) * 5)},
        "weak_configurations": {"count": len(weak), "deduction": min(15, len(weak) * 5)},
    }
    total = sum(x["deduction"] for x in breakdown.values())
    score = round(max(0, 100 - total), 2)
    if score >= 80:
        risk, label = "LOW", "High readiness"
    elif score >= 60:
        risk, label = "MODERATE", "Moderate readiness"
    elif score >= 40:
        risk, label = "HIGH", "Low readiness"
    else:
        risk, label = "CRITICAL", "Poor readiness"

    reasons = []
    descriptions = {
        "quantum_vulnerable": (f"{len(quantum)} RSA/ECC inventory records detected. These public-key algorithms are vulnerable to sufficiently capable quantum computers."),
        "deprecated_algorithms": (f"{len(deprecated)} MD5, SHA-1 or DES inventory records detected."),
        "critical_findings": (f"{len(critical)} distinct critical findings detected. These require immediate security review."),
        "weak_configurations": (f"{len(weak)} distinct weak configuration findings detected."),
    }
    categories = {
        "quantum_vulnerable": "Quantum-vulnerable cryptography",
        "deprecated_algorithms": "Deprecated algorithms",
        "critical_findings": "Critical security findings",
        "weak_configurations": "Weak configurations",
    }
    for key, item in breakdown.items():
        if item["count"]:
            reasons.append({"category": categories[key], "count": item["count"],
                            "deduction": item["deduction"], "details": descriptions[key]})
    return {
        "readiness_score": score, "score": score, "risk_level": risk,
        "readiness_label": label, "base_score": 100, "total_risk_points": total,
        "risk_breakdown": breakdown, "reasons": reasons,
        "scoring_method": "Shared rule-based weighted risk deductions using inventory records and deduplicated critical/weak findings."
    }
