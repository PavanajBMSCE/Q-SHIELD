from assessment.scoring import calculate_readiness_metrics


def test_readiness_breakdown_matches_audit_report_example():
    inventory = [
        {"algorithm": "RSA"}, {"algorithm": "ECC"},
        {"algorithm": "MD5"}, {"algorithm": "MD5"},
        {"algorithm": "DES"}, {"algorithm": "SHA-1"},
    ]
    findings = [
        {"file_name": "config.js", "line_number": 14, "algorithm": "Hardcoded Secret",
         "severity": "CRITICAL", "finding": "Potential hardcoded credential"},
        {"file_name": "main.py", "line_number": 21, "algorithm": "Hardcoded Secret",
         "severity": "CRITICAL", "finding": "Potential hardcoded credential"},
    ]
    findings.extend(
        {"file_name": f"source_{i}.py", "line_number": i + 1,
         "algorithm": "Weak Configuration", "severity": "HIGH",
         "finding": "Weak configuration detected"}
        for i in range(7)
    )
    result = calculate_readiness_metrics(inventory, findings)
    assert result["readiness_score"] == 5
    assert result["risk_level"] == "CRITICAL"
    assert result["total_risk_points"] == 95
    assert result["risk_breakdown"]["quantum_vulnerable"]["deduction"] == 40
    assert result["risk_breakdown"]["deprecated_algorithms"]["deduction"] == 30
    assert result["risk_breakdown"]["critical_findings"]["deduction"] == 10
    assert result["risk_breakdown"]["weak_configurations"]["deduction"] == 15


def test_duplicate_critical_and_weak_findings_are_deduplicated():
    inventory = [{"algorithm": "RSA"}]
    finding = {"file_name": "app.py", "line_number": 8, "algorithm": "Weak Configuration",
               "severity": "CRITICAL", "finding": "TLS verification disabled"}
    result = calculate_readiness_metrics(inventory, [finding, dict(finding)])
    assert result["risk_breakdown"]["critical_findings"]["count"] == 1
    assert result["risk_breakdown"]["weak_configurations"]["count"] == 1
