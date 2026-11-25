import io
import os
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from flask import Flask
from end_to_end_audit.engine import (
    end_to_end_audit_bp, _profile_comparison, _decision_counts, _policy_recommendations
)


def project_zip(source=b"from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"):
    out=io.BytesIO()
    with zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED) as z:z.writestr("sample.py",source)
    return out.getvalue()


class Module710Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        app=Flask(__name__); app.config.update(TESTING=True,UPLOAD_FOLDER=self.tmp.name,MAX_CONTENT_LENGTH=30*1024*1024)
        app.register_blueprint(end_to_end_audit_bp); self.client=app.test_client()

    def tearDown(self): self.tmp.cleanup()

    def test_run_audit_and_retrieve(self):
        r=self.client.post("/api/end-to-end-audit/run",data={"file":(io.BytesIO(project_zip()),"demo.zip"),"policy_profile":"TRANSITION"},content_type="multipart/form-data")
        self.assertEqual(r.status_code,201); job=r.get_json(); self.assertTrue(job["audit_id"]); self.assertFalse(job["source_retained"]); self.assertFalse(job["source_modified"])
        self.assertEqual(self.client.get("/api/end-to-end-audit/"+job["audit_id"]).status_code,200)

    def test_pqc_source_verification_receives_archive_contents(self):
        source = b"from pqcrypto.kem.ml_kem_768 import generate_keypair\\nMLKEM768PrivateKey.generate()\\n"
        r = self.client.post(
            "/api/end-to-end-audit/run",
            data={"file": (io.BytesIO(project_zip(source)), "pqc-demo.zip")},
            content_type="multipart/form-data",
        )
        self.assertEqual(r.status_code, 201, r.get_json())
        evidence = r.get_json()["verification_evidence"]
        self.assertIn(evidence["verification_level"], {
            "PARTIAL_OR_TOKEN_ONLY", "FUNCTIONAL_KEM_SOURCE_PRESENT",
            "INTEGRATION_STRUCTURE_PRESENT"
        })
        self.assertTrue(any(item["file"] == "sample.py" for item in evidence["source_evidence"]))

    def test_transition_and_strict_profile_delta_uses_same_findings(self):
        raw_findings = [
            {"finding_id":"F-RSA","algorithm":"RSA","severity":"HIGH","file":"crypto.py","line_number":4,"recommendation":"Plan PQC migration"},
            {"finding_id":"F-MD5","algorithm":"MD5","severity":"HIGH","file":"hash.py","line_number":8,"recommendation":"Review hash context"},
            {"finding_id":"F-AES","algorithm":"AES","severity":"MEDIUM","file":"cipher.py","line_number":12,"recommendation":"Review mode"},
            {"finding_id":"F-DES","algorithm":"DES","severity":"HIGH","file":"legacy.py","line_number":2,"recommendation":"Replace legacy crypto"},
        ]
        comparison = _profile_comparison(raw_findings)
        transition = comparison["profiles"]["TRANSITION"]
        strict = comparison["profiles"]["STRICT"]
        self.assertEqual(transition["total_findings"], strict["total_findings"])
        self.assertEqual(transition["total_findings"], 4)
        self.assertGreater(comparison["changed_findings_count"], 0)
        self.assertNotEqual(transition["status_counts"], strict["status_counts"])
        evaluated = [
            {"finding_id":"F-RSA","algorithm":"RSA","severity":"HIGH","file":"crypto.py","line_number":4,
             "policy_status":"MIGRATION_PLAN_REQUIRED","policy_action":"PLAN_PQC_MIGRATION",
             "target_guidance":"ML-KEM / ML-DSA","policy_priority":"HIGH","decision":"PENDING"},
        ]
        recs = _policy_recommendations(evaluated, comparison)
        self.assertEqual(recs[0]["policy_status"], "MIGRATION_PLAN_REQUIRED")
        self.assertEqual(_decision_counts(evaluated)["PENDING"], 1)
        self.assertEqual(_decision_counts(evaluated)["APPROVED"], 0)

    def test_reject_invalid_zip(self):
        r=self.client.post("/api/end-to-end-audit/run",data={"file":(io.BytesIO(b"not zip"),"bad.zip")},content_type="multipart/form-data")
        self.assertEqual(r.status_code,400)

    def test_reject_path_traversal(self):
        out=io.BytesIO()
        with zipfile.ZipFile(out,"w") as z:z.writestr("../escape.py","print('bad')")
        r=self.client.post("/api/end-to-end-audit/run",data={"file":(io.BytesIO(out.getvalue()),"bad.zip")},content_type="multipart/form-data")
        self.assertEqual(r.status_code,400)

    def test_human_decision_and_audit_event(self):
        r=self.client.post("/api/end-to-end-audit/run",data={"file":(io.BytesIO(project_zip()),"demo.zip")},content_type="multipart/form-data")
        job=r.get_json(); finding=job["findings"][0]
        d=self.client.post(f"/api/end-to-end-audit/{job['audit_id']}/decisions",json={"actor":"security-reviewer","decisions":[{"finding_id":finding["finding_id"],"decision":"APPROVE_REMEDIATION_PLAN","note":"Reviewed migration plan"}]})
        self.assertEqual(d.status_code,200); saved=d.get_json()["audit"]
        self.assertEqual(saved["findings"][0]["decision"],"APPROVE_REMEDIATION_PLAN")
        self.assertEqual(saved["audit_events"][-1]["actor"],"security-reviewer")

    def test_exception_requires_future_expiry_and_rationale(self):
        r=self.client.post("/api/end-to-end-audit/run",data={"file":(io.BytesIO(project_zip()),"demo.zip")},content_type="multipart/form-data")
        job=r.get_json(); fid=job["findings"][0]["finding_id"]
        d=self.client.post(f"/api/end-to-end-audit/{job['audit_id']}/decisions",json={"decisions":[{"finding_id":fid,"decision":"ACCEPT_TIME_BOUND_EXCEPTION","note":"Temporary risk","exception_expiry":"2000-01-01"}]})
        self.assertEqual(d.status_code,400)

    def test_pdf_and_evidence_bundle(self):
        r=self.client.post("/api/end-to-end-audit/run",data={"file":(io.BytesIO(project_zip()),"demo.zip")},content_type="multipart/form-data")
        aid=r.get_json()["audit_id"]
        pdf=self.client.get(f"/api/end-to-end-audit/{aid}/pdf"); self.assertEqual(pdf.status_code,200); self.assertTrue(pdf.data.startswith(b"%PDF"))
        ev=self.client.get(f"/api/end-to-end-audit/{aid}/evidence"); self.assertEqual(ev.status_code,200)
        with zipfile.ZipFile(io.BytesIO(ev.data)) as z:self.assertIn("audit_report.json",z.namelist()); self.assertNotIn("original_source.zip",z.namelist())

    def test_history_lists_audit(self):
        r=self.client.post("/api/end-to-end-audit/run",data={"file":(io.BytesIO(project_zip()),"demo.zip")},content_type="multipart/form-data")
        self.assertEqual(r.status_code,201); h=self.client.get("/api/end-to-end-audit/history").get_json(); self.assertEqual(h["count"],1)


if __name__=="__main__":unittest.main()
