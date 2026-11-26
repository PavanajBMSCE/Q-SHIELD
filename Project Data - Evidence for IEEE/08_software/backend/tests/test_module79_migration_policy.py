import io
import json
import unittest
import zipfile
from app import app


def make_zip(entries=None):
    entries = entries or {
        "src/crypto.py": (
            "import hashlib\n"
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
            "digest = hashlib.md5(b'demo').hexdigest()\n"
        )
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    buffer.seek(0)
    return buffer


class Module79MigrationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def evaluate(self, profile="TRANSITION"):
        archive = make_zip()
        return self.client.post(
            "/api/crypto-lab/migration-policy/evaluate",
            data={
                "file": (archive, "policy-test.zip"),
                "policy_profile": profile,
            },
            content_type="multipart/form-data",
        )

    def test_policy_catalog(self):
        response = self.client.get("/api/crypto-lab/migration-policy/catalog")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertIn("RSA", body["catalog"]["algorithm_policies"])
        self.assertIn("ML-DSA", body["catalog"]["algorithm_policies"]["RSA"]["target"])

    def test_evaluate_zip_and_record_human_decision(self):
        response = self.evaluate()
        self.assertEqual(response.status_code, 201, response.get_json())
        job = response.get_json()
        self.assertFalse(job["source_modified"])
        self.assertGreaterEqual(len(job["scanned_files"]), 1)
        self.assertGreaterEqual(len(job["findings"]), 1)
        finding = job["findings"][0]
        decision = self.client.post(
            f"/api/crypto-lab/migration-policy/{job['job_id']}/decisions",
            json={
                "actor": "security-reviewer",
                "decisions": [{
                    "finding_id": finding["finding_id"],
                    "decision": "APPROVE_REMEDIATION_PLAN",
                    "note": "Approved for remediation planning and controlled testing."
                }]
            },
        )
        self.assertEqual(decision.status_code, 200, decision.get_json())
        self.assertEqual(decision.get_json()["recorded"], 1)
        self.assertFalse(decision.get_json()["source_modified"])
        fetched = self.client.get(
            f"/api/crypto-lab/migration-policy/{job['job_id']}"
        ).get_json()
        self.assertEqual(fetched["findings"][0]["decision"], "APPROVE_REMEDIATION_PLAN")

    def test_rejects_invalid_profile_and_invalid_zip(self):
        archive = make_zip()
        response = self.client.post(
            "/api/crypto-lab/migration-policy/evaluate",
            data={"file": (archive, "bad.zip"), "policy_profile": "UNKNOWN"},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        response = self.client.post(
            "/api/crypto-lab/migration-policy/evaluate",
            data={"file": (io.BytesIO(b"not zip"), "bad.zip")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)

    def test_rejects_zip_path_traversal(self):
        archive = make_zip({"../escape.py": "print('unsafe')"})
        response = self.client.post(
            "/api/crypto-lab/migration-policy/evaluate",
            data={"file": (archive, "unsafe.zip")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)

    def test_rejects_expired_exception(self):
        response = self.evaluate()
        self.assertEqual(response.status_code, 201, response.get_json())
        job = response.get_json()
        finding = job["findings"][0]
        result = self.client.post(
            f"/api/crypto-lab/migration-policy/{job['job_id']}/decisions",
            json={
                "decisions": [{
                    "finding_id": finding["finding_id"],
                    "decision": "ACCEPT_TIME_BOUND_EXCEPTION",
                    "note": "Temporary exception requested pending migration.",
                    "exception_expiry": "2000-01-01",
                }]
            },
        )
        self.assertEqual(result.status_code, 400)


if __name__ == "__main__":
    unittest.main()
