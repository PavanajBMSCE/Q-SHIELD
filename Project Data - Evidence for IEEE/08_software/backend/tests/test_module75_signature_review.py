import io
import unittest
import zipfile
from app import app

def sample_zip():
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("signing.py", "signature = private_key.sign(message, padding, algorithm)\n")
        z.writestr("verify.py", "public_key.verify(signature, message)\n")
    out.seek(0)
    return out

class Module75SignatureReviewTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_analyze_finds_signing_candidate_and_never_offers_patch(self):
        r = self.client.post("/api/project-migration/signature/analyze",
                             data={"file": (sample_zip(), "sample.zip")},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200, r.get_json())
        data = r.get_json()
        self.assertGreaterEqual(data["finding_count"], 1)
        self.assertEqual(data["patchable_count"], 0)
        self.assertTrue(all(not x["automatic_patch_available"] for x in data["findings"]))
        self.assertIn("job_id", data)

    def test_human_decision_records_plan_only(self):
        r = self.client.post("/api/project-migration/signature/analyze",
                             data={"file": (sample_zip(), "sample.zip")},
                             content_type="multipart/form-data")
        job = r.get_json()
        fid = job["findings"][0]["finding_id"]
        decision = self.client.post(
            f"/api/project-migration/signature/{job['job_id']}/decisions",
            json={"decisions": [{"finding_id": fid, "decision": "approve_migration_plan"}]})
        self.assertEqual(decision.status_code, 200, decision.get_json())
        self.assertFalse(decision.get_json()["source_modified"])

    def test_rejects_invalid_zip(self):
        r = self.client.post("/api/project-migration/signature/analyze",
                             data={"file": (io.BytesIO(b"not zip"), "bad.zip")},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)

    def test_rejects_unknown_job(self):
        r = self.client.get("/api/project-migration/signature/not-a-job")
        self.assertEqual(r.status_code, 404)

if __name__ == "__main__":
    unittest.main()
