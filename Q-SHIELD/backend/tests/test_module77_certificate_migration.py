import unittest
from app import app


class Module77CertificateMigrationTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_provider_self_test(self):
        response = self.client.get(
            "/api/crypto-lab/certificate-migration/provider-self-test"
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        body = response.get_json()
        self.assertTrue(body["available"])
        self.assertTrue(body["verified"])
        self.assertFalse(body["private_key_disclosed"])

    def test_certificate_chain_and_mldsa_manifest(self):
        response = self.client.post(
            "/api/crypto-lab/certificate-migration/demonstrate", json={}
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        body = response.get_json()
        self.assertTrue(body["all_checks_passed"])
        self.assertEqual(body["module"], "7.7")
        self.assertEqual(
            body["certificate_chain"]["chain_order"],
            ["leaf", "intermediate", "root"],
        )
        self.assertTrue(body["checks"]["root_signature_valid"])
        self.assertTrue(body["checks"]["intermediate_signature_valid"])
        self.assertTrue(body["checks"]["leaf_signature_valid"])
        self.assertTrue(body["checks"]["mldsa_manifest_signature_valid"])
        self.assertTrue(body["checks"]["tampered_manifest_rejected"])
        self.assertTrue(body["checks"]["tampered_manifest_signature_rejected"])
        self.assertTrue(body["checks"]["unrelated_trust_anchor_rejected"])
        self.assertFalse(body["migration_manifest"]["private_key_disclosed"])
        self.assertIn(
            "NOT an ML-DSA-signed X.509 certificate",
            " ".join(body["limitations"]),
        )

    def test_chain_fingerprints_and_sizes_present(self):
        body = self.client.post(
            "/api/crypto-lab/certificate-migration/demonstrate", json={}
        ).get_json()
        for role in ("root", "intermediate", "leaf"):
            cert = body["certificate_chain"][role]
            self.assertEqual(len(cert["sha256_fingerprint"]), 64)
            self.assertGreater(cert["der_bytes"], 0)

    def test_rejects_non_object_json(self):
        response = self.client.post(
            "/api/crypto-lab/certificate-migration/demonstrate",
            data='["not","an","object"]',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
