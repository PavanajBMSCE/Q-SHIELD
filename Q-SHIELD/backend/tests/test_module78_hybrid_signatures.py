import unittest
from app import app


class Module78HybridSignatureTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_provider_self_test(self):
        response = self.client.get(
            "/api/crypto-lab/hybrid-signatures/provider-self-test"
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        body = response.get_json()
        self.assertTrue(body["available"])
        self.assertTrue(body["verified"])
        self.assertFalse(body["private_key_disclosed"])

    def test_dual_signature_and_policy_matrix(self):
        response = self.client.post(
            "/api/crypto-lab/hybrid-signatures/demonstrate",
            json={"message": "Q-SHIELD dual signature demonstration",
                  "context": "qshield-module-7.8"},
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        body = response.get_json()
        self.assertTrue(body["all_checks_passed"])
        self.assertEqual(body["module"], "7.8")
        self.assertTrue(body["checks"]["rsa_valid_signature_accepted"])
        self.assertTrue(body["checks"]["mldsa_valid_signature_accepted"])
        self.assertTrue(body["checks"]["tampered_message_rejected_by_rsa"])
        self.assertTrue(body["checks"]["tampered_message_rejected_by_mldsa"])
        self.assertTrue(body["checks"]["tampered_rsa_signature_rejected"])
        self.assertTrue(body["checks"]["tampered_mldsa_signature_rejected"])
        self.assertTrue(body["policies"]["both_valid"]["DUAL_REQUIRED"]["accepted"])
        self.assertFalse(body["policies"]["classical_signature_invalid"]["DUAL_REQUIRED"]["accepted"])
        self.assertFalse(body["policies"]["pqc_signature_invalid"]["DUAL_REQUIRED"]["accepted"])
        self.assertTrue(body["policies"]["pqc_signature_invalid"]["CLASSICAL_ONLY"]["accepted"])
        self.assertTrue(body["policies"]["classical_signature_invalid"]["PQC_ONLY"]["accepted"])
        self.assertFalse(body["private_keys_disclosed"])

    def test_rejects_invalid_message_and_context(self):
        for payload in (
            {},
            {"message": ""},
            {"message": "hello", "context": ""},
            {"message": 42},
        ):
            response = self.client.post(
                "/api/crypto-lab/hybrid-signatures/demonstrate", json=payload
            )
            self.assertEqual(response.status_code, 400, payload)

    def test_rejects_non_object_json(self):
        response = self.client.post(
            "/api/crypto-lab/hybrid-signatures/demonstrate",
            data='["not","an","object"]',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
