import unittest
from app import app

class Module76SignatureDemoTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_round_trip_and_tamper_rejection_for_all_algorithms(self):
        response = self.client.post(
            "/api/crypto-lab/signature-migration/round-trip",
            json={"message": "Q-SHIELD signature migration test", "context": "unit-test-v1"})
        self.assertEqual(response.status_code, 200, response.get_json())
        result = response.get_json()
        self.assertTrue(result["all_algorithms_passed"])
        self.assertEqual({x["algorithm"] for x in result["results"]},
                         {"RSA-3072", "ECDSA-P-256", "ML-DSA-65"})
        for item in result["results"]:
            self.assertTrue(item["valid_signature_accepted"])
            self.assertTrue(item["tampered_message_rejected"])
            self.assertTrue(item["tampered_signature_rejected"])
            self.assertFalse(item.get("private_key_b64"))
            self.assertGreater(item["signature_bytes"], 0)

    def test_provider_self_test(self):
        response = self.client.get("/api/crypto-lab/signature-migration/provider-self-test")
        self.assertIn(response.status_code, (200, 503))
        if response.status_code == 200:
            self.assertTrue(response.get_json()["verified"])

    def test_rejects_invalid_input(self):
        response = self.client.post("/api/crypto-lab/signature-migration/round-trip",
                                    json={"message": ""})
        self.assertEqual(response.status_code, 400)

    def test_rejects_non_string_message(self):
        response = self.client.post("/api/crypto-lab/signature-migration/round-trip",
                                    json={"message": 123})
        self.assertEqual(response.status_code, 400)

if __name__ == "__main__":
    unittest.main()
