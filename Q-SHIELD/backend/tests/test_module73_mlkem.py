import unittest
from app import app

class MLKEMModule73Tests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_provider_self_test_or_explicit_unavailable(self):
        response = self.client.get('/api/crypto-lab/ml-kem/provider-self-test')
        self.assertIn(response.status_code, (200, 503))
        payload = response.get_json()
        if response.status_code == 200:
            self.assertTrue(payload['available'])
            self.assertTrue(payload['verified'])
            self.assertEqual(payload['public_key_bytes'], 1184)
            self.assertEqual(payload['kem_ciphertext_bytes'], 1088)
            self.assertFalse(payload['private_key_disclosed'])
        else:
            self.assertFalse(payload['available'])

    def test_mlkem_hkdf_aesgcm_round_trip(self):
        response = self.client.post('/api/crypto-lab/ml-kem/round-trip', json={
            'plaintext': 'Q-SHIELD ML-KEM migration demonstration',
            'aad': 'qshield-demo-v1'
        })
        if response.status_code == 503:
            self.skipTest(response.get_json().get('error', 'ML-KEM provider unavailable'))
        self.assertEqual(response.status_code, 200, response.get_json())
        payload = response.get_json()
        self.assertTrue(payload['verified'])
        self.assertTrue(payload['shared_secrets_match'])
        self.assertTrue(payload['plaintext_match'])
        self.assertEqual(payload['kem_ciphertext_bytes'], 1088)
        self.assertFalse(payload['private_key_disclosed'])
        self.assertFalse(payload['shared_secret_disclosed'])

    def test_input_validation(self):
        response = self.client.post('/api/crypto-lab/ml-kem/round-trip', json={'plaintext': 42})
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main()
