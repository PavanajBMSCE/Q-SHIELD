import unittest
from app import app


class MLDSAModule74Tests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_provider_self_test_or_explicit_unavailable(self):
        response = self.client.get('/api/crypto-lab/ml-dsa/provider-self-test')
        self.assertIn(response.status_code, (200, 503))
        payload = response.get_json()
        if response.status_code == 200:
            self.assertTrue(payload['available'])
            self.assertTrue(payload['verified'])
            self.assertEqual(payload['public_key_bytes'], 1952)
            self.assertEqual(payload['signature_bytes'], 3309)
            self.assertFalse(payload['private_key_disclosed'])
        else:
            self.assertFalse(payload['available'])

    def test_signature_round_trip_or_skip_if_provider_unavailable(self):
        response = self.client.post('/api/crypto-lab/ml-dsa/signature-round-trip', json={
            'message': 'Q-SHIELD ML-DSA-65 signature demonstration',
            'context': 'qshield-demo-v1'
        })
        if response.status_code == 503:
            self.skipTest(response.get_json().get('error', 'ML-DSA provider unavailable'))
        self.assertEqual(response.status_code, 200, response.get_json())
        payload = response.get_json()
        self.assertTrue(payload['verified'])
        self.assertEqual(payload['public_key_bytes'], 1952)
        self.assertEqual(payload['signature_bytes'], 3309)
        self.assertFalse(payload['private_key_disclosed'])

        verify = self.client.post('/api/crypto-lab/ml-dsa/verify', json={
            'message': 'Q-SHIELD ML-DSA-65 signature demonstration',
            'context': 'qshield-demo-v1',
            'public_key_b64': payload['public_key_b64'],
            'signature_b64': payload['signature_b64']
        })
        self.assertEqual(verify.status_code, 200, verify.get_json())
        self.assertTrue(verify.get_json()['verified'])

        tampered = self.client.post('/api/crypto-lab/ml-dsa/verify', json={
            'message': 'TAMPERED Q-SHIELD ML-DSA-65 signature demonstration',
            'context': 'qshield-demo-v1',
            'public_key_b64': payload['public_key_b64'],
            'signature_b64': payload['signature_b64']
        })
        self.assertEqual(tampered.status_code, 200, tampered.get_json())
        self.assertFalse(tampered.get_json()['verified'])

    def test_input_validation(self):
        response = self.client.post('/api/crypto-lab/ml-dsa/signature-round-trip', json={
            'message': 'x', 'context': 'c' * 256
        })
        self.assertEqual(response.status_code, 400)

    def test_verify_rejects_wrong_public_key_length(self):
        response = self.client.post('/api/crypto-lab/ml-dsa/verify', json={
            'message': 'x', 'public_key_b64': 'eA==', 'signature_b64': 'eA=='
        })
        self.assertEqual(response.status_code, 400)


if __name__ == '__main__':
    unittest.main()
