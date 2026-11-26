import unittest
from app import app

class CryptoLabTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_aes_gcm_round_trip_and_tamper_rejection(self):
        enc = self.client.post('/api/crypto-lab/aes-gcm/encrypt', json={'plaintext':'Q-SHIELD test','aad':'project:demo'})
        self.assertEqual(enc.status_code, 200)
        payload = enc.get_json()
        dec = self.client.post('/api/crypto-lab/aes-gcm/decrypt', json={k:payload[k] for k in ('key_b64','nonce_b64','ciphertext_b64','aad')})
        self.assertEqual(dec.status_code, 200)
        self.assertEqual(dec.get_json()['plaintext'], 'Q-SHIELD test')
        payload['ciphertext_b64'] = payload['ciphertext_b64'][:-4] + 'AAAA'
        bad = self.client.post('/api/crypto-lab/aes-gcm/decrypt', json={k:payload[k] for k in ('key_b64','nonce_b64','ciphertext_b64','aad')})
        self.assertEqual(bad.status_code, 400)
        self.assertFalse(bad.get_json()['verified'])

    def test_argon2id_hash_verify_and_wrong_password(self):
        hashed = self.client.post('/api/crypto-lab/password/hash', json={'password':'Correct-Horse-42!'})
        self.assertEqual(hashed.status_code, 200)
        encoded = hashed.get_json()['encoded_hash']
        self.assertTrue(encoded.startswith('$argon2id$'))
        good = self.client.post('/api/crypto-lab/password/verify', json={'password':'Correct-Horse-42!','encoded_hash':encoded})
        bad = self.client.post('/api/crypto-lab/password/verify', json={'password':'wrong','encoded_hash':encoded})
        self.assertTrue(good.get_json()['verified'])
        self.assertFalse(bad.get_json()['verified'])

    def test_input_validation(self):
        self.assertEqual(self.client.post('/api/crypto-lab/password/hash', json={'password':''}).status_code, 400)
        self.assertEqual(self.client.post('/api/crypto-lab/aes-gcm/decrypt', json={}).status_code, 400)

if __name__ == '__main__': unittest.main()
