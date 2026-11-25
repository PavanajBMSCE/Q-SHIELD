import pathlib
import unittest

ENGINE = pathlib.Path(__file__).resolve().parents[1] / "project_migration" / "engine.py"

class Module71GuidanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = ENGINE.read_text(encoding="utf-8")

    def test_password_guidance_rejects_plain_sha256_substitution(self):
        self.assertIn("Do not substitute plain SHA-256", self.source)
        self.assertIn("Argon2id", self.source)

    def test_pqc_guidance_distinguishes_kem_from_signatures(self):
        self.assertIn("ML-KEM does not replace RSA signatures", self.source)

    def test_aes_gcm_guidance_requires_nonce_tag_and_aad(self):
        for term in ("unique nonce", "authentication tag", "AAD"):
            self.assertIn(term, self.source)

    def test_tls_guidance_requires_real_call_site(self):
        self.assertIn("standalone verify=True assignment is not evidence", self.source)

    def test_guidance_only_cannot_become_automatic_patch(self):
        self.assertIn('"patch_available": False', self.source)
        self.assertIn('"status": "GUIDANCE_ONLY"', self.source)

if __name__ == "__main__":
    unittest.main()
