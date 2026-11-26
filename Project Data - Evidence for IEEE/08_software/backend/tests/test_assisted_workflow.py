"""Tests for Q-SHIELD human-approved assisted migration proposals."""
import hashlib
import unittest

from project_migration.engine import (
    _apply_assisted_proposal,
    _build_assisted_proposals,
)


class AssistedProposalTests(unittest.TestCase):
    def setUp(self):
        self.files = {
            "security.py": b"import hashlib\nverify = False\nlegacy_cipher = 'DES encryption'\n",
            "main.py": b'API_KEY = "DEMO_NOT_A_REAL_SECRET_123"\npassword_hash = hashlib.md5(b"demo_password")\n',
        }

    def test_tls_patch_is_proposed_not_applied_until_approval(self):
        proposals = _build_assisted_proposals(self.files)
        tls = next(item for item in proposals if item.get("patch_kind") == "tls_verify")
        self.assertEqual(tls["status"], "PENDING_REVIEW")
        self.assertTrue(tls["patch_available"])
        self.assertIn("+verify = True", tls["diff"])
        self.assertEqual(self.files["security.py"].decode().splitlines()[1], "verify = False")

    def test_secret_diff_redacts_original_value(self):
        proposals = _build_assisted_proposals(self.files)
        secret = next(item for item in proposals if item.get("patch_kind") == "secret_env")
        self.assertNotIn("DEMO_NOT_A_REAL_SECRET_123", secret["diff"])
        self.assertIn("<REDACTED>", secret["diff"])

    def test_approved_patch_applies_and_passes_python_ast(self):
        proposals = _build_assisted_proposals(self.files)
        tls = next(item for item in proposals if item.get("patch_kind") == "tls_verify")
        working = dict(self.files)
        result = _apply_assisted_proposal(working, tls)
        self.assertEqual(result["validation"]["status"], "PASS")
        self.assertIn("verify = True", working["security.py"].decode())

    def test_complex_crypto_findings_are_guidance_only(self):
        proposals = _build_assisted_proposals(self.files)
        des = next(item for item in proposals if item["category"] == "Symmetric encryption")
        self.assertFalse(des["patch_available"])
        self.assertEqual(des["status"], "GUIDANCE_ONLY")

    def test_password_md5_is_not_silently_rewritten(self):
        proposals = _build_assisted_proposals(self.files)
        self.assertIn("hashlib.md5", self.files["main.py"].decode())
        self.assertTrue(any(item["category"] == "Hash function" for item in proposals))


if __name__ == "__main__":
    unittest.main()
