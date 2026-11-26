"""Regression tests for the Q-SHIELD final remediation improvements.

Run from backend with the project's virtual environment:
    python -m unittest tests.test_final_remediation -v
"""
import unittest

from scanner.crypto_detector import scan_file
from project_migration.engine import migrate_files
from comparison.engine import _is_informational_inventory, _is_modern_algorithm_adoption


class ScannerRemediationTests(unittest.TestCase):
    def test_aes_gcm_is_classified_as_authenticated_encryption(self):
        source = (
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "cipher = AESGCM(key)\n"
            "encrypted = cipher.encrypt(nonce, payload, aad)\n"
        )
        findings = scan_file("sample.py", source)
        aes = [item for item in findings if item["algorithm"] == "AES"]
        self.assertTrue(aes)
        self.assertTrue(all(item["severity"] == "INFO" for item in aes))
        self.assertTrue(all(item["finding"] == "Authenticated encryption adoption" for item in aes))

    def test_multiline_docstring_does_not_create_crypto_findings(self):
        source = '''"""Documentation mentioning RSA, DES, MD5 and TLSv1.0.\nMore text about ML-KEM-768.\n"""\nvalue = 1\n'''
        findings = scan_file("sample.py", source)
        self.assertEqual(findings, [])

    def test_fstring_literals_do_not_create_pqc_token_evidence(self):
        from scanner.crypto_detector import _remove_python_comments, _mask_strings
        source = 'print(f"ML-KEM-768 demonstration {len(ciphertext)}")\n'
        masked = _mask_strings(_remove_python_comments(source), True)
        self.assertNotIn("ML-KEM-768", masked)
        self.assertIn("len(ciphertext)", masked)

    def test_modern_digest_is_informational(self):
        findings = scan_file("sample.py", "import hashlib\nvalue = hashlib.sha256(b'x')\n")
        digest = [item for item in findings if item["algorithm"] == "SHA-256"]
        self.assertEqual(len(digest), 1)
        self.assertEqual(digest[0]["severity"], "INFO")


class MigrationSafetyTests(unittest.TestCase):
    def test_safe_config_upgrades_and_secret_externalization(self):
        files = {
            "config.js": (
                b'const algorithm = "AES-256-CBC";\n'
                b'const hash = "MD5";\n'
                b'const tlsVersion = "TLSv1.0";\n'
                b'const API_KEY = "DEMO_SECRET_VALUE_12345";\n'
            )
        }
        output, report = migrate_files(files, "automatic")
        text = output["config.js"].decode()
        self.assertIn('"AES-256-GCM"', text)
        self.assertIn('"SHA-256"', text)
        self.assertIn('"TLSv1.3"', text)
        self.assertIn("process.env.API_KEY", text)
        self.assertNotIn("DEMO_SECRET_VALUE_12345", text)
        self.assertTrue(any(x["rule"] == "JS_SECRET_TO_ENV" for x in report["automatic_changes"]))

    def test_python_secret_migration_preserves_future_import_order(self):
        files = {"main.py": b"\"\"\"module docs\"\"\"\nfrom __future__ import annotations\nAPI_KEY = 'DEMO_SECRET_VALUE_12345'\n"}
        output, _ = migrate_files(files, "automatic")
        text = output["main.py"].decode()
        self.assertLess(text.index("from __future__ import annotations"), text.index("import os"))
        self.assertIn("os.environ.get('API_KEY')", text)

    def test_password_md5_is_not_replaced_with_sha256(self):
        files = {"main.py": b"import hashlib\npassword_hash = hashlib.md5(b'password')\n"}
        output, report = migrate_files(files, "automatic")
        self.assertIn("hashlib.md5", output["main.py"].decode())
        self.assertTrue(any(x["category"] == "Password storage" for x in report["manual_review_items"]))

    def test_python_sha1_and_secret_migration(self):
        files = {"security.py": b"import hashlib\nsignature_hash = hashlib.sha1(b'data')\nAPI_KEY = 'DEMO_SECRET_VALUE_12345'\n"}
        output, report = migrate_files(files, "automatic")
        text = output["security.py"].decode()
        self.assertIn("hashlib.sha256", text)
        self.assertIn("import os", text)
        self.assertIn("os.environ.get('API_KEY')", text)
        self.assertNotIn("DEMO_SECRET_VALUE_12345", text)


class ComparisonClassificationTests(unittest.TestCase):
    def test_info_api_reference_is_not_actionable_security_finding(self):
        item = {"algorithm": "Cryptographic API", "severity": "INFO"}
        self.assertTrue(_is_informational_inventory(item))

    def test_aes_gcm_and_sha256_adoptions_are_not_vulnerabilities(self):
        aes = {"algorithm": "AES", "finding": "Authenticated encryption adoption", "severity": "INFO"}
        sha = {"algorithm": "SHA-256", "finding": "Modern digest adoption", "severity": "INFO"}
        self.assertTrue(_is_modern_algorithm_adoption(aes))
        self.assertTrue(_is_modern_algorithm_adoption(sha))


if __name__ == "__main__":
    unittest.main()
