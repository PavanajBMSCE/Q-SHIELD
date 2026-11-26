"""Q-SHIELD remediated sample application.

RSA remains in this sample as a classical baseline pending confirmation of
whether the original operation is key establishment, encryption or signing.
It is upgraded to 3072 bits for the classical baseline but is NOT quantum-safe.
"""
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Classical RSA baseline: stronger classical key size, still requires PQC redesign.
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=3072
)

# Password storage uses a salted, memory-hard password KDF (not SHA-256 alone).
password = b"demo_password"
salt = os.urandom(16)
password_kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
password_hash = password_kdf.derive(password)

# AES-256-GCM authenticated-encryption demonstration.
aead_key = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)
associated_data = b"Q-SHIELD sample metadata"
plaintext = b"Q-SHIELD remediated sample payload"
aesgcm = AESGCM(aead_key)
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
recovered = aesgcm.decrypt(nonce, ciphertext, associated_data)
assert recovered == plaintext

# Set API_KEY in the environment; rotate any value previously committed.
API_KEY = os.environ.get("API_KEY")

print("Scrypt password derivation: PASS")
print("AES-256-GCM authenticated round-trip: PASS")
print("RSA-3072 classical baseline: generated; PQC migration still required")
