
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import algorithms

# RSA implementation with weak key size
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024
)

# Weak hashing algorithm
password_hash = hashlib.md5(b"demo_password")

# AES-256 implementation
cipher = algorithms.AES(
    b"0123456789abcdef0123456789abcdef"
)

# Demo credential - NOT A REAL SECRET
API_KEY = "DEMO_NOT_A_REAL_SECRET_123"
