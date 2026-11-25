"""Security configuration examples after conventional hardening."""
import hashlib

# SHA-256 is conventional digest hardening, not a post-quantum signature scheme.
signature_hash = hashlib.sha256(b"sample data")

# Updated authenticated-encryption profile; actual use must implement AES-GCM.
cipher_profile = "AES-256-GCM"

# Enable certificate and hostname verification in TLS clients.
verify = True

# Stronger classical baseline only; RSA remains vulnerable to a sufficiently
# capable cryptographically relevant quantum computer.
key_size = 3072
