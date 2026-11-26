"""Q-SHIELD ML-KEM-768 key-establishment demonstration.

Requires cryptography>=50.0.0 with native ML-KEM support.
This demonstrates FIPS 203 ML-KEM-768 encapsulation/decapsulation only.
It does not implement signatures, TLS, key persistence or an application protocol.
"""
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

# Receiver creates a private/public key pair.
recipient_private_key = MLKEM768PrivateKey.generate()
recipient_public_key = recipient_private_key.public_key()

# Sender encapsulates to the recipient public key.
shared_secret_sender, kem_ciphertext = recipient_public_key.encapsulate()

# Recipient decapsulates with its private key.
shared_secret_recipient = recipient_private_key.decapsulate(kem_ciphertext)

assert shared_secret_sender == shared_secret_recipient
print("ML-KEM-768 encapsulation/decapsulation: PASS")
print(f"KEM ciphertext bytes: {len(kem_ciphertext)}")
print("Shared secret agreement: PASS")
