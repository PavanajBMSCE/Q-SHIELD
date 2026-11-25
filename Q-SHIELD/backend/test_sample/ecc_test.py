
from cryptography.hazmat.primitives.asymmetric import ec

# Elliptic Curve Digital Signature Algorithm
private_key = ec.generate_private_key(
    ec.SECP256R1()
)

# Elliptic Curve Diffie-Hellman
shared_key_algorithm = ec.ECDH()

# Elliptic Curve public key
public_key = private_key.public_key()

print("ECC cryptographic implementation test")
