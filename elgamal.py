import hashlib
import random
from math import gcd

from utilities import inverse_mod

# ElGamal parameters
P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
G = 2  # Generator (simplified for demonstration)


def generate_elgamal_key_pair():
    """Generate ElGamal private-public key pair."""
    private_key = random.randint(1, P - 1)
    public_key = pow(G, private_key, P)
    return private_key, public_key


def sign_message(message: bytes, private_key: int):
    """Sign a message using ElGamal."""
    k = random.randint(1, P - 2)
    while gcd(k, P - 1) != 1:
        k = random.randint(1, P - 2)

    r = pow(G, k, P)
    k_inv = inverse_mod(k, P - 1)
    s = (k_inv * (int.from_bytes(hashlib.sha256(message).digest(), 'big') - private_key * r)) % (P - 1)
    return r, s


def verify_signature(message: bytes, signature: tuple, public_key: int):
    """Verify an ElGamal signature."""
    r, s = signature
    if not (0 < r < P and 0 < s < P - 1):
        return False

    h = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    v1 = pow(G, h, P)
    v2 = (pow(public_key, r, P) * pow(r, s, P)) % P
    return v1 == v2
