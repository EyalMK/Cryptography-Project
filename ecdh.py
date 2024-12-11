import hashlib
import os

from utilities import inverse_mod

# Elliptic curve parameters for secp256r1 (P-256)
# Source: https://neuromancer.sk/std/nist/P-256
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Base point (generator)
G = (Gx, Gy)


def point_add(p_point, q_point):
    """Add two points P and Q on the elliptic curve."""
    if p_point is None:  # Point at infinity
        return q_point
    if q_point is None:  # Point at infinity
        return p_point
    if p_point == q_point:
        return point_double(p_point)

    x1, y1 = p_point
    x2, y2 = q_point
    if x1 == x2 and y1 != y2:
        return None  # Point at infinity

    # Slope
    m = ((y2 - y1) * inverse_mod(x2 - x1, p)) % p
    x3 = (m**2 - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return x3, y3


def point_double(p_point):
    """Double a point P on the elliptic curve."""
    if p_point is None:
        return None

    x1, y1 = p_point
    m = ((3 * x1**2 + a) * inverse_mod(2 * y1, p)) % p
    x3 = (m**2 - 2 * x1) % p
    y3 = (m * (x1 - x3) - y1) % p
    return x3, y3


def scalar_mult(k, p_point):
    """Multiply a point P by a scalar k."""
    result = None  # Point at infinity
    addend = p_point

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1

    return result


def generate_key_pair():
    """Generate a private-public key pair."""
    private_key = int.from_bytes(os.urandom(32), byteorder="big") % n
    public_key = scalar_mult(private_key, G)
    return private_key, public_key


def compute_shared_secret(private_key, public_key):
    """Compute the shared secret."""
    shared_point = scalar_mult(private_key, public_key)
    return shared_point[0]  # Use x-coordinate as the shared secret


def derive_key(shared_secret, length=16):
    """Derive a symmetric key from the shared secret using SHA-256."""
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder="big")
    hashed = hashlib.sha256(shared_secret_bytes).digest()
    return hashed[:length]  # Truncate to desired length
