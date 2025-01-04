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


class ECDH:
    """
       Implements the Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol
       using secp265r1 (256-bit prime field Weierstrass curve) parameters.
       Enables two parties to securely establish a shared secret over an insecure channel.
       Based on the difficulty of solving the discrete logarithm problem in elliptic curve groups ([56]).
   """
    @staticmethod
    def point_add(p_point, q_point):
        """Add two points P and Q on the elliptic curve."""
        if p_point is None:  # Point at infinity
            return q_point
        if q_point is None:  # Point at infinity
            return p_point
        if p_point == q_point:
            return ECDH.point_double(p_point)

        x1, y1 = p_point
        x2, y2 = q_point
        if x1 == x2 and y1 != y2:
            return None  # Point at infinity

        # Slope
        m = ((y2 - y1) * inverse_mod(x2 - x1, p)) % p
        x3 = (m ** 2 - x1 - x2) % p
        y3 = (m * (x1 - x3) - y1) % p
        return x3, y3

    @staticmethod
    def point_double(p_point):
        """Double a point P on the elliptic curve."""
        if p_point is None:
            return None

        x1, y1 = p_point
        m = ((3 * x1 ** 2 + a) * inverse_mod(2 * y1, p)) % p
        x3 = (m ** 2 - 2 * x1) % p
        y3 = (m * (x1 - x3) - y1) % p
        return x3, y3

    @staticmethod
    def scalar_mult(k, p_point):
        """Multiply a point P by a scalar k."""
        result = None  # Point at infinity
        addend = p_point

        while k:
            if k & 1:
                result = ECDH.point_add(result, addend)
            addend = ECDH.point_double(addend)
            k >>= 1

        return result

    @staticmethod
    def generate_key_pair():
        """
           Generates a private and public key pair.

           Returns:
               tuple: (private_key, public_key)
                   - private_key (int): A randomly chosen private key.
                   - public_key (int): The corresponding public key computed on the curve.

           Key Generation:
           - Private key: A randomly chosen integer in the range [1, n-1], where n is the curve's order.
           - Public key: Computed as the product of the private key and the curve's base point.

           Security Note:
           - The private key must remain secret to prevent compromise of the shared secret - as taught in our lectures.
       """
        private_key = int.from_bytes(os.urandom(32), byteorder="big") % n
        public_key = ECDH.scalar_mult(private_key, G)
        return private_key, public_key

    @staticmethod
    def compute_shared_secret(private_key, public_key):
        """
            Computes the shared secret using the ECDH algorithm.

            Args:
                private_key (int): The private key of the party.
                public_key (int): The public key of the other party.

            Returns:
                bytes: A shared secret derived from the ECDH computation.

            Shared Secret:
            - Derived as the scalar multiplication of the private key with the other's public key.
            - Provides a common value for both parties without revealing private keys.

            Security Note:
            - The shared secret is typically hashed before use in symmetric key encryption - as taught in our lectures.
        """
        shared_point = ECDH.scalar_mult(private_key, public_key)
        return shared_point[0]  # Use x-coordinate as the shared secret

    @staticmethod
    def derive_key(shared_secret, length=16):
        """
            Derives a symmetric key from the shared secret.

            Args:
                shared_secret (bytes): The shared secret from the ECDH computation.
                length (int): The desired length of the derived key in bytes.

            Returns:
                bytes: The derived symmetric key.

            Key Derivation:
            - Ensures the shared secret is transformed into a usable key for encryption.
            - Hash-based key derivation methods are recommended - as taught in our lectures.
        """
        # Todo: look at shared_secret_bytes -- might not be course-correct...
        shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder="big")
        hashed = hashlib.sha256(shared_secret_bytes).digest()
        return hashed[:length]  # Truncate to desired length
