import hashlib
import random
from math import gcd

from utilities import inverse_mod

# ElGamal parameters
# P = 2^256 - 2^32 - 977  # This is the prime modulus used by the elliptic curve secp256k1
P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

# Generator source: https://github.com/maK-/Digital-Signature-ElGamal/blob/master/generator-g
G = int(
    "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e"
    "373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641"
    "a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f54966"
    "4bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68",
    16
)


class ELGamal:
    """
        Implements the ElGamal digital signature scheme.
        Provides message authentication, integrity, and non-repudiation - as taught in our lectures.
    """
    @staticmethod
    def generate_elgamal_key_pair():
        """
            Generates a private and public key pair for ElGamal signature.

            Returns:
                tuple: (private_key, public_key)
                    - private_key (int): The private key for signing.
                    - public_key (int): The public key for verification.

            Key Pair:
            - Private key: Randomly chosen from the range [1, p-1].
            - Public key: Computed using modular exponentiation with a generator.
        """
        private_key = random.randint(1, P - 1)
        public_key = pow(G, private_key, P)
        return private_key, public_key

    @staticmethod
    def sign_message(message: bytes, private_key: int):
        """
            Signs a message using the ElGamal signature algorithm.

            Args:
                message (bytes): The message to sign.
                private_key (int): The private key for signing.

            Returns:
                tuple: (r, s) - The digital signature components.

            Process:
            1. Hash the message for compact representation.
            2. Generate a random k coprime to (p-1).
            3. Compute signature components (r, s).

            Security Note:
            - k must be unique for every signature to prevent private key recovery - as taught in our lectures.
        """
        k = random.randint(1, P - 2)
        while gcd(k, P - 1) != 1:
            k = random.randint(1, P - 2)

        r = pow(G, k, P)
        k_inv = inverse_mod(k, P - 1)
        s = (k_inv * (int.from_bytes(hashlib.sha256(message).digest(), 'big') - private_key * r)) % (P - 1)
        return r, s

    @staticmethod
    def verify_signature(message: bytes, signature: tuple, public_key: int):
        """
            Verifies an ElGamal signature.

            Args:
                message (bytes): The signed message.
                signature (tuple): The (r, s) signature components.
                public_key (int): The public key for verification.

            Returns:
                bool: True if the signature is valid, False otherwise.

            Process:
            1. Hash the message.
            2. Verify the signature equation using modular arithmetic.

            Security Note:
            - Validation ensures the message was signed by the private key owner.
        """
        r, s = signature
        if not (0 < r < P and 0 < s < P - 1):
            return False

        h = int.from_bytes(hashlib.sha256(message).digest(), 'big')
        v1 = pow(G, h, P)
        v2 = (pow(public_key, r, P) * pow(r, s, P)) % P
        return v1 == v2
