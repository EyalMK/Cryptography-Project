# Helper functions
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte arrays."""
    return bytes(i ^ j for i, j in zip(a, b))


def inverse_mod(k, p):
    """Compute the modular inverse of k mod p."""
    if k == 0:
        raise ValueError("Division by zero")
    return pow(k, -1, p)
