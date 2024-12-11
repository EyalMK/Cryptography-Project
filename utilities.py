# Helper functions
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte arrays."""
    return bytes(i ^ j for i, j in zip(a, b))
