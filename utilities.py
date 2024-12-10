# Helper functions
from enum import Enum


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte arrays."""
    return bytes(i ^ j for i, j in zip(a, b))


def rotate_bytes(data: bytes, shift: int) -> bytes:
    """Circularly rotate bytes by the given shift."""
    return data[shift:] + data[:shift]


class RoundsToBytes(Enum):
    """Number of rounds to bytes mapping."""
    ROUND_128 = 12
    ROUND_192 = 14
    ROUND_256 = 16

    # Get the number of rounds based on the key size
    @classmethod
    def get_rounds(cls, key_size_bytes: int) -> int:
        if key_size_bytes == 16:
            return cls.ROUND_128.value
        elif key_size_bytes == 24:
            return cls.ROUND_192.value
        elif key_size_bytes == 32:
            return cls.ROUND_256.value
        else:
            raise ValueError("Invalid key size")
