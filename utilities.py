# Helper functions
from globals import BLOCK_SIZE, debug_mode


def print_block(s, block_number, end='\n'):
    """Print the byte array in a formatted hex style."""
    if not debug_mode:
        return
    print(" Round {0:0>2}: ".format(block_number), end='')
    for byte in s:
        print(f"{byte:02x}", end=' ')
    print(end, end='')


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
        XORs two byte sequences.

        Args:
            a (bytes): The first byte sequence.
            b (bytes): The second byte sequence.

        Returns:
            bytes: The XOR result.

        XOR in Cryptography:
        - Fundamental to CBC mode for chaining blocks and ARIA.
        - Ensures plaintext is randomized before encryption.
    """
    return bytes(i ^ j for i, j in zip(a, b))


def inverse_mod(k, p):
    """Compute the modular inverse of k mod p."""
    if k == 0:
        raise ValueError("Division by zero")
    return pow(k, -1, p)


def rotate_and_xor(s, n, target):
    """
        Input: Byte array 's' of size 16, integer 'n', Byte array 'target' of size 16
        Output: Byte array of size 16 which is result of operation
        Right-rotate 's' by 'n' bits and XOR with 'target' then return the result
        """
    q = n // 8
    n %= 8
    for i in range(BLOCK_SIZE):
        target[(q + i) % BLOCK_SIZE] ^= (s[i] >> n)
        if n != 0:
            target[(q + i + 1) % BLOCK_SIZE] ^= ((s[i] << (8 - n)) % 256)
    return target


def invert_s_box(s_box_2d):
    """
    Given a 16x16 S-box (2D list), this function returns its 16x16 inverse S-box.
    """
    # 1) Flatten the 16x16 table into a single list of 256 elements
    flat_s_box = []
    for row in s_box_2d:
        flat_s_box.extend(row)

    # 2) Create an empty list of 256 elements for the inverse
    inv_flat_s_box = [0] * 256

    # 3) Fill inv_flat_s_box so that inverse[s_box[i]] = i
    for i, val in enumerate(flat_s_box):
        inv_flat_s_box[val] = i

    # 4) Reshape the 256-element list back into a 16x16 table
    inverse_s_box_2d = [
        inv_flat_s_box[i: i + BLOCK_SIZE] for i in range(0, 256, BLOCK_SIZE)
    ]

    return inverse_s_box_2d
