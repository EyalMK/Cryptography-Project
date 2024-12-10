from aria import ARIA
from utilities import xor_bytes


# CBC Mode Wrapper
class CBCMode:
    def __init__(self, cipher: ARIA, iv: bytes, key_size_bytes: int):
        self.cipher = cipher
        self.iv = iv  # Initialization vector
        self.key_size_bytes = key_size_bytes

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data using CBC mode."""
        blocks = [plaintext[i:i + self.key_size_bytes] for i in range(0, len(plaintext), self.key_size_bytes)]
        ciphertext = b""
        previous = self.iv

        for block in blocks:
            if len(block) < self.key_size_bytes:  # Padding
                block = block.ljust(self.key_size_bytes, b'\x00')
            encrypted_block = self.cipher.encrypt(xor_bytes(block, previous))
            ciphertext += encrypted_block
            previous = encrypted_block

        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data using CBC mode."""
        blocks = [ciphertext[i:i + self.key_size_bytes] for i in range(0, len(ciphertext), self.key_size_bytes)]
        plaintext = b""
        previous = self.iv

        for block in blocks:
            decrypted_block = xor_bytes(self.cipher.decrypt(block), previous)
            plaintext += decrypted_block
            previous = block

        return plaintext.rstrip(b'\x00')  # Remove padding