from aria_cipher import ARIACipher
from utilities import xor_bytes

# Todo: Is it okay to pad the last block with zeros?


class CBCMode:
    def __init__(self, cipher: ARIACipher, iv: bytes, key_size_bytes: int):
        self.cipher = cipher
        self.iv = iv
        self.key_size_bytes = key_size_bytes

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data using CBC mode."""
        blocks = [plaintext[i:i + self.key_size_bytes] for i in range(0, len(plaintext), self.key_size_bytes)]
        ciphertext = b""
        previous = self.iv

        print("========================= Encrypting =========================")
        for block in blocks:
            if len(block) < self.key_size_bytes:  # Add padding
                block = block.ljust(self.key_size_bytes, b'\x00')
            encrypted_block = self.cipher.encrypt_block(xor_bytes(block, previous))
            ciphertext += encrypted_block
            previous = encrypted_block

        print("\nE-mail successfully encrypted using ARIA cipher in CBC mode.")
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data using CBC mode."""
        blocks = [ciphertext[i:i + self.key_size_bytes] for i in range(0, len(ciphertext), self.key_size_bytes)]
        plaintext = b""
        previous = self.iv

        print("========================= Decrypting =========================")
        for block in blocks:
            decrypted_block = xor_bytes(self.cipher.decrypt_block(block), previous)
            plaintext += decrypted_block
            previous = block

        print("\nE-mail successfully decrypted using ARIA cipher in CBC mode.")
        return plaintext.rstrip(b'\x00')  # Remove padding
