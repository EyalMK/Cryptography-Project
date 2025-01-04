from aria_cipher import ARIACipher
from utilities import xor_bytes


class CBCMode:
    """
        Implements the Cipher Block Chaining (CBC) mode for block ciphers.
        Uses an initialization vector (IV) to randomize the encryption process,
        ensuring that identical plaintexts produce different ciphertexts.
    """
    def __init__(self, cipher: ARIACipher, key_size_bytes: int, iv: bytes | None = None):
        """
            Initializes the CBCMode instance.

            Args:
                cipher: The block cipher used (e.g., ARIA cipher).
                iv (bytes): The initialization vector (random and unique for each encryption).
                key_size_bytes (int): The size of the encryption key in bytes.

            Importance of IV:
            - The IV ensures that the same plaintext encrypted multiple times produces different ciphertexts.
            - According to our lectures, CBC mode requires a unique IV for every encryption to prevent patterns.
        """
        self.cipher = cipher
        self.key_size_bytes = key_size_bytes
        self.iv = iv

    def encrypt(self, plaintext: bytes) -> bytes:
        """
            Encrypts the plaintext using the CBC mode of operation.

            Args:
                plaintext (bytes): The plaintext data to be encrypted.

            Returns:
                bytes: The IV prepended to the ciphertext.

            Process:
            1. Divide plaintext into blocks of key_size_bytes.
            2. XOR the first block with the IV before encrypting.
            3. Use each ciphertext block as the IV for the next plaintext block.
            4. Prepend the IV to the final ciphertext.

            Why this matters:
            - XORing the plaintext with the previous ciphertext block ensures
              dependency between blocks, as described in our lectures.
        """
        blocks = [plaintext[i:i + self.key_size_bytes] for i in range(0, len(plaintext), self.key_size_bytes)]
        ciphertext = b""
        previous = self.iv

        print("========================= Encrypting =========================")
        for block in blocks:
            # Pad the last block if it's smaller than the block size
            if len(block) < self.key_size_bytes:
                block = block.ljust(self.key_size_bytes, b'\x00')  # Padding with null bytes

            # XOR block with the previous ciphertext (or IV for the first block)
            xor_result = xor_bytes(block, previous)

            encrypted_block = self.cipher.encrypt_block(xor_result)
            ciphertext += encrypted_block

            # Update the 'previous' to the current encrypted block
            previous = encrypted_block

        print("\nE-mail successfully encrypted using ARIA cipher in CBC mode.")
        # Common practice - prepend the IV to the ciphertext to ensure it's available for decryption
        return self.iv + ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
            Decrypts the ciphertext using the CBC mode of operation.

            Args:
                ciphertext (bytes): The ciphertext to be decrypted.

            Returns:
                bytes: The original plaintext.

            Process:
            1. Extract the IV from the beginning of the ciphertext.
            2. Decrypt each block, XORing it with the previous ciphertext block.
            3. Remove padding from the final plaintext.

            Security Considerations:
            - The IV must be extracted correctly to ensure proper decryption.
            - Padding ensures data integrity when plaintext is not an exact multiple of the block size.
        """
        # Extract the IV from the beginning of the ciphertext
        iv = ciphertext[:self.key_size_bytes]
        ciphertext = ciphertext[self.key_size_bytes:]

        # Split remaining ciphertext into blocks
        blocks = [ciphertext[i:i + self.key_size_bytes] for i in range(0, len(ciphertext), self.key_size_bytes)]
        plaintext = b""
        previous = iv

        print("========================= Decrypting =========================")
        for block in blocks:
            decrypted_block = self.cipher.decrypt_block(block)

            # XOR decrypted block with the previous ciphertext (or IV for the first block)
            plaintext_block = xor_bytes(decrypted_block, previous)
            plaintext += plaintext_block

            # Update the 'previous' to the current ciphertext block
            previous = block

        print("\nE-mail successfully decrypted using ARIA cipher in CBC mode.")
        # Remove padding (if any) from the plaintext:
        # 'rstrip' removes \x00 at the end of the string but keeps any nulls in the middle.
        return plaintext.rstrip(b'\x00')
