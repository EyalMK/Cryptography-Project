import os
from aria_cipher import ARIACipher
from cbc import CBCMode


# Main email encryption/decryption
def main():
    key_size_bits = 128  # Key size in bits
    key_size_bytes = key_size_bits // 8

    # Input: Email content
    email_content = input("Enter the email content to encrypt: ").encode()

    # Key and IV setup (placeholder)
    key = os.urandom(key_size_bytes)  # Generate a random key
    iv = os.urandom(key_size_bytes)  # Generate a random IV

    print(f"Generated Key: {key.hex()}")
    print(f"Generated Initialization Vector: {iv.hex()}")

    # Initialize ARIA and CBC
    aria_cipher = ARIACipher(key)
    cbc_cipher = CBCMode(aria_cipher, iv, key_size_bytes)

    # Encrypt the email
    encrypted_email = cbc_cipher.encrypt(email_content)
    print(f"\nEncrypted Email: {encrypted_email.hex()}")

    # Decrypt the email
    decrypted_email = cbc_cipher.decrypt(encrypted_email)
    print(f"\nDecrypted Email: {decrypted_email.decode()}")


if __name__ == "__main__":
    main()
