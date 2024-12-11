import os
from aria_cipher import ARIACipher
from cbc import CBCMode
from ecdh import generate_key_pair, compute_shared_secret, derive_key
from elgamal import generate_elgamal_key_pair, sign_message, verify_signature


# Main email encryption/decryption
def main():
    key_size_bits = 128  # Key size in bits
    key_size_bytes = key_size_bits // 8

    # Generate ECDH key pairs
    sender_private_key, sender_public_key = generate_key_pair()
    recipient_private_key, recipient_public_key = generate_key_pair()

    # Sender signs their public key with ElGamal
    elgamal_private_key, elgamal_public_key = generate_elgamal_key_pair()
    public_key_message = str(sender_public_key).encode()
    signature = sign_message(public_key_message, elgamal_private_key)

    # Sender computes shared secret
    shared_secret = compute_shared_secret(sender_private_key, recipient_public_key)
    # Derive key from shared secret
    derived_key = derive_key(shared_secret, length=key_size_bytes)  # 128-bit key

    # Input: Email content
    email_content = input("Enter the email content to encrypt: ").encode()

    # IV setup
    iv = os.urandom(key_size_bytes)  # Generate a random IV

    print(f"Generated Initialization Vector: {iv.hex()}")

    # Initialize ARIA and CBC
    aria_cipher = ARIACipher(derived_key)
    cbc_cipher = CBCMode(aria_cipher, iv, key_size_bytes)

    # Encrypt the email
    encrypted_email = cbc_cipher.encrypt(email_content)

    # Send encrypted email and public key
    print("\n================================================================")
    print("\nSending:")
    print(f"Encrypted Email: {encrypted_email.hex()}")
    print(f"Sender Public Key: {sender_public_key}")
    print(f"Signature: {signature}")
    print(f"ElGamal Public Key: {elgamal_public_key}")

    # Recipient verifies signature
    print("\n====================== Verifying Signature =====================")
    is_valid = verify_signature(public_key_message, signature, elgamal_public_key)
    if not is_valid:
        raise ValueError("Signature verification failed!")

    print("\nSignature verified!")

    # Recipient computes shared secret
    recipient_shared_secret = compute_shared_secret(recipient_private_key, sender_public_key)
    recipient_derived_key = derive_key(recipient_shared_secret, length=key_size_bytes)

    # Decrypt the email
    recipient_cipher = ARIACipher(recipient_derived_key)
    recipient_cbc = CBCMode(recipient_cipher, iv, key_size_bytes)
    decrypted_email = recipient_cbc.decrypt(encrypted_email)
    print(f"\nDecrypted Email: {decrypted_email.decode()}")


if __name__ == "__main__":
    main()
