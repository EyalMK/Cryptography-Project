import os
import globals
from aria_cipher import ARIACipher
from cbc import CBCMode
from ecdh import ECDH
from elgamal import ELGamal


# Main email encryption/decryption
def encrypt_email(key_size_bytes, content):
    # IV setup
    iv = os.urandom(key_size_bytes)  # Generate a random IV
    if globals.debug_mode:
        print(f"Generated Initialization Vector: {iv.hex()}")

    # Generate ECDH key pairs
    sender_private_key, sender_public_key = ECDH.generate_key_pair()
    recipient_private_key, recipient_public_key = ECDH.generate_key_pair()

    if globals.debug_mode:
        print("\n======================= Sender ========================")
        print(f"Sender Private Key: {sender_private_key}")
        print(f"Sender Public Key: {sender_public_key}")
        print("\n======================= Recipient ========================")
        print(f"Recipient Private Key: {recipient_private_key}")
        print(f"Recipient Public Key: {recipient_public_key}")

    # Sender signs their public key with ElGamal
    elgamal_private_key, elgamal_public_key = ELGamal.generate_elgamal_key_pair()
    if globals.debug_mode:
        print("\n======================= ElGamal ========================")
        print(f"ElGamal Private Key: {elgamal_private_key}")
        print(f"ElGamal Public Key: {elgamal_public_key}")

    public_key_message = str(sender_public_key).encode()
    signature = ELGamal.sign_message(public_key_message, elgamal_private_key)
    if globals.debug_mode:
        print(f"Signature: {signature}")

    # Sender computes shared secret
    sender_shared_secret = ECDH.compute_shared_secret(sender_private_key, recipient_public_key)
    if globals.debug_mode:
        print(f"\nShared Secret: {sender_shared_secret}")

    # Derive key from shared secret
    derived_key = ECDH.derive_key(sender_shared_secret, length=key_size_bytes)  # 128-bit key
    if globals.debug_mode:
        print(f"Derived Key: {derived_key.hex()}")

    # Initialize ARIA and CBC
    sender_aria_cipher = ARIACipher(derived_key)
    sender_cbc_cipher = CBCMode(sender_aria_cipher, key_size_bytes, iv)

    # Encrypt the email
    encrypted_email = sender_cbc_cipher.encrypt(content)

    # Send encrypted email and public key
    print("\n================================================================")
    print("Sending:")
    print(f"Encrypted Email: {encrypted_email.hex()}")
    print(f"Sender Public Key: {sender_public_key}")
    print(f"Signature: {signature}")
    print(f"ElGamal Public Key: {elgamal_public_key}")
    return {
        "encrypted_email": encrypted_email,
        "sender_public_key": sender_public_key,
        "signature": signature,
        "elgamal_public_key": elgamal_public_key,
        "recipient_private_key": recipient_private_key
    }


def decrypt_email(key_size_bytes, sender_object):
    # Recipient verifies signature
    print("\n====================== Verifying Signature =====================")
    is_valid = ELGamal.verify_signature(str(sender_object["sender_public_key"]).encode(), sender_object["signature"],
                                        sender_object["elgamal_public_key"])
    if not is_valid:
        raise ValueError("Signature verification failed!")

    print("\nSignature verified!")

    # Recipient computes shared secret
    recipient_shared_secret = ECDH.compute_shared_secret(sender_object["recipient_private_key"],
                                                         sender_object["sender_public_key"])
    if globals.debug_mode:
        print(f"\nShared Secret: {recipient_shared_secret}")
    recipient_derived_key = ECDH.derive_key(recipient_shared_secret, length=key_size_bytes)
    if globals.debug_mode:
        print(f"Derived Key: {recipient_derived_key.hex()}")

    # Decrypt the email
    recipient_cipher = ARIACipher(recipient_derived_key)
    recipient_cbc = CBCMode(recipient_cipher, key_size_bytes)
    decrypted_email = recipient_cbc.decrypt(sender_object["encrypted_email"])
    print(f"\nDecrypted Email: {decrypted_email.decode()}")


def main():
    key_size_bits = 128  # Key size in bits
    key_size_bytes = key_size_bits // 8

    print("Email Encryption/Decryption using ECDH, ElGamal, ARIA, and CBC")
    print("===============================================================")
    print("Would you like to use debug mode? (y/n)")
    globals.debug_mode = input().lower() == 'y'

    if globals.debug_mode:
        print("Debug mode enabled!")
        print("Key size (bits):", key_size_bits)
        print("Key size (bytes):", key_size_bytes)

    sender_object = None
    while True:
        print("\nSelect a mode:")
        print("1. Encrypt Email")
        print("2. Decrypt Email")
        print("3. Exit")
        mode = input()

        if mode == '1':
            print("\n======================= Encrypt Email ========================")
            # Input: Email content
            email_content = input("Enter the email content to encrypt: ").encode()
            sender_object = encrypt_email(key_size_bytes, content=email_content)
        elif mode == '2':
            print("\n======================= Decrypt Email ========================")
            if sender_object is not None:
                decrypt_email(key_size_bytes, sender_object)
                sender_object = None  # Reset
            else:
                print("No email to decrypt!")
        elif mode == '3':
            print("Exiting...")
            break
        else:
            print("Invalid mode!")


if __name__ == "__main__":
    main()
