import os

from aria_cipher import ARIACipher
from cbc import CBCMode
from ecdh import ECDH
from elgamal import ELGamal
from config import KEY_SIZE, debug_mode
from email_recipient import Recipient


class Sender:
    def __init__(self):
        self.private_key, self.public_key = ECDH.generate_key_pair()
        if debug_mode:
            print("\n======================= Sender ========================")
            print(f"Sender Private Key: {self.private_key}")
            print(f"Sender Public Key: {self.public_key}")

    def get_public_key(self):
        return self.public_key

    def __get_digital_signature(self):
        # Sender signs their public key with ElGamal
        elgamal_private_key, elgamal_public_key = ELGamal.generate_elgamal_key_pair()
        if debug_mode:
            print("\n======================= ElGamal ========================")
            print(f"ElGamal Private Key: {elgamal_private_key}")
            print(f"ElGamal Public Key: {elgamal_public_key}")

        public_key_message = str(self.public_key).encode()
        signature = ELGamal.sign_message(public_key_message, elgamal_private_key)

        if debug_mode:
            print(f"Signature: {signature}")

        return signature, elgamal_public_key

    def __derive_key_from_shared_secret(self, recipient_public_key):
        # Sender computes shared secret
        shared_secret = ECDH.compute_shared_secret(self.private_key, recipient_public_key)
        if debug_mode:
            print(f"\nShared Secret: {shared_secret}")

        # Derive key from shared secret
        derived_key = ECDH.derive_key(shared_secret, length=KEY_SIZE)
        if debug_mode:
            print(f"Derived Key: {derived_key.hex()}")

        return derived_key

    def encrypt_email(self, content, recipient: Recipient):
        # Get Recipient Public Key
        recipient_public_key = recipient.get_public_key()

        # IV setup
        iv = os.urandom(KEY_SIZE)  # Generate a random IV
        if debug_mode:
            print(f"Generated Initialization Vector: {iv.hex()}")

        signature, elgamal_public_key = self.__get_digital_signature()

        derived_key = self.__derive_key_from_shared_secret(recipient_public_key)

        # Initialize ARIA and CBC
        aria_cipher = ARIACipher(derived_key)
        cbc_mode = CBCMode(aria_cipher, KEY_SIZE, iv)

        # Encrypt the email
        encrypted_email = cbc_mode.encrypt(content)

        # Send encrypted email and public key
        print("\n================================================================")
        print("Sending:")
        print(f"Encrypted Email: {encrypted_email.hex()}")
        print(f"Sender Public Key: {self.public_key}")
        print(f"Signature: {signature}")
        print(f"ElGamal Public Key: {elgamal_public_key}")

        return {
            "encrypted_email": encrypted_email,
            "sender_public_key": self.public_key,
            "signature": signature,
            "elgamal_public_key": elgamal_public_key
        }
