import os

import config
from aria_cipher import ARIACipher
from cbc import CBCMode
from ecdh import ECDH
from elgamal import ELGamal
from config import KEY_SIZE, get_debug_mode
from email_recipient import Recipient
from utilities import exportToFile


class Sender:
    def __init__(self):
        self.private_key, self.public_key = ECDH.generate_key_pair()
        self.elgamal_private_key, self.elgamal_public_key = ELGamal.generate_elgamal_key_pair()
        if config.get_debug_mode():
            print("\n======================= Sender ========================")
            print(f"Sender Private Key: {self.private_key}")
            print(f"Sender Public Key: {self.public_key}")
            print("\n======================= ElGamal ========================")
            print(f"ElGamal Private Key: {self.elgamal_private_key}")
            print(f"ElGamal Public Key: {self.elgamal_public_key}")

    def get_public_keys(self):
        return self.public_key, self.elgamal_public_key

    def __get_digital_signature(self):
        public_key_message = str(self.public_key).encode()
        signature = ELGamal.sign_message(public_key_message, self.elgamal_private_key)

        if config.get_debug_mode():
            print(f"Signature: {signature}")

        return signature

    def __derive_key_from_shared_secret(self, recipient_public_key):
        # Sender computes shared secret
        shared_secret = ECDH.compute_shared_secret(self.private_key, recipient_public_key)
        if config.get_debug_mode():
            print(f"\nShared Secret: {shared_secret}")

        # Derive key from shared secret
        derived_key = ECDH.derive_key(shared_secret, length=KEY_SIZE)
        if config.get_debug_mode():
            print(f"Derived Key: {derived_key.hex()}")

        return derived_key

    def encrypt_email(self, content, recipient: Recipient):
        # Get Recipient Public Key
        recipient_public_key = recipient.exchange_public_keys(self.public_key, self.elgamal_public_key)
        if config.get_debug_mode():
            print(f"Recipient Public Key: {recipient_public_key}")

        # IV setup
        iv = os.urandom(KEY_SIZE)  # Generate a random IV
        if config.get_debug_mode():
            print(f"Generated Initialization Vector: {iv.hex()}")

        signature = self.__get_digital_signature()

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
        print(f"Signature: {signature}")

        package = {
            "encrypted_email": encrypted_email.hex(),
            "signature": signature
        }

        exportToFile(config.encryption_file_name, package)

        return package
