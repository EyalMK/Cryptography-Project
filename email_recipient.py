import config
from aria_cipher import ARIACipher
from cbc import CBCMode
from ecdh import ECDH
from elgamal import ELGamal
from config import KEY_SIZE, debug_mode
from utilities import exportToFile


class Recipient:
    def __init__(self):
        self.private_key, self.public_key = ECDH.generate_key_pair()
        self.sender_public_key = None
        self.elgamal_public_key = None
        if debug_mode:
            print("\n======================= Recipient ========================")
            print(f"Recipient Private Key: {self.private_key}")
            print(f"Recipient Public Key: {self.public_key}")

    def exchange_public_keys(self, sender_public_key, elgamal_public_key):
        self.sender_public_key = sender_public_key
        self.elgamal_public_key = elgamal_public_key
        if debug_mode:
            print("\n======================= Key Exchange ========================")
            print(f"Sender Public Key: {self.sender_public_key}")
            print(f"ElGamal Public Key: {self.elgamal_public_key}")
        return self.public_key

    @staticmethod
    def __verify_signature(sender_public_key, signature, elgamal_public_key):
        print("\n====================== Verifying Signature =====================")
        is_valid = ELGamal.verify_signature(str(sender_public_key).encode(), signature, elgamal_public_key)
        if not is_valid:
            raise ValueError("Signature verification failed!")
        print("\nSignature verified!")

    def __derive_key_from_shared_secret(self, sender_public_key):
        # Recipient computes shared secret
        recipient_shared_secret = ECDH.compute_shared_secret(self.private_key, sender_public_key)
        if debug_mode:
            print(f"\nShared Secret: {recipient_shared_secret}")

        # Derive key from shared secret
        derived_key = ECDH.derive_key(recipient_shared_secret, length=KEY_SIZE)
        return derived_key

    def decrypt_email(self, sender_object):
        try:
            signature = sender_object["signature"]
            encrypted_email = bytearray.fromhex(sender_object["encrypted_email"])

            self.__verify_signature(self.sender_public_key, signature, self.elgamal_public_key)

            derived_key = self.__derive_key_from_shared_secret(self.sender_public_key)

            # Decrypt the email
            recipient_cipher = ARIACipher(derived_key)
            recipient_cbc = CBCMode(recipient_cipher, KEY_SIZE)
            decrypted_email = recipient_cbc.decrypt(encrypted_email)

            print(f"\nDecrypted Email:\n{decrypted_email.decode()}")
            exportToFile(config.decryption_file_name, decrypted_email.decode())
        except Exception as e:
            print(f"Error - Could not decrypt email: {e}")
