from aria_cipher import ARIACipher
from cbc import CBCMode
from ecdh import ECDH
from elgamal import ELGamal
from config import KEY_SIZE, debug_mode


class Recipient:
    def __init__(self):
        self.private_key, self.public_key = ECDH.generate_key_pair()
        if debug_mode:
            print("\n======================= Recipient ========================")
            print(f"Recipient Private Key: {self.private_key}")
            print(f"Recipient Public Key: {self.public_key}")

    def get_public_key(self):
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
            sender_public_key = sender_object["sender_public_key"]
            signature = sender_object["signature"]
            elgamal_public_key = sender_object["elgamal_public_key"]
            encrypted_email = sender_object["encrypted_email"]

            self.__verify_signature(sender_public_key, signature, elgamal_public_key)

            derived_key = self.__derive_key_from_shared_secret(sender_public_key)

            # Decrypt the email
            recipient_cipher = ARIACipher(derived_key)
            recipient_cbc = CBCMode(recipient_cipher, KEY_SIZE)
            decrypted_email = recipient_cbc.decrypt(encrypted_email)

            print(f"\nDecrypted Email: {decrypted_email.decode()}")
        except Exception as e:
            print(f"Error - Could not decrypt email: {e}")
