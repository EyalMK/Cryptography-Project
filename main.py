import config
from email_recipient import Recipient
from email_sender import Sender


def main():
    print("Email Encryption/Decryption using ECDH, ElGamal, ARIA, and CBC")
    print("===============================================================")
    print("Would you like to use debug mode? (y/n)")
    config.debug_mode = input().lower() == 'y'

    if config.debug_mode:
        print("Debug mode enabled!")
        print("Key size (bytes):", config.KEY_SIZE)

    sender_object = None
    recipient = None
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

            sender = Sender()
            recipient = Recipient()
            sender_object = sender.encrypt_email(content=email_content, recipient=recipient)
        elif mode == '2':
            print("\n======================= Decrypt Email ========================")
            if recipient is not None and sender_object is not None:
                recipient.decrypt_email(sender_object)

                # Reset the sender object and recipient
                sender_object = None
                recipient = None
            else:
                print("No email to decrypt!")
        elif mode == '3':
            print("Exiting...")
            break
        else:
            print("Invalid mode!")


if __name__ == "__main__":
    main()
