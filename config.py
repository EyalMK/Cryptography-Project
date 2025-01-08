BLOCK_SIZE = 16  # 128 bits
KEY_SIZE = 16  # 128 bits
_debug_mode = False
encryption_file_name = "encrypted_email.txt"
decryption_file_name = "decrypted_email.txt"


def set_debug_mode(value: bool):
    global _debug_mode
    _debug_mode = value


def get_debug_mode() -> bool:
    return _debug_mode
