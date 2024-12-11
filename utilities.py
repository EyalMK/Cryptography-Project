# Helper functions
from enum import Enum


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte arrays."""
    return bytes(i ^ j for i, j in zip(a, b))


def rotate_bytes(data: bytes, shift: int) -> bytes:
    """Circularly rotate bytes by the given shift."""
    return data[shift:] + data[:shift]


def text_to_hex(text):
    """
    Converts a given text into a list of hexadecimal values as integers.

    :param text: The string to convert.
    :return: A list of hexadecimal values as integers.
    """
    hex_strings = [hex(ord(char)) for char in text]
    return [int(hex_str, 16) for hex_str in hex_strings]


def hex_to_text(hex_list):
    """
    Converts a list of hexadecimal values (e.g., [0x48, 0x65]) into a string.

    :param hex_list: A list of hexadecimal values as integers (e.g., [0x48, 0x65]).
    :return: The translated string.
    """
    return ''.join(chr(hex_value) for hex_value in hex_list)
