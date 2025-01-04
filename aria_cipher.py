# https://datatracker.ietf.org/doc/html/rfc5794 - Tested using the test data for 128-bit key.
import os

from globals import BLOCK_SIZE, KEY_SIZE
from utilities import rotate_and_xor, invert_s_box, print_block

# ARIA - Globals
FEISTEL_ROUNDS = 3


class ARIACipher:

    def __init__(self, key=None):
        """Initialize ARIA Cipher with a given key or generate a random 16-byte key."""
        self.key = key or os.urandom(KEY_SIZE)
        self.round_keys_encrypt = []
        self.round_keys_decrypt = []

    @staticmethod
    def __s1_box(pos=None):
        s1 = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
              [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
              [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
              [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
              [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
              [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
              [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
              [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
              [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
              [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
              [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
              [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
              [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
              [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
              [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
              [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]
        if pos is None:
            return s1
        return s1[pos // BLOCK_SIZE][pos % BLOCK_SIZE]

    @staticmethod
    def __s2_box(pos=None):
        s2 = [[0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1],
              [0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1],
              [0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb],
              [0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb],
              [0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd],
              [0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53],
              [0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1],
              [0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40],
              [0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc],
              [0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5],
              [0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43],
              [0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8],
              [0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda],
              [0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c],
              [0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d],
              [0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81]]
        if pos is None:
            return s2
        return s2[pos // BLOCK_SIZE][pos % BLOCK_SIZE]

    def __inversed_s1(self, pos):
        return invert_s_box(self.__s1_box())[pos // BLOCK_SIZE][pos % BLOCK_SIZE]

    def __inversed_s2(self, pos):
        return invert_s_box(self.__s2_box())[pos // BLOCK_SIZE][pos % BLOCK_SIZE]

    @staticmethod
    def __diffusion_layer(i):
        """
            Input: Byte array 'i' of size 16
            Output: Byte array of size 16 which is diffusion of 'i'
            Diffuse 'i' and return it
            """
        o = [0] * BLOCK_SIZE
        t = i[3] ^ i[4] ^ i[9] ^ i[14]
        o[0] = i[6] ^ i[8] ^ i[13] ^ t
        o[5] = i[1] ^ i[10] ^ i[15] ^ t
        o[11] = i[2] ^ i[7] ^ i[12] ^ t
        o[14] = i[0] ^ i[5] ^ i[11] ^ t
        t = i[2] ^ i[5] ^ i[8] ^ i[15]
        o[1] = i[7] ^ i[9] ^ i[12] ^ t
        o[4] = i[0] ^ i[11] ^ i[14] ^ t
        o[10] = i[3] ^ i[6] ^ i[13] ^ t
        o[15] = i[1] ^ i[4] ^ i[10] ^ t
        t = i[1] ^ i[6] ^ i[11] ^ i[12]
        o[2] = i[4] ^ i[10] ^ i[15] ^ t
        o[7] = i[3] ^ i[8] ^ i[13] ^ t
        o[9] = i[0] ^ i[5] ^ i[14] ^ t
        o[12] = i[2] ^ i[7] ^ i[9] ^ t
        t = i[0] ^ i[7] ^ i[10] ^ i[13]
        o[3] = i[5] ^ i[11] ^ i[14] ^ t
        o[6] = i[2] ^ i[9] ^ i[12] ^ t
        o[8] = i[1] ^ i[4] ^ i[15] ^ t
        o[13] = i[3] ^ i[6] ^ i[8] ^ t
        return o

    def __encryption_key_expansion(self):
        """
            Input: Byte array 'key' of size 16
            Output: 13 size array of byte arrays each of size 16
            Generate encryption round keys
            """
        ck = [[0x51, 0x7c, 0xc1, 0xb7, 0x27, 0x22, 0x0a, 0x94, 0xfe, 0x13, 0xab, 0xe8, 0xfa, 0x9a, 0x6e, 0xe0],
              [0x6d, 0xb1, 0x4a, 0xcc, 0x9e, 0x21, 0xc8, 0x20, 0xff, 0x28, 0xb1, 0xd5, 0xef, 0x5d, 0xe2, 0xb0],
              [0xdb, 0x92, 0x37, 0x1d, 0x21, 0x26, 0xe9, 0x70, 0x03, 0x24, 0x97, 0x75, 0x04, 0xe8, 0xc9, 0x0e]]
        idx = len(self.key) // 8 - 2
        t = list()
        for i in range(4):
            t.append(self.__s1_box(ck[idx][4 * i] ^ self.key[4 * i]))
            t.append(self.__s2_box(ck[idx][4 * i + 1] ^ self.key[4 * i + 1]))
            t.append(self.__inversed_s1(ck[idx][4 * i + 2] ^ self.key[4 * i + 2]))
            t.append(self.__inversed_s2(ck[idx][4 * i + 3] ^ self.key[4 * i + 3]))
        w_1 = self.__diffusion_layer(t)

        idx = 0 if idx == 2 else idx + 1
        for i in range(4):
            t[4 * i] = self.__inversed_s1(ck[idx][4 * i] ^ w_1[4 * i])
            t[4 * i + 1] = self.__inversed_s2(ck[idx][4 * i + 1] ^ w_1[4 * i + 1])
            t[4 * i + 2] = self.__s1_box(ck[idx][4 * i + 2] ^ w_1[4 * i + 2])
            t[4 * i + 3] = self.__s2_box(ck[idx][4 * i + 3] ^ w_1[4 * i + 3])
        w_2 = self.__diffusion_layer(t)
        for i in range(BLOCK_SIZE):
            w_2[i] ^= self.key[i]

        idx = 0 if idx == 2 else idx + 1
        for i in range(4):
            t[4 * i] = self.__s1_box(ck[idx][4 * i] ^ w_2[4 * i])
            t[4 * i + 1] = self.__s2_box(ck[idx][4 * i + 1] ^ w_2[4 * i + 1])
            t[4 * i + 2] = self.__inversed_s1(ck[idx][4 * i + 2] ^ w_2[4 * i + 2])
            t[4 * i + 3] = self.__inversed_s2(ck[idx][4 * i + 3] ^ w_2[4 * i + 3])
        w_3 = self.__diffusion_layer(t)
        for i in range(BLOCK_SIZE):
            w_3[i] ^= w_1[i]

        w_0 = self.key[:BLOCK_SIZE]
        round_keys = list(list())
        for i in range(FEISTEL_ROUNDS):
            round_keys.append(rotate_and_xor(w_0, 0, [0] * BLOCK_SIZE))
            round_keys[4 * i] = rotate_and_xor(w_1, i * i * 12 + 19, round_keys[4 * i])
            round_keys.append(rotate_and_xor(w_1, 0, [0] * BLOCK_SIZE))
            round_keys[4 * i + 1] = rotate_and_xor(w_2, i * i * 12 + 19, round_keys[4 * i + 1])
            round_keys.append(rotate_and_xor(w_2, 0, [0] * BLOCK_SIZE))
            round_keys[4 * i + 2] = rotate_and_xor(w_3, i * i * 12 + 19, round_keys[4 * i + 2])
            round_keys.append(rotate_and_xor(w_3, 0, [0] * BLOCK_SIZE))
            round_keys[4 * i + 3] = rotate_and_xor(w_0, i * i * 12 + 19, round_keys[4 * i + 3])
        round_keys.append(rotate_and_xor(w_0, 0, [0] * BLOCK_SIZE))
        round_keys[12] = rotate_and_xor(w_1, 97, round_keys[12])
        return round_keys

    def __decryption_key_expansion(self):
        """
            Input: Byte array 'key' of size 16/24/32
            Output: 13/15/17 size array of byte arrays each of size 16
            Generate decryption round keys
            """
        rounds = len(self.key) // 4 + 8
        round_keys = self.__encryption_key_expansion()
        for i in range(BLOCK_SIZE):
            round_keys[0][i], round_keys[rounds][i] = round_keys[rounds][i], round_keys[0][i]
        for i in range(1, rounds // 2 + 1):
            t = self.__diffusion_layer(round_keys[i])
            round_keys[i] = self.__diffusion_layer(round_keys[rounds - i])
            for j in range(BLOCK_SIZE):
                round_keys[rounds - i][j] = t[j]
        return round_keys

    def __cipher(self, plain, round_keys, print_rounds=False):
        """
            Input: Byte array 'plain' of size 16, 13/15/17 size array 'round_keys' of byte arrays each of size 16,
                   boolean 'print_rounds'
            Output: Byte array of size 16, which is result of running SPN using 'plain' and 'round_keys'
            Run SPN using 'plain' and 'round_keys' then return the result.
            Since encryption/decryption of ARIA uses same SPN structure, it depends on round_keys to determine
            whether process is encryption or decryption.
            """
        c = plain[:]
        t = [0] * BLOCK_SIZE
        rounds = len(round_keys) - 1
        i = 0
        for i in range(rounds // 2):
            # Odd case
            for j in range(4):  # AddRoundKey and SubstLayer
                t[4 * j] = self.__s1_box(round_keys[2 * i][4 * j] ^ c[4 * j])
                t[4 * j + 1] = self.__s2_box(round_keys[2 * i][4 * j + 1] ^ c[4 * j + 1])
                t[4 * j + 2] = self.__inversed_s1(round_keys[2 * i][4 * j + 2] ^ c[4 * j + 2])
                t[4 * j + 3] = self.__inversed_s2(round_keys[2 * i][4 * j + 3] ^ c[4 * j + 3])
            c = self.__diffusion_layer(t)  # DiffLayer
            if print_rounds:
                print_block(c, 2 * i + 1)
            # Even case
            for j in range(4):  # AddRoundKey and SubstLayer
                t[4 * j] = self.__inversed_s1(round_keys[2 * i + 1][4 * j] ^ c[4 * j])
                t[4 * j + 1] = self.__inversed_s2(round_keys[2 * i + 1][4 * j + 1] ^ c[4 * j + 1])
                t[4 * j + 2] = self.__s1_box(round_keys[2 * i + 1][4 * j + 2] ^ c[4 * j + 2])
                t[4 * j + 3] = self.__s2_box(round_keys[2 * i + 1][4 * j + 3] ^ c[4 * j + 3])
            c = self.__diffusion_layer(t)  # DiffLayer
            if 2 * i + 1 != rounds - 1 and print_rounds:
                print_block(c, 2 * i + 2)
        t = self.__diffusion_layer(c)
        for j in range(BLOCK_SIZE):
            c[j] = round_keys[len(round_keys) - 1][j] ^ t[j]
        print_block(c, 2 * i + 2)
        print()
        return c

    def print_keys(self):
        """Print the encryption and decryption keys."""
        print("Encryption Round Keys:")
        for i, key in enumerate(self.round_keys_encrypt):
            print_block(key, i + 1)

        print("Decryption Round Keys:")
        for i, key in enumerate(self.round_keys_decrypt):
            print_block(key, i + 1)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"Block must be exactly {BLOCK_SIZE} bytes")
        if not self.round_keys_encrypt:
            self.round_keys_encrypt = self.__encryption_key_expansion()

        plain_list = list(block)
        cipher_list = self.__cipher(plain_list, self.round_keys_encrypt, print_rounds=True)
        return bytes(cipher_list)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"Block must be exactly {BLOCK_SIZE} bytes")
        if not self.round_keys_decrypt:
            self.round_keys_decrypt = self.__decryption_key_expansion()

        cipher_list = list(block)
        plain_list = self.__cipher(cipher_list, self.round_keys_decrypt, print_rounds=True)
        return bytes(plain_list)
