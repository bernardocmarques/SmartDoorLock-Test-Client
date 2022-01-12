import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import math
import base64


def _as_c_array(byte_arr):
    hex_str = ''
    for idx, byte in enumerate(byte_arr):
        hex_str += "0x{:02x}, ".format(byte)
        bytes_per_line = 8
        if idx % bytes_per_line == bytes_per_line - 1:
            hex_str += '\n'
    return hex_str


def _pad(text, block_size):
    """
    Performs padding on the given plaintext to ensure that it is a multiple
    of the given block_size value in the parameter. Uses the PKCS7 standard
    for performing padding.
    """
    no_of_blocks = math.ceil(len(text) / float(block_size))
    pad_value = int(no_of_blocks * block_size - len(text))

    if pad_value == 0:
        return text + chr(block_size) * block_size
    else:
        return text + chr(pad_value) * pad_value


def _unpad(s):
    return s[:-ord(s[len(s) - 1:])]


class AES_Util():

    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def encrypt(self, plain_str):
        iv = bytearray(os.urandom(16))
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        plain = bytearray(_pad(plain_str, 32).encode())
        enc = encryptor.update(plain) + encryptor.finalize()
        base64_enc = base64.b64encode(enc).decode()
        base64_iv = base64.b64encode(iv).decode()

        return base64_enc + " " + base64_iv

    def decrypt(self, enc_base64, iv_base64):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(base64.b64decode(iv_base64)), backend=default_backend())
        encryptor = cipher.decryptor()
        enc = base64.b64decode(enc_base64)
        dec = encryptor.update(enc) + encryptor.finalize()
        plain = _unpad(dec).decode()

        return plain
