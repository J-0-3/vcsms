import sys
sys.path.append('../..')
from vcsms.cryptography.aes256 import encrypt_cbc as enc, decrypt_cbc as dec
from vcsms.cryptography.exceptions import DecryptionFailureException as fail
import random

class PaddingOracle:
    def __init__(self):
        self.key = random.randrange(2, 2**256)
    def encrypt(self, data: bytes):
        iv = random.randrange(1, 2**128)
        return iv, enc(data, self.key, iv, True)
    def decrypt_succeeded(self, data: bytes, iv: int):
        try:
            dec(data, self.key, iv, True)
        except fail:
            return False
        return True

def crack_block(ciphertext_block: bytes, iv: int, oracle):
    known_intermediary_values = []
    for num_pad_bytes in range(1, 17):
        calculated_iv_bytes = b''
        for value in known_intermediary_values[::-1]:
            calculated_iv_bytes += (num_pad_bytes ^ value).to_bytes()
        for byte in range(256):
            pad_iv = byte.to_bytes() + calculated_iv_bytes
            while len(pad_iv) < 16:
                pad_iv = b'\x00' + pad_iv
            if oracle.decrypt_succeeded(ciphertext_block, int.from_bytes(pad_iv)):
                known_intermediary_values.append(byte ^ num_pad_bytes)
    plaintext = b''
    iv_bytes = iv.to_bytes(16)
    for i in range(16):
        plaintext_byte = known_intermediary_values[::-1][i] ^ iv_bytes[i]
        plaintext += plaintext_byte.to_bytes()
    return plaintext

def crack_message(ciphertext: bytes, iv: int, oracle: PaddingOracle):
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    plaintext = b''
    for i, block in enumerate(blocks):
        if i == 0:
            plaintext += crack_block(block, iv, oracle)
        else:
            plaintext += crack_block(block, int.from_bytes(blocks[i-1]), oracle)
    return plaintext

if __name__ == "__main__":
    secret_holder = PaddingOracle()
    message = b"THIS IS SOME SUPER SECRET DATA"
    iv, ciphertext = secret_holder.encrypt(message)

    print(crack_message(ciphertext, iv, secret_holder))
