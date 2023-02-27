from . import sha256
from .utils import xor_b
_IPAD = b'\x36' * 32
_OPAD = b'\x5c' * 32
def calculate(ciphertext: bytes, iv: int, key: int):
    key_bytes = key.to_bytes(32, 'big')
    iv_bytes = iv.to_bytes(16, 'big')
    inner_key = xor_b(key_bytes, _IPAD) 
    outer_key = xor_b(key_bytes, _OPAD)
    inner_hash = sha256.hash(ciphertext + iv_bytes + inner_key).to_bytes(32, 'big')
    outer_hash = sha256.hash(inner_hash + outer_key).to_bytes(32, 'big')
    return outer_hash

def verify(hmac: bytes, ciphertext: bytes, iv: int, key: int):
    if calculate(ciphertext, iv, key) == hmac:
        return True
    return False