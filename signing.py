from cryptographylib import rsa, sha256, utils
def sign(data: bytes, priv_key: tuple) -> bytes:
    hash = sha256.hash(data)
    
    signature = rsa.encrypt(hex(hash)[2:].encode(), *priv_key)
    return hex(int.from_bytes(signature, 'big'))[2:].encode()

def verify(data: bytes, signature: bytes, pub_key: tuple):
    hash = hex(sha256.hash(data))[2:].encode()
    
    sig_hash = rsa.decrypt(utils.i_to_b(int(signature, 16)), *pub_key)
    if sig_hash == hash:
        return True
    return False