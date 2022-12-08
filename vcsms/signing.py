from .cryptographylib import rsa, sha256, utils, dhke
import time

def sign(data: bytes, priv_key: tuple, ttl: int = 20) -> bytes:
    timestamp = time.time_ns().to_bytes(8, 'big')
    time_to_live = (ttl*1000000000).to_bytes(8, 'big')
    hash = sha256.hash(data).to_bytes(32, 'big')
    sig_data = timestamp + time_to_live + hash
    signature = rsa.encrypt(sig_data, *priv_key)
    return signature.hex().encode('utf-8')

<<<<<<< HEAD
def sign(data: bytes, priv_key: tuple) -> bytes:
    sha_hash = sha256.hash(data)
    signature = rsa.encrypt(hex(sha_hash)[2:].encode(), *priv_key)
    return hex(int.from_bytes(signature, 'big'))[2:].encode()


def verify(data: bytes, signature: bytes, pub_key: tuple) -> bool:
    sha_hash = hex(sha256.hash(data))[2:].encode()
    sig_hash = rsa.decrypt(utils.i_to_b(int(signature, 16)), *pub_key)
    if sig_hash == sha_hash:
        return True
    return False

=======
def verify(data: bytes, signature: bytes, pub_key: tuple) -> bool:
        data_hash = sha256.hash(data)
        signature_data = rsa.decrypt(bytes.fromhex(signature.decode('utf-8')), *pub_key)
        timestamp = int.from_bytes(signature_data[0:8], 'big')
        ttl = int.from_bytes(signature_data[8:16], 'big')
        signature_hash = int.from_bytes(signature_data[16:], 'big')
        if data_hash == signature_hash and time.time_ns() - timestamp <= ttl or ttl == 0:
            return True
        return False
    
>>>>>>> b675b9ea3d90341106fef9a9de69133f34300024

def gen_signed_diffie_hellman(dh_private_key: int, rsa_private_key: tuple, dh_group: tuple, message_id: int = 0) -> tuple[int,bytes]:
    dh_public_key = dhke.generate_public_key(dh_private_key, dh_group)
    dh_public_key_hex = hex(dh_public_key)[2:].encode()
    message_id_hex = hex(message_id)[2:].encode()
    if message_id:
        dh_signature = sign(dh_public_key_hex + b':' + message_id_hex, rsa_private_key)
    else:
        dh_signature = sign(dh_public_key_hex, rsa_private_key)
    return dh_public_key, dh_signature
