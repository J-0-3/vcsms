from .cryptographylib import rsa, sha256, utils, dhke


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


def gen_signed_diffie_hellman(dh_private_key: int, rsa_private_key: tuple, dh_group: tuple, message_id: int = 0) -> tuple[int,bytes]:
    dh_public_key = dhke.generate_public_key(dh_private_key, dh_group)
    dh_public_key_hex = hex(dh_public_key)[2:].encode()
    message_id_hex = hex(message_id)[2:].encode()
    if message_id:
        dh_signature = sign(dh_public_key_hex + b':' + message_id_hex, rsa_private_key)
    else:
        dh_signature = sign(dh_public_key_hex, rsa_private_key)
    return dh_public_key, dh_signature
