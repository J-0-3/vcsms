import time
from .cryptography import rsa, sha256, dhke
from .cryptography.exceptions import DecryptionFailureException

def sign(data: bytes, priv_key: tuple, ttl: int = 60) -> bytes:
    """Sign some data using a given RSA private key.

    Args:
        data (bytes): The data to sign.
        priv_key (tuple[int, int]): The signer's RSA private key
        ttl (int, optional): The Time-To-Live in seconds (Default: 60)

    Returns:
        bytes: The (detached) signature
    """
    timestamp = time.time_ns().to_bytes(8, 'big')
    time_to_live = (ttl*1000000000).to_bytes(8, 'big')
    data_hash = sha256.hash(data).to_bytes(32, 'big')
    sig_data = timestamp + time_to_live + data_hash
    signature = rsa.encrypt(sig_data, *priv_key)
    return signature.hex().encode('utf-8')


def verify(data: bytes, signature: bytes, pub_key: tuple) -> bool:
    """Verify that a signature is valid for a piece of data with a given public key.

    Args:
        data (bytes): The data that has been signed.
        signature (bytes): The signature to verify.
        pub_key (tuple[int, int]): The public key of the sender.

    Returns:
        bool: Whether the signature is valid
    """
    data_hash = sha256.hash(data)
    try:
        signature_bytes = bytes.fromhex(signature.decode('utf-8'))
    except ValueError:
        return False
    try:
        signature_data = rsa.decrypt(signature_bytes, *pub_key)
    except DecryptionFailureException:
        return False
    timestamp = int.from_bytes(signature_data[0:8], 'big')
    ttl = int.from_bytes(signature_data[8:16], 'big')
    signature_hash = int.from_bytes(signature_data[16:], 'big')
    time_valid = time.time_ns() - timestamp <= ttl or ttl == 0
    if data_hash == signature_hash and time_valid:
        return True
    return False


def gen_signed_dh(dh_private_key: int, rsa_private_key: tuple,
                              dh_group: tuple, message_id: int = 0) -> tuple:
    """Generate a signed diffie hellman public key.

    Args:
        dh_private_key (int): The diffie hellman private key for which to calculate a public key.
        rsa_private_key (tuple[int, int]): The RSA private key to use to sign the key in the form.
        dh_group (tuple[int, int]): The diffie hellman group to use in the form (generator, modulus).
        message_id (int, optional): An optional value to add to the public key 
            when it is signed to tie it to one specific message index.
            (Default 0).

    Returns:
        tuple[int, bytes]: The diffie hellman public key and signature
    """
    dh_public_key = dhke.generate_public_key(dh_private_key, dh_group)
    dh_public_key_hex = hex(dh_public_key)[2:].encode()
    message_id_hex = hex(message_id)[2:].encode()
    if message_id:
        dh_signature = sign(dh_public_key_hex + b':' + message_id_hex, rsa_private_key)
    else:
        dh_signature = sign(dh_public_key_hex, rsa_private_key)
    return dh_public_key, dh_signature

def verify_signed_dh(dh_public_key: int, signature: bytes, 
                                 rsa_public_key: tuple[int, int], message_id: int = 0) -> bool:
    """Verify whether a diffie hellman public key was signed correctly. 

    Args:
        dh_public_key (int): The public key to verify.
        rsa_public_key (tuple[int, int]): The RSA public key of the sender.
        message_id (int, optional): Optional value added to the public key. 
            (Default 0).

    Returns:
        bool: Whether or not the key was signed correctly.
    """
    dh_public_key_hex = hex(dh_public_key)[2:].encode()
    message_id_hex = hex(message_id)[2:].encode()
    if message_id:
        sig_data = dh_public_key_hex + b':' + message_id_hex
    else:
        sig_data = dh_public_key_hex
    return verify(sig_data, signature, rsa_public_key)
