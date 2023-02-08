"""Defines a number of methods for interacting with cryptographic keys."""

from .cryptography import rsa, sha256, aes256
import random


def write_key(key: tuple[int, int], out: str, encryption_key: int = 0):
    """Write an RSA key out to a specified file.

    Args:
        key (tuple[int, int]): The RSA key in the form (exponent, modulus)
        out (str): The file path to write the key to.
        encryption_key (int) (optional): Key used to encrypt the RSA key
            in storage. 0 = no encryption. (Defaults to 0)
    """
    with open(out, 'w') as f:
        serialized_key = f"{hex(key[0])[2:]}:{hex(key[1])[2:]}"
        if encryption_key:
            initialisation_vector = random.randrange(1, 2**128)
            encrypted_key = aes256.encrypt_cbc(serialized_key.encode('utf-8'), encryption_key, initialisation_vector)
            f.write(f"{initialisation_vector}:{encrypted_key.hex()}")
        else:
            f.write(f"{hex(key[0])[2:]}:{hex(key[1])[2:]}")


def generate_keys(pub_out: str, priv_out: str, encryption_key: int) -> tuple[tuple[int, int], tuple[int, int]]:
    """Generate an RSA public/private key pair and write them out to files.

    Args:
        pub_out (str): The file path to write the public key to.
        priv_out (str): The file path to write the private key to.
        encryption_key (int): Key used to encrypt the private key in storage.

    Returns:
        tuple[tuple[int, int], tuple[int, int]]: The public and private keys in the form (exponent, modulus)
    """
    pub, priv = rsa.gen_keypair(2048)
    write_key(pub, pub_out)
    write_key(priv, priv_out, encryption_key)
    return pub, priv


def load_key(path: str, encryption_key: int = 0) -> tuple[int, int]:
    """Load an RSA key from a specified file path.

    Args:
        path (str): The filepath where the RSA key can be found.

    Returns:
        tuple[int, int]: The RSA key in the form (exponent, modulus)
    """
    with open(path, 'r') as f:
        if encryption_key:
            initialisation_vector, ciphertext_hex = f.read().split(':')
            initialisation_vector = int(initialisation_vector)
            ciphertext = bytes.fromhex(ciphertext_hex)
            serialized_key = aes256.decrypt_cbc(ciphertext, encryption_key, initialisation_vector).decode('utf-8')
        else:
            serialized_key = f.read()
        exp, mod = serialized_key.split(':')
        key = (int(exp, 16), int(mod, 16))
    return key


def fingerprint(key: tuple[int, int], fp_length: int = 24) -> str:
    """Calculate a SHA256 fingerprint of a given RSA key.

    Args:
        key (tuple[int, int]): The RSA key in the form (exponent, modulus)  
        fp_length (int): The number of characters to truncate the fingerprint to. 
            (max 64) (Default 24).

    Returns:
        str: The SHA256 fingerprint of the key in hex format. 
    """
    if fp_length > 64 or fp_length <= 1:
        raise ValueError(f"Fingerprint length must not be greater than 64 or less than 1. ({fp_length}) provided.")
    hash = sha256.hash(hex(key[0])[2:].encode() + hex(key[1])[2:].encode())
    hex_fp = hex(hash)[2:fp_length + 2]
    while len(hex_fp) < fp_length:
        hex_fp = "0" + hex_fp
    return hex_fp
