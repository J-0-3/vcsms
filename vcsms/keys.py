"""Defines a number of methods for interacting with cryptographic keys."""

from .cryptographylib import rsa, sha256


def write_key(key: tuple[int, int], out: str):
    """Write an RSA key out to a specified file.

    Args:
        key (tuple[int, int]): The RSA key in the form (exponent, modulus)  
        out (str): The file path to write the key to. 
    """
    with open(out, 'w') as f:
        f.write(f"{hex(key[0])[2:]}:{hex(key[1])[2:]}")


def generate_keys(pub_out: str, priv_out: str) -> tuple[tuple[int, int], tuple[int, int]]:
    """Generate an RSA public/private key pair and write them out to files.

    Args:
        pub_out (str): The file path to write the public key to.  
        priv_out (str): The file path to write the private key to. 

    Returns:
        tuple[tuple[int, int], tuple[int, int]]: The public and private keys in the form (exponent, modulus) 
    """
    pub, priv = rsa.gen_keypair(2048)
    write_key(pub, pub_out)
    write_key(priv, priv_out)
    return pub, priv


def load_key(path: str) -> tuple[int, int]:
    """Load an RSA key from a specified file path.

    Args:
        path (str): The filepath where the RSA key can be found. 

    Returns:
        tuple[int, int]: The RSA key in the form (exponent, modulus) 
    """
    with open(path, 'r') as f:
        exp, mod = f.read().split(':')
        key = (int(exp, 16), int(mod, 16))
    return key


def fingerprint(key: tuple[int, int]) -> str:
    """Calculate a SHA256 fingerprint of a given RSA key.

    Args:
        key (tuple[int, int]): The RSA key in the form (exponent, modulus)  

    Returns:
        str: The SHA256 fingerprint of the key in hex format. 
    """
    hash = sha256.hash(hex(key[0])[2:].encode() + hex(key[1])[2:].encode())
    hex_fp = hex(hash)[2:]
    while len(hex_fp) < 64:
        hex_fp = "0" + hex_fp
    return hex_fp
