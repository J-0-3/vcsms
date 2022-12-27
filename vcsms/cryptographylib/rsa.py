import random
from typing import Union
from . import primes
from .utils import i_to_b


def gcd_extended_euclid(a: int, b: int) -> tuple:
    """Recursively calculate the GCD of two integers a and b and also the values x and y such that ax + by = gcd (a,b).

    Args:
        a (int)
        b (int)

    Returns:
        tuple: (gcd, x, y)
    """
    if a == 0:
        return b, 0, 1
    gcd, x, y = gcd_extended_euclid(b % a, a)

    stored_x = x
    x = y - x * (b // a)
    y = stored_x

    return gcd, x, y


def calculate_keys(p: int, q: int, e: int = 65537) -> tuple:
    """Calculate the RSA public and private keys for a pair of primes p and q and an exponent e.

    Args:
        p (int): A prime number
        q (int): A prime number
        e (int, optional): The RSA exponent. Defaults to 65537.

    Returns:
        tuple: public key (public exponent, modulus), private key (private exponenet, modulus)
    """
    # p and q must be very large prime numbers
    # e must be coprime to and less than (p-1) * (q-1)

    # calculate the modulus and public key
    n = p * q
    public_key = (e, n)
    phi = (p - 1) * (q - 1)

    # Here d is the private key exponent and is chosen such that (d * e) mod phi = 1

    # This works as the extended euclidean algorithm returns d and a such that  (d * e) + (a * phi) = 1. When both
    # sides are taken modulo phi we get ((d * e) + (a * phi)) mod phi = 1 mod phi. ((d * e) + (a * phi)) mod phi can
    # be expanded to (d * e) mod phi + (a * phi) mod phi by the laws of modular arithmetic and (a * phi) mod phi must
    # always be 0 as (a * phi) is a multiple of phi. This gives (d * e) mod phi + 0 = 1 mod phi.
    # 1 mod phi = 1 therefore we are left with d such that (d * e) mod phi = 1

    gcd, d, null = gcd_extended_euclid(e, phi)
    d %= phi  # this is to eliminate the possibility of negative values for d
    if e >= phi or gcd != 1:  # e must be coprime to phi
        raise ValueError("INVALID EXPONENT.")
    private_key = (d, n)
    return public_key, private_key


def encrypt(plaintext: bytes, exponent: int, modulus: int) -> bytes:
    """Encrypt a bytestring using a given RSA key exponent and modulus.

    Args:
        plaintext (bytes): The plaintext bytestring to encrypt
        exponent (int): The RSA encryption exponent
        modulus (int): The RSA modulus

    Returns:
        int: The encrypted ciphertext
    """
    
    plaintext = int.from_bytes(plaintext, 'big')
    return i_to_b(pow(plaintext, exponent, modulus))


def decrypt(ciphertext: bytes, exponent: int, modulus: int) -> bytes:
    """Decrypt a piece of ciphertext using a given RSA key exponent and modulus. 

    Args:
        ciphertext (int): The ciphertext to decrypt
        exponent (int): The RSA decryption exponent
        modulus (int): The RSA modulus

    Returns:
        bytes: The decrypted plaintext
    """
    
    return i_to_b(pow(int.from_bytes(ciphertext, 'big'), exponent, modulus))


def gen_keypair(length: int = 2048):
    """Generate an RSA keypair with a given length modulus.

    Args:
        length (int, optional): The bit length of the RSA modulus. Defaults to 2048.

    Returns:
        tuple: (public exponent, modulus), (private exponent, modulus)
    """
    while True:
        if length % 2 != 0:
            raise ValueError("INVALID KEYLENGTH. MUST BE EVEN.")
        
        p = random.randrange(1, 2**(length//2))
        while not primes.is_prime(p):
            p = random.randrange(1, 2**(length//2))
        q = random.randrange(1, 2**(length//2))
        while not primes.is_prime(q):
            q = random.randrange(1, 2**(length//2))
    
        pub, priv = calculate_keys(p, q)
        ciphertext = encrypt(b'\xb0\x0b\x1e\x50', *pub)
        if decrypt(ciphertext, *priv) == b'\xb0\x0b\x1e\x50':
            return pub,priv
