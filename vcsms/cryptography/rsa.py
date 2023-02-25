import random
from typing import Union
from . import primes
from .utils import i_to_b
from .exceptions import DecryptionFailureException

def gcd_extended_euclid(a: int, b: int) -> tuple:
    """Recursively calculate the GCD of two integers a and b 
    and also the values s and t such that at + bs = gcd (a,b).

    Args:
        a (int)
        b (int)

    Returns:
        tuple: (gcd, s, t)
    """
    if a == 0:
        if b == 0:
            return 0, 1, 1
        return 0, 1, 0
    elif b == 0:
        return 0, 0, 1
    quotient = a // b
    remainder = a % b
    s1 = 1
    s2 = 0
    s3 = 1
    t1 = 0
    t2 = 1
    t3 = t1 - quotient * t2
    while remainder != 0:
        quotient = b // remainder
        remainder_copy = remainder
        remainder = b % remainder
        # print(f"{b} = {quotient} * {remainder_copy} + {remainder}")
        b = remainder_copy
        s1 = s2
        s2 = s3
        s3 = s1 - quotient * s2
        t1 = t2
        t2 = t3
        t3 = t1 - quotient * t2
    return b, s2, t2


def calculate_keys(p: int, q: int, e: int = 65537) -> tuple:
    """Calculate the RSA public and private keys for a pair
    of primes p and q and an exponent e.

    p and q must be large prime number and e must be coprime 
    to and less than (p - 1) * (q - 1).

    Args:
        p (int): A prime number
        q (int): A prime number
        e (int, optional): The RSA exponent. Defaults to 65537.

    Returns:
        tuple: public key (public exponent, modulus), 
            private key (private exponent, modulus)
    """
    n = p * q
    public_key = (e, n)
    phi = (p - 1) * (q - 1)

    gcd, d, _ = gcd_extended_euclid(e, phi)
    d %= phi  # d must not be negative
    if e >= phi or gcd != 1:
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

    plaintext_as_int = int.from_bytes(b'RSA' + plaintext, 'big')
    return i_to_b(pow(plaintext_as_int, exponent, modulus))


def decrypt(ciphertext: bytes, exponent: int, modulus: int) -> bytes:
    """Decrypt a piece of ciphertext using a given RSA key exponent and modulus. 

    Args:
        ciphertext (int): The ciphertext to decrypt
        exponent (int): The RSA decryption exponent
        modulus (int): The RSA modulus

    Returns:
        bytes: The decrypted plaintext
    """

    plaintext = i_to_b(pow(int.from_bytes(ciphertext, 'big'), exponent, modulus))
    if plaintext[:3] == b'RSA':
        return plaintext[3:]
    else:
        raise DecryptionFailureException(exponent)


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
        try:
            decrypt(encrypt(b'test123abc', *pub), *priv)
            decrypt(encrypt(b'cba321tset', *priv), *pub)
        except DecryptionFailureException:
            continue
        return pub, priv
