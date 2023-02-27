import math


def get_msb(x: int) -> int:
    """Get the index of the most significant bit of an integer

    Args:
        x (int): An integer of any length

    Returns:
        int: The index (0 -> log x) of the most significant bit 
    """
    return x.bit_length() - 1


def i_to_b(n: int) -> bytes:
    """Convert an int to a byte representation

    Args:
        n (int): int to convert
    Returns:
        bytes: int in byte format
    """
    byte_length = math.ceil((get_msb(n) + 1) / 8)
    return n.to_bytes(byte_length, 'big') 

def xor_b(b1: bytes, b2: bytes) -> bytes:
    """XOR together two bytestrings. If the lengths are different,
    prepend zeroes before the shorter of the bytestrings."""
    while len(b1) < len(b2):
        b1 = b'\x00' + b1
    while len(b2) < len(b1):
        b2 = b'\x00' + b2
    xored = b''
    for a, b in zip(b1, b2):
        xored += (a ^ b).to_bytes(1, 'big')
    return xored