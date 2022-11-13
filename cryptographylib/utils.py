import math

def get_msb(x: int) -> int:
    """Get the index of the most significant bit of an integer

    Args:
        x (int): An integer of any length

    Returns:
        int: The index (0 -> log x) of the most significant bit 
    """
    cur = x
    msb = 0
    while cur != 0:
        cur >>= 1
        msb += 1
    return msb - 1

def i_to_b(n: int) -> bytes:
    """Convert an int to a byte representation

    Args:
        n (int): int to convert
    Returns:
        bytes: int in byte format
    """
    byte_length = math.ceil((get_msb(n) + 1) / 8)
    return n.to_bytes(byte_length, 'big') 