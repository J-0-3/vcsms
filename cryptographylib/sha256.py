# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
# https://sha256algorithm.com/

def circular_right_shift(n: int, b: int) -> int:
    """Perform a circular right bit shift on a 32 bit integer

    Args:
        n (int): A 32 bit integer to shift
        b (int): The amount of bits to shift the integer by

    Returns:
        int: The integer after the shift
    """
    # right shift 32-bit integer n by b and wrap bits around
    bits_to_wrap = (n << (32 - b)) % 2 ** 32
    shifted_bits = n >> b
    return bits_to_wrap | shifted_bits


def hash(message: bytes) -> int:
    """Calculate the SHA256 hash value of a given bytestring.

    Args:
        message (bytes): The message to hash

    Returns:
        int: The resultant 256 bit hash value
    """
    message_block = b''
    message_block += message
    message_block += (0b10000000).to_bytes(1,
                                           byteorder='big')  # append 1000000 so that it will always pad even if already 464 bits
    while (len(message_block) * 8 + 64) % 512 != 0:  # a 64-bit integer will be added to end so pad to 512*n - 64
        message_block += (0).to_bytes(1, byteorder='big')

    message_block += (len(message) * 8).to_bytes(8,
                                                 byteorder='big')  # 64-bit integer containing the length of the message

    chunks = []
    for i in range(0, len(message_block), 64):  # split into 512-bit (64 byte) chunks
        chunks.append(message_block[i:i + 64])

    # government document says use these wacky magic numbers

    # first 32 bits of the fractional parts of the square roots of the first 8 primes
    H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    # first 32 bits of the fractional parts of the cube roots of the first 64 primes
    k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    for c in chunks:

        def sigma_zero(x: int) -> int:
            return circular_right_shift(x, 7) ^ circular_right_shift(x, 18) ^ (x >> 3)

        def sigma_one(x: int) -> int:
            return circular_right_shift(x, 17) ^ circular_right_shift(x, 19) ^ (x >> 10)

        words = []
        for i in range(0, len(c), 4):
            words.append(int.from_bytes(c[i:i + 4], byteorder='big'))
        for i in range(16, 64):
            words.append((sigma_one(words[i - 2]) + words[i - 7] + sigma_zero(words[i - 15]) + words[i - 16]) % 2 ** 32)

        a, b, c, d, e, f, g, h = H

        def sigma_zero(x: int) -> int:
            return circular_right_shift(x, 2) ^ circular_right_shift(x, 13) ^ circular_right_shift(x, 22)

        def sigma_one(x: int) -> int:
            return circular_right_shift(x, 6) ^ circular_right_shift(x, 11) ^ circular_right_shift(x, 25)

        def choice(x: int, y: int, z: int) -> int:
            return (x & y) ^ (~x & z)

        def majority(x: int, y: int, z: int) -> int:
            return (x & y) ^ (x & z) ^ (y & z)

        for i in range(64):
            t_word_1 = (h + sigma_one(e) + choice(e, f, g) + k[i] + words[i]) % 2 ** 32
            t_word_2 = (sigma_zero(a) + majority(a, b, c)) % 2 ** 32
            h = g
            g = f
            f = e
            e = (d + t_word_1) % 2 ** 32
            d = c
            c = b
            b = a
            a = (t_word_1 + t_word_2) % 2 ** 32

        H[0] = (H[0] + a) % 2 ** 32
        H[1] = (H[1] + b) % 2 ** 32
        H[2] = (H[2] + c) % 2 ** 32
        H[3] = (H[3] + d) % 2 ** 32
        H[4] = (H[4] + e) % 2 ** 32
        H[5] = (H[5] + f) % 2 ** 32
        H[6] = (H[6] + g) % 2 ** 32
        H[7] = (H[7] + h) % 2 ** 32

    resultant_hash = H[7] + H[6] * 2 ** 32 + H[5] * 2 ** 64 + H[4] * 2 ** 96 + H[3] * 2 ** 128 + H[2] * 2 ** 160 + H[
        1] * 2 ** 192 + H[0] * 2 ** 224  # concatenate final hash values
    return resultant_hash


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(hex(hash(input().encode()))[2:])
    else:
        for file in sys.argv[1:]:
            with open(file, "rb") as data:
                print(hex(hash(data.read()))[2:])
