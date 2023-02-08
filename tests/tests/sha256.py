import sys
import hashlib
import random
sys.path.append("..")
sys.path.append(".....")
from testing import Test, TestSet
import vcsms.cryptographylib.sha256 as sha256

if __name__ == "__main__":
    print("Generating unit tests...")
single_byte_test = Test(
    "all single byte values",
    sha256.hex_digest,
    [((byte.to_bytes(1, 'big'), ), hashlib.sha256(byte.to_bytes(1, 'big')).hexdigest()) for byte in range(256)],
    "eq"
)

random_32_byte_test = Test(
    "500 random 32 byte values",
    sha256.hex_digest,
    [((val,), hashlib.sha256(val).hexdigest()) for val in [random.randbytes(32) for _ in range(500)]],
    "eq"
)

random_length_value_test = Test(
    "1000 random < 1KB bytestrings",
    sha256.hex_digest,
    [((val,), hashlib.sha256(val).hexdigest()) for val in [random.randbytes(random.randrange(0, 1024)) for _ in range(1000)]],
    "eq"
)

random_4mb_value_test = Test(
    "5 1MB pieces of data",
    sha256.hex_digest,
    [((val, ), hashlib.sha256(val).hexdigest()) for val in [random.randbytes(1048576) for _ in range(5)]],
    "eq"
)
tests = TestSet("SHA256 Tests", single_byte_test, random_32_byte_test, random_length_value_test, random_4mb_value_test)

if __name__ == "__main__":
    tests.run_all()
