import sys
import random
import time
sys.path.append("..")
sys.path.append("../..")
from testing import Test, TestSet
from vcsms.signing import sign, verify
from vcsms.cryptography.rsa import gen_keypair

if __name__ == "__main__":
    print("Generating tests...")

public_key, private_key = gen_keypair()

signature_verifies_successfully_test = Test(
    "20 signatures successfully verify for unmodified data with correct key",
    lambda d, s: verify(d, s, public_key),
    [
        ((data, sign(data, private_key, 0)), True)
        for data in [random.randbytes(4096) for _ in range(20)]
    ],
    "eq"
)

signature_random_data_test = Test(
    "20 signatures fail to verify for different random data with correct key",
    lambda d, s: verify(d, s, public_key),
    [
        ((random.randbytes(4096), sign(data, private_key, 0)), False)
        for data in [random.randbytes(4096) for _ in range(20)]
    ],
    "eq"
)

signature_1b_append_test = Test(
    "20 signatures fail to verify for data with 1 byte appended with correct key",
    lambda d, s: verify(d, s, public_key),
    [
        ((data + random.randbytes(1), sign(data, private_key, 0)), False)
        for data in [random.randbytes(4096) for _ in range(20)]
    ],
    "eq"
)

public_key2, private_key2 = gen_keypair()
signature_wrong_key_test = Test(
    "20 signatures fail to verify for unmodified data with incorrect key",
    lambda d, s: verify(d, s, public_key),
    [
        ((data, sign(data, private_key2, 0)), False)
        for data in [random.randbytes(4096) for _ in range(20)]
    ],
    "eq"
)

def sign_wait_and_verify(d):
    s = sign(d, private_key, 5)
    time.sleep(5.5)
    return verify(d, s, public_key)

signature_timeout_test = Test(
    "signature fails to verify for correct data + key after 5s TTL expires",
    sign_wait_and_verify,
    [
        ((random.randbytes(4096), ), False)
    ],
    "eq"
)

tests = TestSet(
    "Signing Tests",
    signature_verifies_successfully_test,
    signature_random_data_test,
    signature_1b_append_test,
    signature_wrong_key_test,
    signature_timeout_test
)

if __name__ == "__main__":
    tests.run()
