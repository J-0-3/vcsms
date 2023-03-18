import sys
sys.path.append("..")
sys.path.append("../..")
import random
import vcsms.cryptography.rsa as rsa
from vcsms.cryptography.exceptions import DataTooLong, DecryptionFailureException
from testing import Test, TestSet

if __name__ == "__main__":
    print("Generating tests...")

keypair4096_pub, keypair4096_priv = rsa.gen_keypair(4096);
fixed_4096_bit_keypair_test = Test(
    "100 public->private encrypt/decrypt of < 500B with same 4096 bit keypair",
    lambda c: rsa.decrypt(c, *keypair4096_priv),
    [
        ((rsa.encrypt(plaintext, *keypair4096_pub),), plaintext)
        for plaintext in [random.randbytes(random.randrange(1, 500)) for _ in range(100)]],
    "eq"
)

fixed_4096_bit_keypair_test_reversed = Test(
    "100 private->public encrypt/decrypt of < 500B with same 4096 bit keypair",
    lambda c: rsa.decrypt(c, *keypair4096_pub),
    [
        ((rsa.encrypt(plaintext, *keypair4096_priv),), plaintext)
        for plaintext in [random.randbytes(random.randrange(1, 500)) for _ in range(100)]
    ],
    "eq"
)

random_2048_bit_keypair_test = Test(
    "25 public->private encrypt/decrypt of < 200B using new 2048 bit keypairs",
    rsa.decrypt,
    [
        ((rsa.encrypt(plaintext, *(keypair := rsa.gen_keypair(2048))[0]), *keypair[1]), plaintext)
        for plaintext in [random.randbytes(random.randrange(1, 200)) for _ in range(25)]
    ],
    "eq"
)

random_2048_bit_keypair_test_reversed = Test(
    "25 private->public encrypt/decrypt of < 200B using new 2048 bit keypairs",
    rsa.decrypt,
    [
        ((rsa.encrypt(plaintext, *(keypair := rsa.gen_keypair(2048))[1]), *keypair[0]), plaintext)
        for plaintext in [random.randbytes(random.randrange(1, 200)) for _ in range(25)]
    ],
    "eq"
)

correct_exception_test_too_long = Test(
    "Attempting to encrypt data over the maximum size for the keylength",
    lambda p: rsa.encrypt(p, *keypair4096_pub),
    [
        ((random.randbytes(8192), ), None)
        for i in range(20)
    ],
    "raises",
    DataTooLong

)

correct_exception_test_wrong_key = Test(
    "Attempting to decrypt data using an incorrect key",
    lambda p: rsa.decrypt(p, *keypair4096_priv),
    [
        ((rsa.encrypt(random.randbytes(64), 65537, random.randrange(2**512, 2**4096)), ), None)
        for i in range(20)
    ],
    "raises",
    DecryptionFailureException
)

tests = TestSet(
    "RSA Tests",
    fixed_4096_bit_keypair_test,
    fixed_4096_bit_keypair_test_reversed,
    random_2048_bit_keypair_test,
    random_2048_bit_keypair_test_reversed,
    correct_exception_test_too_long,
    correct_exception_test_wrong_key
)

if __name__ == "__main__":
    tests.run()
