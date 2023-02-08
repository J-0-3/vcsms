import sys
sys.path.append("..")
sys.path.append("../..")
import random
import vcsms.cryptographylib.rsa as rsa
from vcsms.cryptographylib.exceptions import DecryptionFailureException
from testing import Test, TestSet

if __name__ == "__main__":
    print("Generating tests...")
keypair4096_pub, keypair4096_priv = rsa.gen_keypair(4096);
fixed_4096_bit_keypair_test = Test(
    "100 256 bit pub encrypts -> priv decrypts with same 4096 bit keypair",
    rsa.decrypt,
    [((rsa.encrypt(plaintext, *keypair4096_pub), *keypair4096_priv), plaintext) for plaintext in [random.randbytes(64) for i in range(100)]],
    "eq"
)

fixed_4096_bit_keypair_test_reversed = Test(
    "100 256 bit priv encrypts -> pub decrypts with same 4096 bit keypair",
    rsa.decrypt,
    [((rsa.encrypt(plaintext, *keypair4096_priv), *keypair4096_pub), plaintext) for plaintext in [random.randbytes(64) for i in range(100)]],
    "eq"
)

tests = TestSet("RSA Tests", fixed_4096_bit_keypair_test, fixed_4096_bit_keypair_test_reversed)

if __name__ == "__main__":
    tests.run_all()
