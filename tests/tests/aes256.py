import random
import sys
sys.path.append("..")
from testing import Test, TestSet
sys.path.append("../..")
import vcsms.cryptography.aes256 as aes256
from vcsms.cryptography.exceptions import DecryptionFailureException

if __name__ == "__main__":
    print("Generating unit tests...")
one_byte_test_vectors = []
for i in range(256):
    key = random.randrange(0, 2**256)
    iv = random.randrange(0, 2**128)
    ciphertext = aes256.encrypt_cbc(i.to_bytes(1, 'big'), key, iv)
    one_byte_test_vectors.append(((ciphertext, key, iv), i.to_bytes(1, 'big')))

unsuccessful_decryption_1_byte_test = Test(
    "failure to encrypt and decrypt 1B with wrong key",
    aes256.decrypt_cbc,
    [((ciphertext, random.randrange(0, 2**256), iv), None) for (ciphertext, _, iv), _ in one_byte_test_vectors],
    "raises",
    DecryptionFailureException
)

successful_decryption_1_byte_test = Test(
    "encryption and decryption of every 1B value",
    aes256.decrypt_cbc,
    one_byte_test_vectors,
    "eq"
)

thirty_two_byte_test_vectors = []
for i in range(500):
    key = random.randrange(0, 2**256)
    iv = random.randrange(0, 2**128)
    plaintext = random.randbytes(32)
    ciphertext = aes256.encrypt_cbc(plaintext, key, iv)
    thirty_two_byte_test_vectors.append(((ciphertext, key, iv), plaintext))

successful_decryption_32_byte_test = Test(
    "500 encryptions and decryptions of 32B",
    aes256.decrypt_cbc,
    thirty_two_byte_test_vectors,
    "eq"
)

unsuccessful_decryption_32_byte_test = Test(
    "500 failures to encrypt and decrypt 32B with wrong key",
    aes256.decrypt_cbc,
    [((ciphertext, random.randrange(0, 2**256), iv), None) for (ciphertext, _, iv), _ in thirty_two_byte_test_vectors],
    "raises",
    DecryptionFailureException
)

zero_key_encryption_test = Test(
    "100 1KB values encrypted and decrypted with key 0",
    aes256.decrypt_cbc,
    [((aes256.encrypt_cbc(plaintext, 0, 0), 0, 0), plaintext) for plaintext in [random.randbytes(1024) for i in range(100)]],
    "eq"
)

zero_key_decryption_failure_test = Test(
    "500 failures to decrypt 1KB encrypted with key 0 using wrong key",
    aes256.decrypt_cbc,
    [((ciphertext, random.randrange(0, 2**256), random.randrange(0, 2**128)), None) for (ciphertext, _, _), _ in zero_key_encryption_test.tests],
    "raises",
    DecryptionFailureException
)


tests = TestSet(
    "AES256 Tests",
    successful_decryption_1_byte_test,
    unsuccessful_decryption_1_byte_test,
    successful_decryption_32_byte_test,
    unsuccessful_decryption_32_byte_test,
    zero_key_encryption_test,
    zero_key_decryption_failure_test
)
if __name__ == "__main__":
    tests.run_all()
