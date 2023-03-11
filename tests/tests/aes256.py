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

nist_aesavs_GFSbox_test = Test(
    "NIST AES Algorithm Verification Suite 'GFSBox' known answer test values",
    lambda p: aes256.encrypt_cbc(p, 0, 0, True, False).hex()[:32],  # NIST vectors do not use PKCS#7, remove the added block
    [
        ((bytes.fromhex('014730f80ac625fe84f026c60bfd547d'),), '5c9d844ed46f9885085e5d6a4f94c7d7'),
        ((bytes.fromhex('0b24af36193ce4665f2825d7b4749c98'),), 'a9ff75bd7cf6613d3731c77c3b6d0c04'),
        ((bytes.fromhex('761c1fe41a18acf20d241650611d90f1'),), '623a52fcea5d443e48d9181ab32c7421'),
        ((bytes.fromhex('8a560769d605868ad80d819bdba03771'),), '38f2c7ae10612415d27ca190d27da8b4'),
        ((bytes.fromhex('91fbef2d15a97816060bee1feaa49afe'),), '1bc704f1bce135ceb810341b216d7abe')
    ],
    "eq"
)

nist_aesavs_KeySBox_test = Test(
    "NIST AES Algorithm Verification Suite 'KeySBox' known answer test values",
    lambda k: aes256.encrypt_cbc(b'\x00' * 16, k, 0, True, False).hex()[:32],
    [
        ((0xc47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558,), '46f2fb342d6f0ab477476fc501242c5f'),
        ((0x28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64,), '4bf3b0a69aeb6657794f2901b1440ad4'),
        ((0xc1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c,), '352065272169abf9856843927d0674fd')
    ],
    "eq"
)

tests = TestSet(
    "AES256 Tests",
    successful_decryption_1_byte_test,
    unsuccessful_decryption_1_byte_test,
    successful_decryption_32_byte_test,
    unsuccessful_decryption_32_byte_test,
    zero_key_encryption_test,
    zero_key_decryption_failure_test,
    nist_aesavs_GFSbox_test,
    nist_aesavs_KeySBox_test
)
if __name__ == "__main__":
    tests.run()
