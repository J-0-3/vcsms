import sys
sys.path.append("..")
sys.path.append("../..")
import random
import vcsms.cryptography.dhke as dhke
from testing import Test, TestSet

if __name__ == "__main__":
    print("Generating tests...")

establish_shared_secret_test = Test(
    "Identical shared secret is established by both parties",
    lambda pub, priv: dhke.calculate_shared_key(priv, pub, dhke.group16_4096),
    [
        ((dhke.generate_public_key(private_key1, dhke.group16_4096), private_key2), 
          dhke.calculate_shared_key
                (private_key1, 
                dhke.generate_public_key(private_key2, dhke.group16_4096), 
                dhke.group16_4096)
        )
        for private_key1, private_key2 in zip(
            [random.randrange(2, dhke.group16_4096[1]) for _ in range(100)],
            [random.randrange(2, dhke.group16_4096[1]) for _ in range(100)]
        )
    ],
    "eq"
)

tests = TestSet(
    "DHKE Tests",
    establish_shared_secret_test
)

if __name__ == "__main__":
    tests.run()
