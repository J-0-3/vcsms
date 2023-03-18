import sys
import random
sys.path.append("../..")
from vcsms import signing
from vcsms import keys
import vcsms.cryptography.dhke as dhke

if __name__ == "__main__":
    rsa_private_key = keys.load_key("./fake_privkey.priv")
    private_key = random.randrange(2, dhke.group14_2048[1])
    public_key, signature = signing.gen_signed_dh(private_key, rsa_private_key, dhke.group14_2048)
    packet = hex(public_key)[2:].encode() + b':' +signature.hex().encode() + b'\xff'
    sys.stdout.buffer.write(packet)
