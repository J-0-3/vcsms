from cryptographylib import rsa, sha256
import signing


def write_key(key: tuple, out: str):
    with open(out, 'w') as f:
        f.write(f"{hex(key[0])[2:]}:{hex(key[1])[2:]}")
def generate_keys(pub_out, priv_out):
    pub, priv = rsa.gen_keypair(2048)
    write_key(pub, pub_out)
    write_key(priv, priv_out)

    return pub, priv

def load_key(path: str):
    with open(path, 'r') as f:
        exp, mod = f.read().split(':')
        key = (int(exp, 16), int(mod, 16))
    return key
def fingerprint(key: tuple):
    return sha256.hash(hex(key[0])[2:].encode() + hex(key[1])[2:].encode())
