from cryptographylib import rsa, sha256
import signing

def generate_keys(pub_out, priv_out):
    pub, priv = rsa.gen_keypair(2048)
    with open(pub_out, 'w') as f:
        f.write(f"{hex(pub[0])[2:]}:{hex(pub[1])[2:]}")
    with open(priv_out, 'w') as f:
        f.write(f"{hex(priv[0])[2:]}:{hex(priv[1])[2:]}")

    return pub, priv

def load_keys(pubkey, privkey):
    with open(pubkey, 'r') as f:
        exp,mod = f.read().split(':')
        pub = (int(exp, 16), int(mod, 16))
    with open(privkey, 'r') as f:
        exp,mod = f.read().split(':')
        priv = (int(exp, 16), int(mod, 16))
    return pub,priv

def fingerprint(key: tuple):
    return sha256.hash(hex(key[0])[2:].encode() + hex(key[1])[2:].encode())
