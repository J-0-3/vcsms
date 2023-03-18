import sys
import argparse
import json
import random
sys.path.append("../..")
from vcsms.server_connection import ServerConnection
from vcsms.logger import Logger
from vcsms.cryptography import rsa, aes256

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("server_config_file", type=str, help="the server's .vcsms config file")
    args = parser.parse_args() 
    with open(args.server_config_file, "r") as f:
        serverconf = json.load(f)
    ip = serverconf["ip"]
    port = serverconf["port"]
    fp = serverconf["fingerprint"]
    l = Logger(0, "/dev/null")
    s = ServerConnection(ip, port, fp, l)
    pubkey, privkey = rsa.gen_keypair(2048)
    print("Connected to server.")
    s.connect(pubkey, privkey)
    print("Connected.")
    print("Encrypting random data...")
    iv = random.randrange(2, 2**128)
    ciphertext = aes256.encrypt_cbc(random.randbytes(2048), random.randrange(2, 2**256), iv)
    print("Formatting ciphertext...")
    formatted = hex(iv)[2:].encode('utf-8') + b':' + ciphertext.hex().encode('utf-8')
    print("Sending data...")
    s._socket.send(formatted)
    response = s.recv()
    print(f"Response received from server: {response}")
    s.close()
