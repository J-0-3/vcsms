#!/bin/python
import argparse
import os
import json

from vcsms.server import Server
from vcsms.logger import Logger
from vcsms import keys
from vcsms.cryptographylib import sha256
from vcsms.cryptographylib.exceptions import DecryptionFailureException

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=str, help="The directory in which to store all the server's files")
    parser.add_argument("-o", "--config-out", type=str, help="A location to output the server's connection file to")
    args = parser.parse_args()
    server_directory = args.directory
    key_directory = os.path.join(server_directory, "keys")
    os.makedirs(key_directory, exist_ok=True)
    public_key_path = os.path.join(server_directory, "server.pub")
    private_key_path = os.path.join(server_directory, "server.priv")
    config_path = os.path.join(server_directory, "config_path")
    log_path = os.path.join(server_directory, "log.txt")
    database_path = os.path.join(server_directory, "server.db")

    private_key_password = input("Enter private key encryption password: ").encode('utf-8')
    private_key_encryption_key = sha256.hash(private_key_password)
    try:
        pub = keys.load_key(public_key_path)
        priv = keys.load_key(private_key_path, private_key_encryption_key)
    except FileNotFoundError:
        pub, priv = keys.generate_keys(public_key_path, private_key_path, private_key_encryption_key)
    except DecryptionFailureException:
        print("Private key password incorrect. Try again.")
        quit()

    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    else:
        config = {
            "ip": "127.0.0.1",
            "port": 6000
        }

    if args.config_out:
        with open(args.config_out, 'w', encoding='utf-8') as f:
            json.dump({
                "port": config["port"],
                "fingerprint": keys.fingerprint(pub)
            }, f)

    logger = Logger(5, log_path)
    server = Server(config["ip"], config["port"], (pub, priv), database_path, key_directory, logger)
    server.run()
