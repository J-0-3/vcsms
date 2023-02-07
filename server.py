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
    parser.add_argument("-i", "--interface", type=str, help="The IP address of the network interface to run on. (Default 127.0.0.1)", default="127.0.0.1")
    parser.add_argument("-p", "--port", type=int, help="The port for the service to listen on. (Default 6000)", default=6000)
    args = parser.parse_args()
    server_directory = args.directory
    key_directory = os.path.join(server_directory, "keys")
    os.makedirs(key_directory, exist_ok=True)
    public_key_path = os.path.join(server_directory, "server.pub")
    private_key_path = os.path.join(server_directory, "server.priv")
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

    if args.config_out:
        with open(args.config_out, 'w', encoding='utf-8') as f:
            json.dump({
                "ip": "localhost",
                "port": args.port,
                "fingerprint": keys.fingerprint(pub, 64)
            }, f)
        print(f"Config file created at: {os.path.abspath(args.config_out)}.")
        print("Edit it to reflect your publically facing IP.")

    logger = Logger(5, log_path)
    server = Server(args.interface, args.port, (pub, priv), database_path, key_directory, logger)
    print(f"Running server on {args.interface}:{args.port}...")
    server.run()
