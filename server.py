#!/usr/bin/env python3
import argparse
import getpass
import os
import json

from vcsms.server import Server
from vcsms.logger import Logger
from vcsms import keys
from vcsms.cryptography import sha256
from vcsms.cryptography.exceptions import CryptographyException, DecryptionFailureException

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", type=str, default="vcsms_server", help="the directory in which to store all the server's files")
    parser.add_argument("-o", "--config-out", type=str, help="a location to output the server's connection file to")
    parser.add_argument("-P", "--password", type=str, help="the server master key to encrypt the private key at rest")
    parser.add_argument("-i", "--interface", type=str, help="the IP address of the network interface to run on. (Default 127.0.0.1)", default="127.0.0.1")
    parser.add_argument("-p", "--port", type=int, help="the port for the service to listen on. (Default 6000)", default=6000)
    parser.add_argument("-l", "--loglevel", type=int, default=5, help="the verbosity of the server log file")
    args = parser.parse_args()
    server_directory = args.directory
    key_directory = os.path.join(server_directory, "keys")
    os.makedirs(key_directory, exist_ok=True)
    public_key_path = os.path.join(server_directory, "server.pub")
    private_key_path = os.path.join(server_directory, "server.priv")
    log_path = os.path.join(server_directory, "server.log")
    database_path = os.path.join(server_directory, "server.db")

    private_key_password = args.password or getpass.getpass(prompt="Enter private key encryption password: ")
    pk_encryption_key = keys.derive_key(private_key_password)
    try:
        pub = keys.load_key(public_key_path)
        priv = keys.load_key(private_key_path, pk_encryption_key)
    except FileNotFoundError:
        pub, priv = keys.generate_keys(public_key_path, private_key_path, pk_encryption_key)
    except CryptographyException:
        print("Private key password incorrect. Try again.")
        quit()

    print(f"The server's fingerprint is:\n{keys.fingerprint(pub, 64)}")
    print("(clients will need this to connect to the server without using a config file)")
    if args.config_out:
        with open(args.config_out, 'w', encoding='utf-8') as f:
            json.dump({
                "ip": "localhost",
                "port": args.port,
                "fingerprint": keys.fingerprint(pub, 64)
            }, f)
        print(f"Config file created at: {os.path.abspath(args.config_out)}.")
        print("Clients can use this file to connect to the server.")
        print("Edit it to reflect your publically facing IP.\n")

    logger = Logger(5, log_path)
    server = Server(args.interface, args.port, (pub, priv), database_path, key_directory, logger)
    print(f"Running server on {args.interface}:{args.port}...")
    server.run()
