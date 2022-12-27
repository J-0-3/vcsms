#!/bin/python
import argparse
import os
import json

from vcsms.server import Server
from vcsms.logger import Logger
from vcsms import keys

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=str, help="The directory in which to store all the server's files")
    parser.add_argument("-o", "--config-out", type=str, help="A location to output the server's connection file to")
    args = parser.parse_args()
    server_directory = args.directory
    os.makedirs(os.path.join(server_directory, "keys"), exist_ok=True)
    try:
        pub = keys.load_key(os.path.join(server_directory, "server.pub"))
        priv = keys.load_key(os.path.join(server_directory, "server.priv"))
    except FileNotFoundError:
        pub, priv = keys.generate_keys(os.path.join(server_directory, "server.pub"), os.path.join(server_directory, "server.priv"))

    if os.path.exists(os.path.join(server_directory, "server.conf")):
        with open(os.path.join(server_directory, "server.conf")) as f:
            config = json.loads(f.read())
    else:
        config = {
            "ip": "127.0.0.1",
            "port": 6000
        }

    if args.config_out:
        with open(args.config_out, 'w') as f:
            f.write(json.dumps({
                "port": config["port"],
                "fingerprint": keys.fingerprint(pub)
            }))

    logger = Logger(5, os.path.join(server_directory, "log.txt"))
    server = Server(config["ip"], config["port"], (pub, priv), os.path.join(server_directory, "server.db"), os.path.join(server_directory, "keys"), logger)
    server.run()
