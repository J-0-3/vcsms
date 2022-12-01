import socket
import random
import sys
import os
import json
import threading
import argparse
from queue import Queue

import keys
import signing
from server_db import Server_DB
from cryptographylib import dhke, sha256, aes256, utils
from non_stream_socket import NonStreamSocket


class Server:
    def __init__(self, addr: str, port: int, keypair: tuple, db_path: str, pubkey_directory: str):
        self.addr = addr
        self.port = port
        self.pub = keypair[0]
        self.priv = keypair[1]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.dhke_group = dhke.group14_2048
        self.in_queue = Queue()
        self.out_queue = Queue()
        self.client_outboxes = {}
        self.db_path = db_path
        self.pubkey_path = pubkey_directory

    def handshake(self, client: NonStreamSocket):
        pub_exp = hex(self.pub[0])[2:].encode()
        pub_mod = hex(self.pub[1])[2:].encode()
        client.send(pub_exp + b':' + pub_mod)
        auth_packet = client.recv()
        c_id, c_exp, c_mod = auth_packet.split(b':')
        print(f"Client ID is {c_id.decode()}")
        client_pubkey = (int(c_exp, 16), int(c_mod, 16))
        if keys.fingerprint(client_pubkey) != c_id.decode():
            print(f"Public Key Validation Failed")
            client.send(b"PUBLIC KEY VALIDATION FAILED")
            client.close()
            return

        db = self.db_connect()
        db.user_login(c_id.decode(), client_pubkey)
        db.close()

        dhke_priv = random.randrange(1, self.dhke_group[1])
        dhke_pub = hex(dhke.generate_public_key(dhke_priv, self.dhke_group))[2:].encode()
        dhke_pub_sig = signing.sign(dhke_pub, self.priv)
        client.send(dhke_pub + b":" + dhke_pub_sig)

        c_dhke_pub, c_dhke_pub_sig = client.recv().split(b':')

        if not signing.verify(c_dhke_pub, c_dhke_pub_sig, client_pubkey):
            client.send(b"SIGNATURE VERIFICATION FAILED")
            client.close()
            return

        shared_key = dhke.calculate_shared_key(dhke_priv, int(c_dhke_pub, 16), self.dhke_group)

        encryption_key = sha256.hash(utils.i_to_b(shared_key))
        outbox = Queue()
        self.client_outboxes[c_id.decode()] = outbox
        t_in = threading.Thread(target=self.__in_thread, args=(client, encryption_key, c_id.decode()))
        t_out = threading.Thread(target=self.__out_thread, args=(client, outbox, encryption_key))
        t_in.start()
        t_out.start()

    def __in_thread(self, client: NonStreamSocket, encryption_key: int, id: str):
        while True:
            dat = client.recv()
            iv, data = dat.split(b':', 1)
            iv = int(iv, 16)
            data = aes256.decrypt_cbc(bytes.fromhex(data.decode()), encryption_key, iv)

            recipient, msg = data.split(b':', 1)
            if recipient.decode() not in self.client_outboxes:
                self.client_outboxes[recipient.decode()] = Queue()
            if recipient == b'0':
                request = msg.split(b':')
                if request[0] == b'GetKey':
                    req_id = request[1].decode()
                    print(f"key request for {req_id}")
                    db = self.db_connect()
                    if db.user_known(req_id):
                        print("Found")
                        key = db.get_pubkey(req_id)
                        self.client_outboxes[id].put(
                            b'0:KeyFound:' + req_id.encode() + b':' + hex(key[0]).encode() + b':' + hex(
                                key[1]).encode())
                        db.close()
                        continue
                    else:
                        print("Not Found")
                        self.client_outboxes[id].put(b'0:KeyNotFound:' + request[1])
                        continue
                elif request[0] == b'QUIT':
                    db = self.db_connect()
                    db.user_logout(id)
                    db.close()
                    self.client_outboxes[id].put(b'CLOSE')
                    break
            outgoing_msg = id.encode() + b':' + msg
            self.send(recipient.decode(), outgoing_msg)

    def __out_thread(self, sock: NonStreamSocket, outbox: Queue, encryption_key: int):
        while True:
            message = outbox.get()
            if message == b'CLOSE':
                sock.send(b'CLOSE')
                print("closing")
                break
            aes_iv = random.randrange(1, 2 ** 128)
            encrypted_message = hex(int.from_bytes(aes256.encrypt_cbc(message, encryption_key, aes_iv), 'big')).encode()
            sock.send(hex(aes_iv).encode() + b':' + encrypted_message)
        sock.close()

    def connect(self, client: NonStreamSocket):
        self.handshake(client)

    def send(self, client: str, message: bytes):
        if client not in self.client_outboxes:
            self.client_outboxes[client] = Queue()
        self.client_outboxes[client].put(message)

    def run(self):
        self.sock.bind((self.addr, self.port))
        self.sock.listen(30)
        db = self.db_connect()
        db.setup_db()
        db.close()

        print(f"Running on {self.addr}:{self.port}...")
        while True:
            conn, addr = self.sock.accept()
            print(f"New connection from: {addr}")
            ns_sock = NonStreamSocket(conn)
            ns_sock.listen()
            t_connect = threading.Thread(target=self.connect, args=(ns_sock,))
            t_connect.start()

    def db_connect(self):
        db = Server_DB(self.db_path, self.pubkey_path)
        return db


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
            "ip": "0.0.0.0",
            "port": 6000
        }

    if args.config_out:
        with open(args.config_out, 'w') as f:
            f.write(json.dumps({
                "port": config["port"],
                "fingerprint": keys.fingerprint(pub)
            }))
    server = Server(config["ip"], config["port"], (pub, priv), os.path.join(server_directory, "server.db"), os.path.join(server_directory, "keys"))
    server.run()
