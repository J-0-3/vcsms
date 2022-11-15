import socket
import random
from queue import Queue
import json
import threading
import keys
import signing
from cryptographylib import dhke, sha256, aes256, utils

port = 6000
interface = "0.0.0.0"


class Server:
    def __init__(self, addr: str, port: int, keypair: tuple):
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
        self.client_pubkeys = {}

    def handshake(self, client: socket.socket):
        pub_exp = hex(self.pub[0])[2:].encode()
        pub_mod = hex(self.pub[1])[2:].encode()
        client.send(pub_exp + b':' + pub_mod)
        auth_packet = client.recv(2048)
        c_id, c_exp, c_mod = auth_packet.split(b':')
        print(f"Client ID is {c_id.decode()}")
        client_pubkey = (int(c_exp, 16), int(c_mod, 16))
        if keys.fingerprint(client_pubkey) != int(c_id, 16):
            print(f"Public Key Validation Failed")
            client.send(b"PUBLIC KEY VALIDATION FAILED")
            client.close()
            return

        dhke_priv = random.randrange(1, self.dhke_group[1])
        dhke_pub = hex(dhke.generate_public_key(dhke_priv, self.dhke_group))[2:].encode()
        dhke_pub_sig = signing.sign(dhke_pub, self.priv)
        client.send(dhke_pub + b":" + dhke_pub_sig)

        c_dhke_pub, c_dhke_pub_sig = client.recv(2048).split(b':')

        if not signing.verify(c_dhke_pub, c_dhke_pub_sig, client_pubkey):
            client.send(b"SIGNATURE VERIFICATION FAILED")
            client.close()
            return

        shared_key = dhke.calculate_shared_key(dhke_priv, int(c_dhke_pub, 16), self.dhke_group)

        encryption_key = sha256.hash(utils.i_to_b(shared_key))
        outbox = Queue()
        self.client_outboxes[c_id.decode()] = outbox
        self.client_pubkeys[c_id.decode()] = client_pubkey
        t_in = threading.Thread(target=self.__in_thread, args=(client, encryption_key, c_id.decode()))
        t_out = threading.Thread(target=self.__out_thread, args=(client, outbox, encryption_key))
        t_in.start()
        t_out.start()
        return c_id.decode()

    def __in_thread(self, client: socket.socket, encryption_key: int, id: str):
        while True:
            dat = client.recv(4096)
            if dat == b'':
                continue
            iv, data = dat.split(b':', 1)
            iv = int(iv, 16)
            data = aes256.decrypt_cbc(utils.i_to_b(int(data, 16)), encryption_key, iv)
            recipient, msg = data.split(b':', 1)
            if recipient == b'0':
                request = msg.split(b':')
                if request[0] == b'GetKey':
                    print(f"key request for {request[1].decode()}")
                    if request[1].decode() in self.client_pubkeys:
                        print("Found")
                        key = self.client_pubkeys[request[1].decode()]
                        self.client_outboxes[id].put(b'0:KeyFound:' + request[1] + b':' + hex(key[0]).encode() + b':' + hex(key[1]).encode())
                        continue
                    else:
                        print("Not Found")
                        self.client_outboxes[id].put(b'0:KeyNotFound:' + request[1])
                        continue
            outgoing_msg = id.encode() + b':' + msg
            if recipient.decode() not in self.client_outboxes:
                self.client_outboxes[recipient.decode()] = Queue()
            self.client_outboxes[recipient.decode()].put(outgoing_msg)

            print(f"Message to {recipient} from {id}")

    def __out_thread(self, sock: socket.socket, outbox: Queue, encryption_key: int):
        while True:
            message = outbox.get()
            aes_iv = random.randrange(1, 2**128)
            encrypted_message = hex(int.from_bytes(aes256.encrypt_cbc(message, encryption_key, aes_iv), 'big')).encode()
            sock.send(hex(aes_iv).encode() + b':' + encrypted_message)

    def connect(self, client: socket.socket):
        self.handshake(client)

    def send(self, client: str, message: bytes):
        self.client_outboxes[client].put(message)

    def accept_thread(self):
        while True:
            conn, addr = self.sock.accept()
            print(f"New connection from: {addr}")
            t_connect = threading.Thread(target=self.connect, args=(conn,))
            t_connect.start()

    def run(self):
        self.sock.bind((self.addr, self.port))
        self.sock.listen(30)

        t_accept = threading.Thread(target=self.accept_thread, args=())
        t_accept.start()


if __name__ == "__main__":
    try:
        keypair = keys.load_keys("server.pub", "server.priv")
    except FileNotFoundError:
        keypair = keys.generate_keys("server.pub", "server.priv")

    with open("server.conf", 'w') as f:
        f.write(json.dumps({
            "ip": "0.0.0.0",
            "port": 6000,
            "fingerprint": hex(keys.fingerprint(keypair[0]))[2:]
        }))
    server = Server("0.0.0.0", 6000, keypair)
    server.run()
