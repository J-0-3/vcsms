import socket
import random
import threading
from queue import Queue

from . import keys
from . import signing
from .server_db import Server_DB
from .logger import Logger
from .cryptographylib import dhke, sha256, aes256, utils
from .non_stream_socket import NonStreamSocket
from .message_parser import MessageParser
from .exceptions.message_parser import MessageParseException

INCOMING_MESSAGE_TYPES = {
    "GetKey": (1, [str], ['utf-8']),
    "Quit": (0, [], [])
}

OUTGOING_MESSAGE_TYPES = {
    "KeyFound": (3, [str, int, int], ['utf-8', 16, 16]),
    "KeyNotFound": (1, [str], ['utf-8']) 
}


class Server:
    def __init__(self, addr: str, port: int, keypair: tuple, db_path: str, pubkey_directory: str, logger: Logger):
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
        self.sockets = {}
        self.db_path = db_path
        self.pubkey_path = pubkey_directory
        self.logger = logger
        response_map = {
            "GetKey": self._handler_get_key,
            "Quit": self._handler_quit
        }
        self.message_parser = MessageParser(INCOMING_MESSAGE_TYPES, OUTGOING_MESSAGE_TYPES, response_map)

    def run(self):
        self.sock.bind((self.addr, self.port))
        self.sock.listen(30)
        db = self._db_connect()
        db.setup_db()
        db.close()
        self.logger.log(f"Running on {self.addr}:{self.port}", 0)
        while True:
            conn, addr = self.sock.accept()
            self.logger.log(f"New connection from: {addr}", 2)
            ns_sock = NonStreamSocket(conn)
            ns_sock.listen()
            t_connect = threading.Thread(target=self._connect, args=(ns_sock,))
            t_connect.start()

    def _connect(self, client: NonStreamSocket):
        self._handshake(client)

    def send(self, client: str, message: bytes):
        if client not in self.client_outboxes:
            self.logger.log("Message to offline/unknown user {client}", 3)
            self.client_outboxes[client] = Queue()
        self.client_outboxes[client].put(message)

    def _handshake(self, client: NonStreamSocket):
        pub_exp = hex(self.pub[0])[2:].encode()
        pub_mod = hex(self.pub[1])[2:].encode()
        client.send(pub_exp + b':' + pub_mod)
        identity_packet = client.recv()
        try:
            c_id, c_exp, c_mod = identity_packet.split(b':')
            c_id = c_id.decode()
        except ValueError:
            self.logger.log("Connection failure. Malformed identity packet.", 1)
            client.send(b"MalformedIdentityPacket")
            client.close()
            return
        self.logger.log(f"Client ID is {c_id}", 2)
        client_pubkey = (int(c_exp, 16), int(c_mod, 16))
        if keys.fingerprint(client_pubkey) != c_id:
            self.logger.log(f"Connection failure. Public key validation failed for {c_id}", 1)
            client.send(b"PubKeyIdMismatch")
            client.close()
            return

        dhke_priv = random.randrange(1, self.dhke_group[1])
        dhke_pub, dhke_sig = signing.gen_signed_diffie_hellman(dhke_priv, self.priv, self.dhke_group)
        client.send(hex(dhke_pub)[2:].encode() + b":" + dhke_sig)

        c_dhke_pub, c_dhke_pub_sig = client.recv().split(b':')
        if not signing.verify(c_dhke_pub, c_dhke_pub_sig, client_pubkey):
            self.logger.log(f"Connection failure. Bad signature from {c_id}", 1)
            client.send(b"BadSignature")
            client.close()
            return

        shared_key = dhke.calculate_shared_key(dhke_priv, int(c_dhke_pub, 16), self.dhke_group)
        encryption_key = sha256.hash(utils.i_to_b(shared_key))
        if c_id in self.client_outboxes:
            outbox = self.client_outboxes[c_id]
        else:
            outbox = Queue()
            self.client_outboxes[c_id] = outbox

        self.sockets[c_id] = client
        db = self._db_connect()
        db.user_login(c_id, client_pubkey)
        db.close()
        self.logger.log(f"User {c_id} successfully authenticated", 1)
        t_in = threading.Thread(target=self._in_thread, args=(client, encryption_key, c_id))
        t_out = threading.Thread(target=self._out_thread, args=(client, outbox, encryption_key))
        t_in.start()
        t_out.start()

    # thread methods
    def _in_thread(self, client: NonStreamSocket, encryption_key: int, id: str):
        while client.connected():
            if client.new():
                raw = client.recv()
                try:
                    iv, ciphertext = raw.decode().split(':', 1)
                except ValueError:
                    self.logger.log(f"Malformed message from {id}", 2)
                    return
                try:
                    iv = int(iv, 16)
                except ValueError:
                    self.logger.log(f"Invalid initialization vector {iv}", 2)
                    return
                data = aes256.decrypt_cbc(bytes.fromhex(ciphertext), encryption_key, iv)
                try:
                    recipient, message_type, message_values = self.message_parser.parse_message(data)
                except MessageParseException as e:
                    self.logger.log(str(e), 2)
                    return

                self.logger.log(f"{message_type} {id} -> {recipient}", 3)
                if recipient == "0":
                    response = self.message_parser.handle(id, message_type, message_values)
                    if response:
                        self.send(id, response)
                else:
                    to_send = self.message_parser.construct_message(id, message_type, *message_values)
                    self.send(recipient, to_send)

        db = self._db_connect()
        db.user_logout(id)
        db.close()
        self.logger.log(f"User {id} closed the connection", 1)
        self.sockets.pop(id)

    @staticmethod
    def _out_thread(sock: NonStreamSocket, outbox: Queue, encryption_key: int):
        while sock.connected():
            if not outbox.empty():
                message = outbox.get()
                aes_iv = random.randrange(1, 2 ** 128)
                encrypted_message = aes256.encrypt_cbc(message, encryption_key, aes_iv).hex().encode('utf-8')
                sock.send(hex(aes_iv).encode() + b':' + encrypted_message)

    # message type handler methods
    def _handler_get_key(self, sender: str, values: list) -> tuple[str, tuple]:
        target = values[0]

        self.logger.log(f"User {sender} requested key for user {target}", 3) 
        db = self._db_connect()
        if db.user_known(target):
            self.logger.log(f"Key found for user {target}", 3)
            key = db.get_pubkey(target)
            db.close()
            return "KeyFound", (target, *key)

        self.logger.log(f"Key not found for user {target}", 3)
        db.close()
        return "KeyNotFound", (target, )

    def _handler_quit(self, sender: str, _: list):
        self.logger.log(f"User {sender} requested a logout", 1)
        self.sockets[sender].close()

    def _db_connect(self) -> Server_DB:
        db = Server_DB(self.db_path, self.pubkey_path)
        return db
