import json
import threading
import sys
import os
import re
from cryptographylib import dhke, sha256, aes256
from cryptographylib.utils import i_to_b
from server_connection import ServerConnection
import keys
import signing
import random
import client_db


MESSAGE_TYPES = {
    "client": {

            #type       #argc #arg types         #additional type info (encoding, base, etc)
            "NewMessage": (3, [int, int, bytes], [10, 16]),
            "MessageAccept": (3, [int, int, bytes], [10, 16]),
            "MessageData": (3, [int, int, int], [10, 16, 16])

            "IndexInUse": (1, [int], [10]),
            "InvalidSignature": (1, [int], [10]),
            "NoSuchIndex": (1, [int], [10])

    },
    "server": {
        "KeyFound": (3, [str, int, int], ['utf-8', 16, 16]),

        "KeyNotFound": (1, [str], ['utf-8'])
    }
}

def cast_from_bytes(values: list, message_schema: tuple) -> list:
    length, types, type_info = message_schema
    if len(values) != length:
        print(f"Cannot cast {len(values)} values to {length} types")
        return []
    casted = []
    for i in range(len(values)):
        try:
            if types[i] is int:
                casted.append(int(values[i], type_info[i]))
            elif types[i] is str:
                casted.append(str(values[i], type_info[i]))
            elif types[i] is bytes:
                casted.append(values[i])
        except TypeError:
            print(f"Cannot cast {values[i]} to {types[i]}")
            return []
    return casted

def construct_message(recipient: str, message_type: str, values: list) -> bytes:
    if recipient == '0':
        if message_type in MESSAGE_TYPES["server"]:
            message_schema = MESSAGE_TYPES["server"][message_type]
        else:
            print(f"Invalid server message type: {message_type}")
            return b''
    else:
        if message_type in MESSAGE_TYPES["client"]:
            message_schema = MESSAGE_TYPES["client"][message_type]
        else:
            print(f"Invalid client message type: {message_type}")
            return b''

    length, types, type_info = message_schema
    if len(values) != length:
        print(f"Invalid number of values for message type {message_type}")


def construct_server_message(message_type: str, *values) -> bytes:
    """
    Create a message to the server, of a specified type with specified values
    Args:
        message_type:
        *values:

    Returns:

    """
    if message_type not in MESSAGE_TYPES["server"]["valid"]:
        print(f"Invalid Message Type to Server: {message_type}")
        return b''
    length, types, type_info = MESSAGE_TYPES["server", "valid", "message_type"]
    if len(values) != length:
        print(f"Message to Server Has Wrong Number Of Arguments. Message Type: {message_type}")

def construct_exception(recipient: str, exception: str, *values) -> bytes:


class Client:
    def __init__(self, server_config_file: str, application_directory: str = "vcsms"):
        self.server_conf = server_config_file
        self.server = None
        self.app_dir = application_directory
        self.pub = ()
        self.priv = ()
        self.dhke_group = dhke.group14_2048
        self.messages = {}
        self.client_pubkeys = {}
        self.running = False

    def db_connect(self):
        db = client_db.Client_DB(os.path.join(self.app_dir, "client.db"))
        return db

    def message_handle(self, sender, message):
        db = self.db_connect()
        nickname = db.get_nickname(sender)
        print(f"New message from {nickname if nickname is not None else sender}: {message}\n\nvcsms:> ", end='')
        db.insert_message(sender, message)
        db.close()

    def process_server_exception(self, type: str, values: list):
        match type:
            case "KeyNotFound":
                print(f"Public Key Unknown For {values[0]}")

    def process_server_message(self, type: str, values: list):
        match type:
            case "KeyFound":
                self.client_pubkeys[values[0]] = (values[1], values[2])

    def process_client_exception(self, type: str, payload: list):
        match type:
            case "IndexInUse":
                if int(payload[0])

    def parse_message(self, data: bytes) -> bytes:
        """
        Parse a message, handle it, and return a response or empty bytestring if no response needed
        Args:
            data: The raw bytes of the message

        Returns:
            bytes: Either the response to the message or ''

        """
        if len(data) < 4096:
            return "invalid length"

        if re.fullmatch(re.compile('^[0-9a-fA-F]+:[A-z]+(:[A-z0-9])*'), data.decode()) is None:
            return "invalid format"

        sender, message_type, payload = data.decode().split(':')

        if sender == b'0':
            self.process_server_message(message_type, payload)

    def __msg_process_thread(self, data:bytes):
        msg = data.split(b':')

        sender = msg[0]
        if sender == b'0':
            if msg[1] == b'KeyFound':
                self.client_pubkeys[msg[2].decode()] = (int(msg[3], 16), int(msg[4], 16))

            elif msg[1] == b'KeyNotFound':
                print(f"Public Key Unknown For {msg[2].decode()}.")
        else:
            msg_type = msg[1]
            index = int(msg[2])

            if msg_type == b"NewMessage":
                if index in self.messages:
                    self.server.send(sender + b':IndexInUse:' + msg[2])
                    return

                p_dh_pub = int(msg[3], 16)
                p_dh_pub_sig = msg[4]
                if sender.decode() not in self.client_pubkeys:
                    self.server.send(b'0:GetKey:' + sender)
                    while sender.decode() not in self.client_pubkeys: continue

                if not signing.verify(msg[3], p_dh_pub_sig, self.client_pubkeys[sender.decode()]):
                    self.server.send(sender + b':InvalidSignature:' + msg[2])
                    return

                m_dh_priv = random.randrange(1, self.dhke_group[1])
                m_dh_pub = dhke.generate_public_key(m_dh_priv, self.dhke_group)
                m_dh_pub_sig = signing.sign(hex(m_dh_pub)[2:].encode(), self.priv)
                shared_secret = dhke.calculate_shared_key(m_dh_priv, p_dh_pub, self.dhke_group)
                encryption_key = sha256.hash(i_to_b(shared_secret))
                self.messages[index] = {"dh_private": 0,
                                        "encryption_key": encryption_key,
                                        "data": b''}
                self.server.send(sender + b':MessageAccept:' + msg[2] + b':' + hex(m_dh_pub)[2:].encode() + b':' + m_dh_pub_sig)

            elif msg_type == b"MessageAccept":
                if index not in self.messages:
                    self.server.send(sender + b':NoSuchIndex:' + msg[2])
                    return
                p_dh_pub = int(msg[3], 16)
                p_dh_pub_sig = msg[4]
                if sender.decode() not in self.client_pubkeys:
                    self.server.send(b'0:GetKey:' + sender)
                    while sender.decode() not in self.client_pubkeys: continue

                if not signing.verify(msg[3], p_dh_pub_sig, self.client_pubkeys[sender.decode()]):
                    self.server.send(sender + b':InvalidSignature:' + msg[2])
                    return

                m_dh_priv = self.messages[index]["dh_private"]
                shared_secret = dhke.calculate_shared_key(m_dh_priv, p_dh_pub, self.dhke_group)
                encryption_key = sha256.hash(i_to_b(shared_secret))
                plaintext = self.messages[index]["data"]
                aes_iv = random.randrange(1, 2**128)
                ciphertext = aes256.encrypt_cbc(plaintext, encryption_key, aes_iv)
                self.messages.pop(index)
                self.server.send(sender + b':MessageData:' + msg[2] + b':' + hex(aes_iv)[2:].encode() + b':' + hex(int.from_bytes(ciphertext, 'big'))[2:].encode())

            elif msg_type == b"MessageData":
                if index not in self.messages:
                    self.server.send(sender + b':NoSuchIndex:' + msg[2])
                    return
                iv = int(msg[3], 16)
                ciphertext = i_to_b(int(msg[4], 16))
                key = self.messages[index]["encryption_key"]
                plaintext = aes256.decrypt_cbc(ciphertext, key, iv)
                self.messages.pop(index)
                self.message_handle(sender.decode(), plaintext)
            else:
                print(f"Unrecognised message type: {msg_type.decode()}")

    def send(self, client: str, message: bytes):
        index = random.randrange(1, 2**64)
        db = self.db_connect()
        id = db.get_id(client)
        db.close()
        m_dh_priv = random.randrange(1, self.dhke_group[1])
        m_dh_pub = dhke.generate_public_key(m_dh_priv, self.dhke_group)
        m_dh_pub_sig = signing.sign(hex(m_dh_pub)[2:].encode(), self.priv)
        self.messages[index] = {
            "dh_private": m_dh_priv,
            "encryption_key": 0,
            "data": message
        }

        self.server.send((id.encode() if id else client.encode()) + b':NewMessage:' + str(index).encode() + b':' + hex(m_dh_pub)[2:].encode() + b':' + m_dh_pub_sig)
    def __thread_incoming(self):
        while self.running:
            if self.server.new_msg():
                msg = self.server.read()
                t_process = threading.Thread(target=self.__msg_process_thread, args=(msg, ))
                t_process.start()

    def add_contact(self, nickname: str, id: str):
        db = self.db_connect()
        db.set_nickname(id, nickname)
        db.close()
    def quit(self):
        self.running = False
        
    def run(self):
        os.makedirs(os.path.join(self.app_dir, "messages"), exist_ok=True)
        db = self.db_connect()
        db.setup()
        db.close()
        try:
            self.pub = keys.load_key(os.path.join(self.app_dir, "client.pub"))
            self.priv = keys.load_key(os.path.join(self.app_dir, "client.priv"))
        except FileNotFoundError:
            self.pub, self.priv = keys.generate_keys(os.path.join(self.app_dir, "client.pub"), os.path.join(self.app_dir, "client.priv"))

        with open(self.server_conf, 'r') as conf:
            config = json.loads(conf.read())
        self.server = ServerConnection(config["ip"], config["port"], config["fingerprint"])
        self.server.connect(self.pub, self.priv, skip_fp_verify=False)
        print(f"I AM {hex(keys.fingerprint(self.pub))[2:]}")
        self.running = True

        t_incoming = threading.Thread(target=self.__thread_incoming, args=())
        t_incoming.start()
