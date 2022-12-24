import threading
import os
import random
import re
from typing import Union
from queue import Queue

from .cryptographylib import dhke, sha256, aes256
from .cryptographylib.utils import i_to_b
from .server_connection import ServerConnection
from .message_parser import MessageParser
from . import keys
from . import signing
from . import client_db
from .logger import Logger

INCOMING_MESSAGE_TYPES = {
        # type       argc arg types         additional type info (encoding, base, etc)
        "NewMessage": (3, [int, int, bytes], [10, 16]),
        "MessageAccept": (3, [int, int, bytes], [10, 16]),
        "MessageData": (3, [int, int, bytes], [10, 16]),
        "KeyFound": (3, [str, int, int], ['utf-8', 16, 16]),
        "KeyNotFound": (1, [str], ['utf-8']),
        "IndexInUse": (1, [int], [10]),
        "DecryptionFailure": (1, [int], [10]),
        "InvalidSignature": (1, [int], [10]),
        "NoSuchIndex": (1, [int], [10]),
        "ResendAuthPacket": (1, [int], [10])
}

OUTGOING_MESSAGE_TYPES = {
        "NewMessage": (3, [int, int, bytes], [10, 16]),
        "MessageAccept": (3, [int, int, bytes], [10, 16]),
        "MessageData": (3, [int, int, bytes], [10, 16]),
        "IndexInUse": (1, [int], [10]),
        "DecryptionFailure": (1, [int], [10]),
        "InvalidSignature": (1, [int], [10]),
        "NoSuchIndex": (1, [int], [10]),
        "ResendAuthPacket": (1, [int], [10]),
        "GetKey": (1, [str], ['utf-8'])
}

class Client:
    def __init__(self, ip: str, port: int, fingerprint: str, application_directory: str, logger: Logger):
        self.ip = ip
        self.port = port
        self.fingerprint = fingerprint
        self.server = None
        self.app_dir = application_directory
        self.pub = ()
        self.priv = ()
        self.dhke_group = dhke.group14_2048
        self.messages = {}
        self.client_pubkeys = {}
        self.running = False
        self.message_queue = Queue()
        message_response_map = {
            "KeyFound": self.handler_key_found,
            "KeyNotFound": self.handler_key_not_found,
            "NewMessage": self.handler_new_message,
            "MessageAccept": self.handler_message_accept,
            "MessageData": self.handler_message_data,
            "IndexInUse": self.handler_index_in_use,
            "ResendAuthPacket": self.handler_resend_auth_packet
        }
        self.message_parser = MessageParser(INCOMING_MESSAGE_TYPES, OUTGOING_MESSAGE_TYPES, message_response_map)
        self.logger = logger
    
    def receive(self) -> tuple[str, str]:
        return self.message_queue.get()

    def new_message(self) -> bool:
        return not self.message_queue.empty()
    
    def add_contact(self, nickname: str, id: str):
        db = self.db_connect()
        id = id.strip().lower()
        if re.fullmatch('^[0-9a-f]{64}$', id):
            db.set_nickname(id, nickname)
            db.close()
        else:
            self.logger.log("Invalid ID Format", 1)
            db.close()
    
    def get_contacts(self) -> list:
        db = self.db_connect()
        contacts = db.get_users()
        db.close()
        return contacts

    def send(self, recipient: str, message: bytes):
        db = self.db_connect()
        recipient_id = db.get_id(recipient)
        if recipient_id is None and re.fullmatch('^[a-fA-F0-9]{64}$', recipient):
            db.set_nickname(recipient, recipient)
        db.close()
        dh_priv = random.randrange(1, self.dhke_group[1])
        index = random.randrange(1, 2 ** 64)
        while index in self.messages:
            index = random.randrange(1, 2 ** 64)
        dh_pub, dh_sig = signing.gen_signed_diffie_hellman(dh_priv, self.priv, self.dhke_group, index)
        self.messages[index] = {
            "dh_private": dh_priv,
            "encryption_key": 0,
            "data": message
        }
        recipient = recipient_id if recipient_id else recipient
        message = self.message_parser.construct_message(recipient, "NewMessage", index, dh_pub, dh_sig)
        self.server.send(message)
        
    def run(self):
        os.makedirs(os.path.join(self.app_dir, "messages"), exist_ok=True)
        os.makedirs(os.path.join(self.app_dir, "keys"), exist_ok=True)
        db = self.db_connect()
        db.setup()
        db.close()
        try:
            self.pub = keys.load_key(os.path.join(self.app_dir, "client.pub"))
            self.priv = keys.load_key(os.path.join(self.app_dir, "client.priv"))
        except FileNotFoundError:
            self.pub, self.priv = keys.generate_keys(os.path.join(self.app_dir, "client.pub"), os.path.join(self.app_dir, "client.priv"))

        self.server = ServerConnection(self.ip, self.port, self.fingerprint, self.logger)
        self.server.connect(self.pub, self.priv, skip_fp_verify=False)
        self.running = True
        t_incoming = threading.Thread(target=self.incoming_thread, args=())
        t_incoming.start()
    
    def quit(self):
        self.server.send(self.message_parser.construct_message("0", "Quit"))
        self.running = False
        self.server.close()

    def get_id(self) -> str:
        return keys.fingerprint(self.pub)

    # methods for threads
    def incoming_thread(self):
        while self.running:
            if self.server.new_msg():
                msg = self.server.read()
                t_process = threading.Thread(target=self.msg_process_thread, args=(msg,))
                t_process.start()    
   
    def msg_process_thread(self, data: bytes):
        try:
            sender, message_type, message_values = self.message_parser.parse_message(data)
        except MessageParseException as e:
            self.logger.log(str(e), 1)

        response = self.message_parser.handle(sender, message_type, message_values)
        if response:
            self.server.send(response)
    
    # message type handlers

    def handler_key_found(self, _, values: list) -> None:
        db = self.db_connect()
        db.save_key(values[0], (values[1], values[2]))
        db.close()
    
    def handler_key_not_found(self, _, values: list) -> None:
        self.logger.log(f"Server could not locate public key for {values[0]}", 2)
    
    def handler_new_message(self, sender: str, values: list) -> tuple[str, tuple]:
        message_index, sender_dh_pub, sender_dh_sig = values

        db = self.db_connect()
        if message_index in self.messages:
            db.close()
            self.logger.log(f"Message from {sender} requested use of already-in-use index {message_index}", 3) 
            return "IndexInUse", (message_index, )

        if not db.user_known(sender):
            db.close()
            self.server.send(self.message_parser.construct_message("0", "GetKey", sender))
            self.logger.log(f"Message from unknown user {sender}", 3)
            return "ResendAuthPacket", (message_index, )
        
        signature_data = hex(sender_dh_pub)[2:].encode('utf-8') + b':' + hex(message_index)[2:].encode('utf-8')
        if not signing.verify(signature_data, sender_dh_sig, db.get_key(sender)):
            db.close()
            self.logger.log(f"Invalid Diffie Hellman signature from {sender}", 2)
            return "InvalidSignature", (message_index, )

        dh_priv = random.randrange(1, self.dhke_group[1])
        dh_pub, dh_pub_sig = signing.gen_signed_diffie_hellman(dh_priv, self.priv, self.dhke_group, message_index)
        shared_secret = dhke.calculate_shared_key(dh_priv, sender_dh_pub, self.dhke_group)
        encryption_key = sha256.hash(i_to_b(shared_secret))
        
        self.messages[message_index] = {"dh_private": dh_priv, "encryption_key": encryption_key, "data": b''}
        return "MessageAccept", (message_index, dh_pub, dh_pub_sig)

    def handler_message_accept(self, sender: str, values: list) -> tuple[str, tuple]:
        message_index, sender_dh_pub, sender_dh_sig = values

        if message_index not in self.messages:
            self.logger.log(f"Message acceptance from {sender} for non-existent message {message_index}", 2)
            return "NoSuchIndex", (message_index, )
        db = self.db_connect()
        if not db.user_known(sender):
            self.server.send(self.message_parser.construct_message("0", "GetKey", sender))
            db.close()
            self.logger.log(f"Message to unknown user {sender}", 2)
            return "ResendAuthPacket", (message_index, )
        
        signature_data = hex(sender_dh_pub)[2:].encode('utf-8') + b':' + hex(message_index)[2:].encode('utf-8')
        if not signing.verify(signature_data, sender_dh_sig, db.get_key(sender)):
            db.close()
            self.logger.log("Invalid Diffie Hellman signature from {sender}", 2)
            return "InvalidSignature", (message_index, )
        db.close()

        dh_priv = self.messages[message_index]["dh_private"]
        shared_secret = dhke.calculate_shared_key(dh_priv, sender_dh_pub, self.dhke_group)
        encryption_key = sha256.hash(i_to_b(shared_secret))
        plaintext = self.messages[message_index]["data"]
        aes_iv = random.randrange(2, 2 ** 128)
        ciphertext = aes256.encrypt_cbc(plaintext, encryption_key, aes_iv)
        self.messages.pop(message_index)
        return "MessageData", (message_index, aes_iv, ciphertext)
    
    def handler_message_data(self, sender: str, values: list) -> tuple[str, tuple]|None:
        message_index, aes_iv, ciphertext = values
        if message_index not in self.messages:
            self.logger.log(f"Message data from {sender} for non-existent message {message_index}", 2)
            return "NoSuchIndex", (message_index, )
        encryption_key = self.messages[message_index]["encryption_key"]
        plaintext = aes256.decrypt_cbc(ciphertext, encryption_key, aes_iv)
        try:
            plaintext = plaintext.decode('utf-8')
        except:
            self.logger.log(f"Failed to decrypt message from {sender}", 1)
            return "DecryptionFailure", (message_index, ) 
        self.messages.pop(message_index)
        db = self.db_connect()
        db.insert_message(sender, plaintext)
        nickname = db.get_nickname(sender)
        db.close()
        if nickname is None:
            self.message_queue.put((sender, plaintext))
        else:
            self.message_queue.put((nickname, plaintext))
            
    def handler_index_in_use(self, sender: str, values: list) -> tuple[str, tuple]:
        message_index = values[0]    

        self.logger.log(f"Requested message index {message_index} from {sender} but it was already in use", 3)
        message = self.messages[message_index]
        new_id = random.randrange(1, 2 ** 64)
        self.messages.pop(message_index)
        self.messages[new_id] = message
        dh_private = message["dh_private"]
        dh_public, dh_signature = signing.gen_signed_diffie_hellman(dh_private, self.priv, self.dhke_group, new_id)
        return "NewMessage", (new_id, dh_public, dh_signature)
        
    def handler_resend_auth_packet(self, sender: str, values: list) -> tuple[str, tuple]:
        message_index = values[0]

        self.logger.log(f"{sender} requested that I resend an authentication packet for message index {message_index}", 2)
        message = self.messages[message_index]
        dh_private = message["dh_private"]
        dh_public, dh_signature = signing.gen_signed_diffie_hellman(dh_private, self.priv, self.dhke_group, message_index)
        if message["encryption_key"]:
            return "MessageAccept", (message_index, dh_public, dh_signature)
        else:
            return "NewMessage", (message_index, dh_public, dh_signature)  

    def db_connect(self):
        db = client_db.Client_DB(os.path.join(self.app_dir, "client.db"), os.path.join(self.app_dir, "messages") + "/", os.path.join(self.app_dir, "keys") + "/")
        return db
