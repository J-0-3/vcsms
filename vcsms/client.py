"""Defines the Client class for messaging other VCSMS clients."""

import threading
import os
import random
import re
from queue import Queue

from .cryptographylib import dhke, sha256, aes256
from .cryptographylib.utils import i_to_b
from .cryptographylib.exceptions import DecryptionFailureException
from .server_connection import ServerConnection
from .message_parser import MessageParser
from .exceptions.message_parser import MessageParseException
from .exceptions.client import UserNotFoundException, IncorrectMasterKeyException
from . import keys
from . import signing
from . import client_db
from .logger import Logger

INCOMING_MESSAGE_TYPES = {
    # type       argc arg types         additional type info (encoding, base, etc)
    "NewMessage": (3, [int, int, bytes], [10, 16]),
    "MessageAccept": (3, [int, int, bytes], [10, 16]),
    "MessageData": (3, [int, int, bytes], [10, 16]),
    "KeyFound": (3, [int, int, int], [10, 16, 16]),
    "KeyNotFound": (1, [int], [10]),
    "IndexInUse": (1, [int], [10]),
    "DecryptionFailure": (1, [int], [10]),
    "InvalidSignature": (1, [int], [10]),
    "NoSuchIndex": (1, [int], [10]),
    "ResendAuthPacket": (1, [int], [10]),
    "UnknownMessageType": (1, [str], ['utf-8']),
    "NotAllowed": (1, [str], ['utf-8'])
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
    "GetKey": (2, [int, str], [10, 'utf-8']),
    "PublicKeyMismatch": (3, [str, int, int], ['utf-8', 16, 16]),
    "UnknownMessageType": (1, [str], ['utf-8']),
    "NotAllowed": (1, [str], ['utf-8'])
}


class Client:
    """
    A VCSMS messaging client. Allows for communication with other VCSMS clients.

    Remember to call the run() method before using the Client class.
    """

    def __init__(self, ip: str, port: int, fingerprint: str, application_directory: str,
                 master_password: str, logger: Logger):
        """Initialise a VCSMS messaging client.

        Args:
            ip (str): The ip address of the VCSMS server.
            port (int): The port of the VCSMS server (specified in the server's .vcsms file).
            fingerprint (str): The server's fingerprint (specified in the server's .vcsms file).
            application_directory (str): Where to store files created by the client.
            master_password (str): The master password used to encrypt data at rest.
            logger (Logger): An instance of vcsms.logger.Logger used to log all application events.
        """
        self._ip = ip
        self._port = port
        self._fingerprint = fingerprint
        self._server = None
        self._app_dir = application_directory
        self._pub = ()
        self._priv = ()
        self._dhke_group = dhke.group14_2048
        self._messages = {}
        self._key_requests = {}
        self._client_pubkeys = {}
        self._running = False
        self._encryption_key = sha256.hash(master_password.encode('utf-8'))
        self._nickname_iv = 0
        self._message_queue = Queue()
        message_response_map = {
            "KeyFound": self._handler_key_found,
            "KeyNotFound": self._handler_key_not_found,
            "NewMessage": self._handler_new_message,
            "MessageAccept": self._handler_message_accept,
            "MessageData": self._handler_message_data,
            "IndexInUse": self._handler_index_in_use,
            "ResendAuthPacket": self._handler_resend_auth_packet
        }
        self._message_parser = MessageParser(
            INCOMING_MESSAGE_TYPES, OUTGOING_MESSAGE_TYPES, message_response_map)
        self._logger = logger

    def receive(self) -> tuple[str, bytes]:
        """Block until a new message is available and then return it.

        Returns:
            tuple[str, bytes]: The message sender and data
        """
        return self._message_queue.get()

    def new_message(self) -> bool:
        """Check whether there is a new message available.

        Returns:
            bool: Whether a new message is available
        """
        return not self._message_queue.empty()

    def add_contact(self, nickname: str, client_id: str):
        """Add a new contact with a (unique) nickname and client ID.

        Args:
            nickname (str): The nickname for the contact.
            client_id (str): The contact's client ID (a 64 char hex string).
        """
        db = self._db_connect()
        client_id = client_id.strip().lower()
        if re.fullmatch('^[0-9a-f]{64}$', client_id):
            db.set_nickname(client_id, nickname)
            db.close()
        else:
            self._logger.log("Invalid ID Format", 1)
            db.close()

    def get_contacts(self) -> list[str]:
        """Get a list of all contacts known.

        Returns:
            list[str]: The nicknames of every stored contact.
        """
        db = self._db_connect()
        contacts = db.get_users()
        db.close()
        return contacts

    def get_messages(self, nickname: str, count: int) -> list[tuple[bytes, bool]]:
        """Get the last *count* messages to/from the specified nickname.

        Args:
            nickname (str): The nickname to lookup.
            count (int): The (maximum) number of messages to/from the specified nickname to return.

        Returns:
            list[tuple[bytes, bool]]: The last *count* messages to/from the client in time order
                (newest first) in the format (message, outgoing) where message is the raw message
                and outgoing is a bool determining whether the message was sent or received.
        """
        db = self._db_connect()
        messages = db.get_messages_by_nickname(nickname, count)
        db.close()
        return messages
    
    def message_count(self, nickname: str) -> int:
        """Get the number of previous messages to/from the specified nickname.

        Args:
            nickname (str): The nickname to lookup. 

        Returns:
            int: The number of messages available. 
        """
        db = self._db_connect()
        count = db.count_messages(nickname)
        db.close()
        return count

    def send(self, recipient: str, message: bytes):
        """Send a message to a given recipient.

        Args:
            recipient (str): The recipient (nickname or client ID) to send the message to.
            message (bytes): The message to send.
        """
        db = self._db_connect()
        recipient_id = db.get_id(recipient)
        if recipient_id is None:
            if re.fullmatch('^[a-fA-F0-9]{64}$', recipient):
                db.set_nickname(recipient, recipient)
                recipient_id = recipient
            else:
                raise UserNotFoundException(recipient)        
        db.insert_message(recipient_id, message, True)
        db.close()
        dh_priv = random.randrange(1, self._dhke_group[1])
        index = random.randrange(1, 2 ** 64)
        while index in self._messages:
            index = random.randrange(1, 2 ** 64)
        dh_pub, dh_sig = signing.gen_signed_diffie_hellman(
            dh_priv, self._priv, self._dhke_group, index)
        self._messages[index] = {
            "client_id": recipient_id,
            "dh_private": dh_priv,
            "encryption_key": 0,
            "data": message
        }
        message = self._message_parser.construct_message(
            recipient_id, "NewMessage", index, dh_pub, dh_sig)
        self._server.send(message)

    def run(self):
        """Connect to the VCSMS server and begin running the client program.
        This should always be the first method called on the Client class.

        Raises:
            IncorrectMasterKeyException: The supplied master key is not correct.
        """
        os.makedirs(os.path.join(self._app_dir, "keys"), exist_ok=True)
        if os.path.exists(os.path.join(self._app_dir, "keytest")):
            if not self._check_master_key():
                raise IncorrectMasterKeyException()
        else:
            self._create_master_key_test()

        if os.path.exists(os.path.join(self._app_dir, "nickname.iv")):
            with open(os.path.join(self._app_dir, "nickname.iv"), 'r', encoding='utf-8') as f:
                ciphertext_iv, ciphertext = f.read().split(':')
            ciphertext_iv = int(ciphertext_iv, 16)
            ciphertext = bytes.fromhex(ciphertext)
            self._nickname_iv = int(aes256.decrypt_cbc(
                ciphertext, self._encryption_key, ciphertext_iv), 16)
        else:
            self._nickname_iv = random.randrange(0, 2**128)
            with open(os.path.join(self._app_dir, "nickname.iv"), 'w+', encoding='utf-8') as f:
                ciphertext_iv = random.randrange(0, 2**128)
                ciphertext = aes256.encrypt_cbc(hex(self._nickname_iv)[2:].encode(
                    'utf-8'), self._encryption_key, ciphertext_iv)
                f.write(f"{hex(ciphertext_iv)[2:]}:{ciphertext.hex()}")

        db = self._db_connect()
        db.setup()
        db.close()
        try:
            self._pub = keys.load_key(
                os.path.join(self._app_dir, "client.pub"))
            self._priv = keys.load_key(
                os.path.join(self._app_dir, "client.priv"))
        except FileNotFoundError:
            self._pub, self._priv = keys.generate_keys(os.path.join(
                self._app_dir, "client.pub"), os.path.join(self._app_dir, "client.priv"))

        self._server = ServerConnection(
            self._ip, self._port, self._fingerprint, self._logger)
        self._server.connect(self._pub, self._priv)
        self._running = True
        t_incoming = threading.Thread(target=self._incoming_thread, args=())
        t_incoming.start()

    def quit(self):
        """Close the connection with the server and shutdown the client program."""
        self._server.send(self._message_parser.construct_message("0", "Quit"))
        self._running = False
        self._server.close()

    def get_id(self) -> str:
        """Get the client ID associated with this client instance.

        Returns:
            str: The client ID (pub key fingerprint) corresponding with this instance of the client.
        """
        return keys.fingerprint(self._pub)

    def _request_key(self, client_id: str):
        request_index = random.randrange(1, 2**64)
        while request_index in self._key_requests:
            request_index = random.randrange(1, 2**64)
        self._key_requests[request_index] = client_id
        self._server.send(self._message_parser.construct_message(
            "0", "GetKey", request_index, client_id))

    def _create_master_key_test(self):
        """Create a file containing some random plaintext and ciphertext
        encrypted with the currently set master key
        for checking the correctness of the master key in future runs.
        This should only get run on the first run of the client program."""
        with open(os.path.join(self._app_dir, "keytest"), 'w+', encoding='utf-8') as f:
            data = random.randbytes(1024)
            aes_iv = random.randrange(0, 2**128)
            encrypted_data = aes256.encrypt_cbc(data, self._encryption_key, aes_iv)
            f.write(f"{data.hex()}:{hex(aes_iv)[2:]}:{encrypted_data.hex()}")

    def _check_master_key(self) -> bool:
        """Check whether the currently set master key is correct
        (corresponds with the original master key that was set on first run).

        Returns:
            bool: Whether the master key is correct
        """
        with open(os.path.join(self._app_dir, "keytest"), 'r', encoding='utf-8') as f:
            plaintext, aes_iv, ciphertext = f.read().split(':')
        plaintext = bytes.fromhex(plaintext)
        aes_iv = int(aes_iv, 16)
        ciphertext = bytes.fromhex(ciphertext)
        if ciphertext == aes256.encrypt_cbc(plaintext, self._encryption_key, aes_iv):
            return True
        return False

    # methods for threads
    def _incoming_thread(self):
        """The function run by the incoming thread. 
        Keeps checking for new messages and processes them on a new thread as they arrive.
        """
        while self._running:
            if self._server.new_msg():
                msg = self._server.read()
                t_process = threading.Thread(
                    target=self._msg_process_thread, args=(msg,))
                t_process.start()

    def _msg_process_thread(self, data: bytes):
        """The function run by the processing thread for each incoming message.
        Parses the message data and runs the corresponding handler function.

        Args:
            data (bytes): The raw message bytes.
        """
        try:
            sender, message_type, message_values = self._message_parser.parse_message(
                data)
        except MessageParseException as parse_exception:
            self._logger.log(str(parse_exception), 1)

        response = self._message_parser.handle(
            sender, message_type, message_values)
        if response:
            self._server.send(response)

    # message type handlers

    def _handler_key_found(self, sender: str, values: list) -> None | tuple[str, tuple]:
        """Handler function for the KeyFound message type.

        Args:
            sender (str): The client ID which sent the message
            values (list): The parameters of the message (request index, exponent, modulus)

        Returns:
            None | tuple[str, tuple]: None if successful
                PublicKeyMismatch: The supplied key's fingerprint does not match the client ID.
                NotAllowed: The message did not originate from the server.
                NoSuchIndex: The request index does not match any existing key request
        """
        request_index, exponent, modulus = values

        if sender == '0':
            if request_index in self._key_requests:
                client_id = self._key_requests[request_index]
                self._key_requests.pop(request_index)
                if keys.fingerprint((exponent, modulus)) == client_id:
                    db = self._db_connect()
                    db.save_key(client_id, (exponent, modulus))
                    db.close()
                    return None
                return "PublicKeyMismatch", (client_id, exponent, modulus)
            return "NoSuchIndex", (request_index, )
        return "NotAllowed", ("KeyFound", )

    def _handler_key_not_found(self, sender: str, values: list) -> None | tuple[str, tuple]:
        """Handler function for the KeyNotFound message type.

        Args:
            values (list): The parameters of the message (client ID)

        Returns:
            None | tuple[str, tuple]: None if successful.
                NoSuchIndex: The request index does not match any existing key request.
                NotAllowed: The message did not originate from the server.
        """
        if sender == '0':
            req_index = values[0]
            if req_index in self._key_requests:
                client_id = self._key_requests[req_index]
                self._logger.log(
                    f"Server could not locate key for {client_id}", 2)
                self._key_requests.pop(req_index)
                return None
            return "NoSuchIndex", (req_index, )
        return "NotAllowed", ("KeyNotFound", )

    def _handler_new_message(self, sender: str, values: list) -> tuple[str, tuple]:
        """Handler function for the NewMessage message type.

        Args:
            sender (str): The client ID who sent the message.
            values (list): The parameters of the message
                (message index (int), diffie hellman key (int), diffie hellman signature (bytes))

        Returns:
            tuple[str, tuple]: MessageAccept if successful.
                IndexInUse: The message index is already being used by another message in process.
                ResendAuthPacket: The sender is unknown and authentication needs to be retried
                    after the public key is obtained (also sends a GetKey request).
                InvalidSignature: The diffie hellman public key was incorrectly signed.
        """
        message_index, sender_dh_pub, sender_dh_sig = values
        if message_index in self._messages:
            self._logger.log(
                f"Message from {sender} requested use of already-in-use index {message_index}", 3)
            return "IndexInUse", (message_index, )

        db = self._db_connect()
        if not db.user_known(sender):
            db.close()
            self._request_key(sender)
            self._logger.log(f"Message from unknown user {sender}", 3)
            return "ResendAuthPacket", (message_index, )

        signature_data = hex(sender_dh_pub)[2:].encode(
            'utf-8') + b':' + hex(message_index)[2:].encode('utf-8')
        if not signing.verify(signature_data, sender_dh_sig, db.get_key(sender)):
            db.close()
            self._logger.log(
                f"Invalid Diffie Hellman signature from {sender}", 2)
            return "InvalidSignature", (message_index, )

        db.close()
        dh_priv = random.randrange(1, self._dhke_group[1])
        dh_pub, dh_pub_sig = signing.gen_signed_diffie_hellman(
            dh_priv, self._priv, self._dhke_group, message_index)
        shared_secret = dhke.calculate_shared_key(
            dh_priv, sender_dh_pub, self._dhke_group)
        encryption_key = sha256.hash(i_to_b(shared_secret))

        self._messages[message_index] = {
            "client_id": sender,
            "dh_private": dh_priv,
            "encryption_key": encryption_key,
            "data": b''}
        return "MessageAccept", (message_index, dh_pub, dh_pub_sig)

    def _handler_message_accept(self, sender: str, values: list) -> tuple[str, tuple]:
        """Handler for the MessageAccept message type.

        Args:
            sender (str): The client ID who sent the message.
            values (list): The message parameters
                (message index (int), diffie hellman key (int), diffie hellman signature (bytes))

        Returns:
            tuple[str, tuple]: MessageData if successful.
                NoSuchIndex: The message index does not correspond to any in process message.
                ResendAuthPacket: The sender is unknown and authentication needs to be retried
                    after the public key is obtained (also sends a GetKey request).
                InvalidSignature: The diffie hellman public key was incorrectly signed.
                NotAllowed: The message index is in use by a different client to the sender.
        """
        message_index, sender_dh_pub, sender_dh_sig = values

        if message_index not in self._messages:
            self._logger.log(
                f"Message acceptance from {sender} for non-existent message {message_index}", 2)
            return "NoSuchIndex", (message_index, )
        if sender == self._messages[message_index]["client_id"]:
            db = self._db_connect()
            if not db.user_known(sender):
                self._request_key(sender)
                db.close()
                self._logger.log(f"Message to unknown user {sender}", 2)
                return "ResendAuthPacket", (message_index, )

            signature_data = hex(sender_dh_pub)[2:].encode('utf-8') + b':' + hex(message_index)[2:].encode('utf-8')
            if not signing.verify(signature_data, sender_dh_sig, db.get_key(sender)):
                db.close()
                self._logger.log("Invalid Diffie Hellman public key signature from {sender}", 2)
                return "InvalidSignature", (message_index, )
            db.close()

            dh_priv = self._messages[message_index]["dh_private"]
            shared_secret = dhke.calculate_shared_key(
                dh_priv, sender_dh_pub, self._dhke_group)
            encryption_key = sha256.hash(i_to_b(shared_secret))
            plaintext = self._messages[message_index]["data"]
            aes_iv = random.randrange(2, 2 ** 128)
            ciphertext = aes256.encrypt_cbc(plaintext, encryption_key, aes_iv)
            self._messages.pop(message_index)
            return "MessageData", (message_index, aes_iv, ciphertext)
        return "NotAllowed", ("MessageAccept", )

    def _handler_message_data(self, sender: str, values: list) -> tuple[str, tuple] | None:
        """Handler function for the MessageData message type.

        Args:
            sender (str): The client ID who sent the message. 
            values (list): The parameters of the message (message index (int), AES initialisation vector (int), ciphertext (bytes)) 

        Returns:
            tuple[str, tuple] | None: None if successful.
                NoSuchIndex: The message index does not correspond to any in process message.
                DecryptionFailure: The message ciphertext was unable to be decrypted.
                NotAllowed: The message index is in use by a different client id to the sender.
        """
        message_index, aes_iv, ciphertext = values
        if message_index not in self._messages:
            self._logger.log(
                f"Message data from {sender} for non-existent message {message_index}", 2)
            return "NoSuchIndex", (message_index, )

        if sender == self._messages[message_index]["client_id"]:
            encryption_key = self._messages[message_index]["encryption_key"]
            try:
                plaintext = aes256.decrypt_cbc(ciphertext, encryption_key, aes_iv)
            except DecryptionFailureException:
                self._logger.log(f"Failed to decrypt message from {sender}", 1)
                return "DecryptionFailure", (message_index, )
            self._messages.pop(message_index)
            db = self._db_connect()
            db.insert_message(sender, plaintext, False)
            nickname = db.get_nickname(sender)
            if nickname is None:
                db.set_nickname(sender, sender)
                self._message_queue.put((sender, plaintext))
            else:
                self._message_queue.put((nickname, plaintext))
            db.close()
            return None
        return "NotAllowed", ("MessageData", )

    def _handler_index_in_use(self, sender: str, values: list) -> tuple[str, tuple]:
        """Handler function for the IndexInUse message type.

        Args:
            sender (str): The client ID who sent the message. 
            values (list): The parameters of the message (message index (int))

        Returns:
            tuple[str, tuple]: NewMessage if successful
                NotAllowed: The message index is in use by a different client id to the sender
        """
        message_index = values[0]

        if sender == self._messages[message_index]["client_id"]:
            self._logger.log(f"Requested message index {message_index} from {sender} but it was already in use", 3)
            message = self._messages[message_index]
            new_id = random.randrange(1, 2 ** 64)
            self._messages.pop(message_index)
            self._messages[new_id] = message
            dh_private = message["dh_private"]
            dh_public, dh_signature = signing.gen_signed_diffie_hellman(dh_private, self._priv, self._dhke_group, new_id)
            return "NewMessage", (new_id, dh_public, dh_signature)
        return "NotAllowed", ("IndexInUse", )

    def _handler_resend_auth_packet(self, sender: str, values: list) -> tuple[str, tuple]:
        """Handler function for the ResendAuthPacket message type.

        Args:
            sender (str): The client ID who sent the message. 
            values (list): The parameters of the message (message index (int)) 

        Returns:
            tuple[str, tuple]: NewMessage or MessageAccept depending on the message state.
                NotAllowed: The message index is in use by a different client ID to the sender.
        """
        message_index = values[0]

        if sender == self._messages[message_index]["client_id"]:
            self._logger.log(f"{sender} requested that I resend an authentication packet for message index {message_index}", 2)
            message = self._messages[message_index]
            dh_private = message["dh_private"]
            dh_public, dh_signature = signing.gen_signed_diffie_hellman(dh_private, self._priv, self._dhke_group, message_index)
            if message["encryption_key"]:
                return "MessageAccept", (message_index, dh_public, dh_signature)
            return "NewMessage", (message_index, dh_public, dh_signature)
        return "NotAllowed", ("ResentAuthPacket", )

    def _handler_unknown(self, sender: str, message_type: str, values: list) -> tuple[str, tuple]:
        """Handler function for unknown message types.

        Args:
            sender (str): The client ID which sent the message.
            message_type (str): The unknown message type.
            values (list): The parameters of the message.

        Returns:
            tuple[str, tuple]: UnknownMessageType
        """
        self._logger.log(f"{sender} sent a message of unknown type {message_type} with values {values}", 2)
        return "UnknownMessageType", (message_type, )

    def _db_connect(self) -> client_db.Client_DB:
        """Connect to the client database.

        Returns:
            Client_DB: A connection to the client database 
        """
        db = client_db.Client_DB(os.path.join(self._app_dir, "client.db"), os.path.join(
            self._app_dir, "keys") + "/", self._encryption_key, self._nickname_iv)
        return db
