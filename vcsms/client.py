"""Defines the Client class for messaging other VCSMS clients."""

import threading
import os
import random
import re
import time
import json
from json.decoder import JSONDecodeError
from queue import Queue
from typing import Callable

from .cryptographylib import dhke, sha256, aes256, rsa
from .cryptographylib.utils import i_to_b
from .cryptographylib.exceptions import DecryptionFailureException
from .server_connection import ServerConnection
from .message_parser import MessageParser
from .exceptions.message_parser import MessageParseException
from .exceptions.client import UserNotFoundException, IncorrectMasterKeyException, GroupNameInUseException
from . import keys
from . import signing
from . import client_db
from .logger import Logger

INCOMING_MESSAGE_TYPES = {
    # type       argc arg types         additional type info (encoding, base, etc)
    # message index, diffie hellman pub, diffie hellman sig
    "NewMessage": (3, [int, int, bytes], [10, 16, None]),
    # message index, diffie hellman pub, diffie hellman sig
    "MessageAccept": (3, [int, int, bytes], [10, 16, None]),
    # message index, initialisation vector, message data
    "MessageData": (3, [int, int, bytes], [10, 16, None]),
    # request index, exponent, modulus (server only)
    "KeyFound": (3, [int, int, int], [10, 16, 16]),
    # request index (server only)
    "KeyNotFound": (1, [int], [10]),
    # message index
    "IndexInUse": (1, [int], [10]),
    "MessageDecryptionFailure": (1, [int], [10]),
    "InvalidSignature": (1, [int], [10]),
    "NoSuchIndex": (1, [int], [10]),
    "ResendAuthPacket": (1, [int], [10]),
    # message type
    "UnknownMessageType": (1, [str], ['utf-8']),
    "NotAllowed": (1, [str], ['utf-8']),
    # encrypted group name, signature, group id, members
    "CreateGroup": (4, [bytes, bytes, int, list], [None, None, 10, (str, 'utf-8')]),
    # group id, new group id, signature
    "ChangeGroupID": (3, [int, int, bytes], [10, 10, None]),
    # group id, signature
    "GroupIDInUse": (2, [int, bytes], [10, None]),
    # group id
    "NoSuchGroup": (1, [int], [10]),
    "GroupNameDecryptionFailure": (1, [int], [10])
}

OUTGOING_MESSAGE_TYPES = {
    # message index, diffie hellman pub, diffie hellman sig
    "NewMessage": (3, [int, int, bytes], [10, 16, None]),
    # message index, diffie hellman pub, diffie hellman sig
    "MessageAccept": (3, [int, int, bytes], [10, 16, None]),
    # message index, initialisation vector, message data
    "MessageData": (3, [int, int, bytes], [10, 16, None]),
    # message index
    "IndexInUse": (1, [int], [10]),
    "MessageDecryptionFailure": (1, [int], [10]),
    "InvalidSignature": (1, [int], [10]),
    "NoSuchIndex": (1, [int], [10]),
    "ResendAuthPacket": (1, [int], [10]),
    # request index, client id (server only)
    "GetKey": (2, [int, str], [10, 'utf-8']),
    # client id, exponent, modulus (server only)
    "PublicKeyMismatch": (3, [str, int, int], ['utf-8', 16, 16]),
    # request index (server only)
    "NoSuchKeyRequest": (1, [int], [10]),
    # message type
    "UnknownMessageType": (1, [str], ['utf-8']),
    "NotAllowed": (1, [str], ['utf-8']),
    # encrypted group name, signature, group id, members
    "CreateGroup": (4, [bytes, bytes, int, list], [None, None, 10, (str, 'utf-8')]),
    # group id, new id, signature
    "ChangeGroupID": (3, [int, int, bytes], [10, 10, None]),
    # group id, signature
    "GroupIDInUse": (2, [int, bytes], [10, None]),
    # group id
    "NoSuchGroup": (1, [int], [10]),
    "GroupNameDecryptionFailure": (1, [int], 10)
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
        self._group_message_queue = Queue()
        message_response_map = {
            "KeyFound": self._handler_key_found,
            "KeyNotFound": self._handler_key_not_found,
            "NewMessage": self._handler_new_message,
            "MessageAccept": self._handler_message_accept,
            "MessageData": self._handler_message_data,
            "IndexInUse": self._handler_index_in_use,
            "ResendAuthPacket": self._handler_resend_auth_packet,
            "CreateGroup": self._handler_create_group,
            "ChangeGroupID": self._handler_change_group_id,
            "GroupIDInUse": self._handler_group_id_in_use
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

    def rename_contact(self, old_nickname: str, new_nickname: str):
        """Rename the contact with the old nickname to have the new nickname.

        The new nickname must not match any existing contact nickname

        Args:
            old_nickname (str): The nickname of the contact to rename.
            new_nickname (str): The new nickname of the contact.

        Raises:
            sqlite3.IntegrityError: The new nickname is already in use
        """
        db = self._db_connect()
        db.change_nickname(old_nickname, new_nickname)
        db.close()

    def delete_contact(self, nickname: str):
        """Delete the contact with a given nickname.

        Args:
            nickname (str): The nickname of the contact to delete.
        """
        db.delete_contact_by_nickname(nickname)
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

    def get_messages(self, name: str, count: int) -> list[tuple[bytes, bool]]:
        """Get the last *count* messages to/from the specified user.

        Args:
            nickname (str): The nickname to lookup.
            count (int): The (maximum) number of messages to/from the specified nickname to return.

        Returns:
            list[tuple[bytes, bool]]: The last *count* messages to/from the client in time order
                (newest first) in the format (message, outgoing) where message is the raw message
                and outgoing is a bool determining whether the message was sent or received.
        """
        db = self._db_connect()
        messages = db.get_messages_by_nickname(name, count)
        db.close()
        return messages

    def get_group_messages(self, group_name: str, count: int) -> list[tuple[bytes, str]]:
        """Get the last *count* messages to/from the specified group.

        Args:
            group_name (str): The name of the group to lookup 
            count (int): The (maximum) number of messages to return 

        Returns:
            list[tuple[bytes, str]]: The last *count* messages to/from the group in time order
                (newest first) in the format (message, sender) where message is the raw message
                and sender is the client id who sent the message.
        """
        db = self._db_connect()
        messages = db.get_group_messages(group_name, count)
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
            "data": message.decode('latin1'),  # needs to be JSON serializable
            "group": ''
        }
        message = self._message_parser.construct_message(
            recipient_id, "NewMessage", index, dh_pub, dh_sig)
        self._server.send(message)

    def group_send(self, group: str, message: bytes):
        """Send a message to all recipients in the sepecified group.

        Args:
            group (str): The name of the group to sent the messages to.
            message (bytes): The message to send.
        """
        db = self._db_connect()
        recipients = db.get_members(group)

        for recipient in recipients:
            db.insert_message(recipient, message, True)
            db.close()
            dh_priv = random.randrange(1, self._dhke_group[1])
            index = random.randrange(1, 2**64)
            while index in self._messages:
                index = random.randrange(1, 2**64)
            dh_pub, dh_sig = signing.gen_signed_diffie_hellman(dh_priv, self._priv, self._dhke_group, index)
            self._messages[index] = {
                "client_id": recipient,
                "dh_private": dh_priv,
                "encryption_key": 0,
                "data": message.decode('latin1'),
                "group": group
            }
            message = self._message_parser.construct_message(recipient, "NewMessage", index, dh_pub, dh_sig)
            self._server.send(message)

    def create_group(self, name: str, *members: str):
        """Create a group of users which can be used to send group messages.

        Args:
            name (str): The name of the group.
            *members (str): The ids/nicknames of the members to add to the group.
        """
        member_ids = []
        db = self._db_connect()
        for member in members:
            member_id = db.get_id(member)
            if member_id is None:
                if re.fullmatch("^[a-fA-F0-9]{64}$", member_id):
                    member_id = member
                else:
                    raise UserNotFoundException(member)
            member_ids.append(member_id)

        group_id = random.randrange(1, 2**64)
        while db.get_group_name(group_id):
            group_id = random.randrange(1, 2**64)

        if db.get_group_id(name) or db.get_id(name):
            raise GroupNameInUseException(name)

        db.create_group(name, group_id, self.get_id(), member_ids)

        def invite_user(user: str):
            key = db.get_key(user)

            signature_data = (name + hex(group_id) + ''.join(member_ids) + user).encode('utf-8')
            signature = signing.sign(signature_data, self._priv)
            encrypted_group_name = rsa.encrypt(name.encode('utf-8'), *key)
            invite_message = self._message_parser.construct_message(
                user, "CreateGroup",
                encrypted_group_name, signature, group_id, member_ids)
            self._server.send(invite_message)

        for member_id in member_ids:
            if db.user_known(member_id):
                invite_user(member_id)
            else:
                self._request_key(member_id)
                await_key_thread = threading.Thread(target=self._await_key, args=(member_id, invite_user, member_id))
                await_key_thread.start()

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
            self._nickname_iv = int(aes256.decrypt_cbc(ciphertext, self._encryption_key, ciphertext_iv), 16)
        else:
            self._nickname_iv = random.randrange(0, 2**128)
            with open(os.path.join(self._app_dir, "nickname.iv"), 'w+', encoding='utf-8') as f:
                ciphertext_iv = random.randrange(0, 2**128)
                ciphertext = aes256.encrypt_cbc(hex(self._nickname_iv)[2:].encode('utf-8'), self._encryption_key, ciphertext_iv)
                f.write(f"{hex(ciphertext_iv)[2:]}:{ciphertext.hex()}")

        db = self._db_connect()
        db.setup()
        db.close()
        public_key_path = os.path.join(self._app_dir, "client.pub")
        private_key_path = os.path.join(self._app_dir, "client.priv")
        try:
            self._pub = keys.load_key(public_key_path)
            self._priv = keys.load_key(private_key_path, self._encryption_key)
        except FileNotFoundError:
            self._pub, self._priv = keys.generate_keys(public_key_path, private_key_path, self._encryption_key)

        self._server = ServerConnection(self._ip, self._port, self._fingerprint, self._logger)
        self._server.connect(self._pub, self._priv)
        self._running = True
        self._load_saved_in_process_messages()
        t_incoming = threading.Thread(target=self._incoming_thread, args=())
        t_incoming.start()

    def quit(self):
        """Close the connection with the server and shutdown the client program."""
        self._server.send(self._message_parser.construct_message("0", "Quit"))
        self._running = False
        self._server.close()
        self._save_in_process_messages()

    def get_id(self) -> str:
        """Get the client ID associated with this client instance.

        Returns:
            str: The client ID (pub key fingerprint) corresponding with this instance of the client.
        """
        return keys.fingerprint(self._pub)

    def _request_key(self, client_id: str):
        """Request a user's public key from the server.

        Args:
            client_id (str): The client ID to request. 
        """
        request_index = random.randrange(1, 2**64)
        while request_index in self._key_requests:
            request_index = random.randrange(1, 2**64)
        self._key_requests[request_index] = client_id
        message = self._message_parser.construct_message("0", "GetKey", request_index, client_id)
        self._server.send(message)

    def _await_key(self, client_id: str, callback: Callable, *args):
        """Wait until the public key for a given client id is known and then execute
        a callback function. Useful if the public key is required for some operation
        which can be executed asynchronously.

        Args:
            client_id (str): The client id to await the public key of
            callback (Callable): A callback function to execute once the key is received. Use 'lambda: None' to run no callback.
            *args: The arguments of the callback function
        """
        db = self._db_connect()
        while not db.user_known(client_id):
            time.sleep(0.1)
        db.close()
        callback(*args)

    def _save_in_process_messages(self):
        """Save the status of currently in process messages so that they
        can be sent when next online."""
        with open(os.path.join(self._app_dir, "in_process.msgs"), 'w+', encoding='utf-8') as f:
            encrypted_statuses_json = {}
            for index,message in self._messages.items():
                message_status_json = json.dumps(message)
                initialisation_vector = random.randrange(1, 2**128)
                encrypted_message_status = aes256.encrypt_cbc(message_status_json.encode('utf-8'), self._encryption_key, initialisation_vector)
                encrypted_statuses_json[index] = f"{initialisation_vector}:{encrypted_message_status.hex()}"
            json.dump(encrypted_statuses_json, f)

    def _load_saved_in_process_messages(self):
        """Load any saved message states to continue sending/receiving them."""
        if os.path.exists(os.path.join(self._app_dir, "in_process.msgs")):
            with open(os.path.join(self._app_dir, "in_process.msgs"), 'r', encoding='utf-8') as f:
                encrypted_statuses_json = json.load(f)
                for index,encrypted_record in encrypted_statuses_json.items():
                    initialisation_vector, ciphertext_hex = encrypted_record.split(':')
                    initialisation_vector = int(initialisation_vector)
                    ciphertext = bytes.fromhex(ciphertext_hex)
                    message_status = aes256.decrypt_cbc(ciphertext, self._encryption_key, initialisation_vector)
                    message_status_json = json.loads(message_status.decode('utf-8'))
                    self._messages[int(index)] = message_status_json

    def _create_master_key_test(self):
        """Create a file containing some random plaintext and ciphertext
        encrypted with the currently set master key
        for checking the correctness of the master key in future runs.
        This should only get run on the first run of the client program.
        """
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

    def _handler_create_group(self, sender: str, values: list) -> None | tuple[str, tuple]:
        """Handler function for the CreateGroup message type

        Args:
            sender (str): The client ID which sent the message
            value (list): The parameters of the message
                (encrypted group name, signature, group id, members)

        Returns:
            None | tuple[str, tuple]: None if successful
                GroupIDInUse: There is already a group with that ID on this client
                InvalidSignature: The message was improperly signed
                GroupNameDecryptionFailure: The group name could not be decrypted
        """
        encrypted_group_name, signature, group_id, members = values
        try:
            group_name = rsa.decrypt(encrypted_group_name, self._priv[0], self._priv[1])
        except DecryptionFailureException:
            return "GroupNameDecryptionFailure", (group_id, )
        group_name = group_name.decode('utf-8')
        signature_data = (group_name + hex(group_id) + ''.join(members)
                          + self.get_id()).encode('utf-8')
        db = self._db_connect()
        if not db.user_known(sender):
            self._request_key(sender)
            self._await_key(sender, lambda: None)

        if signing.verify(signature_data, signature, db.get_key(sender)):
            if db.get_group_name(group_id):
                response_signature_data = f"{group_id}{group_name}{sender}".encode('utf-8')
                response_signature = signing.sign(response_signature_data, self._priv)
                return "GroupIDInUse", (group_id, response_signature)
            postfix = 1
            while db.get_group_id(group_name):
                group_name = f"{group_name} ({postfix})"
                postfix += 1
            db.create_group(group_name, group_id, sender, members)
            db.close()
            return None
        else:
            db.close()
            return "InvalidSignature", (group_id, )

    def _handler_group_id_in_use(self, sender: str, values: list) -> tuple[str, tuple]:
        """Handler function for the GroupIDInUse message type.

        Args:
            sender (str): The client ID which sent the message
            value (list): The parameters of the message (group id, signature)

        Returns:
            tuple[str, tuple]: ChangeGroupID if successful,
                NotAllowed: I am not the owner of the group
                NoSuchGroup: The group ID does not exist
                InvalidSignature: The message was improperly signed
        """
        group_id, request_signature = values

        db = self._db_connect()
        group_name = db.get_group_name(group_id)
        group_members = db.get_members(group_id)
        if group_members:
            if self.get_id() == db.get_owner(group_id) and sender in group_members:
                if not db.user_known(sender):
                    self._request_key(sender)
                    self._await_key(sender, lambda: None)

                request_signature_data = f"{group_name}{group_id}{self.get_id()}".encode('utf-8')
                if signing.verify(request_signature_data, request_signature, db.get_key(sender)):
                    new_group_id = random.randrange(1, 2**64)
                    while db.get_group_name(new_group_id):
                        new_group_id = random.randrange(1, 2**64)
                    db.change_group_id(group_id, new_group_id)
                    for member in group_members:
                        if member != sender:
                            response_signature_data = f"{group_name}{group_id}{new_group_id}{member}".encode('utf-8')
                            response_signature = signing.sign(response_signature_data, self._priv)
                            message = self._message_parser.construct_message(member, "ChangeGroupID",
                                                                             group_id, new_group_id,
                                                                             response_signature)
                            self._server.send(message)
                    response_signature_data = f"{group_name}{group_id}{new_group_id}{sender}".encode('utf-8')
                    response_signature = signing.sign(response_signature_data, self._priv)
                    return "ChangeGroupID", (group_id, new_group_id, response_signature)
                return "InvalidSignature", (group_id, )
            return "NotAllowed", ("GroupIDInUse", )
        return "NoSuchGroup", (group_id, )

    def _handler_change_group_id(self, sender: str, values: list) -> None | tuple[str, tuple]:
        """Handler function for the ChangeGroupID message type.

        Args:
            sender (str): The client ID which sent the message.
            values (list): The parameters of the message (old group id, new group id)

        Return:
            None | tuple[str, tuple]: None if successful
                NoSuchGroup: The group ID being changed does not exist.
                NotAllowed: The sender is not the owner of the group.
                GroupIDInUse: The new group ID is already in use on this client.
                InvalidSignature: The message was incorrectly signed.
        """
        old_group_id, new_group_id, signature = values
        db = self._db_connect()
        if sender == db.get_owner(old_group_id):
            group_name = db.get_group_name(old_group_id)
            if group_name:
                signature_data = f"{group_name}{old_group_id}{new_group_id}{self.get_id()}".encode('utf-8')
                if not db.user_known(sender):
                    self._request_key(sender) 
                    self._await_key(sender, lambda: None)
                if signing.verify(signature_data, signature, db.get_key(sender)):
                    if db.get_group_name(new_group_id):
                        response_signature_data = f"{group_name}{new_group_id}{self.get_id()}".encode('utf-8')
                        response_signature = signing.sign(response_signature_data, self._priv)
                        return "GroupIDInUse", (new_group_id, response_signature)
                    db.change_group_id(old_group_id, new_group_id) 
                    return None
                return "InvalidSignature", (old_group_id)
            return "NoSuchGroup", (old_group_id, )
        return "NotAllowed", ("ChangeGroupID")

    def _handler_key_found(self, sender: str, values: list) -> None | tuple[str, tuple]:
        """Handler function for the KeyFound message type.

        Args:
            sender (str): The client ID which sent the message
            values (list): The parameters of the message (request index, exponent, modulus)

        Returns:
            None | tuple[str, tuple]: None if successful
                PublicKeyMismatch: The supplied key's fingerprint does not match the client ID.
                NotAllowed: The message did not originate from the server.
                NoSuchKeyRequest: The request index does not match any existing key request
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
            return "NoSuchKeyRequest", (request_index, )
        return "NotAllowed", ("KeyFound", )

    def _handler_key_not_found(self, sender: str, values: list) -> None | tuple[str, tuple]:
        """Handler function for the KeyNotFound message type.

        Args:
            values (list): The parameters of the message (client ID)

        Returns:
            None | tuple[str, tuple]: None if successful.
                NoSuchKeyRequest: The request index does not match any existing key request.
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
            return "NoSuchKeyRequest", (req_index, )
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
            "data": '',
            "group": ''}
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
            plaintext = json.dumps({
                "data": self._messages[message_index]["data"],
                "group": self._messages[message_index]["group"]
            }).encode('utf-8')
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
                MessageDecryptionFailure: The message ciphertext was unable to be decrypted.
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
                return "MessageDecryptionFailure", (message_index, )
            try:
                message_data = json.loads(plaintext)
            except JSONDecodeError:
                return "MessageMalformed", (message_index)
            
            group = message_data['group']
            data = message_data['data'].encode('latin1')
                
            db = self._db_connect()
            if group:
                if sender in db.get_members_by_id(group):
                    groupname = db.get_group_name(group)
                    db.insert_group_message(group, data, sender)
                    nickname = db.get_nickname(sender)
                    if nickname is None:
                        self._group_message_queue.put((groupname, (sender, data)))
                    else:
                        self._group_message_queue.put((groupname, (nickname, data)))
                    db.close()
                    self._messages.pop(message_index)
                    return None
                return "NotAllowed", ("MessageData", )
            else:
                db.insert_message(sender, plaintext, False)
                nickname = db.get_nickname(sender)
                if nickname is None:
                    db.set_nickname(sender, sender)
                    self._message_queue.put((sender, plaintext))
                else:
                    self._message_queue.put((nickname, plaintext))
                db.close()
                self._messages.pop(message_index)
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

