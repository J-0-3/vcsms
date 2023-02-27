"""Defines the Client class for messaging other VCSMS clients."""

import threading
import os
import random
import re
import time
import json
from json.decoder import JSONDecodeError
from typing import Callable

from .queue import Queue
from .cryptography import dhke, sha256, aes256, rsa
from .cryptography.utils import i_to_b
from .cryptography.exceptions import DecryptionFailureException
from .server_connection import ServerConnection
from .message_parser import MessageParser
from .exceptions.message_parser import MessageParseException
from .exceptions.server_connection import ConnectionException
from .exceptions.client import *
from . import keys
from . import signing
from . import client_db
from .logger import Logger

INCOMING_MESSAGE_TYPES = {
    # type       argc arg types         additional type info (encoding, base, etc)
    # message index, diffie hellman pub, diffie hellman sig
    "NewMessage": ([int, int, bytes], [10, 16, None]),
    # message index, diffie hellman pub, diffie hellman sig
    "MessageAccept": ([int, int, bytes], [10, 16, None]),
    # message index, initialisation vector, message data
    "MessageData": ([int, int, bytes], [10, 16, None]),
    # request index, exponent, modulus (server only)
    "KeyFound": ([int, int, int], [10, 16, 16]),
    # request index (server only)
    "KeyNotFound": ([int], [10]),
    # message index
    "IndexInUse": ([int], [10]),
    "MessageDataDecryptionFailure": ([int], [10]),
    "MessageDataMalformed" :([int], [10]),
    "InvalidSignature": ([int], [10]),
    "NoSuchIndex": ([int], [10]),
    # message type
    "UnknownMessageType": ([str], ['utf-8']),
    "NotAllowed": ([str], ['utf-8']),
    # encrypted group name, signature, group id, members
    "CreateGroup": ([bytes, bytes, int, list], [None, None, 10, (str, 'utf-8')]),
    # group id, new group id, signature
    "ChangeGroupID": ([int, int, bytes], [10, 10, None]),
    # group id, signature
    "GroupIDInUse": ([int, bytes], [10, None]),
    # group id, new name, signature
    "RenameGroup": ([int, bytes, bytes], [10, None, None]),
    # group id, signature
    "LeaveGroup": ([int, bytes], [10, None]),
    # group id
    "NoSuchGroup": ([int], [10]),
    "GroupNameDecryptionFailure": ([int], [10]),

    "CiphertextMalformed": ([], []),
    "MessageDecryptionFailure": ([], []),
    "InvalidIV": ([], []),
    "MessageMalformed": ([], [])
}

OUTGOING_MESSAGE_TYPES = {
    # message index, diffie hellman pub, diffie hellman sig
    "NewMessage": ([int, int, bytes], [10, 16, None]),
    # message index, diffie hellman pub, diffie hellman sig
    "MessageAccept": ([int, int, bytes], [10, 16, None]),
    # message index, initialisation vector, message data
    "MessageData": ([int, int, bytes], [10, 16, None]),
    # message index
    "IndexInUse": ([int], [10]),
    "MessageDataDecryptionFailure": ([int], [10]),
    "MessageDataMalformed": ([int], [10]),
    "InvalidSignature": ([int], [10]),
    "NoSuchIndex": ([int], [10]),
    "ResendAuthPacket": ([int], [10]),
    # request index, client id (server only)
    "GetKey": ([int, str], [10, 'utf-8']),
    # client id, exponent, modulus (server only)
    "PublicKeyMismatch": ([str, int, int], ['utf-8', 16, 16]),
    # request index (server only)
    "NoSuchKeyRequest": ([int], [10]),
    # message type
    "UnknownMessageType": ([str], ['utf-8']),
    "NotAllowed": ([str], ['utf-8']),
    # encrypted group name, signature, group id, members
    "CreateGroup": ([bytes, bytes, int, list], [None, None, 10, (str, 'utf-8')]),
    # group id, new id, signature
    "ChangeGroupID": ([int, int, bytes], [10, 10, None]),
    # group id, signature
    "GroupIDInUse": ([int, bytes], [10, None]),
    # group id, new name, signature
    "RenameGroup": ([int, bytes, bytes], [10, None, None]),
    # group id, signature
    "LeaveGroup": ([int, bytes], [10, None]),
    # group id
    "NoSuchGroup": ([int], [10]),
    "GroupNameDecryptionFailure": ([int], 10),
    "Quit": ([], [])
}

class Client:
    """
    A VCSMS messaging client. Allows for communication with other VCSMS clients.

    Remember to call the run() method before using the Client class.
    """

    def __init__(self, ip: str, port: int, fingerprint: str, application_directory: str, logger: Logger):
        """Initialise a VCSMS messaging client.

        Args:
            ip (str): The ip address of the VCSMS server.
            port (int): The port of the VCSMS server (specified in the server's .vcsms file).
            fingerprint (str): The server's fingerprint (specified in the server's .vcsms file).
            application_directory (str): Where to store files created by the client.
            logger (Logger): An instance of vcsms.logger.Logger used to log all application events.
        """
        self._id = ""
        self._server = ServerConnection(ip, port, fingerprint, logger)
        self._app_dir = application_directory
        self._pub = (0, 0)
        self._priv = (0, 0)
        self._dhke_group = dhke.group14_2048
        self._messages = {}
        self._key_requests = {}
        self._running = False
        self._local_encryption_key = 0
        self._name_salt = b''
        self._message_queue = Queue()
        message_response_map = {
            "KeyFound": self._handler_key_found,
            "KeyNotFound": self._handler_key_not_found,
            "NewMessage": self._handler_new_message,
            "MessageAccept": self._handler_message_accept,
            "MessageData": self._handler_message_data,
            "IndexInUse": self._handler_index_in_use,
            "CreateGroup": self._handler_create_group,
            "ChangeGroupID": self._handler_change_group_id,
            "GroupIDInUse": self._handler_group_id_in_use,
            "RenameGroup": self._handler_rename_group,
            "LeaveGroup": self._handler_leave_group,
            "unknown": self._handler_unknown,
            "default": self._handler_default
        }
        self._message_parser = MessageParser(
            INCOMING_MESSAGE_TYPES, OUTGOING_MESSAGE_TYPES, message_response_map)
        self._logger = logger

    @property
    def running(self) -> bool:
        return self._running

    @property
    def id(self) -> str:
        return self._id

    @property
    def new(self) -> bool:
        return not self._message_queue.empty

    @property
    def contacts(self) -> list:
        db = self._db_connect()
        users = db.get_users()
        groups = db.get_groups()
        contacts = [u for u in zip(users, [False] * len(users))] + [g for g in zip(groups, [True] * len(groups))]
        db.close()
        return contacts

    def receive(self) -> tuple[str, tuple]:
        """Block until a new message is available and then return it.

        Returns:
            tuple[str, str, bytes]: The message sender, group name and contents
        """
        return self._message_queue.pop()

    def add_contact(self, nickname: str, client_id: str):
        """Add a new contact with a (unique) nickname and client ID.

        Args:
            nickname (str): The nickname for the contact.
            client_id (str): The contact's client ID (a 64 char hex string).
        """
        db = self._db_connect()
        client_id = client_id.strip().lower()
        if re.fullmatch('^[0-9a-f]{32}$', client_id):
            if client_id != self._id:
                if db.get_id(nickname):
                    self._logger.log(f"Nickname {nickname} is already in use", 1)
                    raise NickNameInUseException(nickname)
                if db.get_nickname(client_id):
                    self._logger.log(f"User {client_id} already exists", 1)
                    raise UserAlreadyExistsException()
                db.set_nickname(client_id, nickname)
            db.close()
        else:
            db.close()
            self._logger.log(f"{client_id} does not look like a valid client id.", 1)
            raise InvalidIDException()

    def rename_contact(self, old_name: str, new_name: str):
        """Rename the contact with the old name to have the new name.

        The new name must not match any existing contact name

        Args:
            old_name (str): The name of the contact to rename.
            new_name (str): The new name of the contact.

        Raises:
            sqlite3.IntegrityError: The new name is already in use
        """
        db = self._db_connect()
        if db.get_id(new_name) or db.get_group_id(new_name):
            raise NickNameInUseException(new_name)
        if db.get_id(old_name):
            db.change_nickname(old_name, new_name)
        elif gid := db.get_group_id(old_name):
            members = db.get_members(old_name)
            for member in members:
                signature_data = f"RENAME{new_name}{gid}{member}".encode('utf-8')
                signature = signing.sign(signature_data, self._priv)
                if not db.user_known(member):
                    self._request_key(member)
                    if not self._await_key(member, 60, lambda: None):
                        self._logger.log(f"Could not inform {member} of group rename. Public key timeout.", 2)
                        continue
                key = db.get_key(member)
                encrypted_group_name = rsa.encrypt(new_name.encode('utf-8'), *key)
                message = self._message_parser.construct_message(member, "RenameGroup", gid, encrypted_group_name, signature)
                self._server.send(message)
            db.rename_group(gid, new_name)
        db.close()

    def delete_contact(self, name: str):
        """Delete the contact with a given nickname.

        Args:
            nickname (str): The nickname of the contact to delete.
        """
        db = self._db_connect()
        if db.get_id(name):
            db.delete_contact_by_nickname(name)
        elif gid:= db.get_group_id(name):
            for member in db.get_members(name):
                signature_data = f"LEAVE{gid}{member}".encode('utf-8')
                signature = signing.sign(signature_data, self._priv)
                message = self._message_parser.construct_message(member, "LeaveGroup", gid, signature)
                self._server.send(message)
            db.delete_group_by_group_name(name)
        db.close()

    def get_messages(self, name: str, count: int = 0) -> list[tuple[bytes, str]]:
        """Get the last *count* messages to/from the specified user or group.

        Args:
            name (str): The user/group name to lookup.
            count (int): The (maximum) number of messages to/from the specified contact to return. (0 if no limit)

        Returns:
            list[tuple[bytes, bool]]: The last *count* messages to/from the client in time order
                (newest first) in the format (message, sender) where message is the raw message
                and sender is the user who sent the message.
        """
        db = self._db_connect()
        if db.get_group_id(name):
            messages = db.get_group_messages(name, count)
        else:
            messages_in_single_user_form = db.get_messages_by_nickname(name, count)
            messages = []
            for message in messages_in_single_user_form:
                data, outgoing = message
                messages.append((data, self._id if outgoing else name))

        db.close()
        return messages

    def send(self, recipient: str, message: bytes):
        """Send a message to a given recipient.

        Args:
            recipient (str): The recipient (nickname or client ID) to send the message to.
            message (bytes): The message to send.
        """
        db = self._db_connect()
        recipient_id = db.get_id(recipient)
        if recipient_id is None:
            if db.get_group_id(recipient):
                self._group_send(recipient, message)
                return
            if re.fullmatch('^[a-fA-F0-9]{32}$', recipient):
                db.set_nickname(recipient, recipient)
                recipient_id = recipient
            else:
                self._logger.log(f"User {recipient} not found.", 1)
                raise UserNotFoundException(recipient)
        db.insert_message(recipient_id, message, True)
        db.close()
        dh_priv = random.randrange(1, self._dhke_group[1])
        index = random.randrange(1, 2 ** 64)
        while index in self._messages:
            index = random.randrange(1, 2 ** 64)
        dh_pub, dh_sig = signing.gen_signed_dh(
            dh_priv, self._priv, self._dhke_group, index)
        self._messages[index] = {
            "client_id": recipient_id,
            "dh_private": dh_priv,
            "data": message.decode('latin1'), # needs to be JSON serialisable
            "group": 0
        }
        message = self._message_parser.construct_message(
            recipient_id, "NewMessage", index, dh_pub, dh_sig)
        self._server.send(message)

    def _group_send(self, group_name: str, message: bytes):
        """Send a message to all recipients in the specified group.

        Args:
            group_name (str): The name of the group to sent the messages to.
            message (bytes): The message to send.
        """
        db = self._db_connect()
        group = db.get_group_id(group_name)
        if group is None:
            self._logger.log(f"Group {group_name} not found", 1)
            raise GroupNotFoundException(group_name)
        recipients = db.get_members(group_name)

        db.insert_group_message(group, message, self._id)
        for recipient in recipients:
            if recipient != self._id:
                dh_priv = random.randrange(1, self._dhke_group[1])
                index = random.randrange(1, 2**64)
                while index in self._messages:
                    index = random.randrange(1, 2**64)
                dh_pub, dh_sig = signing.gen_signed_dh(dh_priv, self._priv, self._dhke_group, index)
                self._messages[index] = {
                    "client_id": recipient,
                    "dh_private": dh_priv,
                    "data": message.decode('latin1'),
                    "group": group
                }
                constructed_message = self._message_parser.construct_message(recipient, "NewMessage", index, dh_pub, dh_sig)
                self._server.send(constructed_message)

    def create_group(self, name: str, *members: str):
        """Create a group of users which can be used to send group messages.

        Args:
            name (str): The name of the group.
            *members (str): The ids/nicknames of the members to add to the group.
        """
        member_ids = []
        db = self._db_connect()
        for member in members:
            if member != self._id:
                member_id = db.get_id(member)
                if member_id is None:
                    if re.fullmatch("^[a-fA-F0-9]{32}$", member):
                        member_id = member
                    else:
                        self._logger.log(f"User {member} not found.", 1)
                        raise UserNotFoundException(member)
                member_ids.append(member_id)

        group_id = random.randrange(1, 2**64)
        while db.get_group_name(group_id):
            group_id = random.randrange(1, 2**64)

        if db.get_group_id(name) or db.get_id(name):
            self._logger.log(f"Name {name} already in use.", 1)
            raise GroupNameInUseException(name)
        self._logger.log(f"Creating group {name}: id = {group_id}, members = {member_ids}", 1)

        db.create_group(name, group_id, self._id, member_ids)

        def invite_user(user: str):
            key = db.get_key(user)
            signature_data = ("CREATE" + name + ":" + hex(group_id) + ":" + ''.join(member_ids) + ":" + user).encode('utf-8')
            signature = signing.sign(signature_data, self._priv)
            encrypted_group_name = rsa.encrypt(name.encode('utf-8'), *key)
            invite_message = self._message_parser.construct_message(
                user, "CreateGroup",
                encrypted_group_name, signature, group_id, member_ids
            )
            self._server.send(invite_message)

        for member_id in member_ids:
            if db.user_known(member_id):
                invite_user(member_id)
            else:
                self._request_key(member_id)
                await_key_thread = threading.Thread(target=self._await_key, args=(member_id, 60, invite_user, member_id))
                await_key_thread.start()

    def run(self, password: str):
        """Connect to the VCSMS server and begin running the client program.
        This should always be the first method called on the Client class.

        Args:
            password (str): The master password for the client program

        Raises:
            IncorrectMasterKeyException: The supplied master key is not correct.
        """
        os.makedirs(os.path.join(self._app_dir, "keys"), exist_ok=True)
        self._local_encryption_key = keys.derive_key(password)
        if os.path.exists(os.path.join(self._app_dir, "keytest")):
            if not self._check_master_key():
                self._logger.log("Incorrect master key attempt.", 0)
                raise IncorrectMasterKeyException()
            self._logger.log("Successful login", 2)
        else:
            self._logger.log("Generating master key challenge", 2)
        self._create_master_key_test()

        if os.path.exists(os.path.join(self._app_dir, "names.salt")):
            with open(os.path.join(self._app_dir, "names.salt"), 'r', encoding='utf-8') as f:
                salt_iv_hex, salt_encrypted_hex = f.read().split(':')
                salt_iv = int(salt_iv_hex, 16)
                salt_encrypted = bytes.fromhex(salt_encrypted_hex)
                self._name_salt = aes256.decrypt_cbc(salt_encrypted, self._local_encryption_key, salt_iv)
        else:
            with open(os.path.join(self._app_dir, "names.salt"), 'w+', encoding='utf-8') as f:
                self._name_salt = random.randbytes(256)
                salt_iv = random.randrange(1, 2**128)
                salt_encrypted = aes256.encrypt_cbc(self._name_salt, self._local_encryption_key, salt_iv)
                salt_iv_hex = hex(salt_iv)[2:]
                salt_encrypted_hex = salt_encrypted.hex()
                f.write(f"{salt_iv_hex}:{salt_encrypted_hex}")
        db = self._db_connect()
        db.setup()
        db.close()
        public_key_path = os.path.join(self._app_dir, "client.pub")
        private_key_path = os.path.join(self._app_dir, "client.priv")
        try:
            self._pub = keys.load_key(public_key_path)
            self._priv = keys.load_key(private_key_path, self._local_encryption_key)
            self._logger.log("Successfully loaded RSA keypair", 2)
        except FileNotFoundError:
            self._logger.log("Generating RSA keypair", 2)
            self._pub, self._priv = keys.generate_keys(public_key_path, private_key_path, self._local_encryption_key)

        self._id = keys.fingerprint(self._pub)
        self._logger.log("Connecting to server.", 2)
        try:
            self._server.connect(self._pub, self._priv)
        except ConnectionException as e:
            self._logger.log(str(e), 0)
            raise ConnectionFailureException from e
        self._logger.log("Connection successful.", 2)
        self._running = True
        self._load_saved_in_process_messages()
        t_incoming = threading.Thread(target=self._incoming_thread, args=())
        t_incoming.start()

    def quit(self):
        """Close the connection with the server and shutdown the client program."""
        self._logger.log("Shutting down client program", 2)
        self._server.send(self._message_parser.construct_message("0", "Quit"))
        self._running = False
        self._server.close()
        self._save_in_process_messages()

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

    def _await_key(self, client_id: str, timeout: int, callback: Callable, *args):
        """Wait until the public key for a given client id is known and then execute
        a callback function. Useful if the public key is required for some operation
        which can be executed asynchronously.

        Args:
            client_id (str): The client id to await the public key of
            timeout (int): The maximum time to await the key for. (0 for no maximum)
            callback (Callable): A callback function to execute once the key is received. Use 'lambda: None' to run no callback.
            *args: The arguments of the callback function
        """
        db = self._db_connect()
        start = time.time()
        while not db.user_known(client_id):
            time.sleep(0.1)
            if time.time() - start >= timeout and timeout > 0:
                return False
        db.close()
        callback(*args)
        return True

    def _save_in_process_messages(self):
        """Save the status of currently in process messages so that they
        can be sent when next online."""
        with open(os.path.join(self._app_dir, "in_process.msgs"), 'w+', encoding='utf-8') as f:
            encrypted_statuses_json = {}
            for index,message in self._messages.items():
                message_status_json = json.dumps(message)
                initialisation_vector = random.randrange(1, 2**128)
                encrypted_message_status = aes256.encrypt_cbc(message_status_json.encode('utf-8'), self._local_encryption_key, initialisation_vector)
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
                    message_status = aes256.decrypt_cbc(ciphertext, self._local_encryption_key, initialisation_vector)
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
            encrypted_data = aes256.encrypt_cbc(data, self._local_encryption_key, aes_iv)
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
        try:
            if plaintext == aes256.decrypt_cbc(ciphertext, self._local_encryption_key, aes_iv):
                return True
        except DecryptionFailureException:
            return False
        return False

    # methods for threads
    def _incoming_thread(self):
        """The function run by the incoming thread.
        Keeps checking for new messages and processes them on a new thread as they arrive.
        """
        while self._running:
            if self._server.new:
                msg = self._server.recv()
                t_process = threading.Thread(
                    target=self._process_message, args=(msg,))
                t_process.start()

    def _process_message(self, data: bytes):
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
            return

        response = self._message_parser.handle(
            sender, message_type, message_values)
        if response:
            self._server.send(response)

    # message type handlers

    def _handler_create_group(self, sender: str, encrypted_group_name: bytes, signature: bytes,
            group_id: int, members: list) -> None | tuple[str, tuple]:
        """Handler function for the CreateGroup message type

        Args:
            sender (str): The client ID which sent the message
            encrypted_group_name (bytes): The name of the group encrypted with my RSA public key.
            signature (bytes): The signature of the group name, group ID, member list, and my client ID.
            group_id (int): The ID to use for the new group.
            members (list): A list of the members of the group.

        Returns:
            None | tuple[str, tuple]: None if successful
                GroupIDInUse: There is already a group with that ID on this client
                InvalidSignature: The message was improperly signed
                GroupNameDecryptionFailure: The group name could not be decrypted
        """
        try:
            group_name = rsa.decrypt(encrypted_group_name, self._priv[0], self._priv[1])
        except DecryptionFailureException:
            self._logger.log(f"Unable to decrypt group name in creation request from {sender}.", 2)
            return "GroupNameDecryptionFailure", (group_id, )
        group_name = group_name.decode('utf-8')
        signature_data = ("CREATE" + group_name + ":" + hex(group_id) + ":" +''.join(members) +
                          ":" + self._id).encode('utf-8')
        self._logger.log(f"Group creation attempt from {sender}: id = {group_id}", 1)
        db = self._db_connect()
        if not db.user_known(sender):
            self._request_key(sender)
            if not self._await_key(sender, 60, lambda: None):
                self._logger.log("Unable to create group. Creator's public key was not received.", 2)
                return None

        if signing.verify(signature_data, signature, db.get_key(sender)):
            if db.get_group_name(group_id):
                response_signature_data = f"IDINUSE{group_id}{sender}".encode('utf-8')
                response_signature = signing.sign(response_signature_data, self._priv)
                self._logger.log(f"ID {group_id} is already in use. Reporting to creator.", 3)
                return "GroupIDInUse", (group_id, response_signature)
            postfix = 1
            while db.get_group_id(group_name) or db.get_id(group_name):
                group_name = f"{group_name} ({postfix})"
                postfix += 1
            try:
                members.remove(self._id)
            except ValueError:
                pass # sender didn't include us in the member list for whatever reason
            db.create_group(group_name, group_id, sender, members)
            db.close()
            self._logger.log(f"Group {group_id} successfully created.", 3)
            self._message_queue.push(("NEWGROUP", (group_name, )))
            return None
        db.close()
        self._logger.log(f"Invalid signature in group creation request.", 2)
        return "InvalidSignature", (group_id, )

    def _handler_leave_group(self, sender: str, group_id: int, signature: bytes) -> None | tuple[str, tuple]:
        """Handler function for the LeaveGroup message type.

        Args:
            sender: (str): The client ID which sent the message
            group_id (int): The group ID they are leaving.
            signature (bytes): The signature of the group ID and my client ID
        """
        db = self._db_connect()
        if members := db.get_members_by_id(group_id):
            if sender in members:
                signature_data = f"LEAVE{group_id}{self._id}".encode('utf-8')
                if not db.user_known(sender):
                    self._request_key(sender)
                    if not self._await_key(sender, 60, lambda: None):
                        self._logger.log(f"Could not get public key of {sender}: timeout", 2)
                        return None
                key = db.get_key(sender)
                if signing.verify(signature_data, signature, key):
                    if sender == db.get_owner(group_id):
                        self._logger.log(f"Deleting group {group_id} as the owner left.", 3)
                        db.delete_group_by_group_id(group_id)
                        return None
                    self._logger.log(f"Removing {sender} from {group_id} as they left.", 4)
                    db.remove_group_member(group_id, sender)
                    return None
                return "InvalidSignature", (group_id, )
            return "NotAllowed", ("LeaveGroup", )
        return "NoSuchGroup", (group_id, )

    def _handler_rename_group(self, sender: str, group_id: int, new_name: bytes, signature: bytes) -> None | tuple[str, tuple]:
        """Handler function for the RenameGroup message type.

        Args:
            sender (str): The client ID which sent the message.
            group_id (int): The ID of the group to rename.
            new_name (bytes): The (encrypted) new group name.
        """
        db = self._db_connect()
        if members := db.get_members_by_id(group_id):
            if sender in members:
                try:
                    name_decrypted = rsa.decrypt(new_name, *self._priv).decode('utf-8')
                except DecryptionFailureException:
                    return "GroupNameDecryptionFailure", (group_id, )
                signature_data = f"RENAME{name_decrypted}{group_id}{self._id}".encode('utf-8')
                if not db.user_known(sender):
                    self._request_key(sender)
                    if not self._await_key(sender, 60, lambda: None):
                        self._logger.log("Could not verify group rename signature. Public key timeout.", 2)
                        return None
                key = db.get_key(sender)
                if signing.verify(signature_data, signature, key):
                    postfix = 1
                    while db.get_group_id(name_decrypted) or db.get_id(name_decrypted):
                        name_decrypted = f"{name_decrypted} ({postfix})"
                        postfix += 1
                    old_name = db.get_group_name(group_id)
                    db.rename_group(group_id, name_decrypted)
                    self._logger.log("Renamed group {group_id}", 2)
                    self._message_queue.push(("RENAMEGROUP", (old_name, name_decrypted)))
                    return None
                return "InvalidSignature", (group_id, )
            return "NotAllowed", ("RenameGroup", )
        return "NoSuchGroup", (group_id, )

    def _handler_group_id_in_use(self, sender: str, group_id: int, signature: bytes) -> tuple[str, tuple] | None:
        """Handler function for the GroupIDInUse message type.

        Args:
            sender (str): The client ID which sent the message
            group_id (int): The ID that was in use.
            signature (bytes): The signature of the group ID and my client ID.

        Returns:
            tuple[str, tuple]: ChangeGroupID if successful,
                NotAllowed: I am not the owner of the group
                NoSuchGroup: The group ID does not exist
                InvalidSignature: The message was improperly signed
        """
        db = self._db_connect()
        if group_members := db.get_members_by_id(group_id):
            if self._id == db.get_owner(group_id) and sender in group_members:
                if not db.user_known(sender):
                    self._request_key(sender)
                    if not self._await_key(sender, 60, lambda: None):
                        self._logger.log("Could not respond to GroupIDInUse. Client public key not received.", 2)
                        return None
                signature_data = f"IDINUSE{group_id}{self._id}".encode('utf-8')
                if signing.verify(signature_data, signature, db.get_key(sender)):
                    new_group_id = random.randrange(1, 2**64)
                    while db.get_group_name(new_group_id):
                        new_group_id = random.randrange(1, 2**64)
                    db.change_group_id(group_id, new_group_id)
                    for member in group_members:
                        if member != sender:
                            response_signature_data = f"CHANGEID{group_id}{new_group_id}{member}".encode('utf-8')
                            response_signature = signing.sign(response_signature_data, self._priv)
                            message = self._message_parser.construct_message(member, "ChangeGroupID",
                                                                             group_id, new_group_id,
                                                                             response_signature)
                            self._server.send(message)
                    response_signature_data = f"CHANGEID{group_id}{new_group_id}{sender}".encode('utf-8')
                    response_signature = signing.sign(response_signature_data, self._priv)
                    self._logger.log(f"Requesting members of group {group_id} change their group IDs in response to ID in use error.", 3)
                    return "ChangeGroupID", (group_id, new_group_id, response_signature)
                self._logger.log(f"Invalid signature for ID in use error.", 2)
                return "InvalidSignature", (group_id, )
            self._logger.log(f"ID in use error from user who is not part of the group, or for a group I am not the owner of.", 2)
            return "NotAllowed", ("GroupIDInUse", )
        self._logger.log(f"ID in use error for non-existent group {group_id}.", 2)
        return "NoSuchGroup", (group_id, )

    def _handler_change_group_id(self, sender: str, old_id: int, new_id: int, signature: bytes) -> None | tuple[str, tuple]:
        """Handler function for the ChangeGroupID message type.

        Args:
            sender (str): The client ID which sent the message.
            old_id (int): The current ID of the group.
            new_id (int): The ID to change it to.
            signature (bytes): A signature of the message.

        Return:
            None | tuple[str, tuple]: None if successful
                NoSuchGroup: The group ID being changed does not exist.
                NotAllowed: The sender is not the owner of the group.
                GroupIDInUse: The new group ID is already in use on this client.
                InvalidSignature: The message was incorrectly signed.
        """
        db = self._db_connect()
        if sender == db.get_owner(old_id):
            group_name = db.get_group_name(old_id)
            if group_name:
                signature_data = f"CHANGEID{old_id}{new_id}{self._id}".encode('utf-8')
                if not db.user_known(sender):
                    self._request_key(sender)
                    if not self._await_key(sender, 60, lambda: None):
                        self._logger.log("Unable to verify group ID change request. Client public key not received.", 2)
                        return None
                if signing.verify(signature_data, signature, db.get_key(sender)):
                    if db.get_group_name(new_id):
                        response_signature_data = f"IDINUSE{new_id}{self._id}".encode('utf-8')
                        response_signature = signing.sign(response_signature_data, self._priv)
                        self._logger.log(f"{sender} tried to change a group ID to one already in use.", 3)
                        return "GroupIDInUse", (new_id, response_signature)
                    db.change_group_id(old_id, new_id)
                    self._logger.log(f"Changed group ID {old_id} to {new_id}", 3)
                    return None
                self._logger.log(f"Invalid new group info signature from {sender}.", 2)
                return "InvalidSignature", (old_id, )
            self._logger.log(f"{sender} tried to change the ID of a non-existent group.", 2)
            return "NoSuchGroup", (old_id, )
        self._logger.log(f"Unauthorised group ID change request.", 2)
        return "NotAllowed", ("ChangeGroupID", )

    def _handler_key_found(self, sender: str, request_index: int, exponent: int, modulus: int) -> None | tuple:
        """Handler function for the KeyFound message type.

        Args:
            sender (str): The client ID which sent the message (should be '0').
            request_index (int): The request index the server is responding to.
            exponent (int): The exponent part of the client's public key.
            modulus (int): The modulus part of the client's public key.

        Returns:
            None | tuple[str, tuple]: None if successful
                PublicKeyMismatch: The supplied key's fingerprint does not match the client ID.
                NotAllowed: The message did not originate from the server.
                NoSuchKeyRequest: The request index does not match any existing key request
        """
        if sender == '0':
            if request_index in self._key_requests:
                client_id = self._key_requests[request_index]
                self._key_requests.pop(request_index)
                if keys.fingerprint((exponent, modulus)) == client_id:
                    db = self._db_connect()
                    db.save_key(client_id, (exponent, modulus))
                    db.close()
                    self._logger.log(f"Key received from server for {client_id}.", 3)
                    return None
                self._logger.log(f"Client's public key fingerprint did not match the expected client ID.", 1)
                return "PublicKeyMismatch", (client_id, exponent, modulus)
            self._logger.log(f"Received response to non-existent key request {request_index}", 2)
            return "NoSuchKeyRequest", (request_index, )
        self._logger.log(f"Received unauthorised key request response.", 2)
        return "NotAllowed", ("KeyFound", )

    def _handler_key_not_found(self, sender: str, request_index: int) -> None | tuple[str, tuple]:
        """Handler function for the KeyNotFound message type.

        Args:
            sender (str): The client ID who sent the message (should be '0').
            request_index (int): The request index the server is responding to.
        Returns:
            None | tuple[str, tuple]: None if successful.
                NoSuchKeyRequest: The request index does not match any existing key request.
                NotAllowed: The message did not originate from the server.
        """
        if sender == '0':
            if request_index in self._key_requests:
                client_id = self._key_requests[request_index]
                self._logger.log(
                    f"Server could not locate key for {client_id}", 1)
                self._key_requests.pop(request_index)
                return None
            self._logger.log(f"Received response to non-existent key request {request_index}.", 2)
            return "NoSuchKeyRequest", (request_index, )
        self._logger.log(f"Received unauthorised key request response.", 2)
        return "NotAllowed", ("KeyNotFound", )

    def _handler_new_message(self, sender: str, message_index: int,
            sender_dh_pub: int, sender_dh_sig: bytes) -> tuple[str, tuple] | None:
        """Handler function for the NewMessage message type.

        Args:
            sender (str): The client ID who sent the message.
            message_index (int): The message index the sender is requesting to use.
            sender_dh_pub (int): The sender's diffie hellman public key.
            sender_dh_sig (bytes): The sender's DH public key signature.

        Returns:
            tuple[str, tuple]: MessageAccept if successful.
                IndexInUse: The message index is already being used by another message in process.
                InvalidSignature: The diffie hellman public key was incorrectly signed.
        """
        if message_index in self._messages:
            self._logger.log(
                f"Message from {sender} requested use of already-in-use index {message_index}", 2)
            return "IndexInUse", (message_index, )
        db = self._db_connect()
        if not db.user_known(sender):
            self._request_key(sender)
            self._logger.log(f"Message from unknown user {sender}. Requesting key.", 3)
            if not self._await_key(sender, 60, lambda: None):
                db.close()
                return None

        sender_rsa = db.get_key(sender)
        if not signing.verify_signed_dh(sender_dh_pub, sender_dh_sig, sender_rsa, message_index):
            db.close()
            self._logger.log(
                f"Invalid Diffie Hellman signature from {sender}", 1)
            return "InvalidSignature", (message_index, )

        db.close()
        dh_priv = random.randrange(1, self._dhke_group[1])
        dh_pub, dh_pub_sig = signing.gen_signed_dh(
            dh_priv, self._priv, self._dhke_group, message_index)
        shared_secret = dhke.calculate_shared_key(
            dh_priv, sender_dh_pub, self._dhke_group)
        encryption_key = sha256.hash(i_to_b(shared_secret))

        self._messages[message_index] = {
            "client_id": sender,
            "encryption_key": encryption_key 
            }
        return "MessageAccept", (message_index, dh_pub, dh_pub_sig)

    def _handler_message_accept(self, sender: str, message_index: int,
            sender_dh_pub: int, sender_dh_sig: bytes) -> tuple[str, tuple] | None:
        """Handler for the MessageAccept message type.

        Args:
            sender (str): The client ID who sent the message.
            message_index (int): The message index the acceptance is for.
            sender_dh_pub (int): The sender's diffie hellman public key.
            sender_dh_sig (bytes): The sender signature of the DH public key.

        Returns:
            tuple[str, tuple]: MessageData if successful.
                NoSuchIndex: The message index does not correspond to any in process message.
                InvalidSignature: The diffie hellman public key was incorrectly signed.
                NotAllowed: The message index is in use by a different client to the sender.
        """
        if message_index not in self._messages:
            self._logger.log(
                f"Message acceptance from {sender} for non-existent message {message_index}", 2
            )
            return "NoSuchIndex", (message_index, )
        if sender == self._messages[message_index]["client_id"]:
            db = self._db_connect()
            if not db.user_known(sender):
                self._request_key(sender)
                self._logger.log(f"Message to unknown user {sender}. Requesting key.", 3)
                if not self._await_key(sender, 60, lambda: None):
                    db.close()
                    return None

            sender_rsa = db.get_key(sender)
            if not signing.verify_signed_dh(sender_dh_pub, sender_dh_sig, sender_rsa, message_index):
                db.close()
                self._logger.log(f"Invalid public key signature from {sender}", 1)
                return "InvalidSignature", (message_index, )
            db.close()
            if "dh_private" not in self._messages[message_index]:
                self._logger.log("{sender} attempted to accept a message that they sent.", 2)
                return "NotAllowed", ("MessageAccept", )
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
        self._logger.log(f"{sender} sent message accept for message addressed to another user.", 2)
        return "NotAllowed", ("MessageAccept", )

    def _handler_message_data(self, sender: str, message_index: int, aes_iv: int,
            ciphertext: bytes) -> tuple[str, tuple] | None:
        """Handler function for the MessageData message type.

        Args:
            sender (str): The client ID who sent the message.
            message_index (int): The message index the data is for.
            aes_iv (int): The IV used to encrypt the data.
            ciphertext (bytes): The encrypted message data.

        Returns:
            tuple[str, tuple] | None: None if successful.
                NoSuchIndex: The message index does not correspond to any in process message.
                MessageDecryptionFailure: The message ciphertext was unable to be decrypted.
                NotAllowed: The message index is in use by a different client id to the sender.
        """
        if message_index not in self._messages:
            self._logger.log(
                f"Message data from {sender} for non-existent message {message_index}", 2)
            return "NoSuchIndex", (message_index, )

        if sender == self._messages[message_index]["client_id"]:
            if "encryption_key" not in self._messages[message_index]:
                self._logger.log(f"{sender} attempted to send message data for a message I am sending.", 2)
                return "NotAllowed", ("MessageData", )
            encryption_key = self._messages[message_index]["encryption_key"]
            try:
                plaintext = aes256.decrypt_cbc(ciphertext, encryption_key, aes_iv)
            except DecryptionFailureException:
                self._logger.log(f"Failed to decrypt message from {sender}", 1)
                return "MessageDataDecryptionFailure", (message_index, )
            try:
                message_data = json.loads(plaintext)
            except JSONDecodeError:
                self._logger.log(f"Malformed message data from {sender}", 1)
                return "MessageDataMalformed", (message_index, )
            try:
                group = message_data['group']
                data = message_data['data'].encode('latin1')
            except KeyError:
                self._logger.log(f"Malformed message data from {sender}", 1)
                return "MessageDataMalformed", (message_index, )

            db = self._db_connect()
            group_name = db.get_group_name(group) or ""
            sender_name = db.get_nickname(sender) or sender
            if group:
                if sender in db.get_members_by_id(group):
                    db.insert_group_message(group, data, sender)
                else:
                    self._logger.log(f"{sender} sent a message to group {group} of which they or I am not a member.", 2)
                    return "NotAllowed", ("MessageData", )
            else:
                if sender_name == sender:
                    db.set_nickname(sender, sender)
                db.insert_message(sender, data, False)
            self._message_queue.push(("MESSAGE", (sender_name, group_name, data)))
            db.close()
            self._messages.pop(message_index)
            return None
        self._logger.log(f"{sender} attempted to send message data for message from other user.", 2)
        return "NotAllowed", ("MessageData", )

    def _handler_index_in_use(self, sender: str, message_index: int) -> tuple[str, tuple]:
        """Handler function for the IndexInUse message type.

        Args:
            sender (str): The client ID who sent the message.
            message_index (int): The message index that was in use.

        Returns:
            tuple[str, tuple]: NewMessage if successful
                NotAllowed: The message index is in use by a different client id to the sender
        """
        if message_index in self._messages:
            if sender == self._messages[message_index]["client_id"]:
                self._logger.log(f"Requested message index {message_index} from {sender} but it was already in use", 3)
                message = self._messages[message_index]
                new_id = random.randrange(1, 2 ** 64)
                self._messages.pop(message_index)
                self._messages[new_id] = message
                dh_private = message["dh_private"]
                dh_public, dh_signature = signing.gen_signed_dh(dh_private, self._priv, self._dhke_group, new_id)
                self._logger.log(f"Switching message ID {message_index} to {new_id}", 3)
                return "NewMessage", (new_id, dh_public, dh_signature)
            self._logger.log(f"{sender} reported index in use for message with other user", 2)
            return "NotAllowed", ("IndexInUse", )
        return "NoSuchIndex", (message_index, )

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

    def _handler_default(self, sender: str, message_type: str, values: list):
        """Default handler function.

        Args:
            sender (str): The client ID which sent the message.
            message_type (str): The message type received.
            values (list): The parameters of the message.
        """
        self._logger.log(f"{'Server' if sender == '0' else sender} sent {message_type} message", 3)

    def _db_connect(self) -> client_db.Client_DB:
        """Connect to the client database.

        Returns:
            Client_DB: A connection to the client database
        """
        db = client_db.Client_DB(os.path.join(self._app_dir, "client.db"), os.path.join(
            self._app_dir, "keys") + "/", self._local_encryption_key, self._name_salt)
        return db
