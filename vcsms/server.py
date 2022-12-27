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
    "GetKey": (2, [int, str], [10, 'utf-8']),
    "Quit": (0, [], []),
    "NoSuchIndex": (1, [int], [10]),
}

OUTGOING_MESSAGE_TYPES = {
    "KeyFound": (3, [int, int, int], [10, 16, 16]),
    "KeyNotFound": (1, [int], [10])
}


class Server:
    """A VCSMS messaging server. Provides messaging capabilities to clients."""
    def __init__(self, addr: str, port: int, keypair: tuple[tuple[int, int], tuple[int, int]], db_path: str, pubkey_directory: str, logger: Logger):
        """Initialise a VCSMS server.

        Args:
            addr (str): The IP address of the network interface to bind to. 
            port (int): The TCP port to bind to.
            keypair (tuple[tuple[int, int], tuple[int, int]]): The public and private RSA keys for the server to use in the form (exponent, modulus). 
            db_path (str): The file path at which the sqlite3 database is stored. 
            pubkey_directory (str): The directory to store all client public keys under. 
            logger (Logger): An instance of vcsms.logger.Logger to use for logging errors/events that occur in the server. 
        """
        self._addr = addr
        self._port = port
        self._pub = keypair[0]
        self._priv = keypair[1]
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._dhke_group = dhke.group14_2048
        self._in_queue = Queue()
        self._out_queue = Queue()
        self._client_outboxes = {}
        self._sockets = {}
        self._db_path = db_path
        self._pubkey_path = pubkey_directory
        self._logger = logger
        response_map = {
            "GetKey": self._handler_get_key,
            "Quit": self._handler_quit
        }
        self._message_parser = MessageParser(INCOMING_MESSAGE_TYPES, OUTGOING_MESSAGE_TYPES, response_map)

    def run(self):
        """Begin listening for and processing connections from clients. This should be the first method that is called by this class."""
        self._sock.bind((self._addr, self._port))
        self._sock.listen(30)
        db = self._db_connect()
        db.setup_db()
        db.close()
        self._logger.log(f"Running on {self._addr}:{self._port}", 0)
        while True:
            conn, addr = self._sock.accept()
            self._logger.log(f"New connection from: {addr}", 2)
            ns_sock = NonStreamSocket(conn)
            ns_sock.listen()
            t_connect = threading.Thread(target=self._handshake, args=(ns_sock,))
            t_connect.start()

    def send(self, client: str, message: bytes):
        """Send a message to a specified client ID.

        Args:
            client (str): The client ID to send the message to 
            message (bytes): The raw message bytes to send. 
        """
        if client not in self._client_outboxes:
            self._logger.log("Message to offline/unknown user {client}", 3)
            self._client_outboxes[client] = Queue()
        self._client_outboxes[client].put(message)

    def _handshake(self, client: NonStreamSocket):
        """Handshake with a socket to establish its client ID, setup an encrypted connection and begin routing messages to/from it.

        Args:
            client (NonStreamSocket): An instance of vcsms.non_stream_socket.NonStreamSocket which should be a wrapper around a newly connected tcp socket.
        """
        pub_exp = hex(self._pub[0])[2:].encode()
        pub_mod = hex(self._pub[1])[2:].encode()
        client.send(pub_exp + b':' + pub_mod)
        identity_packet = client.recv()
        try:
            c_id, c_exp, c_mod = identity_packet.split(b':')
            c_id = c_id.decode()
        except ValueError:
            self._logger.log("Connection failure. Malformed identity packet.", 1)
            client.send(b"MalformedIdentityPacket")
            client.close()
            return
        self._logger.log(f"Client ID is {c_id}", 2)
        client_pubkey = (int(c_exp, 16), int(c_mod, 16))
        if keys.fingerprint(client_pubkey) != c_id:
            self._logger.log(f"Connection failure. Public key validation failed for {c_id}", 1)
            client.send(b"PubKeyIdMismatch")
            client.close()
            return

        dhke_priv = random.randrange(1, self._dhke_group[1])
        dhke_pub, dhke_sig = signing.gen_signed_diffie_hellman(dhke_priv, self._priv, self._dhke_group)
        client.send(hex(dhke_pub)[2:].encode() + b":" + dhke_sig)

        c_dhke_pub, c_dhke_pub_sig = client.recv().split(b':')
        if not signing.verify(c_dhke_pub, c_dhke_pub_sig, client_pubkey):
            self._logger.log(f"Connection failure. Bad signature from {c_id}", 1)
            client.send(b"BadSignature")
            client.close()
            return

        shared_key = dhke.calculate_shared_key(dhke_priv, int(c_dhke_pub, 16), self._dhke_group)
        encryption_key = sha256.hash(utils.i_to_b(shared_key))
        if c_id in self._client_outboxes:
            outbox = self._client_outboxes[c_id]
        else:
            outbox = Queue()
            self._client_outboxes[c_id] = outbox

        self._sockets[c_id] = client
        db = self._db_connect()
        db.user_login(c_id, client_pubkey)
        db.close()
        self._logger.log(f"User {c_id} successfully authenticated", 1)
        t_in = threading.Thread(target=self._in_thread, args=(client, encryption_key, c_id))
        t_out = threading.Thread(target=self._out_thread, args=(client, outbox, encryption_key))
        t_in.start()
        t_out.start()

    # thread methods
    def _in_thread(self, client: NonStreamSocket, encryption_key: int, client_id: str):
        """A function to be run by a thread which parses, handles if necessary, and routes incoming messages from a given client.

        Args:
            client (NonStreamSocket): The client socket to listen to.
            encryption_key (int): The encryption key to use for all messages exchanged with the client.
            client_id (str): The client ID associated with this socket.
        """
        while client.connected():
            if client.new():
                raw = client.recv()
                try:
                    aes_iv, ciphertext = raw.decode().split(':', 1)
                except ValueError:
                    self._logger.log(f"Malformed message from {client_id}", 2)
                    return
                try:
                    aes_iv = int(aes_iv, 16)
                except ValueError:
                    self._logger.log(f"Invalid initialization vector {aes_iv}", 2)
                    return
                data = aes256.decrypt_cbc(bytes.fromhex(ciphertext), encryption_key, aes_iv)
                try:
                    recipient, message_type, message_values = self._message_parser.parse_message(data)
                except MessageParseException as parse_exception:
                    self._logger.log(str(parse_exception), 2)
                    return

                self._logger.log(f"{message_type} {client_id} -> {recipient}", 3)
                if recipient == "0":
                    response = self._message_parser.handle(client_id, message_type, message_values, "0")
                    if response:
                        self.send(client_id, response)
                else:
                    to_send = self._message_parser.construct_message(client_id, message_type, *message_values)
                    self.send(recipient, to_send)

        db = self._db_connect()
        db.user_logout(client_id)
        db.close()
        self._logger.log(f"User {client_id} closed the connection", 1)
        self._sockets.pop(client_id)

    @staticmethod
    def _out_thread(sock: NonStreamSocket, outbox: Queue, encryption_key: int):
        """A function to be run by a thread which constantly reads messages from
        the outbox queue, encrypts them, and sends them to the given client socket.

        Args:
            sock (NonStreamSocket): The socket for the client with whom the outbox is associated.
            outbox (Queue): A queue of messages meant for a specific client.
            encryption_key (int): The encryption key to for all messages exchanged with the client.
        """
        while sock.connected():
            if not outbox.empty():
                message = outbox.get()
                aes_iv = random.randrange(1, 2 ** 128)
                ciphertext = aes256.encrypt_cbc(message, encryption_key, aes_iv).hex()
                sock.send(hex(aes_iv).encode() + b':' + ciphertext.encode('utf-8'))

    # message type handler methods
    def _handler_get_key(self, sender: str, values: list) -> tuple[str, tuple]:
        """Handler function for the GetKey message type.

        Args:
            sender (str): The client ID which sent the message. 
            values (list): The parameters of the message (target ID (str)) 

        Returns:
            tuple[str, tuple]: KeyFound if successful.
                KeyNotFound: The public key for the requested user could not be found.
        """
        request_index, target_id = values

        self._logger.log(f"User {sender} requested key for user {target_id}", 3)
        db = self._db_connect()
        if db.user_known(target_id):
            self._logger.log(f"Key found for user {target_id}", 3)
            key = db.get_pubkey(target_id)
            db.close()
            return "KeyFound", (request_index, *key)

        self._logger.log(f"Key not found for user {target_id}", 3)
        db.close()
        return "KeyNotFound", (request_index, )

    def _handler_quit(self, sender: str, _: list):
        """Handler function for the Quit message type.

        Args:
            sender (str): The client ID which sent the message. 
        """
        self._logger.log(f"User {sender} requested a logout", 1)
        self._sockets[sender].close()

    def _db_connect(self) -> Server_DB:
        """Get a connection to the server database.

        Returns:
            Server_DB: An server database connection object 
        """
        db = Server_DB(self._db_path, self._pubkey_path)
        return db
