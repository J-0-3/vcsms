import socket
import random
import threading
from .queue import Queue

from . import keys
from . import signing
from .non_stream_socket import NonStreamSocket
from .logger import Logger
from .cryptography import dhke, sha256, utils, aes256
from .cryptography.exceptions import DecryptionFailureException
from .exceptions.server_connection import *


class ServerConnection:
    """An encrypted connection to a server which speaks the VCSMS handshaking protocol."""
    def __init__(self, ip: str, port: int, fp: str, logger: Logger):
        """Initialise a ServerConnection.

        Args:
            ip (str): The IP address of the server to connect to.
            port (int): The port on the server to connect to.
            fp (str): The server's public key fingerprint.
            logger (Logger): An instance of the vcsms.logger.Logger class to use for logging events/errors.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket = NonStreamSocket(s)
        self._ip = ip
        self._port = port
        self._fp = fp
        self._logger = logger
        self._encryption_key = 0
        self._public_key = (0, 0)
        self._in_queue = Queue()
        self._out_queue = Queue()
        self._connected = False
        self._busy = False

    @property
    def connected(self) -> bool:
        """Get whether the connection is currently open.

        Returns:
            bool: whether the connection is currently open
        """
        return self._connected

    def _handshake(self, pub_key: tuple[int, int], priv_key: tuple[int, int], dhke_group: tuple[int, int]=dhke.group16_4096):
        """Handshake to the server to setup an encrypted connection.

        Args:
            pub_key (tuple[int, int]): The client public key to send the server.
            priv_key (tuple[int, int]): The client private key to use when signing diffie hellman keys.
            dhke_group (tuple[int, int], optional): The diffie hellman group to use in the form (generator, modulus). Defaults to dhke.group16_4096.

        Raises:
            MalformedPacketException: The server sent a message of an invalid form.
            PublicKeyIdMismatchException: The server provided a public key that doesn't match the specified fingerprint.
            SignatureVerifyFailureException: The server provided a badly signed diffie hellman public key.
            ServerConnectionAbort: The server aborted the connection
            KeyConfirmationFailureException: The established shared key failed confirmation
        """
        pub_exp = hex(pub_key[0])[2:].encode()
        pub_mod = hex(pub_key[1])[2:].encode()
        try:
            server_exp, server_mod = self._socket.recv().split(b':')
            self._public_key = (int(server_exp, 16), int(server_mod, 16))
        except ValueError:
            self._socket.send(b"MalformedPacket")
            self._socket.close()
            raise MalformedPacketException()
        if keys.fingerprint(self._public_key, 64) != self._fp:
            self._socket.send(b"PubKeyFpMismatch")
            self._socket.close()
            raise PublicKeyIdMismatchException(keys.fingerprint(self._public_key), self._fp)

        pub_key_hash = keys.fingerprint(pub_key).encode()
        self._socket.send(pub_key_hash + b":" + pub_exp + b":" + pub_mod)

        dhke_priv = random.randrange(1, dhke_group[1])
        dhke_pub, dhke_sig = signing.gen_signed_dh(dhke_priv, priv_key, dhke_group)

        server_auth_packet = self._socket.recv()
        if server_auth_packet == b"MalformedPacket":
            self._socket.close()
            raise ServerConnectionAbort("Malformed identity packet")
        elif server_auth_packet == b"PubKeyIdMismatch":
            self._socket.close()
            raise ServerConnectionAbort("Public key fingerprint does not match client ID")
        try:
            s_dhke_pub, s_dhke_pub_sig = server_auth_packet.split(b':')
        except ValueError:
            self._socket.send(b"MalformedPacket")
            self._socket.close()
            raise MalformedPacketException()

        if not signing.verify(s_dhke_pub, s_dhke_pub_sig, self._public_key):
            self._socket.send(b"BadSignature")
            self._socket.close()
            raise SignatureVerifyFailureException(s_dhke_pub_sig)

        self._socket.send(hex(dhke_pub)[2:].encode() + b":" + dhke_sig)
        shared_key = dhke.calculate_shared_key(dhke_priv, int(s_dhke_pub, 16), dhke_group)
        self._encryption_key = sha256.hash(utils.i_to_b(shared_key))

        encrypted_confirmation = self._socket.recv()
        if encrypted_confirmation == b"MalformedPacket":
            self._socket.close()
            raise ServerConnectionAbort("Malformed authentication packet")
        elif encrypted_confirmation == b"BadSignature":
            self._socket.close()
            raise ServerConnectionAbort("Incorrectly signed diffie hellman public key")
        elif encrypted_confirmation == b"IDCollision":
            self._socket.close()
            raise ServerConnectionAbort("Public key collision for client ID")
        try:
            iv, ciphertext = encrypted_confirmation.split(b':')
            iv = int(iv, 16)
            ciphertext = bytes.fromhex(ciphertext.decode('utf-8'))
        except ValueError:
            self._socket.send(b"MalformedPacket")
            self._socket.close()
            raise MalformedPacketException()
        try:
            plaintext = aes256.decrypt_cbc(ciphertext, self._encryption_key, iv)
        except DecryptionFailureException:
            self._socket.send("CouldNotDecrypt")
            self._socket.close()
            raise KeyConfirmationFailureException()
        self._socket.send(plaintext.hex().encode('utf-8'))
        response = self._socket.recv()
        if response == b"MalformedPacket":
            self._socket.close()
            raise ServerConnectionAbort("Malformed challenge response")
        if response != b"OK":
            self._socket.close()
            raise ServerConnectionAbort("Failed challenge-response confirmation for shared key")

    def connect(self, pub_key: tuple[int, int], priv_key: tuple[int, int]):
        """Begin a connection to the server.

        Args:
            pub_key (tuple[int, int]): The client public key to send to the server.
            priv_key (tuple[int, int]): The client private key to use when signing data.
        """
        try:
            self._socket.connect(self._ip, self._port)
        except OSError as e:
            raise NetworkError(e)
        self._socket.run()
        self._handshake(pub_key, priv_key, dhke.group14_2048)
        self._connected = True
        t_in = threading.Thread(target=self._in_thread, args=())
        t_out = threading.Thread(target=self._out_thread, args=())
        t_in.start()
        t_out.start()

    def _in_thread(self):
        """A function to be run by a thread which receives, parses and decrypts messages from the server."""
        while self._connected:
            if self._socket.new():
                data = self._socket.recv()
                try:
                    iv, data = data.split(b':')
                except ValueError:
                    self._logger.log("Server sent a malformed packet", 2)
                    continue
                try:
                    iv = int(iv, 16)
                except ValueError:
                    self._logger.log("Server sent an invalid initialisation vector", 2)
                    continue
                try:
                    message = aes256.decrypt_cbc(utils.i_to_b(int(data, 16)), self._encryption_key, iv)
                except DecryptionFailureException:
                    self._logger.log("Failed to decrypt message from server", 2)
                    continue
                self._in_queue.put(message)

    def _out_thread(self):
        """A function to be run by a thread which encrypts, formats and sends messages in the outgoing queue to the server."""
        while self._connected:
            if not self._out_queue.empty():
                self._busy = True
                message = self._out_queue.get()
                iv = random.randrange(1, 2 ** 128)
                encrypted = aes256.encrypt_cbc(message, self._encryption_key, iv)
                self._socket.send(hex(iv)[2:].encode() + b':' + encrypted.hex().encode())
                self._busy = False

    def close(self):
        """Shutdown the connection to the server once all queued messages have been sent."""
        self._logger.log("Trying to close connection to server", 3)
        while True:
            if self._out_queue.empty() and not self._busy:
                self._logger.log("Able to close connection", 3)
                self._connected = False
                self._socket.close()
                self._logger.log("Closed connection to server", 2)
                break

    def send(self, data: bytes):
        """Queue some data to be sent to the server.

        Args:
            data (bytes): The bytes of the message to send.
        """
        self._out_queue.put(data)

    def read(self) -> bytes:
        """Block until a new piece of data is available from the connection and then return it.

        Returns:
            bytes: The data received from the server.
        """
        return self._in_queue.get()

    def new_msg(self) -> bool:
        """Check whether there is any new data from the server.

        Returns:
            bool: Whether there is any new data available.
        """
        return not self._in_queue.empty()
