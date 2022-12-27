import socket
import random
import threading
from queue import Queue

from . import keys
from . import signing
from .non_stream_socket import NonStreamSocket
from .logger import Logger
from .cryptographylib import dhke, sha256, utils, aes256
from .cryptographylib.exceptions import DecryptionFailureException
from .exceptions.server_connection import MalformedPacketException, PublicKeyIdMismatchException, SignatureVerifyFailureException


class ServerConnection:
    def __init__(self, ip: str, port: int, fp: str, logger: Logger):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket = NonStreamSocket(s)
        self.ip = ip
        self.port = port
        self.fp = fp
        self._logger = logger
        self._encryption_key = 0
        self._public_key = (0, 0)
        self._in_queue = Queue()
        self._out_queue = Queue()
        self.connected = False
        self._busy = False

        
    def _handshake(self, pub_key, priv_key, dhke_group=dhke.group16_4096, skip_fp_verify=False):
        pub_exp = hex(pub_key[0])[2:].encode()
        pub_mod = hex(pub_key[1])[2:].encode()
        try:
            server_exp, server_mod = self._socket.recv().split(b':')
            self._public_key = (int(server_exp, 16), int(server_mod, 16))
        except ValueError:
            self._socket.send(b"MalformedPacket")
            self._socket.close()
            raise MalformedPacketException()
        if keys.fingerprint(self._public_key) != self.fp and not skip_fp_verify:
            self._socket.send(b"PubKeyIdMismatch")
            self._socket.close()
            raise PublicKeyIdMismatchException(keys.fingerprint(self._public_key), self.fp)

        pub_key_hash = keys.fingerprint(pub_key).encode()
        self._socket.send(pub_key_hash + b":" + pub_exp + b":" + pub_mod)

        dhke_priv = random.randrange(1, dhke_group[1])
        dhke_pub, dhke_sig = signing.gen_signed_diffie_hellman(dhke_priv, priv_key, dhke_group)

        try:
            s_dhke_pub, s_dhke_pub_sig = self._socket.recv().split(b':')
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


    def connect(self, pub_key: tuple[int, int], priv_key: tuple[int, int], skip_fp_verify: bool = False):
        self.connected = True
        self._socket.connect(self.ip, self.port)
        self._socket.listen()
        self._handshake(pub_key, priv_key, dhke.group14_2048, skip_fp_verify)
        t_in = threading.Thread(target=self._in_thread, args=())
        t_out = threading.Thread(target=self._out_thread, args=())
        t_in.start()
        t_out.start()


    def _in_thread(self):
        while self.connected:        
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
        while self.connected:
            if not self._out_queue.empty():
                self._busy = True
                message = self._out_queue.get()
                iv = random.randrange(1, 2 ** 128)
                encrypted = aes256.encrypt_cbc(message, self._encryption_key, iv)
                self._socket.send(hex(iv)[2:].encode() + b':' + encrypted.hex().encode())
                self._busy = False


    def close(self):
        self._logger.log("Trying to close connection to server", 3)
        while True:
            if self._out_queue.empty() and not self._busy:
                self._logger.log("Able to close connection", 3)
                self.connected = False
                self._socket.close()
                self._logger.log("Closed connection to server", 2)
                break


    def send(self, data: bytes):
        self._out_queue.put(data)


    def read(self) -> bytes:
        return self._in_queue.get()


    def new_msg(self) -> bool:
        return not self._in_queue.empty()
