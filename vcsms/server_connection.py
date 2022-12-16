import socket
import random
import threading
import time
from queue import Queue

from . import keys
from . import signing
from .non_stream_socket import NonStreamSocket
from .cryptographylib import dhke, sha256, utils, aes256


class ServerConnection:
    def __init__(self, ip: str, port: int, fp: str):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket = NonStreamSocket(s)
        self.ip = ip
        self.port = port
        self.fp = fp
        self.encryption_key = 0
        self.public_key = (0, 0)
        self.in_queue = Queue()
        self.out_queue = Queue()
        self.connected = False
        self.busy = False

    def __handshake(self, pub_key, priv_key, dhke_group=dhke.group16_4096, skip_fp_verify=False):
        pub_exp = hex(pub_key[0])[2:].encode()
        pub_mod = hex(pub_key[1])[2:].encode()
        try:
            server_exp, server_mod = self.socket.recv().split(b':')
            self.public_key = (int(server_exp, 16), int(server_mod, 16))
        except:
            self.socket.send(b"MalformedIdentityPacket")
            self.socket.close()
            raise Exception("server sent a malformed identity packet")
        if keys.fingerprint(self.public_key) != self.fp and not skip_fp_verify:
            self.socket.send(b"PubKeyIdMismatch")
            self.socket.close()
            raise Exception("server fingerprint mismatch. possible mitm detected, aborting...")

        pub_key_hash = keys.fingerprint(pub_key).encode()
        self.socket.send(pub_key_hash + b":" + pub_exp + b":" + pub_mod)

        dhke_priv = random.randrange(1, dhke_group[1])
        dhke_pub, dhke_sig = signing.gen_signed_diffie_hellman(dhke_priv, priv_key, dhke_group)

        s_dhke_pub, s_dhke_pub_sig = self.socket.recv().split(b':')
        if not signing.verify(s_dhke_pub, s_dhke_pub_sig, self.public_key):
            self.socket.send(b"BadSignature")
            self.socket.close()
            raise Exception("Signature verification failed")

        self.socket.send(hex(dhke_pub)[2:].encode() + b":" + dhke_sig)

        shared_key = dhke.calculate_shared_key(dhke_priv, int(s_dhke_pub, 16), dhke_group)
        self.encryption_key = sha256.hash(utils.i_to_b(shared_key))
        
    def connect(self, pub_key: tuple[int, int], priv_key: tuple[int, int], skip_fp_verify: bool = False):
        self.connected = True
        self.socket.connect(self.ip, self.port)
        self.socket.listen()
        self.__handshake(pub_key, priv_key, dhke.group14_2048, skip_fp_verify)
        t_in = threading.Thread(target=self.__in_thread, args=())
        t_out = threading.Thread(target=self.__out_thread, args=())
        t_in.start()
        t_out.start()

    def __in_thread(self):
        while self.connected:        
            if self.socket.new():
                data = self.socket.recv()
                iv, data = data.split(b':')
                iv = int(iv, 16)
                message = aes256.decrypt_cbc(utils.i_to_b(int(data, 16)), self.encryption_key, iv)
                self.in_queue.put(message)
    
    def __out_thread(self):
        while self.connected:
            if not self.out_queue.empty():
                self.busy = True
                message = self.out_queue.get()
                iv = random.randrange(1, 2 ** 128)
                encrypted = aes256.encrypt_cbc(message, self.encryption_key, iv)
                self.socket.send(hex(iv)[2:].encode() + b':' + encrypted.hex().encode())
                self.busy = False

    def close(self):
        while True:
            if self.out_queue.empty() and not self.busy:
                self.connected = False
                self.socket.close()
                break

    def send(self, data: bytes):
        self.out_queue.put(data)
        
    def read(self) -> bytes:
        return self.in_queue.get()
    
    def new_msg(self) -> bool:
        return not self.in_queue.empty()
