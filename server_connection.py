import socket
import random
import threading
from queue import Queue

import keys
import signing
from cryptographylib import dhke, sha256, utils, aes256

class serverConnection:
    def __init__(self, ip: str, port: int, fp: str):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ip = ip
        self.port = port
        self.fp = fp
        self.encryption_key = 0
        self.public_key = (0, 0)
        self.in_queue = Queue()
        self.out_queue = Queue()
        
    def __handshake(self, pub_key, priv_key, dhke_group = dhke.group16_4096, skip_fp_verify = False):
        pub_exp = hex(pub_key[0])[2:].encode()
        pub_mod = hex(pub_key[1])[2:].encode()
    
        server_exp, server_mod = self.socket.recv(2048).split(b':')
        self.public_key = (int(server_exp, 16), int(server_mod, 16))
        if keys.fingerprint(self.public_key) != int(self.fp, 16) and not skip_fp_verify:
            self.socket.close()
            raise Exception("server fingerprint mismatch. possible mitm detected, aborting...")
    
        pub_key_hash = hex(sha256.hash(pub_exp + pub_mod)).encode()
        self.socket.send(pub_key_hash+b":"+pub_exp+b":"+pub_mod)
        
        dhke_priv = random.randrange(1, dhke_group[1])
        dhke_pub = hex(dhke.generate_public_key(dhke_priv, dhke_group))[2:].encode()
        dhke_pub_sig = signing.sign(dhke_pub, priv_key)

        s_dhke_pub, s_dhke_pub_sig = self.socket.recv(2048).split(b':')

        if not signing.verify(s_dhke_pub, s_dhke_pub_sig, self.public_key):
            self.socket.send("SIGNATURE VERIFICATION FAILED")
            self.socket.close()
            raise("Signature verification failed")
    
        self.socket.send(dhke_pub+b":"+dhke_pub_sig)

        shared_key = dhke.calculate_shared_key(dhke_priv, int(s_dhke_pub, 16), dhke_group)
        self.encryption_key = sha256.hash(utils.i_to_b(shared_key))
        
    def connect(self, pub_key, priv_key, skip_fp_verify: bool = False):
        self.socket.connect((self.ip, self.port))
        self.__handshake(pub_key, priv_key, dhke.group16_4096, skip_fp_verify)
        t_in = threading.Thread(target=self.__in_thread, args=())
        t_out = threading.Thread(target=self.__out_thread, args=())
        t_in.start()
        t_out.start()
        
    def __in_thread(self):
        while True:
            data = self.socket.recv(2048)
            if data == b'':
                continue
            iv, data = data.split(b':')
            iv = int(iv, 16)
            message = aes256.decrypt_cbc(utils.i_to_b(int(data, 16)), self.encryption_key, iv)
            self.in_queue.put(message)
    
    def __out_thread(self):
        while True:
            message = self.out_queue.get()
            iv = random.randrange(1, 2**128)
            encrypted = aes256.encrypt_cbc(message, self.encryption_key, iv)
            self.socket.send(hex(iv)[2:].encode() + b':' + hex(int.from_bytes(encrypted, 'big'))[2:].encode())
            
    def send(self, data: bytes):
        self.out_queue.put(data)
    
    def read(self) -> bytes:
        return self.in_queue.get()
    
    def readall(self) -> list:
        msgs = []
        while not self.in_queue.empty():
            msgs.append(self.in_queue.get())
        return msgs
