from server_connection import ServerConnection
from cryptographylib.utils import i_to_b
import signing
import random
import threading

class Peer:
    def __init__(self, public_key: tuple, my_private_key: tuple, server: ServerConnection, client_id: str):
        self.server = server
        self.id = client_id
        self.public_key = public_key
        self.my_private_key = my_private_key

        self.index = 0

    def __msg_handshake_thread(self, message: bytes, index: int):
        dh_pub_key = random.randrange(1, 1**2048)
        dh_pub_key_sig = signing.sign(i_to_b(dh_pub_key))
        message = b'NewMessage:' + self.id.encode() + b':' + str(index).encode() + b':' + hex(dh_pub_key)[2:].encode() + dh_pub_key_sig
        while True:
            latest = self.server.peek().split(b':')
            if len(latest) >= 3 and latest[2] == str(index).encode():
                response = latest
                break
        if response[0] != b'MessageAccept':
            self.server.send(b'InvalidResponse: ' + self.id.encode() + b':' + str(index).encode())

    def send(self, message: bytes):
        t_send = threading.Thread(target=self.__msg_handshake_thread(message, self.index))
        self.index += 1
        t_send.start()