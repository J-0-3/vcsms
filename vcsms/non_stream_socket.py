import socket
import threading
from queue import Queue


class NonStreamSocket:
    def __init__(self, sock: socket.socket, block_size: int = 4096):
        self.sock = sock
        self.block_size = block_size
        self.queue = Queue()
        self.incoming_in_progress = b''
        self.outgoing_in_progress = b''
        self.open = False
    
    def __in_thread(self):
        while open:
            try:
                data = self.sock.recv(self.block_size)
                for c in data:
                    byte = c.to_bytes(1, 'big')
                    if byte == b'\xff':
                        self.queue.put(self.incoming_in_progress)
                        self.incoming_in_progress = b''
                    else:
                        self.incoming_in_progress += byte
            except OSError as e:
                break

    def connect(self, addr: str, port: int):
        self.sock.connect((addr, port))

    def close(self):
        self.open = False
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

    def send(self, data: bytes):
        self.sock.send(data + b'\xff')

    def recv(self) -> bytes:
        return self.queue.get()

    def new(self) -> bool:
        return not self.queue.empty()

    def listen(self):
        t_in = threading.Thread(target=self.__in_thread, args=())
        t_in.start()
        self.open = True
