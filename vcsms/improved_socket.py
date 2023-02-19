import socket
import threading
import time
from .queue import Queue


class ImprovedSocket:
    """A wrapper class for an existing tcp socket which provides a more reliable connection. The bytes \\xfe and \\xff are reserved.
    """
    def __init__(self, _sock: socket.socket, block_size: int = 4096):
        """Initialise an instance of the NonStreamSocket class.

        Args:
            sock (socket.socket): An existing tcp socket.
            block_size (int, optional): The size of the buffer to use for recieving blocks of data. Defaults to 4096.
        """
        self._sock = _sock
        self._block_size = block_size
        self._queue = Queue()
        self._incoming_in_progress = b''
        self._outgoing_in_progress = b''
        self._send_lock = threading.Lock()
        self._open = False

    def _checklife_thread(self):
        """Constantly attempts to send the byte \\xfe
        to the connected socket to test if it is still connected. 
        Once it is not it closes the socket.
        """
        while self._open:
            time.sleep(1)
            self._send_lock.acquire()
            try:
                self._sock.sendall(b'\xfe')
            except OSError:
                self._open = False
            self._send_lock.release()

    def _in_thread(self):
        """Receives incoming data, parses it, and
         splits it into separate messages using the delimiter \\xff.
        """
        while self._open:
            try:
                data = self._sock.recv(self._block_size)
                for c in data:
                    byte = c.to_bytes(1, 'big')
                    if byte == b'\xff':
                        self._queue.push(self._incoming_in_progress)
                        self._incoming_in_progress = b''
                    elif byte != b'\xfe':
                        self._incoming_in_progress += byte
            except OSError:
                self._open = False
            
    def connect(self, addr: str, port: int):
        """Connect to a port on a given ip address.

        Args:
            addr (str): The ip address to connect to.
            port (int): The port on the target device to connect to.
        """
        self._sock.connect((addr, port))

    def close(self):
        """Close the connection and shutdown the socket."""
        self._open = False
        self._send_lock.acquire()
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # connection has already closed
        self._sock.close()
        self._send_lock.release()

    @property
    def connected(self) -> bool:
        """Get whether the socket is currently connected.

        Returns:
            bool: Whether the socket is connected.
        """
        return self._open

    def send(self, data: bytes):
        """Send the data given.

        Args:
            data (bytes): The payload to send.
        """
        self._send_lock.acquire()
        self._sock.sendall(data + b'\xff')
        self._send_lock.release()

    def recv(self) -> bytes:
        """Block until a new piece of data is available and then return it.

        Returns:
            bytes: The received piece of data.
        """
        return self._queue.pop()

    @property
    def new(self) -> bool:
        """Get whether there is a piece of data available ready to be received.

        Returns:
            bool: Whether there is new data available.
        """
        return not self._queue.empty()

    def run(self):
        """Start the socket listening for incoming data. 
        This must be called before any data can be received from the socket."""
        t_in = threading.Thread(target=self._in_thread, args=())
        t_life = threading.Thread(target=self._checklife_thread, args=())
        self._open = True
        t_in.start()
        t_life.start()
