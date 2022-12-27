import socket
import threading
import time
from queue import Queue


class NonStreamSocket:
    """A wrapper class for an existing tcp socket which provides a more reliable connection.
    """
    def __init__(self, _sock: socket.socket, block_size: int = 4096):
        """Initialise an instance of the NonStreamSocket class.

        Args:
            sock (socket.socket): An existing tcp socket. 
            block_size (int, optional): The size of the buffer to use for recieving blocks of data. Defaults to 4096.
        """
        self.sock = _sock
        self._block_size = block_size
        self._queue = Queue()
        self._incoming_in_progress = b''
        self._outgoing_in_progress = b''
        self._open = False

    def _checklife_thread(self):
        """A function to be run by a thread which constantly attempts to send the string 'alive?' 
        to the connected socket to test if it is still connected. Once it is not is shuts down the socket.
        """
        while self._open:
            time.sleep(1)
            try:
                self.sock.sendall(b'alive?')
            except OSError:
                self._open = False
                break

    def _in_thread(self):
        """A function to be run by a thread which receives incoming data, parses it, and splits it into separate messages using the delimiter \\xff.
        """
        while self._open:
            try:
                data = self.sock.recv(self._block_size)
            except OSError:
                break
            if data != b'alive?':
                for c in data:
                    byte = c.to_bytes(1, 'big')
                    if byte == b'\xff':
                        self._queue.put(self._incoming_in_progress)
                        self._incoming_in_progress = b''
                    else:
                        self._incoming_in_progress += byte

    def connect(self, addr: str, port: int):
        """Connect to a port on a given ip address.

        Args:
            addr (str): The ip address to connect to. 
            port (int): The port on the target device to connect to. 
        """
        self.sock.connect((addr, port))

    def close(self):
        """Close the connection and shutdown the socket."""
        self._open = False
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

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
        self.sock.sendall(data + b'\xff')

    def recv(self) -> bytes:
        """Block until a new piece of data is available and then return it.

        Returns:
            bytes: The received piece of data. 
        """
        return self._queue.get()

    def new(self) -> bool:
        """Get whether there is a piece of data available ready to be received.

        Returns:
            bool: Whether there is new data available. 
        """
        return not self._queue.empty()

    def listen(self):
        """Start the socket listening for incoming data. This must be called before any data can be received from the socket.""" 
        t_in = threading.Thread(target=self._in_thread, args=())
        t_life = threading.Thread(target=self._checklife_thread, args=())
        self._open = True
        t_in.start()
        t_life.start()
