class SocketException(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

class NotConnectedException(SocketException):
    def __init__(self):
        super().__init__("Socket is not connected")

class DisconnectedException(SocketException):
    def __init__(self):
        super().__init__("Socket disconnected while an action was being performed on it")

class SocketAlreadyConnectedException(SocketException):
    def __init__(self):
        super().__init__("Socket is already connected.")

class ConnectionFailureException(SocketException):
    def __init__(self):
        super().__init__("Socket failed to initiate connection.")