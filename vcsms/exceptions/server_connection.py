class ConnectionException(Exception):
    """The parent class for all exceptions raised by the ServerConnection class.

    Args:
        message (str): The exception message to throw.
    """
    def __init__(self, message: str):
        super().__init__(f"Failure connecting to server: {message}")
        self.message = message


class MalformedPacketException(ConnectionException):
    """Received a malformed packet from the server."""
    def __init__(self):
        super().__init__("Malformed packet")


class PublicKeyIdMismatchException(ConnectionException):
    """The public key provided by the server did not match it's specified fingerprint.
    This indicates a potential MITM and so the connection should be aborted.    

    Args:
        public_key_fp (str): The hex SHA256 fingerprint of the key the server provided.
        server_fp (str): The hex SHA256 fingerprint expected from the server.
    """
    def __init__(self, public_key_fp, server_fp):
        super().__init__(f"Public key fingerprint {public_key_fp} did not match server fingerprint {server_fp}")


class SignatureVerifyFailureException(ConnectionException):
    """The server provided an invalidly signed piece of data.
    This could indicate a potential MITM, but is more likely to be caused by an invalid timestamp.

    Args:
        signature (bytes): The signature which could not be verified. 
    """
    def __init__(self, signature: bytes):
        super().__init__(f"Could not verify signature: {signature}")

class ServerConnectionAbort(ConnectionException):
    def __init__(self, reason: str):
        super().__init__(f"Server aborted connection. Reason: {reason}")

class KeyConfirmationFailureException(ConnectionException):
    def __init__(self):
        super().__init__(f"Failed to decrypt confirmation packet")

class NetworkError(ConnectionException):
    def __init__(self, reason: Exception):
        super().__init__(f"Network connection failed. Reason: {str(reason)}")