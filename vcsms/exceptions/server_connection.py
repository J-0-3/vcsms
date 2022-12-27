class ConnectionException(Exception):
    def __init__(self, message: str):
        super().__init__(f"Failure connecting to server: {message}")


class MalformedPacketException(ConnectionException):
    def __init__(self):
        super().__init__("Malformed packet")


class PublicKeyIdMismatchException(ConnectionException):
    def __init__(self, public_key_fp, server_fp):
        super().__init__(f"Public key fingerprint {public_key_fp} did not match server fingerprint {server_fp}")


class SignatureVerifyFailureException(ConnectionException):
    def __init__(self, signature: bytes):
        super().__init__(f"Could not verify signature: {signature}")
