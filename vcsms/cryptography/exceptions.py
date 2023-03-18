class CryptographyException(Exception):
    def __init__(self, message):
        super().__init__(f"Cryptographic failure: {message}")


class DecryptionFailureException(CryptographyException):
    def __init__(self, key: int):
        super().__init__(f"Failed to decrypt data using key {key}")

class DataTooLong(CryptographyException):
    def __init__(self, data: bytes):
        super().__init__(f"Data of length {len(data)} bytes is too long to be processed")

