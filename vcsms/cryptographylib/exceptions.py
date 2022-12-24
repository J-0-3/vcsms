class CryptographyException:
    def __init__(self, message):
        super().__init__(f"Cryptographic failure: {message}")

class DecryptionFailureException:
    def __init__(self, key: int):
        super().__init__(f"Failed to decrypt data using key {key}")
