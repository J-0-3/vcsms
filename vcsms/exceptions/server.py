class ServerException(Exception):
    def __init__(self, message: str):
        super().__init__(f"Server raised an exception: {message}")
        self.message = message

class IDCollisionException(ServerException):
    def __init__(self, id: str = ""):
        super().__init__(f"Collision with {id} existing public key")
