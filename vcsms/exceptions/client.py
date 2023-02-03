"""Exceptions raised by the Client class"""


class ClientException(Exception):
    """Parent class for all exceptions thrown by the VCSMS client."""
    def __init__(self, message: str):
        """Instantiate a ClientException

        Args:
            message (str): The error message to raise.
        """
        super().__init__(f"Client raised an exception: {message}.")
        self.message = message


class UserNotFoundException(ClientException):
    """Raised when a user is referenced who does not exist."""
    def __init__(self, user: str):
        """Instantiate a UserNotFoundException

        Args:
            user (str): The user's nickname/client ID
        """
        super().__init__(f"User {user}{' ' if user else ''}not found")

class IncorrectMasterKeyException(ClientException):
    """Raised when a master key check fails.

    (When the user has supplied an incorrect master key)"""
    def __init__(self):
        super().__init__("Master key incorrect")

class GroupNameInUseException(ClientException):
    """Raised when an attempt is made to create a group with 
    a name that already refers to a group or user.
    """
    def __init__(self, name: str):
        """Instantiate a GroupNameInUseException

        Args:
            name (str): The name of the group
        """
        super().__init__(f"Group {name}{' ' if name else ''}already exists.")

class GroupNotFoundException(ClientException):
    """Raised when a group is referenced which does not exist."""
    def __init__(self, name: str):
        super().__init__(f"Group {name}{' ' if name else ''}does not exist")

class NickNameInUseException(ClientException):
    """Raised when the nickname for a user is already being used"""
    def __init__(self, nickname: str):
        super().__init__(f"Nickname {nickname}{' ' if nickname else ''}is already in use")

class UserAlreadyExistsException(ClientException):
    """Raised when the client ID for a user is already registered"""
    def __init__(self, client_id: str = ""):
        super().__init__(f"User {client_id}{' ' if client_id else ''}already exists.")

class InvalidIDException(ClientException):
    """Raised when an invalid client ID is supplied"""
    def __init__(self, client_id: str = ""):
        super().__init__(f"ID {client_id}{' ' if client_id else ''}is malformed")

class ConnectionFailureException(ClientException):
    """Raised when the client is unable to connect to the server"""
    def __init__(self, reason: str = ""):
        super().__init__(f"Client was unable to connect to server. Reason: {reason or 'None'}")