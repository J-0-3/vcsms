"""Exceptions raised by the Client class"""


class ClientException(Exception):
    """Parent class for all exceptions thrown by the VCSMS client."""
    def __init__(self, message: str):
        """Instantiate a ClientException

        Args:
            message (str): The error message to raise.
        """
        super().__init__(f"Client raised an exception: {message}.")


class UserNotFoundException(ClientException):
    """Raised when a user is referenced who does not exist."""
    def __init__(self, user: str):
        """Instantiate a UserNotFoundException

        Args:
            user (str): The user's nickname/client ID
        """
        super().__init__(f"User {user} not found")

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
        super().__init__(f"Group {name} cannot be created as the name is already in use.")
