"""Defines a Client_DB class for connecting to the client database. """

import sqlite3
import os
import random
from . import keys
from .cryptographylib import aes256


class Client_DB:
    """A connection to the client sqlite3 database"""
    def __init__(self, path: str, key_file_prefix: str, encryption_key: int, nickname_iv: int):
        """Constructor for the Client_DB class.

        Args:
            path (str): The path to the sqlite3 database file. 
            key_file_prefix (str): A string to prepend to all public key files.
            encryption_key (int): The encryption key to use when storing messages and nicknames. 
            nickname_iv (int): The initialization vector used when encrypting contacts' nicknames. 
        """
        self._db = sqlite3.connect(path)
        self._key_file_prefix = key_file_prefix
        self._encryption_key = encryption_key
        self._nickname_iv = nickname_iv

    def setup(self):
        """Create the database if it has not already been created"""

        self._db.execute("CREATE TABLE IF NOT EXISTS nicknames (id text unique, nickname blob unique)")
        self._db.execute("CREATE TABLE IF NOT EXISTS messages (id text, content blob, outgoing integer, timestamp integer, iv text)")
        self._db.commit()

    def get_nickname(self, client_id: str) -> str | None:
        """Get the nickname associated with a given client id.

        Args:
            id (str): The client id to lookup (a 64 char hex string)
            
        Returns:
            str | None: The nickname of the associated contact record (None if there is no such contact)
        """
        cursor = self._db.cursor()
        cursor.execute("SELECT nickname FROM nicknames WHERE id=?", (client_id, ))
        result = cursor.fetchone()
        if result is None:
            return None
        return aes256.decrypt_cbc(result[0], self._encryption_key, self._nickname_iv).decode('utf-8')

    def close(self):
        """Close the connection to the database."""
        self._db.close()

    def get_id(self, nickname: str) -> str | None:
        """Get the client ID associated with a given nickname.

        Args:
            nickname (str): The nickname to lookup 

        Returns:
            str | None: The client ID of the associated contact record (None if there is no such contact) 
        """
        cursor = self._db.cursor()
        nickname_encrypted = aes256.encrypt_cbc(nickname.encode('utf-8'), self._encryption_key, self._nickname_iv)
        cursor.execute("SELECT id FROM nicknames WHERE nickname=?", (nickname_encrypted, ))
        result = cursor.fetchone()
        if result is None:
            return None
        return result[0]

    def get_messages_by_id(self, client_id: str, count: int) -> list[tuple[bytes, bool]]:
        """Get the last *count* messages to/from a specified client ID in descending time order.

        Args:
            id (str): The client ID to lookup 
            count (int): The number of messages to return 

        Returns:
            list[tuple[bytes, bool]]: A list of messages in the format (message, outgoing) where message is the 
                raw message bytes and outgoing is a boolean which is True if the message was sent and False if it was received.  
        """
        cursor = self._db.cursor()
        cursor.execute("SELECT content, outgoing, iv FROM messages WHERE id=? ORDER BY timestamp DESC LIMIT ?", (client_id, count))
        return [(aes256.decrypt_cbc(m[0], self._encryption_key, int(m[2], 16)), bool(m[1])) for m in cursor.fetchall()]

    def get_messages_by_nickname(self, nickname: str, count: int) -> list[tuple[bytes, bool]]:
        """Get the last *count* messages to/from a specified nickname in descending time order.

        Args:
            nickname (str): The contact nickname to lookup
            count (int): The number of messages to return 

        Returns:
            list[tuple[bytes, bool]]: A list of messages in the format (message, outgoing) where message is the 
                raw messages bytes and outgoing is a boolean which is True if the message was sent and False if it was received.  
        """
        nickname_encrypted = aes256.encrypt_cbc(nickname.encode('utf-8'), self._encryption_key, self._nickname_iv)
        cursor = self._db.cursor()
        cursor.execute("SELECT messages.content, messages.outgoing, messages.iv FROM messages INNER JOIN nicknames ON messages.id = nicknames.id WHERE nicknames.nickname=? ORDER BY messages.timestamp DESC LIMIT ?", (nickname_encrypted, count))
        return [(aes256.decrypt_cbc(m[0], self._encryption_key, int(m[2], 16)), bool(m[1])) for m in cursor.fetchall()]

    def insert_message(self, client_id: str, message: bytes, sent: bool):
        """Insert a message into the database.

        Args:
            id (str): The client id which the message was sent to/received from.
            message (bytes): The message contents. 
            sent (bool): Whether the message was sent (False if it was received).
        """
        aes_iv = random.randrange(0, 2**128)
        message_encrypted = aes256.encrypt_cbc(message, self._encryption_key, aes_iv)
        self._db.execute("INSERT INTO messages (id, content, outgoing, timestamp, iv) VALUES (?, ?, ?, strftime('%s','now'), ?)", (client_id, message_encrypted, int(sent), hex(aes_iv)))
        self._db.commit()

    def set_nickname(self, client_id: str, nickname: str):
        """Set the nickname for a given client id.

        Args:
            id (str): The client ID to attach the nickname to. 
            nickname (str): The nickname to attach to the client ID. 
        """
        nickname_encrypted = aes256.encrypt_cbc(nickname.encode('utf-8'), self._encryption_key, self._nickname_iv)
        self._db.execute("REPLACE INTO nicknames VALUES(?, ?)", (client_id, nickname_encrypted))
        self._db.commit()

    def save_key(self, client_id: str, key: tuple[int, int]):
        """Save the public key for a specified ID.

        Args:
            id (str): The ID who the public key belongs to. 
            key (tuple[int, int]): The RSA public key in the form (exponent, modulus) 
        """
        keys.write_key(key, self._key_file_prefix + client_id + ".pub")

    def user_known(self, client_id: str) -> bool:
        """Check whether a given client ID is 'known' (i.e. whether a public key exists for it).

        Args:
            id (str): The client ID to lookup 

        Returns:
            bool: Whether or not the client's public key exists. 
        """
        return os.path.exists(self._key_file_prefix + client_id + ".pub")

    def get_key(self, client_id: str) -> tuple[int, int]:
        """Get the associated public key for a given client ID.

        Args:
            id (str): The client ID to lookup

        Returns:
            tuple[int, int]: The RSA public key in the form (exponent, modulus) 
        """
        return keys.load_key(self._key_file_prefix + client_id + ".pub")

    def get_users(self) -> list[str]:
        """Get a list of all contacts' nicknames.

        Returns:
            list[str]: The nicknames of every known contact. 
        """
        cursor = self._db.cursor()
        cursor.execute("SELECT nickname FROM nicknames")
        nicknames = [aes256.decrypt_cbc(row[0], self._encryption_key, self._nickname_iv).decode('utf-8') for row in cursor.fetchall()]
        return nicknames
