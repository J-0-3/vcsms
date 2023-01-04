"""Defines a Client_DB class for connecting to the client database. """

import sqlite3
import os
import random
from . import keys
from .cryptographylib import aes256


class Client_DB:
    _cached_message_plaintexts = {}
    _cached_nickname_ciphertexts = {}
    _cached_nickname_plaintexts = {}
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
        if result[0] in self._cached_nickname_plaintexts:
            return self._cached_nickname_plaintexts[result[0]]
        else:
            plaintext = aes256.decrypt_cbc(result[0], self._encryption_key, self._nickname_iv).decode('utf-8')
            self._cached_nickname_plaintexts[result[0]] = plaintext
            self._cached_nickname_ciphertexts[plaintext] = result[0]
            return plaintext

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
        if nickname in self._cached_nickname_ciphertexts:
            nickname_encrypted = self._cached_nickname_ciphertexts[nickname]
        else:
            nickname_encrypted = aes256.encrypt_cbc(nickname.encode('utf-8'), self._encryption_key, self._nickname_iv)
            self._cached_nickname_ciphertexts[nickname] = nickname_encrypted
            self._cached_nickname_plaintexts[nickname_encrypted] = nickname
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
        messages = []
        for m in cursor.fetchall():
           if m[0] in self._cached_message_plaintexts:
               messages.append((self._cached_message_plaintexts[m[0]], bool(m[1])))
           else:
               plaintext = aes256.decrypt_cbc(m[0], self._encryption_key, int(m[2], 16))
               self._cached_message_plaintexts[m[0]] = plaintext
               messages.append((plaintext, bool(m[1])))
        return messages

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
        cursor.execute(("SELECT messages.content, messages.outgoing, messages.iv "
                       "FROM messages "
                       "INNER JOIN nicknames ON messages.id = nicknames.id "
                       "WHERE nicknames.nickname=? "
                       "ORDER BY messages.timestamp "
                       "DESC "
                       "LIMIT ?"), (nickname_encrypted, count))

        messages = []
        for m in cursor.fetchall():
           if m[0] in self._cached_message_plaintexts:
               messages.append((self._cached_message_plaintexts[m[0]], bool(m[1])))
           else:
               plaintext = aes256.decrypt_cbc(m[0], self._encryption_key, int(m[2], 16))
               self._cached_message_plaintexts[m[0]] = plaintext
               messages.append((plaintext, bool(m[1])))
        return messages

    def count_messages(self, nickname: str) -> int:
        """Count the number of messages available from a nickname

        Args:
            nickname (str): The contact nickname to lookup

        Returns:
            int: The number of messages available
        """
        cursor = self._db.cursor()
        if nickname in self._cached_nickname_ciphertexts:
            nickname_encrypted = self._cached_nickname_ciphertexts[nickname]
        else:
            nickname_encrypted = aes256.encrypt_cbc(nickname.encode('utf-8'), self._encryption_key, self._nickname_iv)
            self._cached_nickname_ciphertexts[nickname] = nickname_encrypted
            self._cached_nickname_plaintexts[nickname_encrypted] = nickname
        cursor.execute(("SELECT COUNT (*) "
                        "FROM messages "
                        "INNER JOIN nicknames ON messages.id = nicknames.id "
                        "WHERE nicknames.nickname=?"), (nickname_encrypted, ))
        return cursor.fetchone()[0]

    def insert_message(self, client_id: str, message: bytes, sent: bool):
        """Insert a message into the database.

        Args:
            id (str): The client id which the message was sent to/received from.
            message (bytes): The message contents.
            sent (bool): Whether the message was sent (False if it was received).
        """
        aes_iv = random.randrange(0, 2**128)
        message_encrypted = aes256.encrypt_cbc(message, self._encryption_key, aes_iv)
        self._cached_message_plaintexts[message_encrypted] = message
        self._db.execute("INSERT INTO messages (id, content, outgoing, timestamp, iv) VALUES (?, ?, ?, strftime('%s','now'), ?)", (client_id, message_encrypted, int(sent), hex(aes_iv)))
        self._db.commit()

    def set_nickname(self, client_id: str, nickname: str):
        """Set the nickname for a given client id.

        Args:
            id (str): The client ID to attach the nickname to.
            nickname (str): The nickname to attach to the client ID.
        """
        nickname_encrypted = aes256.encrypt_cbc(nickname.encode('utf-8'), self._encryption_key, self._nickname_iv)
        self._cached_nickname_ciphertexts[nickname] = nickname_encrypted
        self._cached_nickname_plaintexts[nickname_encrypted] = nickname
        self._db.execute("REPLACE INTO nicknames VALUES(?, ?)", (client_id, nickname_encrypted))
        self._db.commit()

    def change_nickname(self, old_nickname: str, new_nickname: str):
        """Change the nickname for the client ID associated with the old nickname.

        Does nothing if the old nickname does not exist.

        Args:
            old_nickname (str): The nickname to change.
            new_nickname (str): The nickname to change it to.

        Raises:
            sqlite3.IntegrityError: The new nickname is already in use.
        """
        if old_nickname in self._cached_nickname_ciphertexts:
            encrypted_old_nickname = self._cached_nickname_ciphertexts[old_nickname]
        else:
            encrypted_old_nickname = aes256.encrypt_cbc(old_nickname.encode('utf-8'), self._encryption_key, self._nickname_iv)
            self._cached_nickname_ciphertexts[old_nickname] = encrypted_old_nickname
            self._cached_nickname_plaintexts[encrypted_old_nickname] = old_nickname

        if new_nickname in self._cached_nickname_ciphertexts:
            encrypted_new_nickname = self._cached_nickname_ciphertexts[new_nickname]
        else:
            encrypted_new_nickname = aes256.encrypt_cbc(new_nickname.encode('utf-8'), self._encryption_key, self._nickname_iv)
            self._cached_nickname_ciphertexts[new_nickname] = encrypted_new_nickname
            self._cached_nickname_plaintexts[encrypted_new_nickname] = new_nickname

        self._db.execute("UPDATE nicknames SET nickname=? WHERE nickname=?", (encrypted_new_nickname, encrypted_old_nickname))
        self._db.commit()

    def delete_contact_by_nickname(self, nickname: str):
        """Delete the contact entry and all messages associated with a given nickname.
        
        Args:
            nickname (str): The nickname of the contact to delete
        """
        if nickname in self._cached_nickname_ciphertexts:
            encrypted_nickname = self._cached_nickname_ciphertexts[nickname]
        else:
            encrypted_nickname = aes256.encrypt_cbc(nickname.encode('utf-8'), self._encryption_key, self._nickname_iv)
            self._cached_nickname_ciphertexts[nickname] = encrypted_nickname
            self._cached_nickname_plaintexts[encrypted_nickname] = nickname
        self._db.execute("DELETE FROM messages WHERE id IN (SELECT id FROM nicknames WHERE nickname=?)", (encrypted_nickname, ))
        self._db.execute("DELETE FROM nicknames WHERE nickname=?", (encrypted_nickname, ))
        self._db.commit()

    def delete_contact_by_id(self, client_id: str):
        self._db.execute("DELETE FROM messages WHERE id=?", (client_id, ))
        self._db.execute("DELETE FROM nicknames WHERE id=?", (client_id, ))
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
        nicknames = []
        for nickname in cursor.fetchall():
            if nickname[0] in self._cached_nickname_plaintexts:
                nicknames.append(self._cached_nickname_plaintexts[nickname[0]])
            else:
                plaintext = aes256.decrypt_cbc(nickname[0], self._encryption_key, self._nickname_iv).decode('utf-8')
                self._cached_nickname_ciphertexts[plaintext] = nickname[0]
                self._cached_nickname_plaintexts[nickname[0]] = plaintext
                nicknames.append(plaintext)
        return nicknames
