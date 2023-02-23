"""Defines a Client_DB class for connecting to the client database. """

import sqlite3
import os
import random
from . import keys
from .cryptography import aes256, sha256


class Client_DB:
    """A connection to the client sqlite3 database"""
    _cached_message_plaintexts = {}
    _cached_nickname_hashes = {}
    _cached_nickname_plaintexts = {}
    _cached_groupname_plaintexts = {}
    _cached_groupname_hashes = {}
    def __init__(self, path: str, key_file_prefix: str, encryption_key: int, nickname_salt: bytes):
        """Constructor for the Client_DB class.

        Args:
            path (str): The path to the sqlite3 database file.
            key_file_prefix (str): A string to prepend to all public key files.
            encryption_key (int): The encryption key to use when storing messages and nicknames.
            nickname_salt (bytes): The salt used when hashing contacts' nicknames
                and the names of groups.
        """
        self._db = sqlite3.connect(path)
        self._key_file_prefix = key_file_prefix
        self._encryption_key = encryption_key
        self._name_salt = nickname_salt

    def setup(self):
        """Create the database if it has not already been created"""

        self._db.execute("CREATE TABLE IF NOT EXISTS nicknames (id text primary key unique, hash text unique, ciphertext blob, iv text)")
        self._db.execute("CREATE TABLE IF NOT EXISTS messages (id integer primary key autoincrement, sender_id text, content blob, outgoing integer, timestamp integer, iv text unique)")
        self._db.execute("CREATE TABLE IF NOT EXISTS group_owners (id text primary key unique, owner_id text)")
        self._db.execute("CREATE TABLE IF NOT EXISTS group_names (id text primary key unique, hash text unique, ciphertext blob, iv text)")
        self._db.execute("CREATE TABLE IF NOT EXISTS group_members (id text, client_id text)")
        self._db.execute("CREATE TABLE IF NOT EXISTS group_messages (id integer primary key autoincrement, group_id text, sender_id text, content blob, timestamp integer, iv text unique)")
        self._db.commit()

    def get_group_name(self, group_id: int) -> str | None:
        """Get the group name associated with a given group id.

        Args:
            group_id (int): The group ID to lookup.

        Returns:
            str | None: The group name (None if it does not exist)
        """
        cursor = self._db.cursor()
        cursor.execute("SELECT ciphertext, iv FROM group_names WHERE id=?", (hex(group_id), ))
        res = cursor.fetchone()
        if res is None:
            return None
        ciphertext, iv_hex = res
        iv = int(iv_hex, 16)
        if (ciphertext, iv) in self._cached_groupname_plaintexts:
            return self._cached_groupname_plaintexts[(ciphertext, iv)]
        else:
            plaintext = aes256.decrypt_cbc(ciphertext, self._encryption_key, iv).decode('utf-8')
            self._cached_groupname_plaintexts[(ciphertext, iv)] = plaintext
            return plaintext

    def get_group_id(self, group_name: str) -> int | None:
        """Get the group id associated with a given group name.

        Args:
            group_name (str): The name of the group to lookup.

        Return:
            int | None: The group id (None if it does not exist)
        """
        cursor = self._db.cursor()
        if group_name in self._cached_groupname_hashes:
            name_hash = self._cached_groupname_hashes[group_name]
        else:
            name_hash = sha256.hash_hex(group_name.encode('utf-8') + self._name_salt)
        cursor.execute("SELECT id FROM group_names WHERE hash=?", (name_hash, ))
        res = cursor.fetchone()
        if res is None:
            return None
        return int(res[0], 16)

    def get_members(self, group_name: str) -> list[str]:
        """Get all the members in the group with the given name.

        Args:
            group_name (str): The name of the group to lookup

        Returns:
            list[str]: A list of all the members of the group (empty if the group does not exist)
        """
        cursor = self._db.cursor()
        if group_name in self._cached_groupname_hashes:
            name_hash = self._cached_groupname_hashes[group_name]
        else:
            name_hash = sha256.hash_hex(group_name.encode('utf-8') + self._name_salt)
            self._cached_groupname_hashes[group_name] = name_hash

        cursor.execute(("SELECT client_id "
                       "FROM group_members "
                       "INNER JOIN group_names "
                       "ON group_names.id = group_members.id "
                       "WHERE group_names.hash = ?"), (name_hash, ))

        results = cursor.fetchall()
        return [result[0] for result in results]

    def get_members_by_id(self, group_id: int) -> list[str]:
        """Get all the members in the group with the given id.

        Args:
            group_id (int): The numeric group id to lookup

        Returns:
            list[str]: A list of all the members of the group (empty if the group does not exist)
        """
        cursor = self._db.cursor()
        cursor.execute("SELECT client_id FROM group_members WHERE id=?", (hex(group_id), ))
        results = cursor.fetchall()
        return [result[0] for result in results]

    def create_group(self, group_name: str, group_id: int, owner_id: str, members: list[str]):
        """Create a group of users with a given name, group id, owner and members.

        Args:
            group_name (str): The name of the group
            group_id (int): The groups numeric ID
            owner_id (str): The client ID of the group's owner
            members (list[str]): The client IDs of all the members of the group
                (can include the owner but they will be added anyway if it does not)
        """
        iv = random.randrange(1, 2**128)
        encrypted_group_name = aes256.encrypt_cbc(group_name.encode('utf-8'), self._encryption_key, iv)
        name_hash = sha256.hash_hex(group_name.encode('utf-8') + self._name_salt)
        self._cached_groupname_plaintexts[(encrypted_group_name, iv)] = group_name
        self._cached_groupname_hashes[group_name] = name_hash
        self._db.execute("INSERT INTO group_names (id, hash, ciphertext, iv) VALUES (?, ?, ?, ?)", (hex(group_id), name_hash, encrypted_group_name, hex(iv)))
        self._db.execute("INSERT INTO group_owners (id, owner_id) VALUES (?, ?)", (hex(group_id), owner_id))
        for member in members:
            self._db.execute("INSERT INTO group_members (id, client_id) VALUES (?, ?)", (hex(group_id), member))
        if owner_id not in members:
            self._db.execute("INSERT INTO group_members (id, client_id) VALUES (?, ?)", (hex(group_id), owner_id))
        self._db.commit()

    def remove_group_member(self, group_id: int, member: str):
        """Remove the specified from the specified group.
        
        Args:
            group_id (int): The numeric ID of the group to operate on.
            member (str): The client ID of the member to remove.
        """
        self._db.execute("DELETE FROM group_members WHERE id=? AND client_id=?", (hex(group_id), member))
        self._db.commit()

    def rename_group(self, group_id: int, name: str):
        """Change the name of a group.

        Args:
            group_id (int): The numeric ID of the group to rename.
            name (str): The new name of the group.
        """
        name_hash = sha256.hash_hex(name.encode('utf-8') + self._name_salt)
        name_iv = random.randrange(1, 2*128) 
        name_ciphertext = aes256.encrypt_cbc(name.encode('utf-8'), self._encryption_key, name_iv)
        self._cached_groupname_hashes[name] = name_hash
        self._cached_groupname_plaintexts[(name_ciphertext, name_iv)] = name
        self._db.execute("UPDATE group_names SET hash=?, iv=?, ciphertext=? WHERE id=?", 
            (name_hash, hex(name_iv), name_ciphertext, hex(group_id)))
        self._db.commit()

    def get_nickname(self, client_id: str) -> str | None:
        """Get the nickname associated with a given client id.

        Args:
            id (str): The client id to lookup (a 64 char hex string)

        Returns:
            str | None: The nickname of the associated contact record (None if there is no such contact)
        """
        cursor = self._db.cursor()
        cursor.execute("SELECT ciphertext, iv FROM nicknames WHERE id=?", (client_id, ))
        result = cursor.fetchone()
        if result is None:
            return None
        ciphertext, iv_hex = result
        iv = int(iv_hex, 16)
        if (ciphertext, iv) in self._cached_nickname_plaintexts:
            return self._cached_nickname_plaintexts[(ciphertext, iv)]
        else:
            plaintext = aes256.decrypt_cbc(ciphertext, self._encryption_key, iv).decode('utf-8')
            self._cached_nickname_plaintexts[(ciphertext, iv)] = plaintext
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
        if nickname in self._cached_nickname_hashes:
            nickname_hash = self._cached_nickname_hashes[nickname]
        else:
            nickname_hash = sha256.hash_hex(nickname.encode('utf-8') + self._name_salt)
            self._cached_nickname_hashes[nickname] = nickname_hash
        cursor.execute("SELECT id FROM nicknames WHERE hash=?", (nickname_hash, ))
        result = cursor.fetchone()
        if result is None:
            return None
        return result[0]

    def get_owner(self, group_id: int) -> str | None:
        """Get the client ID of the owner of a group

        Args:
            group_id (int): The ID of the group to lookup

        Returns:
            str | None: The client ID or None if the group does not exist
        """
        cursor = self._db.cursor()
        cursor.execute("SELECT owner_id FROM group_owners WHERE id=?", (group_id, ))
        result = cursor.fetchone()
        if result is None:
            return None
        return result[0]

    def get_messages_by_id(self, client_id: str, count: int = 0) -> list[tuple[bytes, bool]]:
        """Get the last *count* messages to/from a specified client ID in descending time order.

        Args:
            id (str): The client ID to lookup
            count (int): The number of messages to return

        Returns:
            list[tuple[bytes, bool]]: A list of messages in the format (message, outgoing) where message is the
                raw message bytes and outgoing is a boolean which is True if the message was sent and False if it was received.
        """
        cursor = self._db.cursor()
        cursor.execute(f"SELECT content, outgoing, iv FROM messages WHERE sender_id=? ORDER BY timestamp DESC{' LIMIT ?' if count else ''}",
                       (client_id, count) if count else (client_id, ))
        messages = []
        for m in cursor.fetchall():
            ciphertext, sent, aes_iv = m
            aes_iv = int(aes_iv, 16)
            sent = bool(sent)
            if (ciphertext, aes_iv) in self._cached_message_plaintexts:
                messages.append((self._cached_message_plaintexts[(ciphertext, aes_iv)], sent))
            else:
                plaintext = aes256.decrypt_cbc(ciphertext, self._encryption_key, aes_iv)
                self._cached_message_plaintexts[(ciphertext, aes_iv)] = plaintext
                messages.append((plaintext, sent))
        return messages

    def get_messages_by_nickname(self, nickname: str, count: int = 0) -> list[tuple[bytes, bool]]:
        """Get the last *count* messages to/from a specified nickname in descending time order.

        Args:
            nickname (str): The contact nickname to lookup
            count (int): The number of messages to return (0 if unlimited)

        Returns:
            list[tuple[bytes, bool]]: A list of messages in the format (message, outgoing) where message is the
                raw messages bytes and outgoing is a boolean which is True if the message was sent and False if it was received.
        """
        if nickname in self._cached_nickname_hashes:
            nickname_hash = self._cached_nickname_hashes[nickname]
        else:
            nickname_hash = sha256.hash_hex(nickname.encode('utf-8') + self._name_salt)
            self._cached_nickname_hashes[nickname] = nickname_hash
        cursor = self._db.cursor()
        cursor.execute(("SELECT messages.content, messages.outgoing, messages.iv "
                       "FROM messages "
                       "INNER JOIN nicknames ON messages.sender_id = nicknames.id "
                       "WHERE nicknames.hash=? "
                       "ORDER BY messages.timestamp "
                       "DESC"
                       f"{' LIMIT ?' if count else ''}"), (nickname_hash, count) if count else (nickname_hash, ))

        messages = []
        for m in cursor.fetchall():
            ciphertext, sent, aes_iv = m
            sent = bool(sent)
            aes_iv = int(aes_iv, 16)
            if (ciphertext, aes_iv) in self._cached_message_plaintexts:
                messages.append((self._cached_message_plaintexts[(ciphertext, aes_iv)], sent))
            else:
                plaintext = aes256.decrypt_cbc(ciphertext, self._encryption_key, aes_iv)
                self._cached_message_plaintexts[(ciphertext, aes_iv)] = plaintext
                messages.append((plaintext, sent))
        return messages

    def get_group_messages(self, group_name: str, count: int = 0) -> list[tuple[bytes, str]]:
        """Get all messages to/from a given group

        Args:
            group_name (str): The name of the group to lookup
            count (int): The (maximum) number of messages to return

        Returns:
            list[tuple[bytes, str]]: The last *count* messages in the form (message, sender)
        """
        if group_name in self._cached_groupname_hashes:
            group_name_hash = self._cached_groupname_hashes[group_name]
        else:
            group_name_hash = sha256.hash_hex(group_name.encode('utf-8') + self._name_salt)

        cursor = self._db.cursor()
        cursor.execute(("SELECT group_messages.content, group_messages.iv, IFNULL(nicknames.ciphertext, group_messages.sender_id), nicknames.iv "
                        "FROM group_messages "
                        "INNER JOIN group_names "
                        "ON group_messages.group_id = group_names.id "
                        "LEFT JOIN nicknames "
                        "ON group_messages.sender_id = nicknames.id "
                        "WHERE group_names.hash=? "
                        "ORDER BY timestamp "
                        "DESC"
                        f"{' LIMIT ?' if count else ''}"),
                       (group_name_hash, count) if count else (group_name_hash, ))
        results = cursor.fetchall()

        messages = []
        for result in results:
            encrypted_content, aes_iv, sender, sender_iv_hex = result
            if sender_iv_hex is not None: # if it is an encrypted nickname
                sender_iv = int(sender_iv_hex, 16)
                if (sender, sender_iv) in self._cached_nickname_plaintexts:
                    sender = self._cached_nickname_plaintexts[(sender, sender_iv)]
                else:
                    sender = aes256.decrypt_cbc(sender, self._encryption_key, sender_iv).decode('utf-8')
                    self._cached_nickname_plaintexts[(sender, sender_iv)] = sender

            aes_iv = int(aes_iv, 16)
            if (encrypted_content, aes_iv) in self._cached_message_plaintexts:
                messages.append((self._cached_message_plaintexts[(encrypted_content, aes_iv)], sender))
            else:
                content = aes256.decrypt_cbc(encrypted_content, self._encryption_key, aes_iv)
                self._cached_message_plaintexts[(encrypted_content, aes_iv)] = content
                messages.append((content, sender))
        return messages

    def count_messages(self, nickname: str) -> int:
        """Count the number of messages available from a nickname

        Args:
            nickname (str): The contact nickname to lookup

        Returns:
            int: The number of messages available
        """
        cursor = self._db.cursor()
        if nickname in self._cached_nickname_hashes:
            nickname_hash = self._cached_nickname_hashes[nickname]
        else:
            nickname_hash = sha256.hash_hex(nickname.encode('utf-8') + self._name_salt)
            self._cached_nickname_hashes[nickname] = nickname_hash

        cursor.execute(("SELECT COUNT (*) "
                        "FROM messages "
                        "INNER JOIN nicknames ON messages.id = nicknames.id "
                        "WHERE nicknames.hash=?"), (nickname_hash, ))
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
        self._cached_message_plaintexts[(message_encrypted, aes_iv)] = message
        self._db.execute(("INSERT INTO messages (sender_id, content, outgoing, timestamp, iv) "
                          "VALUES (?, ?, ?, strftime('%s','now'), ?)"),
                         (client_id, message_encrypted, int(sent), hex(aes_iv)))
        self._db.commit()

    def insert_group_message(self, group_id: int, message: bytes, sender: str):
        """Insert a group message into the database

        Args:
            group_id (int): The numeric group id of which the message is part
            message (bytes): The message contents
            sender (str): The id of the message sender
        """
        aes_iv = random.randrange(0, 2**128)
        message_encrypted = aes256.encrypt_cbc(message, self._encryption_key, aes_iv)
        self._cached_message_plaintexts[(message_encrypted, aes_iv)] = message
        self._db.execute("INSERT INTO group_messages (group_id, sender_id, content, timestamp, iv) VALUES (?, ?, ?, strftime('%s','now'), ?)",
                         (hex(group_id), sender, message_encrypted, hex(aes_iv)))
        self._db.commit()

    def set_nickname(self, client_id: str, nickname: str):
        """Set the nickname for a given client id.
        The client id and nickname should be unique.

        Args:
            id (str): The client ID to attach the nickname to.
            nickname (str): The nickname to attach to the client ID.
        """
        nickname_hash = sha256.hash_hex(nickname.encode('utf-8') + self._name_salt)
        self._cached_nickname_hashes[nickname] = nickname_hash
        nickname_iv = random.randrange(1, 2**128)
        nickname_ciphertext = aes256.encrypt_cbc(nickname.encode('utf-8'), self._encryption_key, nickname_iv)
        self._db.execute("INSERT INTO nicknames (id, hash, ciphertext, iv ) VALUES(?, ?, ?, ?)", (client_id, nickname_hash, nickname_ciphertext, hex(nickname_iv)))
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
        if old_nickname in self._cached_nickname_hashes:
            old_nickname_hash = self._cached_nickname_hashes[old_nickname]
        else:
            old_nickname_hash = sha256.hash_hex(old_nickname.encode('utf-8') + self._name_salt)
            self._cached_nickname_hashes[old_nickname] = old_nickname_hash

        new_nickname_hash = sha256.hash_hex(new_nickname.encode('utf-8') + self._name_salt)
        new_nickname_iv = random.randrange(1, 2**128)
        new_nickname_ciphertext = aes256.encrypt_cbc(new_nickname.encode('utf-8'), self._encryption_key, new_nickname_iv)
        self._db.execute("UPDATE nicknames SET hash=?, ciphertext=?, iv=? WHERE hash=?",
                         (new_nickname_hash, new_nickname_ciphertext, hex(new_nickname_iv), old_nickname_hash))
        self._db.commit()

    def change_group_id(self, old_id: int, new_id: int):
        """Update the group ID of a group

        Args:
            old_id (int): The ID of the group to update
            new_id (int): The new ID of the group
        """
        self._db.execute("UPDATE group_names SET id=? WHERE id=?", (hex(new_id), hex(old_id)))
        self._db.execute("UPDATE group_messages SET group_id=? WHERE group_id=?", (hex(new_id), hex(old_id)))
        self._db.execute("UPDATE group_members SET id=? WHERE id=?", (hex(new_id), hex(old_id)))
        self._db.execute("UPDATE group_owners SET id=? WHERE id=?", (hex(new_id), hex(old_id)))
        self._db.commit()

    def delete_group_by_group_name(self, group_name: str):
        """Delete the group with a given name

        Args:
            group_name (str): The name of the group to delete
        """
        if group_name in self._cached_groupname_hashes:
            groupname_hash = self._cached_groupname_hashes[group_name]
        else:
            groupname_hash = sha256.hash_hex(group_name.encode('utf-8') + self._name_salt)
            self._cached_groupname_hashes[group_name] = groupname_hash
        self._db.execute("DELETE FROM group_messages WHERE group_id IN (SELECT id FROM group_names WHERE hash=?)", (groupname_hash, ))
        self._db.execute("DELETE FROM group_members WHERE id IN (SELECT id FROM group_names WHERE hash=?)", (groupname_hash, ))
        self._db.execute("DELETE FROM group_owners WHERE id IN (SELECT id FROM group_names WHERE hash=?)", (groupname_hash, ))
        self._db.execute("DELETE FROM group_names WHERE hash=?", (groupname_hash, ))
        self._db.commit()

    def delete_group_by_group_id(self, group_id: int):
        """Delete the group with a given group id

        Args:
            group_id (int): The numeric group id of the group to delete
        """
        self._db.execute("DELETE FROM group_messages WHERE group_id=?", (hex(group_id), ))
        self._db.execute("DELETE FROM group_members WHERE id=?", (hex(group_id), ))
        self._db.execute("DELETE FROM group_owners WHERE id=?", (hex(group_id), ))
        self._db.execute("DELETE FROM group_names WHERE id=?", (hex(group_id), ))
        self._db.commit()

    def delete_contact_by_nickname(self, nickname: str):
        """Delete the contact entry and all messages associated with a given nickname.

        Args:
            nickname (str): The nickname of the contact to delete
        """
        if nickname in self._cached_nickname_hashes:
            nickname_hash = self._cached_nickname_hashes[nickname]
        else:
            nickname_hash = sha256.hash_hex(nickname.encode('utf-8') + self._name_salt)
            self._cached_nickname_hashes[nickname] = nickname_hash
        self._db.execute("DELETE FROM messages WHERE sender_id IN (SELECT id FROM nicknames WHERE hash=?)", (nickname_hash, ))
        self._db.execute("DELETE FROM nicknames WHERE hash=?", (nickname_hash, ))
        self._db.commit()

    def delete_contact_by_id(self, client_id: str):
        """Delete all messages from and the contact record of a given client ID.

        Args:
            client_id (str): The ID of the contact to delete
        """
        self._db.execute("DELETE FROM messages WHERE sender_id=?", (client_id, ))
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
        keypath = self._key_file_prefix + client_id + ".pub"
        return os.path.exists(keypath) and os.path.getsize(keypath) > 0

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
        cursor.execute("SELECT ciphertext, iv FROM nicknames")
        nicknames = []
        for ciphertext, iv_hex in cursor.fetchall():
            iv = int(iv_hex, 16)
            if (ciphertext, iv) in self._cached_nickname_plaintexts:
                nicknames.append(self._cached_nickname_plaintexts[(ciphertext, iv)])
            else:
                plaintext = aes256.decrypt_cbc(ciphertext, self._encryption_key, iv).decode('utf-8')
                self._cached_nickname_plaintexts[(ciphertext, iv)] = plaintext
                nicknames.append(plaintext)
        return nicknames

    def get_groups(self) -> list[str]:
        """Get a list of all group names.

        Returns:
            list[str]: The names of all groups of which you are part.
        """
        cursor = self._db.cursor()
        cursor.execute("SELECT ciphertext, iv FROM group_names")
        names = []
        for ciphertext, iv_hex in cursor.fetchall():
            iv = int(iv_hex, 16)
            if (ciphertext, iv) in self._cached_groupname_plaintexts:
                names.append(self._cached_groupname_plaintexts[(ciphertext, iv)])
            else:
                plaintext = aes256.decrypt_cbc(ciphertext, self._encryption_key, iv).decode('utf-8')
                self._cached_groupname_plaintexts[(ciphertext, iv)] = plaintext
                names.append(plaintext)
        return names
