import sqlite3
import os
import random
from . import keys
from .cryptographylib import aes256


class Client_DB:
    def __init__(self, path: str, key_file_prefix: str, encryption_key: int, nickname_iv: int):
        self.db = sqlite3.connect(path)
        self.key_file_prefix = key_file_prefix
        self.encryption_key = encryption_key
        self.nickname_iv = nickname_iv

    def setup(self):
        self.db.execute("CREATE TABLE IF NOT EXISTS nicknames (id text unique, nickname blob unique)")
        self.db.execute("CREATE TABLE IF NOT EXISTS messages (id text, content blob, outgoing integer, timestamp integer, iv text)")
        self.db.commit()

    def get_nickname(self, id: str):
        cursor = self.db.cursor()
        cursor.execute("SELECT nickname FROM nicknames WHERE id=?", (id, ))
        result = cursor.fetchone()
        if result is None:
            return None
        return aes256.decrypt_cbc(result[0], self.encryption_key, self.nickname_iv).decode('utf-8')

    def close(self):
        self.db.close()

    def get_id(self, nickname: str):
        cursor = self.db.cursor()
        nickname_encrypted = aes256.encrypt_cbc(nickname.encode('utf-8'), self.encryption_key, self.nickname_iv)
        cursor.execute("SELECT id FROM nicknames WHERE nickname=?", (nickname_encrypted, ))
        result = cursor.fetchone()
        if result is None:
            return None
        return result[0]

    def get_messages_by_id(self, id: str, count: int) -> list[tuple[bytes, bool]]:
        cursor = self.db.cursor()
        cursor.execute("SELECT content, outgoing, iv FROM messages WHERE id=? ORDER BY timestamp DESC LIMIT ?", (id, count))
        return [(aes256.decrypt_cbc(m[0], self.encryption_key, int(m[2], 16)), bool(m[1])) for m in cursor.fetchall()]

    def get_messages_by_nickname(self, nickname: str, count: int) -> list[tuple[bytes, bool]]:
        nickname_encrypted = aes256.encrypt_cbc(nickname.encode('utf-8'), self.encryption_key, self.nickname_iv)
        cursor = self.db.cursor()
        cursor.execute("SELECT messages.content, messages.outgoing, messages.iv FROM messages INNER JOIN nicknames ON messages.id = nicknames.id WHERE nicknames.nickname=? ORDER BY messages.timestamp DESC LIMIT ?", (nickname_encrypted, count))
        return [(aes256.decrypt_cbc(m[0], self.encryption_key, int(m[2], 16)), bool(m[1])) for m in cursor.fetchall()] 

    def insert_message(self, id: str, message: bytes, sent: bool):
        iv = random.randrange(0, 2**128)
        message_encrypted = aes256.encrypt_cbc(message, self.encryption_key, iv)
        self.db.execute("INSERT INTO messages (id, content, outgoing, timestamp, iv) VALUES (?, ?, ?, strftime('%s','now'), ?)", (id, message_encrypted, int(sent), hex(iv)))
        self.db.commit()

    def set_nickname(self, id: str, nickname: str):
        nickname_encrypted = aes256.encrypt_cbc(nickname.encode('utf-8'), self.encryption_key, self.nickname_iv)
        self.db.execute("REPLACE INTO nicknames VALUES(?, ?)", (id, nickname_encrypted))
        self.db.commit()

    def save_key(self, id: str, key: tuple[int, int]):
        keys.write_key(key, self.key_file_prefix + id)

    def user_known(self, id: str) -> bool:
        return os.path.exists(self.key_file_prefix + id)

    def get_key(self, id: str) -> tuple[int, int]:
        return keys.load_key(self.key_file_prefix + id)

    def get_users(self) -> list[str]:
        cursor = self.db.cursor()
        cursor.execute("SELECT nickname FROM nicknames")
        nicknames = [aes256.decrypt_cbc(row[0], self.encryption_key, self.nickname_iv).decode('utf-8') for row in cursor.fetchall()]
        return nicknames
