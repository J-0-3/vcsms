import sqlite3
import math
class Client_DB:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.MESSAGE_BLOCK_LENGTH = 100
    def setup(self):
        self.db.execute("CREATE TABLE IF NOT EXISTS nicknames (id text unique, nickname text unique)")
        self.db.execute("CREATE TABLE IF NOT EXISTS message_logs (id text, filename_index integer)")
        self.db.commit()
    def get_nickname(self, id: str):
        cursor = self.db.cursor()
        cursor.execute("SELECT nickname FROM nicknames WHERE id=?", (id, ))
        return cursor.fetchone()[0]

    def get_id(self, nickname: str):
        cursor = self.db.cursor()
        cursor.execute("SELECT id FROM nicknames WHERE nickname=?", (nickname, ))

    def get_messages_by_id(self, id: str, count: int):
        cursor = self.db.cursor()
        num_files = math.ceil(count/self.MESSAGE_BLOCK_LENGTH)
        cursor.execute("SELECT filename_index FROM message_logs WHERE id=? ORDER BY filename_index DESC LIMIT ?", (id, num_files))
        files = cursor.fetchall()
        messages = []
        for file in files:
            try:
                with open(file, 'r') as f:
                    entries = f.read().split(',')
                    for e in entries:
                        messages.append(e)
            except FileNotFoundError:
                print(f"WARNING: FILE NOT FOUND {file}")
        return messages

    def get_messages_by_nickname(self, nickname: str, count: int):
        cursor = self.db.cursor()
        num_files = math.ceil(count / self.MESSAGE_BLOCK_LENGTH)
        cursor.execute("SELECT l.filename_index FROM message_logs l INNER JOIN nicknames n ON l.id = n.id  WHERE n.nickname=? ORDER BY l.filename_index DESC LIMIT? ", (nickname, num_files))
        files = cursor.fetchall()
        messages = []
        for file in files:
            try:
                with open(file, 'r') as f:
                    entries = f.read().split(',')
                    for e in entries:
                        messages.append(e)
            except FileNotFoundError:
                print(f"WARNING FILE NOT FOUND {file}")

        return messages

    def store_messages(self, messages: dict):
        messages_by_sender = {}
        for message, sender_id in messages:
            if sender_id in messages_by_sender:
                messages_by_sender[sender_id].append(message)
            else:
                messages_by_sender[sender_id] = [message]

        for sender, messages in messages_by_sender:
            cursor = self.db.cursor()
            cursor.execute("SELECT ")
            last_filename