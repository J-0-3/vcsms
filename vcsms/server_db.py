import sqlite3
import os
from . import keys

class Server_DB:
    def __init__(self, path='server.db', pubkey_directory='client_public_keys'):
        self.db = sqlite3.connect(path)
        self.pubkeys = pubkey_directory

    def setup_db(self):
        self.db.execute("create table if not exists connection_log (id text, time text)")
        self.db.execute("create table if not exists logged_in (id text unique, connected integer)")
        self.db.execute("update logged_in set connected=0")
        self.db.commit()

    def user_known(self, id: str) -> bool:
        return os.path.exists(os.path.join(self.pubkeys, id))

    def user_login(self, id: str, pubkey: tuple):

        if not self.user_known(id):
            keys.write_key(pubkey, os.path.join(self.pubkeys, id))

        self.db.execute("insert into connection_log values(?, datetime('now', 'localtime'))", (id, ))
        self.db.execute("replace into logged_in values(?, 1)", (id, ))
        self.db.commit()

    def user_logout(self, id: str):
        self.db.execute("replace into logged_in values(?, 0)", (id, ))
        self.db.commit()

    def is_logged_in(self, id: str) -> bool:
        cursor = self.db.execute("select connected from logged_in where id=?", (id, ))
        values = cursor.fetchone()
        if values is None or values[0] == 0:
            return False
        return True

    def get_pubkey(self, id: str) -> tuple:

        if os.path.exists(os.path.join(self.pubkeys, id)):
            key = keys.load_key(os.path.join(self.pubkeys, id))
            return key
        else:
            raise Exception("User not found")

    def close(self):
        self.db.close()
