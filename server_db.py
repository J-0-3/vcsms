import sqlite3


class Server_DB:
    def __init__(self, path=':memory:'):
        self.db = sqlite3.connect(path)
        self.cursor = self.db.cursor()
    def setup_db(self):
        self.cursor.execute("create table if not exists public_keys (id text, exponent integer, modulus integer)")
        self.cursor.execute("create table if not exists connection_log (id text, time text)")
        self.cursor.execute("create table if not exists logged_in (id text, connected integer)")
    def user_login(self, id: str, pubkey: tuple, ):